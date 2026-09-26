// Package puppet — Evilpuppet до талого (без внешнего браузера).
// HttpTelemetry (факт живого upstream) + Fingerprint Challenge:
// коллектор /__fp.js собирает webdriver/plugins/canvas и постит в /__fp/report,
// боты банятся в blocklist. Полный Playwright — только если появится в лабе.
package puppet

import (
	"context"
	"encoding/json"
	"net"
	"net/http"
	"strings"
)

// CollectorFor собирает коллектор под префикс путей.
// Collector — дефолтный /__fp (совместимость).
func CollectorFor(prefix string) string {
	return strings.ReplaceAll(collectorJS, "/__fp/report", prefix+"/report")
}

const collectorJS = `(function(){var t0=performance.now(),mx=0,md=0,lx=-1,ly=-1;addEventListener("mousemove",function(e){mx++;if(lx>=0){md+=Math.abs(e.clientX-lx)+Math.abs(e.clientY-ly);}lx=e.clientX;ly=e.clientY;},{passive:true});addEventListener("scroll",function(){md++;},{passive:true});function send(){var d={webdriver:!!navigator.webdriver,plugins:(navigator.plugins||[]).length,lang:navigator.language||"",tz:(Intl.DateTimeFormat().resolvedOptions().timeZone||"")};try{var c=document.createElement("canvas").getContext("2d");c.fillText("phantom",0,0);d.canvas=1;}catch(e){d.canvas=0;d.mx=mx;d.md=Math.round(md);d.dt=Math.round(performance.now()-t0);try{var g=document.createElement("canvas").getContext("webgl");d.webgl=g?g.getParameter(g.RENDERER):"";}catch(e){d.webgl="";}}fetch("/__fp/report",{method:"POST",headers:{"Content-Type":"application/json"},body:JSON.stringify(d)}).catch(function(){});}setTimeout(send,1500);})();`

var Collector = CollectorFor("/__fp")

type Reporter struct {
	Prefix string // дефолт /__fp
	Block  interface{ Block(key, reason string) }
	Bus    interface {
		Publish(ctx context.Context, topic string, payload any) error
	}
}

func (p Reporter) prefix() string {
	if p.Prefix != "" {
		return p.Prefix
	}
	return "/__fp"
}

func (p Reporter) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	pre := p.prefix()
	switch {
	case r.URL.Path == pre+".js" && r.Method == http.MethodGet:
		w.Header().Set("Content-Type", "application/javascript")
		_, _ = w.Write([]byte(CollectorFor(pre)))
	case r.URL.Path == pre+"/report" && r.Method == http.MethodPost:
		var in struct {
			Webdriver bool   `json:"webdriver"`
			Plugins   int    `json:"plugins"`
			Lang      string `json:"lang"`
			WebGL     string `json:"webgl"`
			MX        int    `json:"mx"`
			MD        int    `json:"md"`
			DT        int64  `json:"dt"`
		}
		_ = json.NewDecoder(r.Body).Decode(&in)
		ip := clientIP(r)
		bot := Score(in.Webdriver, in.Plugins, in.Lang, in.WebGL, in.MX, in.MD, in.DT)
		if bot {
			p.Block.Block(ip, "fp-challenge")
			if p.Bus != nil {
				_ = p.Bus.Publish(r.Context(), "bot.blocked", map[string]string{"ip": ip, "why": "fp"})
			}
		} else {
			// Человек: cookie-пропуск для smart-lures с RequireChallenge (10 мин).
			http.SetCookie(w, &http.Cookie{
				Name: "__fp_ok", Value: "1", Path: "/",
				MaxAge: 600, SameSite: http.SameSiteLaxMode,
			})
		}
		w.WriteHeader(http.StatusNoContent)
	default:
		http.NotFound(w, r)
	}
}

// clientIP — первый X-Forwarded-For без порта (зеркало engine remoteIP).
func clientIP(r *http.Request) string {
	h := r.Header.Get("X-Forwarded-For")
	if h == "" {
		h = r.RemoteAddr
	} else if i := strings.Index(h, ","); i >= 0 {
		h = h[:i]
	}
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

// Score поведенческий скоринг: true означает бот.
// webdriver всегда бан; headless-сигналы плюс нулевая мышиная
// энтропия за окно 1.5 секунды (песочницы без эмуляции input).
func Score(webdriver bool, plugins int, lang, webgl string, mx, md int, dt int64) bool {
	if webdriver {
		return true
	}
	signals := 0
	if plugins == 0 {
		signals++
	}
	if lang == "" {
		signals++
	}
	if webgl == "" || webgl == "SwiftShader" || webgl == "llvmpipe" {
		signals++
	}
	if dt >= 1400 && mx == 0 && md == 0 {
		signals++
	}
	return signals >= 2
}
