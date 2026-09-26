// Campaigns API: CRUD + targets + launch + send.
package api

import (
	"time"
	"encoding/json"
	"io"
	"net/http"
	"strings"

	"github.com/phantom-v2/phantom/internal/campaign"
)

// CampService — то что нужно от campaign.Service (тестируемый интерфейс).
type CampService interface {
	Create(name, phishletID string, ttlMin, maxUses int) *campaign.Campaign
	AddTargets(campaignID string, emails []string) int
	Launch(id string) ([]*campaign.Target, error)
	SendAll(id, subject, body, urlBase string) (int, error)
	Stats(id string) (sent, opened, clicked, submitted, total int)
	Get(id string) (*campaign.Campaign, bool)
	List() []*campaign.Campaign
	CreateStop(name, phishletID string, ttlMin, maxUses int, stopAt time.Time) *campaign.Campaign
}

func campRoutes(mux *http.ServeMux, d Deps, guard func(http.HandlerFunc) http.HandlerFunc) {
	svc := func() CampService {
		if s, ok := d.Campaigns.(CampService); ok {
			return s
		}
		return nil
	}
	mux.HandleFunc("/api/v1/campaigns", guard(func(w http.ResponseWriter, r *http.Request) {
		s := svc()
		if s == nil {
			http.Error(w, "campaigns disabled", http.StatusNotImplemented)
			return
		}
		switch r.Method {
		case http.MethodGet:
			out := []map[string]any{}
			for _, c := range s.List() {
				sent, opened, clicked, submitted, total := s.Stats(c.ID)
				out = append(out, map[string]any{
					"id": c.ID, "name": c.Name, "phishlet": c.PhishletID,
					"status": c.Status, "sent": sent, "opened": opened,
					"clicked": clicked, "submitted": submitted, "total": total,
				})
			}
			_ = json.NewEncoder(w).Encode(out)
		case http.MethodPost:
			var in struct {
				Name       string `json:"name"`
				PhishletID string `json:"phishlet_id"`
				TTLMin     int    `json:"ttl_min"`
				MaxUses    int    `json:"max_uses"`
				EndsAt     int64  `json:"ends_at"`
			}
			if err := json.NewDecoder(io.LimitReader(r.Body, 64<<10)).Decode(&in); err != nil || in.Name == "" || in.PhishletID == "" {
				http.Error(w, "need name, phishlet_id", http.StatusBadRequest)
				return
			}
			var stop time.Time
			if in.EndsAt > 0 {
				stop = time.Unix(in.EndsAt, 0)
			}
			c := s.CreateStop(in.Name, in.PhishletID, in.TTLMin, in.MaxUses, stop)
			w.WriteHeader(http.StatusCreated)
			_ = json.NewEncoder(w).Encode(map[string]string{"id": c.ID})
		default:
			http.Error(w, "method", http.StatusMethodNotAllowed)
		}
	}))
	mux.HandleFunc("/api/v1/campaigns/", guard(func(w http.ResponseWriter, r *http.Request) {
		s := svc()
		if s == nil {
			http.Error(w, "campaigns disabled", http.StatusNotImplemented)
			return
		}
		rest := strings.Trim(strings.TrimPrefix(r.URL.Path, "/api/v1/campaigns/"), "/")
		parts := strings.SplitN(rest, "/", 2)
		id, act := parts[0], ""
		if len(parts) == 2 {
			act = parts[1]
		}
		if id == "" || strings.Contains(id, "/") {
			http.Error(w, "bad id", http.StatusBadRequest)
			return
		}
		if r.Method != http.MethodPost {
			http.Error(w, "method", http.StatusMethodNotAllowed)
			return
		}
		switch act {
		case "targets":
			var in struct {
				Emails []string `json:"emails"`
			}
			if err := json.NewDecoder(io.LimitReader(r.Body, 1<<20)).Decode(&in); err != nil {
				http.Error(w, "bad json", http.StatusBadRequest)
				return
			}
			_ = json.NewEncoder(w).Encode(map[string]int{"added": s.AddTargets(id, in.Emails)})
		case "launch":
			targets, err := s.Launch(id)
			if err != nil {
				http.Error(w, err.Error(), http.StatusBadRequest)
				return
			}
			out := make([]map[string]string, 0, len(targets))
			for _, t := range targets {
				out = append(out, map[string]string{"email": t.Email, "lure": t.LurePath})
			}
			_ = json.NewEncoder(w).Encode(map[string]any{"targets": out})
		case "send":
			var in struct {
				Subject string `json:"subject"`
				Body    string `json:"body"`
				URLBase string `json:"url_base"`
			}
			if err := json.NewDecoder(io.LimitReader(r.Body, 1<<20)).Decode(&in); err != nil || in.Subject == "" {
				http.Error(w, "need subject, body, url_base", http.StatusBadRequest)
				return
			}
			n, err := s.SendAll(id, in.Subject, in.Body, in.URLBase)
			if err != nil {
				http.Error(w, err.Error(), http.StatusBadRequest)
				return
			}
			_ = json.NewEncoder(w).Encode(map[string]int{"sent": n})
		default:
			http.Error(w, "bad action (targets|launch|send)", http.StatusBadRequest)
		}
	}))
}
