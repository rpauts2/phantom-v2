// Package campaign — менеджер кампаний (лучше Gophish):
// per-target одноразовые smart-lures, трекинг open/click/submit,
// Botguard-щит на лендингах, управление из меню/API.
// Почта — internal/mailer; креды SMTP только env.
package campaign

import (
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"
)

// Status жизненного цикла.
const (
	StatusDraft   = "draft"
	StatusRunning = "running"
	StatusDone    = "done"
)

// Campaign — рассылка на фишлет.
type Campaign struct {
	ID         string
	Name       string
	PhishletID string
	LureBase   string // префикс путей, напр. /l/cmp01
	TTLMin     int
	MaxUses    int // 1 = одноразовые (дефолт)
	Status     string
	CreatedAt  time.Time
}

// Target — получатель с персональной приманкой.
type Target struct {
	ID         string
	CampaignID string
	Email      string
	LurePath   string
	SentAt     time.Time
	OpenedAt   time.Time
	ClickedAt  time.Time
	Submitted  bool
}

// Event — трекинг: sent/open/click/submit.
type Event struct {
	Kind       string // sent|open|click|submit
	TargetID   string
	CampaignID string
	At         time.Time
}

// Persister — sqlite-персист (реализация *sqlite.DB, wire в main).
// Методы best-effort: ошибка уходит в OnError, поток не рвется.
type Persister interface {
	UpsertCampaign(id, name, phishletID, status string, ttlMin, maxUses int, createdAt int64) error
	UpsertTarget(id, campaignID, email, lure string, sent, opened, clicked, submitted bool) error
}

// maxEvents — потолок истории событий (память долгоживущего процесса).
const maxEvents = 10000

// Store — in-memory + персист через DAO (sqlite, wire в main).
type Store struct {
	mu        sync.RWMutex
	campaigns map[string]*Campaign
	targets   map[string]*Target
	byLure    map[string]string // lurePath -> targetID
	events    []Event
	DB        Persister
	OnError   func(error)
}

func (s *Store) persist(fn func() error) {
	if s.DB == nil {
		return
	}
	if err := fn(); err != nil && s.OnError != nil {
		s.OnError(err)
	}
}

// Restore загружает кампанию+цели из персиста (старт сервера).
func (s *Store) Restore(c Campaign, targets []Target) {
	s.mu.Lock()
	defer s.mu.Unlock()
	cp := c
	s.campaigns[c.ID] = &cp
	for _, t := range targets {
		tt := t
		s.targets[t.ID] = &tt
		s.byLure[t.LurePath] = t.ID
	}
}

func NewStore() *Store {
	return &Store{
		campaigns: map[string]*Campaign{},
		targets:   map[string]*Target{},
		byLure:    map[string]string{},
	}
}

// Create черновик.
func (s *Store) Create(name, phishletID string, ttlMin, maxUses int) *Campaign {
	if maxUses <= 0 {
		maxUses = 1
	}
	c := &Campaign{
		ID: uuid.NewString()[:8], Name: name, PhishletID: phishletID,
		LureBase: "/l/" + strings.ToLower(slug(name)) + "-",
		TTLMin: ttlMin, MaxUses: maxUses,
		Status: StatusDraft, CreatedAt: time.Now(),
	}
	s.mu.Lock()
	s.campaigns[c.ID] = c
	s.mu.Unlock()
	s.persist(func() error {
		return s.DB.UpsertCampaign(c.ID, c.Name, c.PhishletID, c.Status, c.TTLMin, c.MaxUses, c.CreatedAt.Unix())
	})
	return c
}

// AddTargets пачкой (дубли и мусор отбрасываются).
func (s *Store) AddTargets(campaignID string, emails []string) int {
	s.mu.Lock()
	defer s.mu.Unlock()
	c, ok := s.campaigns[campaignID]
	if !ok || c.Status != StatusDraft {
		return 0
	}
	n := 0
	for _, e := range emails {
		e = strings.ToLower(strings.TrimSpace(e))
		if !strings.Contains(e, "@") || strings.ContainsAny(e, " \t,;") {
			continue
		}
		dup := false
		for _, t := range s.targets {
			if t.CampaignID == campaignID && t.Email == e {
				dup = true
				break
			}
		}
		if dup {
			continue
		}
		id := uuid.NewString()[:8]
		path := fmt.Sprintf("%s%s", c.LureBase, id)
		t := &Target{ID: id, CampaignID: campaignID, Email: e, LurePath: path}
		s.targets[id] = t
		s.byLure[path] = id
		n++
		pp := *t
		s.persist(func() error {
			return s.DB.UpsertTarget(pp.ID, pp.CampaignID, pp.Email, pp.LurePath, false, false, false, false)
		})
	}
	return n
}

// Launch переводит в running, возвращает цели для рассылки.
func (s *Store) Launch(campaignID string) ([]*Target, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	c, ok := s.campaigns[campaignID]
	if !ok {
		return nil, fmt.Errorf("unknown campaign")
	}
	if c.Status != StatusDraft {
		return nil, fmt.Errorf("already %s", c.Status)
	}
	if len(s.targetsFor(campaignID)) == 0 {
		return nil, fmt.Errorf("no targets")
	}
	c.Status = StatusRunning
	s.persist(func() error {
		return s.DB.UpsertCampaign(c.ID, c.Name, c.PhishletID, c.Status, c.TTLMin, c.MaxUses, c.CreatedAt.Unix())
	})
	return s.targetsFor(campaignID), nil
}

// Mark фиксирует событие трекинга.
func (s *Store) Mark(targetID, kind string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	t, ok := s.targets[targetID]
	if !ok {
		return
	}
	now := time.Now()
	switch kind {
	case "sent":
		t.SentAt = now
	case "open":
		if t.OpenedAt.IsZero() {
			t.OpenedAt = now
		}
	case "click":
		if t.ClickedAt.IsZero() {
			t.ClickedAt = now
		}
	case "submit":
		t.Submitted = true
	default:
		return
	}
	s.events = append(s.events, Event{kind, targetID, t.CampaignID, now})
	if len(s.events) > maxEvents {
		s.events = append([]Event(nil), s.events[len(s.events)-maxEvents:]...)
	}
	tt := *t
	s.persist(func() error {
		return s.DB.UpsertTarget(tt.ID, tt.CampaignID, tt.Email, tt.LurePath,
			!tt.SentAt.IsZero(), !tt.OpenedAt.IsZero(), !tt.ClickedAt.IsZero(), tt.Submitted)
	})
}

// TargetByLure — резолюция персональной приманки.
func (s *Store) TargetByLure(path string) (*Target, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	id, ok := s.byLure[path]
	if !ok {
		return nil, false
	}
	t, ok := s.targets[id]
	return t, ok
}

// Stats счетчики кампании.
func (s *Store) Stats(campaignID string) (sent, opened, clicked, submitted, total int) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	for _, t := range s.targets {
		if t.CampaignID != campaignID {
			continue
		}
		total++
		if !t.SentAt.IsZero() {
			sent++
		}
		if !t.OpenedAt.IsZero() {
			opened++
		}
		if !t.ClickedAt.IsZero() {
			clicked++
		}
		if t.Submitted {
			submitted++
		}
	}
	return
}

func (s *Store) targetsFor(campaignID string) []*Target {
	var out []*Target
	for _, t := range s.targets {
		if t.CampaignID == campaignID {
			out = append(out, t)
		}
	}
	return out
}

// EventsCount — размер истории (мониторинг bound).
func (s *Store) EventsCount() int {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return len(s.events)
}

func (s *Store) Get(id string) (*Campaign, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	c, ok := s.campaigns[id]
	return c, ok
}

func (s *Store) List() []*Campaign {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make([]*Campaign, 0, len(s.campaigns))
	for _, c := range s.campaigns {
		out = append(out, c)
	}
	return out
}

func slug(s string) string {
	var b strings.Builder
	for _, r := range strings.ToLower(s) {
		switch {
		case r >= 'a' && r <= 'z', r >= '0' && r <= '9':
			b.WriteRune(r)
		default:
			b.WriteRune('-')
		}
	}
	out := strings.Trim(b.String(), "-")
	if out == "" {
		out = "cmp"
	}
	if len(out) > 16 {
		out = out[:16]
	}
	return out
}
