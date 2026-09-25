// Package blocklist — IP/JA4 бан (Evilginx blacklist паритет).
package blocklist

import "sync"

type Store struct {
	mu sync.RWMutex
	m  map[string]string // key -> reason
}

func New() *Store { return &Store{m: map[string]string{}} }

func (s *Store) Block(key, reason string) {
	if key == "" {
		return
	}
	s.mu.Lock()
	s.m[key] = reason
	s.mu.Unlock()
}

func (s *Store) Blocked(key string) bool {
	if key == "" {
		return false
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	_, ok := s.m[key]
	return ok
}

func (s *Store) Reason(key string) string {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.m[key]
}
