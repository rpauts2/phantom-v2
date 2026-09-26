// Package blocklist — IP/JA4 бан (Evilginx blacklist паритет).
package blocklist

import (
	"net"
	"strings"
	"sync"
)

type Store struct {
	mu sync.RWMutex
	m  map[string]string // key -> reason
}

func New() *Store { return &Store{m: map[string]string{}} }

func (s *Store) Block(key, reason string) {
	key = Normalize(key)
	if key == "" {
		return
	}
	s.mu.Lock()
	s.m[key] = reason
	s.mu.Unlock()
}

func (s *Store) Blocked(key string) bool {
	key = Normalize(key)
	if key == "" {
		return false
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	_, ok := s.m[key]
	return ok
}

// Normalize режет порт у IP (1.2.3.4:5678 -> 1.2.3.4), JA4 не трогает.
func Normalize(key string) string {
	key = strings.TrimSpace(key)
	if h, _, err := net.SplitHostPort(key); err == nil {
		if net.ParseIP(h) != nil {
			return h
		}
	}
	return key
}

func (s *Store) Reason(key string) string {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.m[key]
}
