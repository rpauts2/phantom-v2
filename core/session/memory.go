// Package session — in-memory SessionStore (тесты + dev).
// Redis-реализация позже за тем же интерфейсом core.SessionStore.
package session

import (
	"context"
	"sync"
	"time"

	"github.com/google/uuid"
	"github.com/phantom-v2/phantom/core"
)

type Memory struct {
	mu   sync.RWMutex
	m    map[string]*core.Session
	ttl  time.Duration
}

func NewMemory(ttl time.Duration) *Memory {
	if ttl <= 0 {
		ttl = time.Hour
	}
	m := &Memory{m: map[string]*core.Session{}, ttl: ttl}
	return m
}

// Cleanup удаляет протухшие сессии. Дергается janitor-ом в prod и тестами.
func (s *Memory) Cleanup() int {
	now := time.Now()
	s.mu.Lock()
	defer s.mu.Unlock()
	n := 0
	for id, sess := range s.m {
		if now.Sub(sess.CreatedAt) > s.ttl {
			delete(s.m, id)
			n++
		}
	}
	return n
}

// StartJanitor чистит протухшие сессии до отмены контекста.
func (s *Memory) StartJanitor(ctx context.Context, interval time.Duration) {
	if interval <= 0 {
		interval = time.Minute
	}
	go func() {
		t := time.NewTicker(interval)
		defer t.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-t.C:
				s.Cleanup()
			}
		}
	}()
}

func (s *Memory) Create(ctx context.Context, phishlet, ip string) (*core.Session, error) {
	sess := &core.Session{
		ID:        uuid.NewString(),
		Phishlet:  phishlet,
		IP:        ip,
		CreatedAt: time.Now(),
	}
	s.mu.Lock()
	s.m[sess.ID] = sess
	s.mu.Unlock()
	return sess, nil
}

// Put кладет готовую сессию (для dual-write failover: тот же ID что в Redis).
func (s *Memory) Put(sess *core.Session) {
	if sess == nil {
		return
	}
	cp := *sess
	s.mu.Lock()
	s.m[cp.ID] = &cp
	s.mu.Unlock()
}

func (s *Memory) Get(ctx context.Context, id string) (*core.Session, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	sess, ok := s.m[id]
	if !ok {
		return nil, errNotFound
	}
	if time.Since(sess.CreatedAt) > s.ttl {
		return nil, errNotFound
	}
	return sess, nil
}

// Drop сбрасывает сессию (кнопка оператора).
func (s *Memory) Drop(_ context.Context, id string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.m[id]; !ok {
		return errNotFound
	}
	delete(s.m, id)
	return nil
}

var errNotFound = errString("session not found")

type errString string

func (e errString) Error() string { return string(e) }
