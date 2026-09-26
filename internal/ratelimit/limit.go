// Package ratelimit — фиксированное окно на IP (anti-abuse v1).
package ratelimit

import (
	"sync"
	"time"
)

type Fixed struct {
	mu     sync.Mutex
	max    int
	window time.Duration
	hits   map[string][]time.Time
}

func New(max int, window time.Duration) *Fixed {
	if max <= 0 {
		max = 60
	}
	if window <= 0 {
		window = time.Minute
	}
	return &Fixed{max: max, window: window, hits: map[string][]time.Time{}}
}

func (f *Fixed) Allow(ip string) bool {
	now := time.Now()
	f.mu.Lock()
	defer f.mu.Unlock()
	hs := f.hits[ip]
	fresh := hs[:0]
	for _, t := range hs {
		if now.Sub(t) < f.window {
			fresh = append(fresh, t)
		}
	}
	if len(fresh) >= f.max {
		f.hits[ip] = fresh
		return false
	}
	f.hits[ip] = append(fresh, now)
	return true
}

// RetryAfter — секунд до освобождения окна (для Retry-After заголовка).
func (f *Fixed) RetryAfter(ip string) int64 {
	f.mu.Lock()
	defer f.mu.Unlock()
	hs := f.hits[ip]
	if len(hs) == 0 {
		return 0
	}
	oldest := hs[0]
	for _, t := range hs[1:] {
		if t.Before(oldest) {
			oldest = t
		}
	}
	left := f.window - time.Since(oldest)
	if left <= 0 {
		return 0
	}
	return int64(left/time.Second) + 1
}

// Window возвращает окно (для заголовков).
func (f *Fixed) Window() time.Duration {
	return f.window
}
