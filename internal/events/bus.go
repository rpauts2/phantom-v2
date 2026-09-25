// Package events — EventBus impl (in-memory pub/sub + счетчики).
// NATS/OTel — следующим этапом без смены интерфейса core.EventBus.
package events

import (
	"context"
	"sync"

	"github.com/phantom-v2/phantom/internal/metrics"
)

type Bus struct {
	mu   sync.RWMutex
	subs map[string][]chan any
}

func New() *Bus { return &Bus{subs: map[string][]chan any{}} }

func (b *Bus) Publish(_ context.Context, topic string, payload any) error {
	switch topic {
	case "capture.creds", "capture.token":
		metrics.IncCapture()
	case "bot.blocked":
		metrics.IncBlocked()
	}
	b.mu.RLock()
	defer b.mu.RUnlock()
	for _, ch := range b.subs[topic] {
		select {
		case ch <- payload:
		default:
		}
	}
	return nil
}

func (b *Bus) Subscribe(topic string, buf int) <-chan any {
	ch := make(chan any, buf)
	b.mu.Lock()
	b.subs[topic] = append(b.subs[topic], ch)
	b.mu.Unlock()
	return ch
}
