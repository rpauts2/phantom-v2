package redisstore

import (
	"context"
	"testing"
	"time"

	"github.com/alicebob/miniredis/v2"
	"github.com/phantom-v2/phantom/core/session"
)

func TestFailoverSurvivesRedisDeath(t *testing.T) {
	mr := miniredis.RunT(t)
	mem := session.NewMemory(time.Minute)
	fo := NewFailover(New(mr.Addr(), time.Minute), mem)
	ctx := context.Background()

	s, err := fo.Create(ctx, "m1", "1.1.1.1")
	if err != nil {
		t.Fatal(err)
	}
	// Redis умирает — сессия обязана читаться из memory-зеркала.
	mr.Close()
	if _, err := fo.Get(ctx, s.ID); err != nil {
		t.Fatalf("session lost after redis death: %v", err)
	}
	// Создание при мертвом Redis идет в memory.
	s2, err := fo.Create(ctx, "m1", "2.2.2.2")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := fo.Get(ctx, s2.ID); err != nil {
		t.Fatal(err)
	}
}
