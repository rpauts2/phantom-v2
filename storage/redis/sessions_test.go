package redisstore

import (
	"context"
	"testing"
	"time"

	"github.com/alicebob/miniredis/v2"
)

func TestRoundTrip(t *testing.T) {
	mr := miniredis.RunT(t)
	s := New(mr.Addr(), time.Minute)
	ctx := context.Background()
	if err := s.Ping(ctx); err != nil {
		t.Fatalf("ping: %v", err)
	}
	created, err := s.Create(ctx, "m1", "1.1.1.1")
	if err != nil {
		t.Fatal(err)
	}
	got, err := s.Get(ctx, created.ID)
	if err != nil {
		t.Fatal(err)
	}
	if got.Phishlet != "m1" || got.IP != "1.1.1.1" {
		t.Fatalf("bad session: %+v", got)
	}
	if _, err := s.Get(ctx, "missing"); err == nil {
		t.Fatal("missing must error")
	}
}
