package session

import (
	"context"
	"testing"
	"time"
)

func TestCleanup(t *testing.T) {
	m := NewMemory(10 * time.Millisecond)
	s, err := m.Create(context.Background(), "p1", "1.1.1.1")
	if err != nil {
		t.Fatal(err)
	}
	time.Sleep(25 * time.Millisecond)
	if _, err := m.Get(context.Background(), s.ID); err == nil {
		t.Fatal("expired must miss")
	}
	// протухшая запись все еще в map до Cleanup
	m.mu.RLock()
	_, still := m.m[s.ID]
	m.mu.RUnlock()
	if !still {
		t.Fatal("expected stale entry before Cleanup")
	}
	if n := m.Cleanup(); n != 1 {
		t.Fatalf("cleanup=%d", n)
	}
}
