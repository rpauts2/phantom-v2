package sqlite

import (
	"testing"
	"time"
)

func TestBlockBounded(t *testing.T) {
	db, err := Open(":memory:")
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	start := time.Now()
	w := BlockWrap{Inner: stubBlock{map[string]bool{}}, DB: db}
	w.Block("9.9.9.9", "t")
	if elapsed := time.Since(start); elapsed > time.Second {
		t.Fatalf("block too slow: %v", elapsed)
	}
	if !w.Blocked("9.9.9.9") {
		t.Fatal("not blocked")
	}
}

type stubBlock struct{ m map[string]bool }

func (s stubBlock) Block(k, _ string)   { s.m[k] = true }
func (s stubBlock) Blocked(k string) bool { return s.m[k] }
