package ratelimit

import (
	"testing"
	"time"
)

func TestFixed(t *testing.T) {
	f := New(2, time.Minute)
	if !f.Allow("1.1.1.1") || !f.Allow("1.1.1.1") {
		t.Fatal("first 2 must pass")
	}
	if f.Allow("1.1.1.1") {
		t.Fatal("3rd must block")
	}
}
