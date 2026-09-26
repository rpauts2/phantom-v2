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

func TestRetryAfter(t *testing.T) {
	f := New(1, time.Minute)
	if !f.Allow("1.1.1.1") {
		t.Fatal("first must pass")
	}
	if f.Allow("1.1.1.1") {
		t.Fatal("second must block")
	}
	if s := f.RetryAfter("1.1.1.1"); s <= 0 || s > 61 {
		t.Fatalf("retry=%d", s)
	}
	if s := f.RetryAfter("9.9.9.9"); s != 0 {
		t.Fatalf("unknown=%d", s)
	}
}
