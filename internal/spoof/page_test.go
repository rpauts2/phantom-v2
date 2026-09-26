package spoof

import (
	"strings"
	"testing"
)

func TestRender(t *testing.T) {
	h := Render("login.phish.test")
	if !strings.Contains(h, "login.phish.test") {
		t.Fatalf("host missing: %q", h)
	}
}

func TestChallengeFor(t *testing.T) {
	h := ChallengeFor("/zz9")
	if !strings.Contains(h, "/zz9.js") {
		t.Fatalf("prefix missing: %q", h)
	}
	if strings.Contains(h, "__PREFIX__") {
		t.Fatal("placeholder leaked")
	}
}
func TestJitter(t *testing.T) {
	a, b := Render("h.test"), Render("h.test")
	if a == b {
		t.Fatal("renders must differ (jitter)")
	}
	if !strings.Contains(a, "h.test") {
		t.Fatal("host lost")
	}
}
