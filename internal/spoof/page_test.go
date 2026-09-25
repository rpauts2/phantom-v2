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
