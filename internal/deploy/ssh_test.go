package deploy

import (
	"strings"
	"testing"
)

func TestScript(t *testing.T) {
	s := Script("192.0.2.10", "root", "~/.ssh/id_rsa", "login.example.com")
	if !strings.Contains(s, "192.0.2.10") || !strings.Contains(s, "login.example.com") {
		t.Fatalf("script broken: %q", s)
	}
}
