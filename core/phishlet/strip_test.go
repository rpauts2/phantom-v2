package phishlet

import "testing"

func TestStripPortIPv6(t *testing.T) {
	cases := map[string]string{
		"login.phish.test":      "login.phish.test",
		"login.phish.test:443":  "login.phish.test",
		"[2001:db8::1]:443":     "2001:db8::1",
		"[2001:db8::1]":         "2001:db8::1",
		"2001:db8::1":           "2001:db8::1",
		"127.0.0.1:8443":        "127.0.0.1",
		"LOGIN.PHISH.TEST:8443": "LOGIN.PHISH.TEST",
	}
	for in, want := range cases {
		if got := StripPort(in); got != want {
			t.Errorf("StripPort(%q)=%q want %q", in, got, want)
		}
	}
}
