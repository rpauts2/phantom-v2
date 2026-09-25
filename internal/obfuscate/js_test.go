package obfuscate

import "testing"

func TestPolymorphic(t *testing.T) {
	a := Obfuscate("alert(1)", 1)
	b := Obfuscate("alert(1)", 2)
	if a == b {
		t.Fatal("not polymorphic")
	}
	if len(a) <= len("alert(1)") || !contains(a, "alert(1)") {
		t.Fatal("semantics lost")
	}
}

func contains(s, sub string) bool {
	return len(s) >= len(sub) && (func() bool {
		for i := 0; i+len(sub) <= len(s); i++ {
			if s[i:i+len(sub)] == sub {
				return true
			}
		}
		return false
	})()
}
