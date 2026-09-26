package blocklist

import "testing"

func TestBlock(t *testing.T) {
	s := New()
	if s.Blocked("1.1.1.1") {
		t.Fatal("false positive")
	}
	s.Block("1.1.1.1", "test")
	if !s.Blocked("1.1.1.1") || s.Reason("1.1.1.1") != "test" {
		t.Fatal("block broken")
	}
	s.Block("", "x") // пустой ключ игнор
}
func TestNormalize(t *testing.T) {
	s := New()
	s.Block("9.9.9.9:5678", "x")
	if !s.Blocked("9.9.9.9") || !s.Blocked("9.9.9.9:5678") {
		t.Fatal("port must be stripped")
	}
	s.Block("some-ja4-string", "y")
	if !s.Blocked("some-ja4-string") {
		t.Fatal("ja4 broken")
	}
}
