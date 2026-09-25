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
