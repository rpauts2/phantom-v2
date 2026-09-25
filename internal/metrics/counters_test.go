package metrics

import "testing"

func TestLabels(t *testing.T) {
	IncRequestsFor("m1")
	IncRequestsFor("m1")
	if ByPhishlet("m1") < 2 {
		t.Fatal("label counter broken")
	}
	if ByPhishlet("nope") != 0 {
		t.Fatal("missing must be 0")
	}
}
