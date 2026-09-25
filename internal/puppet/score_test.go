package puppet

import (
	"strings"
	"testing"
)

func TestScoreBehavior(t *testing.T) {
	if !Score(true, 5, "en", "ANGLE", 10, 50, 1600) {
		t.Fatal("webdriver must ban")
	}
	if !Score(false, 0, "", "", 0, 0, 1600) {
		t.Fatal("headless+no-input must ban")
	}
	if Score(false, 3, "en-US", "ANGLE (NVIDIA)", 25, 300, 1600) {
		t.Fatal("human must pass")
	}
	if Score(false, 0, "en", "ANGLE", 0, 0, 200) {
		t.Fatal("fast load without input is not enough alone")
	}
}

func TestCollectorHasBehavior(t *testing.T) {
	for _, s := range []string{"mousemove", "webgl", "setTimeout", "performance.now"} {
		if !strings.Contains(Collector, s) {
			t.Fatalf("collector missing %s", s)
		}
	}
}
