package puppet

import (
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/phantom-v2/phantom/internal/blocklist"
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

func TestPrefix(t *testing.T) {
	if !strings.Contains(CollectorFor("/zz9"), "/zz9/report") {
		t.Fatal("prefix not applied")
	}
	if !strings.Contains(Collector, "/__fp/report") {
		t.Fatal("default broken")
	}
	r := Reporter{Prefix: "/zz9", Block: blocklist.New()}
	req := httptest.NewRequest("GET", "/zz9.js", nil)
	rec := httptest.NewRecorder()
	r.ServeHTTP(rec, req)
	if rec.Code != 200 {
		t.Fatalf("custom js: %d", rec.Code)
	}
	req2 := httptest.NewRequest("GET", "/__fp.js", nil)
	rec2 := httptest.NewRecorder()
	r.ServeHTTP(rec2, req2)
	if rec2.Code != 404 {
		t.Fatalf("old path must 404: %d", rec2.Code)
	}
}
