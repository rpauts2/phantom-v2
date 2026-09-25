package puppet

import (
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/phantom-v2/phantom/internal/blocklist"
)

func TestChallengeBlocksBot(t *testing.T) {
	bl := blocklist.New()
	h := Reporter{Block: bl, Bus: nil}
	// коллектор отдается
	req := httptest.NewRequest("GET", "/__fp.js", nil)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != 200 || !strings.Contains(rec.Body.String(), "webdriver") {
		t.Fatalf("collector: %d", rec.Code)
	}
	// бот-репорт банится
	req2 := httptest.NewRequest("POST", "/__fp/report", strings.NewReader(`{"webdriver":true}`))
	req2.Header.Set("Content-Type", "application/json")
	req2.RemoteAddr = "9.9.9.9:1"
	rec2 := httptest.NewRecorder()
	h.ServeHTTP(rec2, req2)
	if rec2.Code != 204 || !bl.Blocked("9.9.9.9") {
		t.Fatal("bot not blocked")
	}
	if bl.Blocked("9.9.9.9:1") {
		t.Fatal("port must be stripped")
	}
}
