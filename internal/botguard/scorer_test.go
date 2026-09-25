package botguard

import (
	"net/http"
	"testing"
)

func TestScore(t *testing.T) {
	s := Scorer{}
	bot, _ := http.NewRequest("GET", "http://x/", nil)
	bot.Header.Set("User-Agent", "curl/8.0")
	if got := s.Score(bot, ""); got < Threshold {
		t.Fatalf("bot not detected: %d", got)
	}
	human, _ := http.NewRequest("GET", "http://x/", nil)
	human.Header.Set("User-Agent", "Mozilla/5.0 Chrome/126")
	human.Header.Set("Accept-Language", "en-US")
	human.Header.Set("Accept", "text/html")
	if got := s.Score(human, "ja4_abc"); got >= Threshold {
		t.Fatalf("human flagged: %d", got)
	}
}
