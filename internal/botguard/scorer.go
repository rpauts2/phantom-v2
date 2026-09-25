// Package botguard — JA4 + эвристики (Pro Botguard паритет, v1).
// >=80 = бот: отдаем spoof, не redirect.
package botguard

import (
	"net/http"
	"strings"

	"github.com/phantom-v2/phantom/core"
)

const Threshold = 80

var _ core.BotScorer = Scorer{}

type Scorer struct{}

func (Scorer) Score(r *http.Request, ja4 string) int {
	score := 0
	ua := strings.ToLower(r.Header.Get("User-Agent"))
	if ua == "" {
		score += 40
	}
	for _, s := range []string{"curl", "wget", "python", "headless", "phantomjs", "selenium", "puppeteer", "bot", "spider", "crawler"} {
		if strings.Contains(ua, s) {
			score += 60
			break
		}
	}
	if r.Header.Get("Accept-Language") == "" {
		score += 20
	}
	if r.Header.Get("Accept") == "" {
		score += 10
	}
	if ja4 == "" {
		score += 10
	}
	if score > 100 {
		score = 100
	}
	return score
}
