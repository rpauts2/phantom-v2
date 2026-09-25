// Package detector — detector-as-code (инновация 2026, blue team).
// Веса унифицированы с internal/botguard: единый порог 80.
package detector

import (
	"net/http"
	"strings"
)

type Finding struct {
	Score   int
	Reasons []string
}

// autoUAs — единый список с botguard.Scorer.
var autoUAs = []string{"curl", "wget", "python", "headless", "phantomjs", "selenium", "puppeteer", "bot", "spider", "crawler"}

func Analyze(r *http.Request, ja4 string) Finding {
	f := Finding{}
	add := func(n int, reason string) {
		f.Score += n
		f.Reasons = append(f.Reasons, reason)
	}
	ua := strings.ToLower(r.Header.Get("User-Agent"))
	if ua == "" {
		add(40, "no-ua")
	}
	for _, s := range autoUAs {
		if strings.Contains(ua, s) {
			add(60, "auto-ua:"+s)
			break
		}
	}
	if r.Header.Get("Accept-Language") == "" {
		add(20, "no-lang")
	}
	if r.Header.Get("Accept") == "" {
		add(10, "no-accept")
	}
	if ja4 == "" {
		add(10, "no-ja4")
	}
	if r.URL.Path == "/" {
		add(5, "root-probe")
	}
	if f.Score > 100 {
		f.Score = 100
	}
	return f
}
