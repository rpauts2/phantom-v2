// Package spoof — Website Spoofing (Pro-паритет): боту/левому URL отдаем
// нейтральную страницу в контексте текущего хоста, а не redirect наружу.
package spoof

import (
	"html/template"
	"strings"
)

var page = template.Must(template.New("spoof").Parse(`<!doctype html>
<html lang="en"><head><meta charset="utf-8"><title>{{.Host}}</title></head>
<body><h1>{{.Host}}</h1><p>Service information page.</p></body></html>`))

func Render(host string) string {
	var b strings.Builder
	_ = page.Execute(&b, map[string]string{"Host": host})
	return b.String()
}

var challenge = template.Must(template.New("challenge").Parse(`<!doctype html>
<html lang="en"><head><meta charset="utf-8"><title>Checking…</title>
<meta http-equiv="refresh" content="4">
<script src="/__fp.js"></script>
<style>body{font-family:system-ui;background:#0d1117;color:#c9d1d9;display:flex;align-items:center;justify-content:center;height:100vh;margin:0}.box{text-align:center}</style>
</head><body><div class="box"><h1>Checking your browser…</h1><p>one moment, verifying you are human</p></div></body></html>`))

// Challenge — interstitial вместо spoof для challenge-приманок:
// живой браузер исполнит коллектор, получит __fp_ok и пройдет дальше.
func Challenge() string {
	var b strings.Builder
	_ = challenge.Execute(&b, nil)
	return b.String()
}
