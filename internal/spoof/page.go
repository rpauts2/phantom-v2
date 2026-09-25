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
