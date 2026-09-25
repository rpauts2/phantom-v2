// Package webui — встроенный Operator UI (embed в бинарь).
// /ui отдается без stealth-заголовка (браузерная навигация не ставит
// кастомные хедеры), API-вызовы из fetch идут с X-Stealth-Host + Bearer.
package webui

import (
	"embed"
	"io/fs"
	"net/http"
)

//go:embed all:ui
var dist embed.FS

func Handler() http.Handler {
	sub, err := fs.Sub(dist, "ui")
	if err != nil {
		return http.NotFoundHandler()
	}
	return http.FileServer(http.FS(sub))
}
