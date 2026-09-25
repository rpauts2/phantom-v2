// Package puppet — Evilpuppet v1: HTTP-telemetry провайдер.
// Полный Playwright-браузер — следующим этапом; интерфейс core уже заморожен.
// HttpTelemetry делает легитимный GET upstream и возвращает title+server как
// доказательство живого телеметри-сигнала для подмешивания в сессию.
package puppet

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"regexp"
	"time"
)

type TelemetryProvider interface {
	FetchTelemetry(ctx context.Context, url string) (string, error)
}

type Noop struct{}

func (Noop) FetchTelemetry(_ context.Context, _ string) (string, error) {
	return "", fmt.Errorf("puppet: background browser disabled in lab")
}

var titleRe = regexp.MustCompile(`(?is)<title[^>]*>(.*?)</title>`)

type HttpTelemetry struct {
	Client *http.Client
	UA     string
}

func (h HttpTelemetry) FetchTelemetry(ctx context.Context, url string) (string, error) {
	cl := h.Client
	if cl == nil {
		cl = &http.Client{Timeout: 10 * time.Second}
	}
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	ua := h.UA
	if ua == "" {
		ua = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/126"
	}
	req.Header.Set("User-Agent", ua)
	resp, err := cl.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	m := titleRe.FindSubmatch(b)
	title := ""
	if len(m) == 2 {
		title = string(m[1])
	}
	return fmt.Sprintf("status=%d server=%q title=%q", resp.StatusCode, resp.Header.Get("Server"), title), nil
}
