// Evilpuppet на Playwright: фоновый Chromium генерит легитимную
// телеметрию (fingerprint как у живого пользователя) для подмешивания
// в сессии. Цепочка fallback: Playwright -> HttpTelemetry -> Noop.
// Браузеры ставятся отдельно: `go run github.com/mxschmitt/playwright-go/cmd/playwright@latest install chromium --with-deps`
// (нужен Node в PATH на этапе install). Без браузеров — честная ошибка,
// вызывающий падает на HttpTelemetry (см. Chain).
package puppet

import (
	"context"
	"fmt"
	"time"

	"github.com/mxschmitt/playwright-go"
)

const fpJS = `() => ({
  webdriver: !!navigator.webdriver,
  plugins: (navigator.plugins||[]).length,
  lang: navigator.language||"",
  tz: (Intl.DateTimeFormat().resolvedOptions().timeZone||""),
  webgl: (() => { try {
    const g = document.createElement("canvas").getContext("webgl");
    return g ? g.getParameter(g.RENDERER) : "";
  } catch(e) { return ""; } })(),
  ua: navigator.userAgent,
  dnt: navigator.doNotTrack || "",
  hw: navigator.hardwareConcurrency || 0,
})`

// Playwright — фоновый браузер. Zero value готов (Headless default true).
type Playwright struct {
	Headless *bool
	Timeout  time.Duration
}

func (p Playwright) FetchTelemetry(ctx context.Context, url string) (string, error) {
	headless := true
	if p.Headless != nil {
		headless = *p.Headless
	}
	timeout := p.Timeout
	if timeout <= 0 {
		timeout = 30 * time.Second
	}
	pw, err := playwright.Run()
	if err != nil {
		return "", fmt.Errorf("puppet: playwright run: %w (install: playwright install chromium)", err)
	}
	defer pw.Stop() //nolint:errcheck
	browser, err := pw.Chromium.Launch(playwright.BrowserTypeLaunchOptions{Headless: &headless})
	if err != nil {
		return "", fmt.Errorf("puppet: launch: %w", err)
	}
	defer browser.Close() //nolint:errcheck
	page, err := browser.NewPage()
	if err != nil {
		return "", err
	}
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	if _, err := page.Goto(url, playwright.PageGotoOptions{
		WaitUntil: playwright.WaitUntilStateDomcontentloaded,
	}); err != nil {
		return "", fmt.Errorf("puppet: goto: %w", err)
	}
	v, err := page.Evaluate(fpJS)
	if err != nil {
		return "", err
	}
	title, _ := page.Title()
	return fmt.Sprintf("fp=%v title=%q", v, title), nil
}

// Chain пробует провайдеры по порядку, возвращает первую удачу.
func Chain(ctx context.Context, url string, providers ...TelemetryProvider) (string, error) {
	var err error
	for _, p := range providers {
		var s string
		if s, err = p.FetchTelemetry(ctx, url); err == nil {
			return s, nil
		}
	}
	if err == nil {
		err = fmt.Errorf("puppet: no providers")
	}
	return "", err
}
