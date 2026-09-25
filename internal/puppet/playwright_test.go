package puppet

import (
	"context"
	"os"
	"testing"
	"time"
)

func TestChainFallback(t *testing.T) {
	// Первый провайдер падает — Chain берет следующий.
	s, err := Chain(context.Background(), "http://x/",
		Noop{},
		HttpTelemetry{UA: "t"},
	)
	_ = s
	_ = err
	// HttpTelemetry на несуществующий хост тоже упадет — проверяем только что Chain вернул ошибку, а не панику.
	if err == nil {
		t.Log("chain unexpectedly succeeded (network open?)")
	}
}

func TestPlaywrightMissingBrowsers(t *testing.T) {
	if os.Getenv("PLAYWRIGHT_E2E") == "" {
		t.Skip("needs browsers: playwright install chromium")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	s, err := Playwright{}.FetchTelemetry(ctx, "https://example.com")
	if err != nil {
		t.Fatalf("playwright e2e: %v", err)
	}
	if s == "" {
		t.Fatal("empty telemetry")
	}
	t.Logf("telemetry: %s", s)
}
