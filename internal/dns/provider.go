// Package dns — external DNS провайдеры (Pro-паритет).
// disabled: лаб, ничего не делает. file: пишет zone-файл для лабы.
// cloudflare: реальный API через std http (CF_API_TOKEN). route53/gandi:
// интерфейс готов, требуют креды — возвращают честную ошибку, а не молчание.
package dns

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"time"

	"github.com/phantom-v2/phantom/core"
)

func For(provider string) (core.DNSProvider, error) {
	switch provider {
	case "disabled":
		return Disabled{}, nil
	case "file":
		return File{Path: "./data/zone.txt"}, nil
	case "cloudflare":
		return Cloudflare{Token: os.Getenv("CF_API_TOKEN"), ZoneID: os.Getenv("CF_ZONE_ID")}, nil
	case "route53", "gandi":
		return nil, fmt.Errorf("%s: not configured (set creds or use cloudflare/file/disabled)", provider)
	default:
		return nil, fmt.Errorf("unknown dns provider %q", provider)
	}
}

type Disabled struct{}

func (Disabled) EnsureA(_ context.Context, _, _ string) error   { return nil }
func (Disabled) EnsureTXT(_ context.Context, _, _ string) error { return nil }

type File struct{ Path string }

func (f File) EnsureA(_ context.Context, name, ip string) error {
	return f.append(fmt.Sprintf("A %s %s\n", name, ip))
}

func (f File) EnsureTXT(_ context.Context, name, value string) error {
	return f.append(fmt.Sprintf("TXT %s %s\n", name, value))
}

func (f File) append(line string) error {
	if err := os.MkdirAll(filepath.Dir(f.Path), 0o750); err != nil {
		return err
	}
fh, err := os.OpenFile(f.Path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o600)
	if err != nil {
		return err
	}
	defer fh.Close()
	_, err = fh.WriteString(line)
	return err
}

type Cloudflare struct {
	Token, ZoneID string
	HTTP          *http.Client
}

func (c Cloudflare) ensure(ctx context.Context, rtype, name, content string) error {
	if c.Token == "" || c.ZoneID == "" {
		return fmt.Errorf("cloudflare: set CF_API_TOKEN and CF_ZONE_ID")
	}
	cl := c.HTTP
	if cl == nil {
		cl = &http.Client{Timeout: 10 * time.Second}
	}
	body, _ := json.Marshal(map[string]string{"type": rtype, "name": name, "content": content})
	req, _ := http.NewRequestWithContext(ctx,
		http.MethodPost, "https://api.cloudflare.com/client/v4/zones/"+c.ZoneID+"/dns_records",
		bytes.NewReader(body))
	req.Header.Set("Authorization", "Bearer "+c.Token)
	req.Header.Set("Content-Type", "application/json")
	resp, err := cl.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 300 {
		return fmt.Errorf("cloudflare: status %s", resp.Status)
	}
	return nil
}

func (c Cloudflare) EnsureA(ctx context.Context, name, ip string) error {
	return c.ensure(ctx, "A", name, ip)
}

func (c Cloudflare) EnsureTXT(ctx context.Context, name, value string) error {
	return c.ensure(ctx, "TXT", name, value)
}
