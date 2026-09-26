// Package config — config v2 loader + validation (specs/config-v2.md).
package config

import (
	"fmt"
	"net"
	"os"
	"strings"

	"gopkg.in/yaml.v3"
)

type Config struct {
	Bind       string   `yaml:"bind"`
	HTTPSPort  int      `yaml:"https_port"`
	Shared443  bool     `yaml:"shared_443"`
	NodeID     string   `yaml:"node_id"`
	SessCookie string   `yaml:"session_cookie"`
	ChallPath  string   `yaml:"challenge_path"`
	Domains    []string `yaml:"domains"`
	Storage    Storage  `yaml:"storage"`
	TLS        TLS      `yaml:"tls"`
	API        API      `yaml:"api"`
	Notify     Notify   `yaml:"notifications"`
	LogLevel   string   `yaml:"log_level"`
}

type Storage struct {
	SQLitePath    string `yaml:"sqlite_path"`
	RedisAddr     string `yaml:"redis_addr"`
	SessionTTLMin int    `yaml:"session_ttl_min"`
}

type TLS struct {
	Email       string `yaml:"email"`
	DNSProvider string `yaml:"dns_provider"`
	Wildcard    bool   `yaml:"wildcard"`
	UpstreamTLS string `yaml:"upstream_tls"`
	Autocert    *bool  `yaml:"autocert"`
}

type API struct {
	StealthHostname string `yaml:"stealth_hostname"`
	CAFile          string `yaml:"ca_file"`
	CertFile        string `yaml:"cert_file"`
	KeyFile         string `yaml:"key_file"`
}

// Notify — Telegram-алерты. Токен ТОЛЬКО env TELEGRAM_BOT_TOKEN, chat — yaml или env.
type Notify struct {
	TelegramEnabled bool   `yaml:"telegram_enabled"`
	ChatID          string `yaml:"chat_id"`
}

func Load(path string) (*Config, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var c Config
	if err := yaml.Unmarshal(b, &c); err != nil {
		return nil, err
	}
	applyEnv(&c)
	if err := c.Validate(); err != nil {
		return nil, err
	}
	return &c, nil
}

func applyEnv(c *Config) {
	if v := os.Getenv("PHANTOM_REDIS_ADDR"); v != "" {
		c.Storage.RedisAddr = v
	}
	if v := os.Getenv("PHANTOM_SQLITE_PATH"); v != "" {
		c.Storage.SQLitePath = v
	}
	if v := os.Getenv("PHANTOM_LOG_LEVEL"); v != "" {
		c.LogLevel = v
	}
	if v := os.Getenv("PHANTOM_NODE_ID"); v != "" {
		c.NodeID = v
	}
	if v := os.Getenv("TELEGRAM_CHAT_ID"); v != "" {
		c.Notify.ChatID = v
	}
}

func (c *Config) Validate() error {
	if net.ParseIP(c.Bind) == nil && c.Bind != "0.0.0.0" {
		return fmt.Errorf("bind must be IP, got %q", c.Bind)
	}
	if c.HTTPSPort < 1 || c.HTTPSPort > 65535 {
		return fmt.Errorf("https_port out of range")
	}
	if len(c.Domains) == 0 {
		return fmt.Errorf("domains: at least 1 required")
	}
	for _, d := range c.Domains {
		if !strings.Contains(d, ".") || strings.ContainsAny(d, " \t/") {
			return fmt.Errorf("domains: invalid %q (need FQDN)", d)
		}
	}
	if c.Storage.RedisAddr == "" || c.Storage.SQLitePath == "" {
		return fmt.Errorf("storage: redis_addr and sqlite_path required")
	}
	if c.Storage.SessionTTLMin <= 0 {
		c.Storage.SessionTTLMin = 60
	}
	switch c.TLS.DNSProvider {
	case "cloudflare", "route53", "gandi", "disabled":
	default:
		return fmt.Errorf("tls.dns_provider must be cloudflare|route53|gandi|disabled")
	}
	if c.TLS.DNSProvider == "disabled" && c.TLS.Wildcard {
		return fmt.Errorf("tls.wildcard requires external dns_provider")
	}
	if c.TLS.UpstreamTLS == "" {
		c.TLS.UpstreamTLS = "default"
	}
	if c.TLS.Autocert == nil {
		on := true
		c.TLS.Autocert = &on // дефолт ON: старые конфиги без ключа работают как раньше
	}
	switch c.TLS.UpstreamTLS {
	case "default", "chrome":
	default:
		return fmt.Errorf("tls.upstream_tls must be default|chrome")
	}
	if c.Shared443 && c.API.StealthHostname == "" {
		return fmt.Errorf("shared_443 requires api.stealth_hostname")
	}
	if c.NodeID == "" {
		if h, err := os.Hostname(); err == nil && h != "" {
			c.NodeID = h
		} else {
			c.NodeID = "node-local"
		}
	}
	if strings.ContainsAny(c.NodeID, " \t/") {
		return fmt.Errorf("node_id must not contain spaces or slashes")
	}
	if c.SessCookie == "" {
		c.SessCookie = "sid"
	}
	if strings.ContainsAny(c.SessCookie, " \t/;=") {
		return fmt.Errorf("session_cookie: bad chars")
	}
	if c.ChallPath == "" {
		c.ChallPath = "/__fp"
	}
	if !strings.HasPrefix(c.ChallPath, "/") {
		return fmt.Errorf("challenge_path: must start with /")
	}
	switch c.LogLevel {
	case "debug", "info", "warn", "error":
	default:
		return fmt.Errorf("log_level must be debug|info|warn|error")
	}
	return nil
}
