// Package setup — визард первого запуска `phantom -setup`.
// Задает 5 вопросов человеческим языком, пишет готовый config.yaml.
// Никаких ручных правок YAML для старта.
package setup

import (
	"bufio"
	"fmt"
	"io"
	"os"
	"strings"
)

// Answers — собранные ответы.
type Answers struct {
	Domain       string // verdebudget.ru
	Email        string // для ACME
	Mode         string // lab | prod
	TelegramChat string // пусто = выкл
	SMTPHost     string // пусто = dry-run
}

// Ask проводит опрос. Пустой ответ = дефолт в скобках.
func Ask(in io.Reader, out io.Writer) Answers {
	br := bufio.NewReader(in)
	q := func(prompt, def string) string {
		fmt.Fprintf(out, "%s [%s]: ", prompt, def)
		line, _ := br.ReadString('\n')
		line = strings.TrimSpace(line)
		if line == "" {
			return def
		}
		return line
	}
	a := Answers{}
	a.Domain = q("Домен кампании", "phish.test")
	a.Email = q("Email для сертификатов", "ops@example.com")
	mode := q("Режим (lab/prod)", "lab")
	if mode != "prod" {
		mode = "lab"
	}
	a.Mode = mode
	a.TelegramChat = q("Telegram chat_id (пусто = выкл уведомлений)", "")
	a.SMTPHost = q("SMTP host для рассылок (пусто = dry-run)", "")
	return a
}

// Render собирает config.yaml из ответов.
func Render(a Answers) string {
	var b strings.Builder
	b.WriteString("bind: \"0.0.0.0\"\n")
	if a.Mode == "prod" {
		b.WriteString("https_port: 443\nshared_443: true\n")
	} else {
		b.WriteString("https_port: 443\nshared_443: false\n")
	}
	fmt.Fprintf(&b, "node_id: \"\"\ndomains:\n  - %q\n", a.Domain)
	b.WriteString("storage:\n  sqlite_path: \"./data/phantom.db\"\n  redis_addr: \"127.0.0.1:6379\"\n  session_ttl_min: 60\n")
	fmt.Fprintf(&b, "tls:\n  email: %q\n  dns_provider: \"disabled\"\n  wildcard: false\n  autocert: true\n  upstream_tls: \"default\"\n", a.Email)
	b.WriteString("api:\n  stealth_hostname: \"api-internal.example.com\"\n  ca_file: \"./certs/ca.pem\"\n  cert_file: \"./certs/server.pem\"\n  key_file: \"./certs/server-key.pem\"\n")
	tg := "false"
	if a.TelegramChat != "" {
		tg = "true"
	}
	fmt.Fprintf(&b, "notifications:\n  telegram_enabled: %s\n  chat_id: %q\n", tg, a.TelegramChat)
	b.WriteString("log_level: \"info\"\n")
	if a.Mode == "prod" {
		b.WriteString("# PROD: подними dns_provider до cloudflare + wildcard: true, A-записи серые\n")
	}
	return b.String()
}

// WriteFile пишет конфиг (спрашивает перезапись существующего).
func WriteFile(path, content string, in io.Reader, out io.Writer) error {
	if _, err := os.Stat(path); err == nil {
		fmt.Fprintf(out, "%s существует. Перезаписать? [y/N]: ", path)
		br := bufio.NewReader(in)
		line, _ := br.ReadString('\n')
		if strings.ToLower(strings.TrimSpace(line)) != "y" {
			return fmt.Errorf("отмена")
		}
	}
	return os.WriteFile(path, []byte(content), 0o600)
}
