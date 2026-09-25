// Package mailer — SMTP-рассылка кампаний (std net/smtp).
// Креды только env (SMTP_HOST/PORT/USER/PASS/FROM). DryRun по дефолту true:
// без явного DryRun=false письма НЕ уходят. Троттлинг — пауза между письмами.
package mailer

import (
	"bytes"
	"fmt"
	"net/smtp"
	"strings"
	"text/template"
	"time"
)

// Config подключения (из env в main).
type Config struct {
	Host     string
	Port     int
	User     string
	Pass     string
	From     string
	FromName string
	DryRun   bool
	Delay    time.Duration // пауза между письмами (анти-спам троттлинг)
}

// Mail — одно письмо с шаблонными полями.
type Mail struct {
	To      string
	Subject string // text/template: {{.Email}} {{.URL}}
	Body    string // text/template, plain+html обертка
	URL     string // персональная приманка
	Email   string
}

func (m Mail) render() (subject, body string, err error) {
	data := map[string]string{"Email": m.Email, "URL": m.URL}
	ts, err := template.New("s").Parse(m.Subject)
	if err != nil {
		return "", "", err
	}
	var sb strings.Builder
	if err := ts.Execute(&sb, data); err != nil {
		return "", "", err
	}
	subject = sb.String()
	tb, err := template.New("b").Parse(m.Body)
	if err != nil {
		return "", "", err
	}
	sb.Reset()
	if err := tb.Execute(&sb, data); err != nil {
		return "", "", err
	}
	return subject, sb.String(), nil
}

// Sender шлет через SMTP (или пишет в Out при DryRun).
type Sender struct {
	Cfg Config
	Out *bytes.Buffer // dry-run лог
}

func (s *Sender) Send(m Mail) error {
	subj, body, err := m.render()
	if err != nil {
		return err
	}
	msg := "From: " + s.from() + "\r\nTo: " + m.To +
		"\r\nSubject: " + subj +
		"\r\nMIME-Version: 1.0\r\nContent-Type: text/html; charset=UTF-8\r\n\r\n" + body
	if s.Cfg.DryRun {
		if s.Out != nil {
			fmt.Fprintf(s.Out, "DRY to=%s subj=%s\n", m.To, subj)
		}
		return nil
	}
	if s.Cfg.Host == "" || s.Cfg.User == "" {
		return fmt.Errorf("mailer: SMTP not configured (dry-run off, no creds)")
	}
	addr := fmt.Sprintf("%s:%d", s.Cfg.Host, s.Cfg.Port)
	auth := smtp.PlainAuth("", s.Cfg.User, s.Cfg.Pass, s.Cfg.Host)
	if err := smtp.SendMail(addr, auth, s.Cfg.From, []string{m.To}, []byte(msg)); err != nil {
		return err
	}
	if s.Cfg.Delay > 0 {
		time.Sleep(s.Cfg.Delay)
	}
	return nil
}

func (s *Sender) from() string {
	if s.Cfg.FromName != "" {
		return fmt.Sprintf("%s <%s>", s.Cfg.FromName, s.Cfg.From)
	}
	return s.Cfg.From
}
