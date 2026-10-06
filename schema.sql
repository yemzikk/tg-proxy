-- Stats counter for the proxy. A single row (id = 1) holds running totals.
CREATE TABLE IF NOT EXISTS stats (
  id        INTEGER PRIMARY KEY,
  delivered INTEGER NOT NULL DEFAULT 0,
  errors    INTEGER NOT NULL DEFAULT 0
);

INSERT OR IGNORE INTO stats (id, delivered, errors) VALUES (1, 0, 0);

-- Durable error log. Real-time `wrangler ... tail` output is not retained, so
-- failures are also appended here for later review (npm run errors). Captures
-- both proxy failures (kind = upstream_unreachable / log_delivery_failed /
-- stat_write_failed) and Telegram's own rejections (kind = telegram_error), with
-- enough metadata to reproduce them. The bot token is never stored: only the
-- numeric bot id, and `path` has the token redacted.
CREATE TABLE IF NOT EXISTS error_log (
  id          INTEGER PRIMARY KEY AUTOINCREMENT,
  ts          TEXT NOT NULL,    -- ISO 8601 timestamp
  kind        TEXT NOT NULL,    -- upstream_unreachable | telegram_error | log_delivery_failed | stat_write_failed
  status      INTEGER,          -- HTTP status (Telegram's reply, or 502 when unreachable)
  method      TEXT,             -- Telegram method, e.g. sendMessage
  bot_id      TEXT,             -- numeric bot id (token redacted)
  path        TEXT,             -- request path, token redacted
  error_code  INTEGER,          -- Telegram's error_code, from the response body
  description TEXT,             -- Telegram's description, from the response body
  message     TEXT,             -- proxy-side detail (e.g. the fetch exception)
  ip          TEXT,             -- caller IP
  country     TEXT,             -- caller country
  region      TEXT,             -- caller region
  city        TEXT,             -- caller city
  asn         TEXT,             -- caller network ASN
  org         TEXT,             -- caller network organisation
  ua          TEXT,             -- caller user-agent
  colo        TEXT,             -- Cloudflare edge colo that served the request
  ray         TEXT              -- cf-ray trace id
);

-- ---------------------------------------------------------------------------
-- Access control (admin dashboard at /admin). Re-run `npm run db:init` to add
-- these tables to an existing database; it is idempotent.
-- ---------------------------------------------------------------------------

-- Admin-editable settings. Missing keys fall back to the defaults in lib/store.js.
CREATE TABLE IF NOT EXISTS settings (
  key   TEXT PRIMARY KEY,
  value TEXT NOT NULL
);

-- Access keys created in the dashboard. Only the SHA-256 hash is stored; the
-- plaintext key is shown once, at creation.
CREATE TABLE IF NOT EXISTS access_keys (
  id         INTEGER PRIMARY KEY AUTOINCREMENT,
  label      TEXT NOT NULL,
  key_hash   TEXT NOT NULL UNIQUE,
  prefix     TEXT NOT NULL,             -- first characters, to recognise a key
  created_at TEXT NOT NULL,
  last_used  TEXT,
  uses       INTEGER NOT NULL DEFAULT 0
);

-- Bots refused by the proxy, whatever key they present.
CREATE TABLE IF NOT EXISTS blocked_bots (
  bot_id     TEXT PRIMARY KEY,
  reason     TEXT,
  created_at TEXT NOT NULL,
  hits       INTEGER NOT NULL DEFAULT 0, -- requests refused since blocking
  last_seen  TEXT
);

-- Per-bot send* counts per UTC day. `free_count` is the unauthenticated share,
-- which is what the daily limit applies to.
CREATE TABLE IF NOT EXISTS bot_usage (
  day        TEXT NOT NULL,             -- YYYY-MM-DD (UTC)
  bot_id     TEXT NOT NULL,
  count      INTEGER NOT NULL DEFAULT 0,
  free_count INTEGER NOT NULL DEFAULT 0,
  PRIMARY KEY (day, bot_id)
);

-- Messages flagged by the spam detector.
CREATE TABLE IF NOT EXISTS spam_events (
  id      INTEGER PRIMARY KEY AUTOINCREMENT,
  ts      TEXT NOT NULL,
  bot_id  TEXT NOT NULL,
  method  TEXT,
  chat_id TEXT,
  score   INTEGER NOT NULL,
  reasons TEXT,                         -- matched rules, comma-separated
  text    TEXT,                         -- message text, truncated
  action  TEXT NOT NULL,                -- log | drop | block_bot
  ip      TEXT,
  country TEXT
);
CREATE INDEX IF NOT EXISTS spam_events_bot_ts ON spam_events (bot_id, ts);

-- Failed admin logins per IP per hour, for brute-force lockout.
CREATE TABLE IF NOT EXISTS login_failures (
  ip    TEXT NOT NULL,
  hour  TEXT NOT NULL,
  count INTEGER NOT NULL DEFAULT 0,
  PRIMARY KEY (ip, hour)
);
