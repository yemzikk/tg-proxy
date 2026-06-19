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
