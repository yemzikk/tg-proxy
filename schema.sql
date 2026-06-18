-- Stats counter for the proxy. A single row (id = 1) holds running totals.
CREATE TABLE IF NOT EXISTS stats (
  id        INTEGER PRIMARY KEY,
  delivered INTEGER NOT NULL DEFAULT 0,
  errors    INTEGER NOT NULL DEFAULT 0
);

INSERT OR IGNORE INTO stats (id, delivered, errors) VALUES (1, 0, 0);

-- Durable error log. Real-time `wrangler ... tail` output is not retained, so
-- operational failures are also appended here for later review (npm run errors).
CREATE TABLE IF NOT EXISTS error_log (
  id      INTEGER PRIMARY KEY AUTOINCREMENT,
  ts      TEXT NOT NULL,
  kind    TEXT NOT NULL,
  status  INTEGER,
  path    TEXT,
  message TEXT
);
