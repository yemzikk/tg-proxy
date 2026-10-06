// Admin API for the dashboard at /admin. All routes live under /api/admin/.
//
// Auth: ADMIN_PASSWORD (a secret, at least 12 characters) is exchanged for an
// HttpOnly, SameSite=Strict session cookie signed with HMAC. Changing the
// password invalidates every session. Failed logins are capped per IP per hour.
// State-changing calls must be JSON and same-origin (CSRF guard).

import {
  getDb,
  loadSettings,
  defaultSettings,
  SETTING_KEYS,
  utcDay,
  sha256Hex,
  generateAccessKey,
  hmacSign,
  safeEqual,
  escapeHtml,
  sendLogMessage,
} from "../../../lib/store.js";

const COOKIE = "tgp_admin";
const SESSION_SECONDS = 12 * 60 * 60;
const MAX_LOGIN_FAILURES_PER_HOUR = 10;
const MIN_PASSWORD_LENGTH = 12;
const USAGE_RETENTION_DAYS = 30;

export async function onRequest(context) {
  const { request, env, params, waitUntil } = context;
  const route = (params.route || []).join("/");
  const method = request.method;

  if (!env.ADMIN_PASSWORD || env.ADMIN_PASSWORD.length < MIN_PASSWORD_LENGTH) {
    return json(
      { error: `Admin dashboard disabled: set ADMIN_PASSWORD (at least ${MIN_PASSWORD_LENGTH} characters).` },
      503
    );
  }
  const db = getDb(env);
  if (!db) {
    return json({ error: "Admin dashboard needs the D1 binding (see README: Live stats)." }, 503);
  }

  if (method !== "GET" && !isSameOriginJson(request)) {
    return json({ error: "Bad request origin or content type." }, 403);
  }

  try {
    if (route === "login" && method === "POST") return await login(request, env, db);
    if (route === "logout" && method === "POST") return logout();

    if (!(await isAuthenticated(request, env))) {
      return json({ error: "Not signed in." }, 401);
    }

    const body = method === "POST" || method === "PUT" ? await request.json().catch(() => ({})) : null;
    const url = new URL(request.url);
    const [section, id] = route.split("/");

    switch (`${method} ${section}`) {
      case "GET session":
        return json({ ok: true });
      case "GET overview":
        waitUntil(cleanup(db));
        return await overview(db);
      case "GET usage":
        return await usage(db, url.searchParams.get("day") || utcDay());
      case "GET keys":
        return await listKeys(db);
      case "POST keys":
        return await createKey(db, body);
      case "DELETE keys":
        return await deleteKey(db, id);
      case "GET blocked":
        return await listBlocked(db);
      case "POST blocked":
        return await blockBot(db, body);
      case "DELETE blocked":
        return await unblockBot(db, id);
      case "GET spam":
        return await listSpam(db, url.searchParams.get("bot"));
      case "GET settings":
        return json({ settings: await loadSettings(db, env), defaults: defaultSettings(env), logBot: Boolean(env.LOG_BOT_TOKEN) });
      case "PUT settings":
        return await saveSettings(db, env, body);
      case "POST test-alert":
        return await testAlert(db, env, url.origin);
    }
    return json({ error: "Not found." }, 404);
  } catch (err) {
    console.error("admin: request failed", route, err && err.message);
    return json({ error: "Server error: " + (err && err.message) }, 500);
  }
}

// ---- auth -----------------------------------------------------------------

async function login(request, env, db) {
  const ip = request.headers.get("cf-connecting-ip") || "unknown";
  const hour = new Date().toISOString().slice(0, 13);
  const row = await db
    .prepare("SELECT count FROM login_failures WHERE ip = ? AND hour = ?")
    .bind(ip, hour)
    .first();
  if (row && row.count >= MAX_LOGIN_FAILURES_PER_HOUR) {
    return json({ error: "Too many failed attempts. Try again later." }, 429);
  }

  const { password } = await request.json().catch(() => ({}));
  const ok =
    typeof password === "string" &&
    safeEqual(await sha256Hex(password), await sha256Hex(env.ADMIN_PASSWORD));
  if (!ok) {
    await db
      .prepare(
        `INSERT INTO login_failures (ip, hour, count) VALUES (?, ?, 1)
         ON CONFLICT (ip, hour) DO UPDATE SET count = count + 1`
      )
      .bind(ip, hour)
      .run();
    return json({ error: "Wrong password." }, 401);
  }

  const exp = Math.floor(Date.now() / 1000) + SESSION_SECONDS;
  const token = `${exp}.${await hmacSign(env.ADMIN_PASSWORD, "admin-session:" + exp)}`;
  return json({ ok: true }, 200, {
    "set-cookie": `${COOKIE}=${token}; Path=/; HttpOnly; Secure; SameSite=Strict; Max-Age=${SESSION_SECONDS}`,
  });
}

function logout() {
  return json({ ok: true }, 200, {
    "set-cookie": `${COOKIE}=; Path=/; HttpOnly; Secure; SameSite=Strict; Max-Age=0`,
  });
}

async function isAuthenticated(request, env) {
  const cookie = request.headers.get("cookie") || "";
  const m = cookie.match(new RegExp(`(?:^|;\\s*)${COOKIE}=(\\d+)\\.([\\w-]+)`));
  if (!m) return false;
  const [, exp, sig] = m;
  if (Number(exp) < Date.now() / 1000) return false;
  return safeEqual(sig, await hmacSign(env.ADMIN_PASSWORD, "admin-session:" + exp));
}

// Browsers cannot send application/json cross-origin without a CORS preflight
// (which this API never approves), and Origin, when present, must match.
function isSameOriginJson(request) {
  const type = (request.headers.get("content-type") || "").toLowerCase();
  if (request.method !== "DELETE" && !type.includes("application/json")) return false;
  const origin = request.headers.get("origin");
  return !origin || origin === new URL(request.url).origin;
}

// ---- data -------------------------------------------------------------------

async function overview(db) {
  const today = utcDay();
  const since = new Date(Date.now() - 24 * 60 * 60 * 1000).toISOString();
  const [stats, usageToday, keys, blocked, spam] = await db.batch([
    db.prepare("SELECT delivered, errors FROM stats WHERE id = 1"),
    db.prepare(
      "SELECT COALESCE(SUM(count), 0) AS sends, COALESCE(SUM(free_count), 0) AS free, COUNT(*) AS bots FROM bot_usage WHERE day = ?"
    ).bind(today),
    db.prepare("SELECT COUNT(*) AS n FROM access_keys"),
    db.prepare("SELECT COUNT(*) AS n FROM blocked_bots"),
    db.prepare("SELECT COUNT(*) AS n FROM spam_events WHERE ts > ?").bind(since),
  ]);
  const u = usageToday.results[0] || {};
  return json({
    day: today,
    delivered: Number(stats.results[0]?.delivered ?? 0),
    errors: Number(stats.results[0]?.errors ?? 0),
    sendsToday: Number(u.sends ?? 0),
    freeSendsToday: Number(u.free ?? 0),
    botsToday: Number(u.bots ?? 0),
    keys: Number(keys.results[0]?.n ?? 0),
    blocked: Number(blocked.results[0]?.n ?? 0),
    spam24h: Number(spam.results[0]?.n ?? 0),
  });
}

async function usage(db, day) {
  if (!/^\d{4}-\d{2}-\d{2}$/.test(day)) return json({ error: "Bad day." }, 400);
  const { results } = await db
    .prepare(
      `SELECT u.bot_id, u.count, u.free_count,
              b.bot_id IS NOT NULL AS blocked,
              (SELECT COUNT(*) FROM spam_events s WHERE s.bot_id = u.bot_id) AS spam
         FROM bot_usage u LEFT JOIN blocked_bots b ON b.bot_id = u.bot_id
        WHERE u.day = ?
        ORDER BY u.count DESC
        LIMIT 200`
    )
    .bind(day)
    .all();
  return json({ day, bots: results });
}

async function listKeys(db) {
  const { results } = await db
    .prepare("SELECT id, label, prefix, created_at, last_used, uses FROM access_keys ORDER BY id DESC")
    .all();
  return json({ keys: results });
}

async function createKey(db, body) {
  const label = String(body?.label || "").trim().slice(0, 100);
  if (!label) return json({ error: "A label is required." }, 400);
  const key = generateAccessKey();
  await db
    .prepare("INSERT INTO access_keys (label, key_hash, prefix, created_at) VALUES (?, ?, ?, ?)")
    .bind(label, await sha256Hex(key), key.slice(0, 10), new Date().toISOString())
    .run();
  // The only time the plaintext key is ever returned.
  return json({ key });
}

async function deleteKey(db, id) {
  if (!/^\d+$/.test(id || "")) return json({ error: "Bad key id." }, 400);
  await db.prepare("DELETE FROM access_keys WHERE id = ?").bind(Number(id)).run();
  return json({ ok: true });
}

async function listBlocked(db) {
  const { results } = await db
    .prepare("SELECT bot_id, reason, created_at, hits, last_seen FROM blocked_bots ORDER BY created_at DESC")
    .all();
  return json({ blocked: results });
}

async function blockBot(db, body) {
  // Accept a bare id or a whole token; only the numeric id is kept.
  const botId = String(body?.bot_id || "").trim().split(":")[0];
  if (!/^\d{1,20}$/.test(botId)) return json({ error: "Enter a numeric bot id." }, 400);
  const reason = String(body?.reason || "").trim().slice(0, 300) || null;
  await db
    .prepare(
      `INSERT INTO blocked_bots (bot_id, reason, created_at) VALUES (?, ?, ?)
       ON CONFLICT (bot_id) DO UPDATE SET reason = excluded.reason`
    )
    .bind(botId, reason, new Date().toISOString())
    .run();
  return json({ ok: true });
}

async function unblockBot(db, botId) {
  if (!/^\d{1,20}$/.test(botId || "")) return json({ error: "Bad bot id." }, 400);
  await db.prepare("DELETE FROM blocked_bots WHERE bot_id = ?").bind(botId).run();
  return json({ ok: true });
}

async function listSpam(db, botId) {
  const stmt = botId
    ? db.prepare("SELECT * FROM spam_events WHERE bot_id = ? ORDER BY id DESC LIMIT 200").bind(botId)
    : db.prepare("SELECT * FROM spam_events ORDER BY id DESC LIMIT 200");
  const { results } = await stmt.all();
  return json({ events: results });
}

async function saveSettings(db, env, body) {
  const input = body?.settings || {};
  const errors = [];
  const checks = {
    free_daily_limit: (v) => /^\d{0,9}$/.test(v) || "Daily limit must be a whole number (0 = key required, empty = unlimited).",
    spam_detection: (v) => ["on", "off"].includes(v) || "Spam detection must be on or off.",
    spam_action: (v) => ["log", "drop", "block_bot"].includes(v) || "Unknown spam action.",
    spam_keywords: (v) => v.length <= 5000 || "Keyword list is too long (5000 characters max).",
    spam_log_chat_id: (v) => /^(-?\d{1,20}|@\w{4,64})?$/.test(v) || "Log chat must be a numeric id or @channelname.",
  };
  const stmts = [];
  for (const key of SETTING_KEYS) {
    if (!(key in input)) continue;
    const value = String(input[key] ?? "").trim();
    const ok = checks[key](value);
    if (ok !== true) {
      errors.push(ok);
      continue;
    }
    stmts.push(
      db
        .prepare("INSERT INTO settings (key, value) VALUES (?, ?) ON CONFLICT (key) DO UPDATE SET value = excluded.value")
        .bind(key, value)
    );
  }
  if (errors.length) return json({ error: errors.join(" ") }, 400);
  if (stmts.length) await db.batch(stmts);
  return json({ settings: await loadSettings(db, env) });
}

async function testAlert(db, env, origin) {
  const settings = await loadSettings(db, env);
  if (!env.LOG_BOT_TOKEN) return json({ error: "LOG_BOT_TOKEN is not set." }, 400);
  if (!settings.spam_log_chat_id) return json({ error: "Set a log group/chat id first." }, 400);
  try {
    await sendLogMessage(
      env,
      settings.spam_log_chat_id,
      `✅ <b>tg-proxy test alert</b>\nSpam alerts from ${escapeHtml(origin)} will arrive here.`
    );
  } catch (err) {
    return json({ error: err.message }, 502);
  }
  return json({ ok: true });
}

// Drop usage rows past retention and stale login-failure buckets.
async function cleanup(db) {
  const cutoff = utcDay(new Date(Date.now() - USAGE_RETENTION_DAYS * 86400 * 1000));
  const hour = new Date().toISOString().slice(0, 13);
  await db
    .batch([
      db.prepare("DELETE FROM bot_usage WHERE day < ?").bind(cutoff),
      db.prepare("DELETE FROM login_failures WHERE hour < ?").bind(hour),
    ])
    .catch((err) => console.error("admin: cleanup failed", err && err.message));
}

function json(data, status = 200, extraHeaders = {}) {
  return new Response(JSON.stringify(data), {
    status,
    headers: {
      "content-type": "application/json; charset=utf-8",
      "cache-control": "no-store",
      ...extraHeaders,
    },
  });
}
