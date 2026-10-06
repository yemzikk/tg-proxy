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
      case "GET analytics":
        return await analytics(db, env, url.searchParams.get("days"));
      case "GET bot":
        return await botDetail(db, id);
      case "GET errors":
        return await listErrors(db, url.searchParams.get("kind"), url.searchParams.get("bot"));
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
  const yesterday = utcDay(new Date(Date.now() - 86400 * 1000));
  const sinceDay = new Date(Date.now() - 48 * 60 * 60 * 1000).toISOString();
  const [stats, usageToday, keys, blocked, spam, usageYesterday, errors, spamPrev, errorsPrev] = await db.batch([
    db.prepare("SELECT delivered, errors FROM stats WHERE id = 1"),
    db.prepare(
      "SELECT COALESCE(SUM(count), 0) AS sends, COALESCE(SUM(free_count), 0) AS free, COUNT(*) AS bots FROM bot_usage WHERE day = ?"
    ).bind(today),
    db.prepare("SELECT COUNT(*) AS n FROM access_keys"),
    db.prepare("SELECT COUNT(*) AS n FROM blocked_bots"),
    db.prepare("SELECT COUNT(*) AS n FROM spam_events WHERE ts > ?").bind(since),
    db.prepare(
      "SELECT COALESCE(SUM(count), 0) AS sends, COUNT(*) AS bots FROM bot_usage WHERE day = ?"
    ).bind(yesterday),
    db.prepare("SELECT COUNT(*) AS n FROM error_log WHERE ts > ?").bind(since),
    db.prepare("SELECT COUNT(*) AS n FROM spam_events WHERE ts > ? AND ts <= ?").bind(sinceDay, since),
    db.prepare("SELECT COUNT(*) AS n FROM error_log WHERE ts > ? AND ts <= ?").bind(sinceDay, since),
  ]);
  const u = usageToday.results[0] || {};
  const y = usageYesterday.results[0] || {};
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
    sendsYesterday: Number(y.sends ?? 0),
    botsYesterday: Number(y.bots ?? 0),
    errors24h: Number(errors.results[0]?.n ?? 0),
    spamPrev24h: Number(spamPrev.results[0]?.n ?? 0),
    errorsPrev24h: Number(errorsPrev.results[0]?.n ?? 0),
  });
}

// Charts for the overview: per-day series over the last `days` UTC days (usage
// rows are kept USAGE_RETENTION_DAYS) and breakdowns of the same window.
async function analytics(db, env, daysParam) {
  const days = Math.min(Math.max(parseInt(daysParam, 10) || 14, 1), USAGE_RETENTION_DAYS);
  const dayList = [];
  for (let i = days - 1; i >= 0; i--) dayList.push(utcDay(new Date(Date.now() - i * 86400 * 1000)));
  const from = dayList[0];
  const fromTs = from + "T00:00:00.000Z";
  const today = dayList[dayList.length - 1];
  const settings = await loadSettings(db, env);
  const limit = parseInt(settings.free_daily_limit, 10);

  const [usageRes, spamRes, errRes, topRes, reasonRes, countryRes, tgErrRes, methodRes, keyRes, refusedRes, limitRes] =
    await db.batch([
      db.prepare(
        `SELECT day, SUM(count) AS sends, SUM(free_count) AS free, COUNT(*) AS bots
           FROM bot_usage WHERE day >= ? GROUP BY day`
      ).bind(from),
      db.prepare(
        `SELECT substr(ts, 1, 10) AS day, action, COUNT(*) AS n
           FROM spam_events WHERE ts >= ? GROUP BY day, action`
      ).bind(fromTs),
      db.prepare(
        `SELECT substr(ts, 1, 10) AS day, kind, COUNT(*) AS n
           FROM error_log WHERE ts >= ? GROUP BY day, kind`
      ).bind(fromTs),
      db.prepare(
        `SELECT u.bot_id, SUM(u.count) AS sends, SUM(u.free_count) AS free,
                COUNT(*) AS active_days, MAX(u.day) AS last_day,
                b.bot_id IS NOT NULL AS blocked,
                (SELECT COUNT(*) FROM spam_events s WHERE s.bot_id = u.bot_id AND s.ts >= ?) AS spam
           FROM bot_usage u LEFT JOIN blocked_bots b ON b.bot_id = u.bot_id
          WHERE u.day >= ?
          GROUP BY u.bot_id ORDER BY sends DESC LIMIT 10`
      ).bind(fromTs, from),
      db.prepare("SELECT reasons FROM spam_events WHERE ts >= ? ORDER BY id DESC LIMIT 5000").bind(fromTs),
      db.prepare(
        `SELECT COALESCE(country, '??') AS country, COUNT(*) AS n
           FROM spam_events WHERE ts >= ? GROUP BY country ORDER BY n DESC LIMIT 8`
      ).bind(fromTs),
      db.prepare(
        `SELECT error_code, description, COUNT(*) AS n, COUNT(DISTINCT bot_id) AS bots
           FROM error_log WHERE ts >= ? AND kind = 'telegram_error'
          GROUP BY error_code, description ORDER BY n DESC LIMIT 8`
      ).bind(fromTs),
      db.prepare(
        `SELECT COALESCE(method, '(none)') AS method, COUNT(*) AS n
           FROM error_log WHERE ts >= ? GROUP BY method ORDER BY n DESC LIMIT 8`
      ).bind(fromTs),
      db.prepare("SELECT label, prefix, uses, last_used FROM access_keys ORDER BY uses DESC LIMIT 8"),
      db.prepare("SELECT COALESCE(SUM(hits), 0) AS hits FROM blocked_bots"),
      // free_count is bumped before the limit check, so anything past the limit
      // is a request that was refused with 429.
      Number.isFinite(limit) && limit > 0
        ? db.prepare(
            `SELECT COUNT(*) AS bots, COALESCE(SUM(free_count - ?), 0) AS refused
               FROM bot_usage WHERE day = ? AND free_count > ?`
          ).bind(limit, today, limit)
        : db.prepare("SELECT 0 AS bots, 0 AS refused"),
    ]);

  const byDay = Object.fromEntries(usageRes.results.map((r) => [r.day, r]));
  const daily = dayList.map((day) => {
    const r = byDay[day] || {};
    const sends = Number(r.sends ?? 0);
    const free = Number(r.free ?? 0);
    return { day, sends, free, keyed: sends - free, bots: Number(r.bots ?? 0) };
  });

  const reasons = {};
  for (const row of reasonRes.results) {
    for (const reason of String(row.reasons || "").split(", ")) {
      if (reason) reasons[reason] = (reasons[reason] || 0) + 1;
    }
  }

  return json({
    days: dayList,
    limit: Number.isFinite(limit) ? limit : null,
    daily,
    spamDaily: pivot(dayList, spamRes.results, "action"),
    errorsDaily: pivot(dayList, errRes.results, "kind"),
    topBots: topRes.results,
    spamReasons: Object.entries(reasons)
      .map(([reason, n]) => ({ reason, n }))
      .sort((a, b) => b.n - a.n)
      .slice(0, 8),
    spamCountries: countryRes.results,
    telegramErrors: tgErrRes.results,
    errorMethods: methodRes.results,
    keys: keyRes.results,
    blockedHits: Number(refusedRes.results[0]?.hits ?? 0),
    limitBotsToday: Number(limitRes.results[0]?.bots ?? 0),
    limitRefusedToday: Number(limitRes.results[0]?.refused ?? 0),
  });
}

// Rows of { day, <key>, n } -> { keys: [...], rows: [{ day, total, [key]: n }] }.
function pivot(dayList, rows, key) {
  const keys = [...new Set(rows.map((r) => r[key] || "unknown"))].sort();
  const map = Object.fromEntries(dayList.map((day) => [day, { day, total: 0 }]));
  for (const r of rows) {
    const row = map[r.day];
    if (!row) continue;
    const k = r[key] || "unknown";
    row[k] = (row[k] || 0) + Number(r.n);
    row.total += Number(r.n);
  }
  return { keys, rows: dayList.map((day) => map[day]) };
}

async function botDetail(db, botId) {
  if (!/^\d{1,20}$/.test(botId || "")) return json({ error: "Bad bot id." }, 400);
  const [usageRes, blockedRes, spamRes, errRes, totalsRes] = await db.batch([
    db.prepare("SELECT day, count, free_count FROM bot_usage WHERE bot_id = ? ORDER BY day").bind(botId),
    db.prepare("SELECT reason, created_at, hits, last_seen FROM blocked_bots WHERE bot_id = ?").bind(botId),
    db.prepare(
      "SELECT ts, method, chat_id, score, reasons, text, action, ip, country FROM spam_events WHERE bot_id = ? ORDER BY id DESC LIMIT 20"
    ).bind(botId),
    db.prepare(
      "SELECT ts, kind, status, method, error_code, description, message, country FROM error_log WHERE bot_id = ? ORDER BY id DESC LIMIT 20"
    ).bind(botId),
    db.prepare(
      `SELECT (SELECT COUNT(*) FROM spam_events WHERE bot_id = ?1) AS spam,
              (SELECT COUNT(*) FROM error_log WHERE bot_id = ?1) AS errors,
              (SELECT COUNT(DISTINCT chat_id) FROM spam_events WHERE bot_id = ?1) AS spam_chats`
    ).bind(botId),
  ]);
  const byDay = Object.fromEntries(usageRes.results.map((r) => [r.day, r]));
  const daily = [];
  for (let i = USAGE_RETENTION_DAYS - 1; i >= 0; i--) {
    const day = utcDay(new Date(Date.now() - i * 86400 * 1000));
    const r = byDay[day] || {};
    const sends = Number(r.count ?? 0);
    const free = Number(r.free_count ?? 0);
    daily.push({ day, sends, free, keyed: sends - free });
  }
  return json({
    bot_id: botId,
    daily,
    blocked: blockedRes.results[0] || null,
    spam: spamRes.results,
    errors: errRes.results,
    totals: totalsRes.results[0] || {},
  });
}

async function listErrors(db, kind, botId) {
  const where = [];
  const binds = [];
  if (kind) {
    where.push("kind = ?");
    binds.push(kind);
  }
  if (botId) {
    where.push("bot_id = ?");
    binds.push(botId);
  }
  const { results } = await db
    .prepare(
      `SELECT id, ts, kind, status, method, bot_id, error_code, description, message, ip, country, city, org, colo
         FROM error_log ${where.length ? "WHERE " + where.join(" AND ") : ""}
        ORDER BY id DESC LIMIT 200`
    )
    .bind(...binds)
    .all();
  const kinds = await db.prepare("SELECT kind, COUNT(*) AS n FROM error_log GROUP BY kind ORDER BY n DESC").all();
  return json({ errors: results, kinds: kinds.results });
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
