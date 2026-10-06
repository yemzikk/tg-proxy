// Cloudflare Pages Function — catch-all proxy for the Telegram Bot API.
//
// Any request to   https://tgproxy.yemzikk.in/bot<TOKEN>/<method>
// is transparently forwarded to   https://api.telegram.org/bot<TOKEN>/<method>
//
// This is useful where api.telegram.org is blocked/throttled but Cloudflare's
// edge is reachable. The bot token in the path is the only credential Telegram
// needs, so nothing extra has to be configured here.
//
// Optional logging: when LOG_BOT_TOKEN and LOG_CHANNEL_ID are set, every send*
// call routed through the proxy is mirrored to that channel. Logging runs in
// the background (waitUntil) so it never delays or breaks the proxied response.
//
// Optional access control: set ALLOWED_BOT_IDS to a comma-separated list of bot
// ids (the number before ":" in a token) to restrict the proxy to your own
// bots. Leave it unset to run as an open relay (the default).
//
// With the D1 binding, the admin dashboard (/admin) adds access keys, a free
// daily send* limit for bots without a key, a bot block list and a crypto-spam
// detector that alerts a log group. A key is passed as /k/<key>/bot<TOKEN>/...
// or as an X-Proxy-Key header.

import {
  TELEGRAM_ORIGIN,
  getDb,
  defaultSettings,
  mergeSettings,
  utcDay,
  secondsUntilUtcMidnight,
  sha256Hex,
  escapeHtml,
  sendLogMessage,
} from "../lib/store.js";
import { detectSpam, spamText } from "../lib/spam.js";

// Cap on the body size we will buffer for logging. Larger bodies are forwarded
// to Telegram untouched but skipped by the log parser to avoid memory blow-up.
const MAX_LOG_BODY_BYTES = 256 * 1024;

// One spam alert per bot per this window, so a spam run cannot flood the log
// group (every event is still recorded in D1 and shown in the dashboard).
const SPAM_ALERT_WINDOW_MS = 10 * 60 * 1000;

export async function onRequest(context) {
  const { request, next, env, waitUntil } = context;
  const url = new URL(request.url);

  // An access key may be given as a path prefix, /k/<key>/bot<token>/..., which
  // works with any client library's base-URL setting, or as an X-Proxy-Key
  // header. Either way it is stripped before the request reaches Telegram.
  let pathname = url.pathname;
  let accessKey = request.headers.get("x-proxy-key");
  const keyMatch = pathname.match(/^\/k\/([^/]+)(\/.*)$/);
  if (keyMatch) {
    accessKey = decodeURIComponent(keyMatch[1]);
    pathname = keyMatch[2];
  }

  // Telegram Bot API methods live under /bot<token>/..., and file downloads
  // under /file/bot<token>/.... Anything else falls through to the static
  // site (the landing page in index.html).
  const isProxyPath = pathname.startsWith("/bot") || pathname.startsWith("/file/bot");
  if (!isProxyPath) {
    return next();
  }

  // Answer CORS preflights locally so browser-side clients work too.
  if (request.method === "OPTIONS") {
    return new Response(null, { headers: corsHeaders() });
  }

  // Parse the bot id and method out of the path once, with the secret token
  // redacted. Error-log rows reuse this so the full token is never stored.
  const pathInfo = parseRequestPath(pathname);

  // Optional allow-list: when ALLOWED_BOT_IDS is set, only proxy requests for
  // those bot ids. This closes off open-relay abuse (stats poisoning, log
  // flooding, invocation cost) for self-hosters who only run their own bots.
  if (env.ALLOWED_BOT_IDS) {
    const allowed = env.ALLOWED_BOT_IDS.split(",").map((s) => s.trim()).filter(Boolean);
    if (!pathInfo.botId || !allowed.includes(pathInfo.botId)) {
      return telegramError(403, "Forbidden: this bot is not allowed on this proxy.");
    }
  }

  // The D1 binding (optional) backs the public stats, the durable error log and
  // access control. Without it the proxy is an open relay, as before.
  const statsDb = getDb(env);
  const logTarget = getLogTarget(pathname);

  // Access control: blocked bots, access keys and the free daily limit. Returns
  // a ready response when the request is refused.
  let gate = null;
  if (statsDb) {
    gate = await checkAccess(statsDb, env, waitUntil, {
      botId: pathInfo.botId,
      isSend: Boolean(logTarget),
      accessKey,
      request,
    });
    if (gate.response) return gate.response;
  }

  // Parse the call parameters once if logging or spam scanning needs them. Read
  // from a clone: a request body can only be read once, and the original is
  // consumed by the upstream fetch below.
  const loggingEnabled = Boolean(env.LOG_BOT_TOKEN && env.LOG_CHANNEL_ID && logTarget);
  const scanSpam = Boolean(
    logTarget && gate && !gate.authenticated && gate.settings.spam_detection === "on"
  );
  const params =
    loggingEnabled || scanSpam ? await extractParams(request.clone(), url) : null;
  // Capture request metadata from the original request (cf + headers) up front.
  const logMeta = loggingEnabled || scanSpam ? requestMeta(request) : null;

  // Spam check (unauthenticated traffic only; key holders are trusted). Flagged
  // messages are recorded and alerted to the log group, and depending on the
  // spam_action setting dropped and/or the bot blocked.
  if (scanSpam) {
    const media = describeMedia(logTarget.method, params);
    const spam = detectSpam(spamText(params, media.captions), gate.settings.spam_keywords);
    if (spam.isSpam) {
      const action = gate.settings.spam_action;
      waitUntil(
        handleSpam(statsDb, env, {
          spam,
          action,
          settings: gate.settings,
          botId: pathInfo.botId,
          method: logTarget.method,
          params,
          media,
          meta: logMeta,
          request,
          origin: url.origin,
        }).catch((err) => console.error("proxy: spam handling failed", err && err.message))
      );
      if (action === "drop" || action === "block_bot") {
        return telegramError(403, "Forbidden: message rejected as spam by this proxy.");
      }
    }
  }

  // Rebuild the request against the Telegram origin, preserving path, query,
  // method, headers and body, minus the proxy's own access-key header. fetch()
  // recomputes the Host header from the new URL automatically.
  const upstreamUrl = TELEGRAM_ORIGIN + pathname + url.search;
  const upstreamHeaders = new Headers(request.headers);
  upstreamHeaders.delete("x-proxy-key");
  const hasBody = request.method !== "GET" && request.method !== "HEAD";
  let upstream;
  try {
    upstream = await fetch(upstreamUrl, {
      method: request.method,
      headers: upstreamHeaders,
      body: hasBody ? request.body : null,
    });
  } catch (err) {
    // The upstream is unreachable (often the very reason this proxy exists).
    // This is the only failure mode the proxy is actually responsible for, so it
    // is the only thing counted as an error in /stats. Record it in Cloudflare's
    // live logs and the durable error log (neither of which depend on Telegram),
    // bump the errors counter, then return a clean 502 rather than crashing.
    console.error("proxy: upstream fetch failed", pathInfo.redactedPath, err && err.message);
    waitUntil(
      logError(statsDb, "upstream_unreachable", {
        status: 502,
        method: pathInfo.method,
        botId: pathInfo.botId,
        path: pathInfo.redactedPath,
        message: err && err.message,
        ...callerFields(request),
      })
    );
    if (statsDb && logTarget) {
      waitUntil(
        recordStat(statsDb, false).catch((e) => {
          console.error("proxy: stat write failed", e && e.message);
          return logError(statsDb, "stat_write_failed", { message: e && e.message });
        })
      );
    }
    return telegramError(502, "Proxy could not reach api.telegram.org");
  }

  if (loggingEnabled) {
    waitUntil(
      logMessage(params, logTarget, logMeta, env).catch((err) => {
        // A logging failure must never affect the proxied request. Record it in
        // Cloudflare's logs and the durable error log, not the channel itself.
        console.error("proxy: log delivery failed", err && err.message);
        return logError(statsDb, "log_delivery_failed", {
          method: pathInfo.method,
          botId: pathInfo.botId,
          path: pathInfo.redactedPath,
          message: err && err.message,
        });
      })
    );
  }

  // Count send* outcomes for the public /stats endpoint. Optional: needs the
  // D1 binding. Runs in the background so it never delays the response. Getting
  // ANY response back means the proxy did its job, so it counts as delivered,
  // even if Telegram itself replied 4xx/5xx (bad chat_id, blocked, rate limit).
  // Those are between the bot and Telegram, not proxy failures.
  if (statsDb && logTarget) {
    waitUntil(
      recordStat(statsDb, true).catch((err) => {
        console.error("proxy: stat write failed", err && err.message);
        return logError(statsDb, "stat_write_failed", { message: err && err.message });
      })
    );
  }

  // Telegram replied, but with an error (4xx/5xx). Not a proxy failure, so it is
  // not counted in /stats, but the error_code/description says exactly what went
  // wrong, so record it for diagnosis. Read the body from a clone so the response
  // streamed back to the client is left untouched.
  if (statsDb && !upstream.ok) {
    const errorClone = upstream.clone();
    waitUntil(
      readTelegramError(errorClone)
        .then((tg) =>
          logError(statsDb, "telegram_error", {
            status: upstream.status,
            method: pathInfo.method,
            botId: pathInfo.botId,
            path: pathInfo.redactedPath,
            errorCode: tg.errorCode,
            description: tg.description,
            ...callerFields(request),
          })
        )
        .catch((err) => console.error("proxy: telegram-error log failed", err && err.message))
    );
  }

  // Stream the response straight back, adding permissive CORS headers.
  const headers = new Headers(upstream.headers);
  for (const [key, value] of Object.entries(corsHeaders())) {
    headers.set(key, value);
  }

  return new Response(upstream.body, {
    status: upstream.status,
    statusText: upstream.statusText,
    headers,
  });
}

// Decide whether a request may use the proxy. Reads settings, the block list
// and the access key (or bumps the free-tier counter) in one D1 round trip.
// Returns { response } when refused, else { authenticated, settings }.
// On a database error it fails open with the default settings, so a missing
// migration never takes the proxy down; the error is logged.
async function checkAccess(db, env, waitUntil, { botId, isSend, accessKey, request }) {
  const now = new Date();
  const day = utcDay(now);
  const bot = botId || "";
  try {
    const stmts = [
      db.prepare("SELECT key, value FROM settings"),
      db.prepare("SELECT 1 AS hit FROM blocked_bots WHERE bot_id = ?").bind(bot),
    ];
    if (accessKey) {
      stmts.push(
        db.prepare("SELECT id FROM access_keys WHERE key_hash = ?").bind(await sha256Hex(accessKey))
      );
    } else if (isSend) {
      stmts.push(usageUpsert(db, day, bot, 1));
    }
    const [settingsRes, blockedRes, thirdRes] = await db.batch(stmts);
    const settings = mergeSettings(env, settingsRes.results);

    if (blockedRes.results.length) {
      waitUntil(
        db
          .prepare("UPDATE blocked_bots SET hits = hits + 1, last_seen = ? WHERE bot_id = ?")
          .bind(now.toISOString(), bot)
          .run()
          .catch(() => {})
      );
      return { response: telegramError(403, "Forbidden: this bot is blocked on this proxy.") };
    }

    if (accessKey) {
      const keyRow = thirdRes.results[0];
      if (!keyRow) {
        return { response: telegramError(401, "Unauthorized: invalid proxy access key.") };
      }
      const writes = [
        db
          .prepare("UPDATE access_keys SET uses = uses + 1, last_used = ? WHERE id = ?")
          .bind(now.toISOString(), keyRow.id),
      ];
      if (isSend) writes.push(usageUpsert(db, day, bot, 0));
      waitUntil(db.batch(writes).catch((e) => console.error("proxy: key usage write failed", e && e.message)));
      return { authenticated: true, settings };
    }

    // Unauthenticated: 0 means an access key is required; otherwise send* calls
    // are capped per bot per UTC day. Non-numeric means unlimited.
    const limit = parseInt(settings.free_daily_limit, 10);
    if (limit === 0) {
      return {
        response: telegramError(401, "Unauthorized: this proxy requires an access key."),
      };
    }
    if (isSend && Number.isFinite(limit) && limit > 0) {
      const used = Number(thirdRes?.results?.[0]?.free_count ?? 0);
      if (used > limit) {
        const retryAfter = secondsUntilUtcMidnight(now);
        return {
          response: telegramError(
            429,
            `Too Many Requests: daily limit of ${limit} messages for unauthenticated bots reached; ask the proxy admin for an access key. Retry after ${retryAfter}`,
            { retry_after: retryAfter }
          ),
        };
      }
    }
    return { authenticated: false, settings };
  } catch (err) {
    console.error("proxy: access check failed", err && err.message);
    waitUntil(logError(db, "access_check_failed", { botId, message: err && err.message }));
    return { authenticated: false, settings: defaultSettings(env) };
  }
}

// Atomic per-bot daily counter. `free` is 1 for unauthenticated calls.
function usageUpsert(db, day, botId, free) {
  return db
    .prepare(
      `INSERT INTO bot_usage (day, bot_id, count, free_count) VALUES (?, ?, 1, ?)
       ON CONFLICT (day, bot_id) DO UPDATE
         SET count = count + 1, free_count = free_count + excluded.free_count
       RETURNING free_count`
    )
    .bind(day, botId, free);
}

// Record a spam event, apply the configured action, and alert the log group
// (at most once per bot per SPAM_ALERT_WINDOW_MS).
async function handleSpam(db, env, ctx) {
  const { spam, action, settings, botId, method, params, media, meta, request, origin } = ctx;
  const now = new Date();
  const text = String(params.text ?? params.caption ?? media.captions.join("\n\n") ?? "");
  const chatId = params.chat_id != null ? String(params.chat_id) : null;
  const caller = callerFields(request);
  const since = new Date(now.getTime() - SPAM_ALERT_WINDOW_MS).toISOString();

  const [recent] = await db.batch([
    db
      .prepare("SELECT COUNT(*) AS n FROM spam_events WHERE bot_id = ? AND ts > ?")
      .bind(botId || "", since),
    db
      .prepare(
        `INSERT INTO spam_events (ts, bot_id, method, chat_id, score, reasons, text, action, ip, country)
         VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`
      )
      .bind(
        now.toISOString(),
        botId || "",
        method,
        chatId,
        spam.score,
        spam.reasons.join(", "),
        text.slice(0, 2000),
        action,
        caller.ip,
        caller.country
      ),
    ...(action === "block_bot"
      ? [
          db
            .prepare(
              "INSERT OR IGNORE INTO blocked_bots (bot_id, reason, created_at) VALUES (?, ?, ?)"
            )
            .bind(botId || "", `auto: spam (${spam.reasons.join(", ")})`.slice(0, 300), now.toISOString()),
        ]
      : []),
  ]);

  const chat = settings.spam_log_chat_id;
  if (!env.LOG_BOT_TOKEN || !chat) return;
  if (Number(recent.results[0]?.n ?? 0) > 0) return;

  const actionLabel = {
    log: "logged, delivered",
    drop: "message dropped",
    block_bot: "message dropped, bot blocked",
  }[action] || action;
  let body = text || "(no text)";
  if (body.length > 3000) body = body.slice(0, 3000) + "…";
  const lines = [
    `🚨 <b>Spam detected</b> · bot <code>${escapeHtml(botId)}</code>`,
    `${escapeHtml(method)}${chatId ? ` → <code>${escapeHtml(chatId)}</code>` : ""}`,
    `Score ${spam.score}: ${escapeHtml(spam.reasons.join(", "))}`,
    `Action: <b>${escapeHtml(actionLabel)}</b>`,
  ];
  if (media.summary) lines.push(media.summary);
  lines.push("", escapeHtml(body));
  lines.push(...requestDetailLines(meta));
  lines.push("", `Manage: ${escapeHtml(origin)}/admin/`);
  await sendLogMessage(env, chat, lines.join("\n"));
}

// Returns { botToken, method } for loggable send* calls, otherwise null.
function getLogTarget(pathname) {
  const match = pathname.match(/^\/bot([^/]+)\/(\w+)/);
  if (!match) return null;
  const [, botToken, method] = match;
  if (!method.startsWith("send")) return null;
  return { botToken, method };
}

async function logMessage(params, target, meta, env) {
  const { botToken, method } = target;
  const chatId = params.chat_id;
  const media = describeMedia(method, params);
  const text = params.text ?? params.caption ?? media.captions.join("\n\n");

  // Avoid an infinite loop if the log bot itself posts to the log channel.
  if (
    botToken === env.LOG_BOT_TOKEN &&
    String(chatId) === String(env.LOG_CHANNEL_ID)
  ) {
    return;
  }

  const botId = botToken.split(":")[0];
  let header = `📤 <b>${escapeHtml(method)}</b> · bot <code>${escapeHtml(botId)}</code>`;
  if (chatId != null) header += ` → <code>${escapeHtml(String(chatId))}</code>`;

  const lines = [header];
  if (media.summary) lines.push(media.summary);
  if (text) {
    let body = String(text);
    if (body.length > 3500) body = body.slice(0, 3500) + "…";
    lines.push("", escapeHtml(body));
  } else if (!media.summary) {
    lines.push("", "<i>(no text — media or non-text payload)</i>");
  }
  lines.push(...requestDetailLines(meta));

  await fetch(`${TELEGRAM_ORIGIN}/bot${env.LOG_BOT_TOKEN}/sendMessage`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({
      chat_id: env.LOG_CHANNEL_ID,
      text: lines.join("\n"),
      parse_mode: "HTML",
      disable_web_page_preview: true,
    }),
  });
}

// Atomically bump the delivered/errors counters in D1. A single UPDATE keeps
// it race-free even under concurrent requests. `delivered` is true when the
// proxy successfully relayed the request and got a response from Telegram
// (whatever its HTTP status); false only when api.telegram.org was unreachable.
async function recordStat(db, delivered) {
  await db
    .prepare(
      "UPDATE stats SET delivered = delivered + ?, errors = errors + ? WHERE id = 1"
    )
    .bind(delivered ? 1 : 0, delivered ? 0 : 1)
    .run();
}

// Append a row to the durable error log in D1. Self-guarded and best-effort: if
// the binding or table is missing, it falls back to console.error so a logging
// failure can never throw into the request path. Review with `npm run errors`.
// All columns are optional; only `kind` is required. The full bot token is never
// passed here (callers send the redacted path and numeric bot id instead).
async function logError(db, kind, fields) {
  if (!db) return;
  fields = fields || {};
  try {
    await db
      .prepare(
        `INSERT INTO error_log
           (ts, kind, status, method, bot_id, path, error_code, description, message,
            ip, country, region, city, asn, org, ua, colo, ray)
         VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`
      )
      .bind(
        new Date().toISOString(),
        kind,
        fields.status ?? null,
        fields.method ?? null,
        fields.botId ?? null,
        fields.path ?? null,
        fields.errorCode ?? null,
        fields.description ?? null,
        fields.message ?? null,
        fields.ip ?? null,
        fields.country ?? null,
        fields.region ?? null,
        fields.city ?? null,
        fields.asn ?? null,
        fields.org ?? null,
        fields.ua ?? null,
        fields.colo ?? null,
        fields.ray ?? null
      )
      .run();
  } catch (e) {
    console.error("proxy: error-log write failed", e && e.message);
  }
}

// Parse the bot id and method out of a proxy path, with the secret token
// redacted so it never reaches the error log. Handles both /bot<token>/<method>
// and /file/bot<token>/<method>. Returns nulls for non-matching paths.
function parseRequestPath(pathname) {
  const match = pathname.match(/^\/(?:file\/)?bot([^/]+)(?:\/(\w+))?/);
  if (!match) return { botId: null, method: null, redactedPath: pathname };
  const [, token, method] = match;
  const botId = token.split(":")[0];
  // Replace the full token with just the numeric id, keeping the rest of the path.
  const redactedPath = pathname.replace("bot" + token, "bot" + botId);
  return { botId, method: method || null, redactedPath };
}

// Pull the caller's network/geo snapshot from request.cf and the CF-* headers,
// shaped to the error_log columns. Reads no body, so it is safe on any path.
function callerFields(request) {
  const cf = request.cf || {};
  const h = request.headers;
  return {
    ip: h.get("cf-connecting-ip") || h.get("x-forwarded-for") || null,
    country: cf.country || null,
    region: cf.region || null,
    city: cf.city || null,
    asn: cf.asn != null ? String(cf.asn) : null,
    org: cf.asOrganization || null,
    ua: h.get("user-agent") || null,
    colo: cf.colo || null,
    ray: h.get("cf-ray") || null,
  };
}

// Read Telegram's error response to extract { errorCode, description }. The body
// is normally small JSON like {"ok":false,"error_code":400,"description":"..."}.
// Falls back to a truncated raw snippet if the body is not JSON (e.g. an edge
// error page), and to nulls if it cannot be read at all. Never throws.
async function readTelegramError(response) {
  try {
    const text = await response.text();
    try {
      const data = JSON.parse(text);
      return {
        errorCode: typeof data.error_code === "number" ? data.error_code : null,
        description: data.description ?? null,
      };
    } catch {
      return { errorCode: null, description: text ? text.slice(0, 500) : null };
    }
  } catch {
    return { errorCode: null, description: null };
  }
}

// Snapshot the requester's network/geo metadata from Cloudflare's request.cf
// object and the CF-* headers. request.cf is populated in production; in local
// `wrangler pages dev` some fields may be missing, hence the null guards.
function requestMeta(request) {
  const cf = request.cf || {};
  const h = request.headers;
  return {
    // HTTP request
    httpMethod: request.method,
    ip: h.get("cf-connecting-ip") || h.get("x-forwarded-for") || "unknown",
    forwardedFor: h.get("x-forwarded-for") || null,
    ua: h.get("user-agent") || "unknown",
    referer: h.get("referer") || h.get("origin") || null,
    lang: h.get("accept-language") || null,
    ray: h.get("cf-ray") || null,

    // Geo
    country: cf.country || null,
    region: cf.region || null,
    city: cf.city || null,
    continent: cf.continent || null,
    postalCode: cf.postalCode || null,
    timezone: cf.timezone || null,
    latitude: cf.latitude || null,
    longitude: cf.longitude || null,

    // Network
    asn: cf.asn || null,
    org: cf.asOrganization || null,

    // Connection / TLS
    colo: cf.colo || null,
    proto: cf.httpProtocol || null,
    tlsVersion: cf.tlsVersion || null,
    tlsCipher: cf.tlsCipher || null,
    rtt: cf.clientTcpRtt ?? null,

    // Bot detection (only populated on plans with Bot Management)
    botScore: cf.botManagement?.score ?? null,
    verifiedBot: cf.botManagement?.verifiedBot ?? null,

    time: new Date().toISOString().replace("T", " ").replace(/\.\d+Z$/, " UTC"),
  };
}

// Render the metadata snapshot as Telegram-HTML log lines. Each line is only
// added when its data is present, so missing cf fields just drop out.
function requestDetailLines(meta) {
  if (!meta) return [];
  const lines = ["", "➖➖➖➖➖"];

  // IP + the HTTP verb actually used to call the proxy.
  lines.push(`🌐 <code>${escapeHtml(meta.ip)}</code> · ${escapeHtml(meta.httpMethod)}`);

  // Location.
  const place = [meta.city, meta.region, meta.country, meta.continent]
    .filter(Boolean)
    .join(", ");
  const locExtra = [meta.postalCode, meta.timezone].filter(Boolean).join(" · ");
  if (place) {
    lines.push(`📍 ${escapeHtml(place)}${locExtra ? " · " + escapeHtml(locExtra) : ""}`);
  }
  if (meta.latitude && meta.longitude) {
    lines.push(`🗺 <code>${escapeHtml(meta.latitude)}, ${escapeHtml(meta.longitude)}</code>`);
  }

  // Network / ASN.
  if (meta.asn || meta.org) {
    const as = meta.asn ? `AS${escapeHtml(meta.asn)} ` : "";
    lines.push(`🏢 ${as}${escapeHtml(meta.org || "")}`.trim());
  }

  // TLS + connection latency.
  const sec = [];
  if (meta.tlsVersion) sec.push(escapeHtml(meta.tlsVersion));
  if (meta.tlsCipher) sec.push(escapeHtml(meta.tlsCipher));
  if (meta.rtt != null) sec.push(`${escapeHtml(meta.rtt)}ms RTT`);
  if (sec.length) lines.push(`🔒 ${sec.join(" · ")}`);

  // Bot Management verdict, when available.
  if (meta.botScore != null) {
    const verified = meta.verifiedBot ? " · verified bot" : "";
    lines.push(`🤖 bot score ${escapeHtml(meta.botScore)}${verified}`);
  }

  // Client details.
  lines.push(`🖥 <code>${escapeHtml(meta.ua)}</code>`);
  if (meta.lang) lines.push(`🗣 ${escapeHtml(meta.lang)}`);
  if (meta.referer) lines.push(`🔗 ${escapeHtml(meta.referer)}`);

  // Edge + trace id + timestamp.
  const tail = [];
  if (meta.colo) tail.push(`📡 ${escapeHtml(meta.colo)}`);
  if (meta.proto) tail.push(escapeHtml(meta.proto));
  if (meta.ray) tail.push(`Ray ${escapeHtml(meta.ray)}`);
  tail.push(`🕐 ${escapeHtml(meta.time)}`);
  lines.push(tail.join(" · "));

  return lines;
}

// Media fields a single-media send* call can carry, in the order we check them.
const MEDIA_FIELDS = [
  "photo", "video", "animation", "audio", "document", "voice", "video_note", "sticker",
];

// Summarise the media/non-text part of a send* call. Returns { summary, captions }
// where summary is a ready-to-push Telegram-HTML line (or null) and captions are
// any captions nested inside the payload (sendMediaGroup keeps them per item).
function describeMedia(method, params) {
  const captions = [];

  if (method === "sendMediaGroup") {
    let items = params.media;
    if (typeof items === "string") {
      try {
        items = JSON.parse(items);
      } catch {
        items = null;
      }
    }
    if (!Array.isArray(items)) return { summary: "🖼 media group", captions };
    const kinds = [];
    for (const item of items) {
      if (!item || typeof item !== "object") continue;
      kinds.push(`${item.type || "media"} (${mediaSource(item.media, params)})`);
      if (item.caption) captions.push(String(item.caption));
    }
    const summary = `🖼 ${items.length} item${items.length === 1 ? "" : "s"}: ${escapeHtml(kinds.join(", "))}`;
    return { summary, captions };
  }

  for (const field of MEDIA_FIELDS) {
    if (params[field] != null) {
      return { summary: `🖼 ${field} (${escapeHtml(mediaSource(params[field], params))})`, captions };
    }
  }

  if (method === "sendLocation" || method === "sendVenue") {
    if (params.latitude != null && params.longitude != null) {
      const title = params.title ? ` · ${escapeHtml(params.title)}` : "";
      return {
        summary: `📍 <code>${escapeHtml(params.latitude)}, ${escapeHtml(params.longitude)}</code>${title}`,
        captions,
      };
    }
  }
  if (method === "sendPoll" && params.question) {
    return { summary: `📊 poll: ${escapeHtml(params.question)}`, captions };
  }
  if (method === "sendContact" && params.phone_number) {
    const name = [params.first_name, params.last_name].filter(Boolean).join(" ");
    return { summary: `👤 contact: ${escapeHtml(name)} <code>${escapeHtml(params.phone_number)}</code>`, captions };
  }
  if (method === "sendChatAction" && params.action) {
    return { summary: `⌨️ chat action: ${escapeHtml(params.action)}`, captions };
  }
  if (method === "sendDice") {
    return { summary: `🎲 dice ${escapeHtml(params.emoji || "🎲")}`, captions };
  }
  return { summary: null, captions };
}

// Describe where a media value comes from: an upload, a URL or a file_id.
function mediaSource(value, params) {
  if (value && typeof value === "object" && value.upload) return describeUpload(value);
  if (typeof value !== "string") return "upload";
  if (value.startsWith("attach://")) {
    const attached = params[value.slice("attach://".length)];
    return attached && attached.upload ? describeUpload(attached) : "upload";
  }
  if (/^https?:\/\//i.test(value)) return "url";
  return "file_id";
}

function describeUpload(file) {
  const parts = [file.name || "upload"];
  if (file.size) parts.push(formatBytes(file.size));
  return parts.join(", ");
}

function formatBytes(n) {
  if (n < 1024) return `${n} B`;
  if (n < 1024 * 1024) return `${(n / 1024).toFixed(1)} KB`;
  return `${(n / (1024 * 1024)).toFixed(1)} MB`;
}

// Collect call parameters from the query string and the body. Uploaded files in
// multipart/form-data are recorded as { upload, name, size } markers, never kept.
async function extractParams(request, url) {
  const params = {};
  for (const [key, value] of url.searchParams) params[key] = value;

  // Skip parsing oversized bodies so logging can never exhaust memory.
  const contentLength = Number(request.headers.get("content-length") || 0);
  if (contentLength > MAX_LOG_BODY_BYTES) return params;

  const contentType = (request.headers.get("content-type") || "").toLowerCase();
  try {
    if (contentType.includes("multipart/form-data")) {
      // Only buffer multipart bodies with a known, capped length; chunked
      // uploads of unknown size are skipped.
      if (!contentLength) return params;
      for (const [key, value] of await request.formData()) {
        params[key] =
          typeof value === "string"
            ? value
            : { upload: true, name: value.name || null, size: value.size || 0 };
      }
      return params;
    }
    if (contentType.includes("application/json")) {
      Object.assign(params, await request.json());
    } else if (contentType.includes("application/x-www-form-urlencoded")) {
      for (const [key, value] of new URLSearchParams(await request.text())) {
        params[key] = value;
      }
    }
  } catch {
    // Unparseable body — keep whatever the query string gave us.
  }
  return params;
}

// A Telegram-shaped error reply, so client libraries surface the description
// (and honour retry_after on 429) as if Telegram itself had answered.
function telegramError(status, description, parameters) {
  const body = { ok: false, error_code: status, description };
  if (parameters) body.parameters = parameters;
  return new Response(JSON.stringify(body), {
    status,
    headers: { "content-type": "application/json; charset=utf-8", ...corsHeaders() },
  });
}

function corsHeaders() {
  return {
    "Access-Control-Allow-Origin": "*",
    "Access-Control-Allow-Methods": "GET, POST, OPTIONS",
    "Access-Control-Allow-Headers": "Content-Type, X-Proxy-Key",
  };
}
