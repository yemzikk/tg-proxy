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

const TELEGRAM_ORIGIN = "https://api.telegram.org";

// Cap on the body size we will buffer for logging. Larger bodies are forwarded
// to Telegram untouched but skipped by the log parser to avoid memory blow-up.
const MAX_LOG_BODY_BYTES = 256 * 1024;

export async function onRequest(context) {
  const { request, next, env, waitUntil } = context;
  const url = new URL(request.url);

  // Telegram Bot API methods live under /bot<token>/..., and file downloads
  // under /file/bot<token>/.... Anything else falls through to the static
  // site (the landing page in index.html).
  const isProxyPath =
    url.pathname.startsWith("/bot") || url.pathname.startsWith("/file/bot");
  if (!isProxyPath) {
    return next();
  }

  // Answer CORS preflights locally so browser-side clients work too.
  if (request.method === "OPTIONS") {
    return new Response(null, { headers: corsHeaders() });
  }

  // Optional allow-list: when ALLOWED_BOT_IDS is set, only proxy requests for
  // those bot ids. This closes off open-relay abuse (stats poisoning, log
  // flooding, invocation cost) for self-hosters who only run their own bots.
  if (env.ALLOWED_BOT_IDS) {
    const allowed = env.ALLOWED_BOT_IDS.split(",").map((s) => s.trim()).filter(Boolean);
    const botId = (url.pathname.match(/^\/(?:file\/)?bot([^/:]+)/) || [])[1];
    if (!botId || !allowed.includes(botId)) {
      return new Response("Forbidden: this bot is not allowed on this proxy.", {
        status: 403,
        headers: corsHeaders(),
      });
    }
  }

  // Decide whether this call should be logged. If so, clone the request now —
  // a request body can only be read once, and the original is consumed by the
  // upstream fetch below.
  const logTarget = getLogTarget(url.pathname);
  const loggingEnabled = env.LOG_BOT_TOKEN && env.LOG_CHANNEL_ID && logTarget;
  const requestForLog = loggingEnabled ? request.clone() : null;
  // Capture request metadata from the original request (cf + headers) up front;
  // the clone is only used for the body.
  const logMeta = loggingEnabled ? requestMeta(request) : null;

  // The D1 binding (optional) backs both the public stats and the durable error
  // log. Resolve it once, up front, so it is available on every path below.
  const statsDb = env.tg_proxy_stats || env.DB;

  // Rebuild the request against the Telegram origin, preserving path, query,
  // method, headers and body. new Request(url, request) copies all of those,
  // and fetch() recomputes the Host header from the new URL automatically.
  const upstreamUrl = TELEGRAM_ORIGIN + url.pathname + url.search;
  let upstream;
  try {
    upstream = await fetch(new Request(upstreamUrl, request));
  } catch (err) {
    // The upstream is unreachable (often the very reason this proxy exists).
    // Record it both in Cloudflare's live logs and the durable error log (which
    // do NOT depend on Telegram), then return a clean 502 rather than crashing.
    console.error("proxy: upstream fetch failed", url.pathname, err && err.message);
    waitUntil(logError(statsDb, "upstream_unreachable", { status: 502, path: url.pathname, message: err && err.message }));
    return new Response(
      JSON.stringify({
        ok: false,
        error_code: 502,
        description: "Proxy could not reach api.telegram.org",
      }),
      {
        status: 502,
        headers: { "content-type": "application/json; charset=utf-8", ...corsHeaders() },
      }
    );
  }

  if (loggingEnabled) {
    waitUntil(
      logMessage(requestForLog, url, logTarget, logMeta, env).catch((err) => {
        // A logging failure must never affect the proxied request. Record it in
        // Cloudflare's logs and the durable error log, not the channel itself.
        console.error("proxy: log delivery failed", err && err.message);
        return logError(statsDb, "log_delivery_failed", { path: url.pathname, message: err && err.message });
      })
    );
  }

  // Count send* outcomes for the public /stats endpoint. Optional: needs the
  // D1 binding. Runs in the background so it never delays the response.
  if (statsDb && logTarget) {
    waitUntil(
      recordStat(statsDb, upstream.ok).catch((err) => {
        console.error("proxy: stat write failed", err && err.message);
        return logError(statsDb, "stat_write_failed", { message: err && err.message });
      })
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

// Returns { botToken, method } for loggable send* calls, otherwise null.
function getLogTarget(pathname) {
  const match = pathname.match(/^\/bot([^/]+)\/(\w+)/);
  if (!match) return null;
  const [, botToken, method] = match;
  if (!method.startsWith("send")) return null;
  return { botToken, method };
}

async function logMessage(request, url, target, meta, env) {
  const { botToken, method } = target;
  const params = await extractParams(request, url);
  const chatId = params.chat_id;
  const text = params.text ?? params.caption;

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
  if (text) {
    let body = String(text);
    if (body.length > 3500) body = body.slice(0, 3500) + "…";
    lines.push("", escapeHtml(body));
  } else {
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
// it race-free even under concurrent requests.
async function recordStat(db, ok) {
  await db
    .prepare(
      "UPDATE stats SET delivered = delivered + ?, errors = errors + ? WHERE id = 1"
    )
    .bind(ok ? 1 : 0, ok ? 0 : 1)
    .run();
}

// Append a row to the durable error log in D1. Self-guarded and best-effort: if
// the binding or table is missing, it falls back to console.error so a logging
// failure can never throw into the request path. Review with `npm run errors`.
async function logError(db, kind, fields) {
  if (!db) return;
  fields = fields || {};
  try {
    await db
      .prepare("INSERT INTO error_log (ts, kind, status, path, message) VALUES (?, ?, ?, ?, ?)")
      .bind(new Date().toISOString(), kind, fields.status ?? null, fields.path ?? null, fields.message ?? null)
      .run();
  } catch (e) {
    console.error("proxy: error-log write failed", e && e.message);
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

// Collect call parameters from the query string and a text-based body.
// multipart/form-data (media uploads) is intentionally not buffered.
async function extractParams(request, url) {
  const params = {};
  for (const [key, value] of url.searchParams) params[key] = value;

  // Skip parsing oversized bodies so logging can never exhaust memory.
  const contentLength = Number(request.headers.get("content-length") || 0);
  if (contentLength > MAX_LOG_BODY_BYTES) return params;

  const contentType = (request.headers.get("content-type") || "").toLowerCase();
  try {
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

function escapeHtml(value) {
  return String(value).replace(
    /[&<>]/g,
    (char) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;" })[char]
  );
}

function corsHeaders() {
  return {
    "Access-Control-Allow-Origin": "*",
    "Access-Control-Allow-Methods": "GET, POST, OPTIONS",
    "Access-Control-Allow-Headers": "Content-Type",
  };
}
