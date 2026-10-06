// Shared helpers for the proxy and the admin API: D1 access, settings, access
// keys, and small crypto utilities. Lives outside functions/ so Pages does not
// turn it into a route; esbuild bundles it into each function that imports it.

export const TELEGRAM_ORIGIN = "https://api.telegram.org";

export function getDb(env) {
  return env.tg_proxy_stats || env.DB || null;
}

// Defaults for every admin-editable setting. Env vars, when set, override the
// built-in default; a value saved in the dashboard overrides both.
export function defaultSettings(env) {
  return {
    free_daily_limit: String(env.FREE_DAILY_LIMIT ?? 50),
    spam_detection: "on",
    spam_action: "log", // log | drop | block_bot
    spam_keywords: "",
    spam_log_chat_id: String(env.SPAM_LOG_CHAT_ID || env.LOG_CHANNEL_ID || ""),
  };
}

export const SETTING_KEYS = [
  "free_daily_limit",
  "spam_detection",
  "spam_action",
  "spam_keywords",
  "spam_log_chat_id",
];

export function mergeSettings(env, rows) {
  const settings = defaultSettings(env);
  for (const row of rows || []) {
    if (SETTING_KEYS.includes(row.key)) settings[row.key] = row.value;
  }
  return settings;
}

export async function loadSettings(db, env) {
  const { results } = await db.prepare("SELECT key, value FROM settings").all();
  return mergeSettings(env, results);
}

// Current UTC day as YYYY-MM-DD, the bucket for daily limits.
export function utcDay(date = new Date()) {
  return date.toISOString().slice(0, 10);
}

export function secondsUntilUtcMidnight(date = new Date()) {
  const next = Date.UTC(date.getUTCFullYear(), date.getUTCMonth(), date.getUTCDate() + 1);
  return Math.max(1, Math.ceil((next - date.getTime()) / 1000));
}

export async function sha256Hex(text) {
  const digest = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(text));
  return [...new Uint8Array(digest)].map((b) => b.toString(16).padStart(2, "0")).join("");
}

function base64url(bytes) {
  let s = "";
  for (const b of bytes) s += String.fromCharCode(b);
  return btoa(s).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

// A new plaintext access key: "tgp_" + 32 random bytes.
export function generateAccessKey() {
  return "tgp_" + base64url(crypto.getRandomValues(new Uint8Array(32)));
}

export async function hmacSign(secret, message) {
  const key = await crypto.subtle.importKey(
    "raw",
    new TextEncoder().encode(secret),
    { name: "HMAC", hash: "SHA-256" },
    false,
    ["sign"]
  );
  const sig = await crypto.subtle.sign("HMAC", key, new TextEncoder().encode(message));
  return base64url(new Uint8Array(sig));
}

// Constant-time string comparison (both sides are hashed/signed values).
export function safeEqual(a, b) {
  if (typeof a !== "string" || typeof b !== "string" || a.length !== b.length) return false;
  let diff = 0;
  for (let i = 0; i < a.length; i++) diff |= a.charCodeAt(i) ^ b.charCodeAt(i);
  return diff === 0;
}

export function escapeHtml(value) {
  return String(value).replace(
    /[&<>]/g,
    (char) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;" })[char]
  );
}

// Send an HTML message with the log bot. Throws on network failure or a
// non-2xx reply so callers can record it.
export async function sendLogMessage(env, chatId, html) {
  const res = await fetch(`${TELEGRAM_ORIGIN}/bot${env.LOG_BOT_TOKEN}/sendMessage`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({
      chat_id: chatId,
      text: html,
      parse_mode: "HTML",
      disable_web_page_preview: true,
    }),
  });
  if (!res.ok) {
    const body = await res.text().catch(() => "");
    throw new Error(`log bot sendMessage ${res.status}: ${body.slice(0, 200)}`);
  }
}
