// Heuristic spam detector for crypto/"bitcoin" spam, the main abuse seen on
// open instances (largely Chinese-language). Each matched rule adds to a score;
// a message is spam once the score reaches SPAM_THRESHOLD. Admin-defined
// keywords count as an immediate match.

export const SPAM_THRESHOLD = 3;

// [label, regex, weight]. Strong terms are rarely used outside crypto spam;
// weak terms only count in combination with something else.
const KEYWORD_RULES = [
  // English
  ["bitcoin", /\bbitcoins?\b/i, 2],
  ["usdt", /\busdt\b/i, 2],
  ["trc20/erc20", /\b(?:trc|erc|bep)-?20\b/i, 2],
  ["airdrop", /\bair-?drops?\b/i, 2],
  ["btc", /\bbtc\b/i, 1],
  ["eth", /\b(?:eth|ethereum)\b/i, 1],
  ["crypto", /\bcrypto(?:currency|currencies)?\b/i, 1],
  ["wallet", /\bwallets?\b/i, 1],
  ["exchange", /\b(?:binance|okx|huobi|bybit)\b/i, 1],
  ["profit", /\b(?:guaranteed profit|daily profit|double your|investment plan)\b/i, 2],
  // Chinese
  ["比特币", /比特币/, 2],
  ["泰达币", /泰达币/, 2],
  ["以太坊", /以太坊/, 2],
  ["空投", /空投/, 2],
  ["资金盘", /资金盘/, 2],
  ["跑分", /跑分/, 2],
  ["usdt兑换", /(?:U|u)币|换汇|承兑/, 2],
  ["虚拟币", /虚拟币|数字货币|加密货币/, 2],
  ["钱包", /钱包/, 1],
  ["交易所", /交易所/, 1],
  ["合约", /合约/, 1],
  ["挖矿", /挖矿|矿机/, 1],
  ["充值/提现", /充值|提现/, 1],
  ["返利", /返利|返佣|带单|稳赚|日赚|日入/, 1],
  ["投资收益", /投资|收益|理财/, 1],
];

// [label, regex] for wallet addresses; each is worth a full match on its own.
const ADDRESS_RULES = [
  ["btc address", /\bbc1[ac-hj-np-z02-9]{25,62}\b/i],
  ["btc address", /\b[13][a-km-zA-HJ-NP-Z1-9]{25,34}\b/],
  ["eth address", /\b0x[a-fA-F0-9]{40}\b/],
  ["tron address", /\bT[1-9A-HJ-NP-Za-km-z]{33}\b/],
];

// Returns { isSpam, score, reasons }.
export function detectSpam(text, customKeywords = "") {
  const reasons = [];
  let score = 0;
  if (!text) return { isSpam: false, score, reasons };

  for (const [label, re] of ADDRESS_RULES) {
    const m = text.match(re);
    // Legacy BTC pattern also matches long digit runs; require a letter.
    if (m && /[a-z]/i.test(m[0]) && !reasons.includes(label)) {
      reasons.push(label);
      score += SPAM_THRESHOLD;
    }
  }

  const lower = text.toLowerCase();
  for (const kw of parseKeywords(customKeywords)) {
    if (lower.includes(kw)) {
      reasons.push(`keyword "${kw}"`);
      score += SPAM_THRESHOLD;
    }
  }

  for (const [label, re, weight] of KEYWORD_RULES) {
    if (re.test(text)) {
      reasons.push(label);
      score += weight;
    }
  }

  return { isSpam: score >= SPAM_THRESHOLD, score, reasons };
}

// Admin keywords: one per line or comma-separated, matched case-insensitively.
export function parseKeywords(raw) {
  return String(raw || "")
    .split(/[\n,]/)
    .map((s) => s.trim().toLowerCase())
    .filter(Boolean);
}

// Everything user-visible in a send* call: text, captions, poll text and
// inline-button labels/URLs (where spam links often hide).
export function spamText(params, captions) {
  const parts = [params.text, params.caption, ...(captions || []), params.question];
  for (const field of ["options", "reply_markup"]) {
    const v = params[field];
    if (v == null) continue;
    // Re-serialise string JSON so \uXXXX escapes become the real characters.
    let parsed = v;
    if (typeof v === "string") {
      try {
        parsed = JSON.parse(v);
      } catch {
        parts.push(v);
        continue;
      }
    }
    parts.push(JSON.stringify(parsed));
  }
  return parts.filter((p) => p != null && p !== "").map(String).join("\n");
}
