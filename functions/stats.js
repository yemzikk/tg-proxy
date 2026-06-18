// GET /stats — public counters for the landing page.
//
// Returns { enabled, delivered, errors, total, errorRate }. When the optional
// D1 binding (DB) is not configured, returns { enabled: false } so the UI can
// hide the stats panel gracefully.

export async function onRequest(context) {
  const { env } = context;
  const db = env.tg_proxy_stats || env.DB;

  if (!db) {
    return json({ enabled: false });
  }

  try {
    const row = await db
      .prepare("SELECT delivered, errors FROM stats WHERE id = 1")
      .first();

    const delivered = Number(row?.delivered ?? 0);
    const errors = Number(row?.errors ?? 0);
    const total = delivered + errors;

    return json({
      enabled: true,
      delivered,
      errors,
      total,
      errorRate: total ? errors / total : 0,
    });
  } catch (err) {
    // DB bound but not initialised (schema not applied yet), etc. Record it in
    // Cloudflare's logs; the public response just reports stats as unavailable.
    console.error("stats: query failed", err && err.message);
    return json({ enabled: false });
  }
}

function json(data) {
  return new Response(JSON.stringify(data), {
    headers: {
      "content-type": "application/json; charset=utf-8",
      "cache-control": "no-store",
      "access-control-allow-origin": "*",
    },
  });
}
