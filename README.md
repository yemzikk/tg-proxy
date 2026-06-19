<h1 align="center">tg-proxy</h1>
<p align="center">Transparent Telegram Bot API proxy on the Cloudflare edge.</p>

<p align="center">
  <a href="LICENSE"><img src="https://img.shields.io/badge/License-MIT-blue.svg" alt="License: MIT"></a><br>
  <a href="https://deploy.workers.cloudflare.com/?url=https://github.com/yemzikk/tg-proxy"><img src="https://deploy.workers.cloudflare.com/button" alt="Deploy to Cloudflare"></a>
</p>

A tiny [Cloudflare Pages](https://pages.cloudflare.com/) app that proxies the
Telegram Bot API. Use it where `api.telegram.org` is unreachable but
Cloudflare's edge is reachable.

```
https://api.telegram.org/bot<TOKEN>/sendMessage    (original)
https://tgproxy.yemzikk.in/bot<TOKEN>/sendMessage  (via this proxy)
```

Path, query string, method, headers, and body are forwarded unchanged, so
**every** Bot API method works: `getUpdates`, `setWebhook`, `sendPhoto`, file
downloads under `/file/bot<TOKEN>/...`, and so on. No bot token is stored here;
the token in the URL is the only credential Telegram needs.

A public instance runs at **https://tgproxy.yemzikk.in**. You can use it as-is,
or host your own in a couple of minutes (recommended for anything serious).

## Self-hosting

### One command

```sh
git clone https://github.com/yemzikk/tg-proxy.git
cd tg-proxy
./setup.sh
```

The script checks prerequisites, installs dependencies, logs you into
Cloudflare, optionally provisions live stats (a D1 database) and channel
logging, and deploys to Cloudflare Pages. Re-run it anytime to change options.
You only need a free [Cloudflare account](https://dash.cloudflare.com/sign-up).

### Manual deploy

If you prefer to do it by hand:

```sh
npm install
npx wrangler login   # once
npm run deploy       # reads wrangler.toml (project name + output dir)
```

Or connect the repo through the dashboard: **Workers & Pages > Create > Pages >
Connect to Git**, with **Framework preset: none**, **Build command: empty**,
**Build output directory: `public`**. The `functions/` folder is detected
automatically.

> Forking? The committed `wrangler.toml` references the original project's D1
> `database_id`. It is not a secret, but it belongs to another account, so
> replace it with your own (`npx wrangler d1 create tg-proxy-stats`) or just run
> `./setup.sh`, which does this for you.

### Custom domain

In the Pages project, open **Custom domains > Set up a custom domain** and add
your hostname. If the domain is on Cloudflare, the DNS record is created for you
and HTTPS is provisioned automatically.

### Local development

```sh
npm install
npm run dev          # wrangler pages dev -> http://localhost:8788
curl "http://localhost:8788/bot<TOKEN>/getMe"
```

## Configuration

All configuration is optional. With nothing set, the proxy simply forwards
requests.

### Access control (`ALLOWED_BOT_IDS`)

By default the proxy is an **open relay**: anyone who finds the URL can route
Bot API calls through it. To lock it to your own bots, set `ALLOWED_BOT_IDS` to
a comma-separated list of bot ids (the number before `:` in a token):

```sh
npx wrangler pages secret put ALLOWED_BOT_IDS   # e.g. 123456789,987654321
```

Requests for any other bot id receive `403`. This is the recommended setting for
a private deployment, and it also prevents the abuse described in
[Security and privacy](#security-and-privacy).

### Live stats (D1)

The landing page can show messages delivered and the error rate, counted in a
D1 database. Without the binding the proxy still works and the stats panel stays
hidden. `./setup.sh` sets this up for you, or do it manually:

```sh
npx wrangler d1 create tg-proxy-stats   # 1. create the database
# 2. paste the printed database_id into wrangler.toml
npm run db:init                          # 3. apply schema.sql to the remote DB
npm run db:init:local                    # (optional) same for local dev
npm run deploy                           # 4. redeploy
```

Each `send*` call records one outcome from the proxy's point of view: any call
the proxy successfully relayed to Telegram counts as delivered, regardless of
Telegram's own HTTP status. A `4xx`/`5xx` from Telegram (bad `chat_id`, bot
blocked, rate limit) is between your bot and Telegram, not a proxy failure, so it
still counts as delivered. Only a call where `api.telegram.org` was unreachable
counts as an error, the same event recorded in `error_log`. Counts are bumped
with a single atomic `UPDATE`, so they stay correct under concurrency, and are
served publicly at `/stats`.

> If the proxy is open (no `ALLOWED_BOT_IDS`), anyone can call it with a junk
> token and inflate these counters. Treat the public stats as a rough activity
> signal, not a verified metric, unless you also set an allow-list.

### Channel logging

When `LOG_BOT_TOKEN` and `LOG_CHANNEL_ID` are set, every `send*` call routed
through the proxy is mirrored to that Telegram channel:

- method, sending bot id, target chat, and message text (captions included);
- requester IP and HTTP verb;
- location: city, region, country, continent, postal code, timezone, coordinates;
- network: ASN and organization (ISP/host);
- connection: TLS version, cipher, TCP round-trip latency;
- client: user-agent, accept-language, referer/origin;
- bot score (only on plans with Bot Management);
- Cloudflare datacenter (colo), HTTP protocol, CF-Ray trace id, UTC timestamp.

It runs in the background via `waitUntil`, so it never slows down or breaks the
proxied request, skips multipart and oversized bodies, and guards against
logging loops. Geo and ASN fields come from `request.cf`, populated in
production (partial under local `wrangler pages dev`).

Set it up with secrets (the bot must be an **admin of the channel**):

```sh
npx wrangler pages secret put LOG_BOT_TOKEN
npx wrangler pages secret put LOG_CHANNEL_ID    # numeric id, e.g. -1001234567890
```

Local dev reads these from `.dev.vars` (gitignored; copy `.dev.vars.example`).
Read the [privacy notice](#privacy-notice-for-logging) before enabling it.

## Logs and errors

Operational failures (an unreachable upstream, a failed log delivery, a failed
stats write) are handled in two layers, neither of which depends on Telegram.

**1. Live logs.** Each failure is written with `console.error`. Stream it with:

```sh
npm run logs   # wrangler pages deployment tail
```

or in the dashboard under **Workers & Pages > your project > the deployment >
View details > Functions**. This is real-time only: Cloudflare does not retain
Pages Function logs, so you only see an error if you are streaming when it
happens.

**2. Durable error log (D1).** Because live logs are not retained, failures are
also appended to an `error_log` table in the stats database, so you can review
them after the fact:

```sh
npm run errors   # last 50 rows: time, kind, status, path, message
```

This needs the D1 binding and table. If you set up stats before this was added,
re-run `npm run db:init` once to create `error_log`.

If the upstream is unreachable, the proxy returns a clean `502` instead of
crashing. The optional [channel logging](#channel-logging) is best-effort message
mirroring, **not** an error log: it can fail exactly when Telegram is down, so
never rely on it to capture errors. For alerting or long-term retention, also
forward errors to a service you control (for example Sentry or a webhook).

## Security and privacy

An independent security review found no code-execution vulnerabilities: the
upstream origin is hard-coded (no SSRF), log output is HTML-escaped, the landing
page uses only `textContent`, SQL is parameterized, and CORS carries no
credentials. The items below are operational and policy, and you should
understand them before exposing an instance.

### Open relay and cost

Left open, the proxy can be used by anyone, which means:

- **Abuse and masking:** third parties can route their own Bot API traffic
  through your domain.
- **Cost:** every request is a Functions invocation plus an upstream fetch (plus
  a D1 write and a log message when those are enabled). Sustained traffic can
  run up usage.
- **Stats and log flooding:** an open instance lets anyone inflate `/stats` or,
  if logging is on, flood your log channel and burn the log bot's rate limit.

Mitigations, in order of effectiveness:

1. Set [`ALLOWED_BOT_IDS`](#access-control-allowed_bot_ids) to serve only your bots.
2. Add a [WAF rate-limiting rule](https://developers.cloudflare.com/waf/rate-limiting-rules/)
   and enable Bot Fight Mode in the Cloudflare dashboard.
3. Put the project behind [Cloudflare Access](https://developers.cloudflare.com/cloudflare-one/policies/access/)
   if it is for internal use only.
4. Prefer `setWebhook` over long-polling `getUpdates`, which otherwise holds a
   Functions invocation open per poll.

### Privacy notice for logging

Channel logging is **off by default** and only activates when both secrets are
set. When enabled, it captures **message content** and **sender metadata**
(IP, precise geolocation, user-agent, and more) and forwards them to a Telegram
channel, where Telegram retains them.

If your instance ever proxies traffic for bots you do not own, enabling logging
makes you a man-in-the-middle recording other people's messages and personal
data. That likely implicates Telegram's Terms of Service and privacy laws such
as GDPR and CCPA. Only enable logging for traffic you own, disclose it to your
users, and keep the log channel private.

### Header forwarding

All client request headers are forwarded to `api.telegram.org` as-is; `fetch()`
recomputes the `Host` header to the Telegram origin, so the original client host
is not leaked. Telegram only uses the in-path token, so any extra client headers
are harmless to it, but be aware they are passed through.

## How it works

```
functions/[[path]].js   catch-all proxy (Pages Function)
functions/stats.js      JSON stats endpoint at /stats
public/index.html       landing page shown at /
public/favicon.*        favicon (SVG, PNG, ICO) + apple-touch-icon
public/og.*             social preview image (og.svg source, og.png output)
wrangler.toml           Pages config and optional D1 binding
schema.sql              stats table schema
setup.sh                one-command install, configure, and deploy
```

A request to `/` (or any non-Telegram path) serves the landing page. Anything
starting with `/bot` or `/file/bot` is rebuilt against `api.telegram.org` and
forwarded, with the response streamed straight back.

## License

[MIT](LICENSE) (c) yemzikk.

## Support

If this saved you some time, you can
[buy me a coffee](https://buymeacoffee.com/yemzikk). Thanks!
