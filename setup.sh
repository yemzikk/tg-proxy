#!/usr/bin/env bash
#
# tg-proxy setup: install, configure, and deploy your own Telegram Bot API
# proxy to Cloudflare Pages in one command.
#
#   git clone https://github.com/yemzikk/tg-proxy.git
#   cd tg-proxy
#   ./setup.sh
#
set -euo pipefail
cd "$(dirname "$0")"

# ---- pretty output -------------------------------------------------------
if [ -t 1 ]; then
  BOLD=$'\033[1m'; DIM=$'\033[2m'; RED=$'\033[31m'; GRN=$'\033[32m'
  YEL=$'\033[33m'; BLU=$'\033[36m'; RST=$'\033[0m'
else
  BOLD=; DIM=; RED=; GRN=; YEL=; BLU=; RST=
fi
step() { printf '\n%s==>%s %s%s\n' "$BLU$BOLD" "$RST$BOLD" "$*" "$RST"; }
ok()   { printf '%s  ok%s %s\n' "$GRN" "$RST" "$*"; }
warn() { printf '%s   !%s %s\n' "$YEL" "$RST" "$*"; }
die()  { printf '%s  x %s%s\n' "$RED" "$*" "$RST" >&2; exit 1; }
ask()  { # ask "Question" "default(y|n)" -> exit 0 for yes
  local q="$1" def="${2:-n}" ans hint="[y/N]"
  [ "$def" = "y" ] && hint="[Y/n]"
  printf '%s ?%s %s %s ' "$BOLD" "$RST" "$q" "$hint"; read -r ans || ans=
  ans="${ans:-$def}"
  case "$ans" in [Yy]*) return 0 ;; *) return 1 ;; esac
}
prompt() { # prompt "Label" -> echoes the entered value
  local label="$1" val
  printf '%s ?%s %s: ' "$BOLD" "$RST" "$label" >&2; read -r val || val=
  printf '%s' "$val"
}

printf '%s\nTelegram Bot API Proxy setup%s\n' "$BOLD" "$RST"
printf '%sDeploys a transparent api.telegram.org proxy to your Cloudflare account.%s\n' "$DIM" "$RST"

# ---- prerequisites -------------------------------------------------------
step "Checking prerequisites"
command -v node >/dev/null 2>&1 || die "Node.js is required: https://nodejs.org"
command -v npm  >/dev/null 2>&1 || die "npm is required (ships with Node.js)"
ok "node $(node -v), npm $(npm -v)"

WRANGLER="npx --yes wrangler"

# ---- dependencies --------------------------------------------------------
step "Installing dependencies"
npm install
ok "dependencies installed"

# ---- Cloudflare auth -----------------------------------------------------
step "Checking Cloudflare login"
if $WRANGLER whoami >/dev/null 2>&1; then
  ok "already logged in to Cloudflare"
else
  warn "not logged in; a browser window will open"
  $WRANGLER login
fi

# ---- optional: live stats (D1) ------------------------------------------
step "Live stats (optional)"
if ask "Enable live stats? This creates a D1 database." "n"; then
  printf '  creating D1 database "tg-proxy-stats"...\n'
  CREATE_OUT="$($WRANGLER d1 create tg-proxy-stats 2>&1 || true)"
  DB_ID="$(printf '%s' "$CREATE_OUT" \
    | grep -Eo '[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}' \
    | head -n1 || true)"
  if [ -z "$DB_ID" ]; then
    warn "could not detect the database id automatically (it may already exist)."
    DB_ID="$(prompt 'Paste the database_id for tg-proxy-stats')"
  fi
  if [ -n "$DB_ID" ]; then
    perl -0pi -e "s/database_id = \"[^\"]*\"/database_id = \"$DB_ID\"/" wrangler.toml
    ok "wrangler.toml updated with database_id $DB_ID"
    printf '  applying schema...\n'
    $WRANGLER d1 execute tg-proxy-stats --remote --file=./schema.sql \
      || warn "remote schema step failed; run 'npm run db:init' later"
    $WRANGLER d1 execute tg-proxy-stats --local --file=./schema.sql || true
    ok "stats enabled"
  else
    warn "no database id provided; skipping stats"
  fi
else
  printf '  skipped\n'
fi

# ---- deploy --------------------------------------------------------------
step "Deploying to Cloudflare Pages"
$WRANGLER pages deploy
ok "deployed"

# ---- optional: channel logging ------------------------------------------
step "Channel logging (optional)"
printf '%s  Mirrors every sent message to a Telegram channel. Logs message text\n' "$DIM"
printf '  and sender metadata (IP, geo, user-agent). Enable only for your own traffic.%s\n' "$RST"
if ask "Set up channel logging now?" "n"; then
  LOG_TOKEN="$(prompt 'Log bot token')"
  LOG_CHAT="$(prompt 'Log channel id (e.g. -1001234567890)')"
  if [ -n "$LOG_TOKEN" ] && [ -n "$LOG_CHAT" ]; then
    printf '%s' "$LOG_TOKEN" | $WRANGLER pages secret put LOG_BOT_TOKEN
    printf '%s' "$LOG_CHAT"  | $WRANGLER pages secret put LOG_CHANNEL_ID
    ok "logging secrets set (remember to make the bot an admin of the channel)"
  else
    warn "both values are required; skipping logging"
  fi
else
  printf '  skipped\n'
fi

# ---- done ----------------------------------------------------------------
step "Done"
printf '%s%sYour proxy is live.%s\n\n' "$GRN" "$BOLD" "$RST"
cat <<EOF
Next steps:
  - Add a custom domain in the Cloudflare dashboard:
      Workers & Pages -> tg-proxy -> Custom domains
  - Use it by swapping the API host:
      https://<your-domain>/bot<TOKEN>/sendMessage

${DIM}Re-run ./setup.sh anytime to change options.${RST}
EOF
