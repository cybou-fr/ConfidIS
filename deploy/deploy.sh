#!/usr/bin/env bash
# =============================================================================
#  CONFIDIS Deployment Script
#  Tested on: Debian 12 / Ubuntu 24.04 LTS
#  Usage: sudo bash deploy.sh [--domain confidis.fr] [--email admin@confidis.fr]
# =============================================================================
set -euo pipefail

# ── Config ────────────────────────────────────────────────────────────────────
DOMAIN="${DOMAIN:-confidis.fr}"
EMAIL="${EMAIL:-admin@confidis.fr}"
INSTALL_DIR="/opt/confidis"
DATA_DIR="/var/confidis"
BINARY="$INSTALL_DIR/bin/confidis"
REPO_DIR="$(cd "$(dirname "$0")/.." && pwd)"

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; NC='\033[0m'
info()  { echo -e "${GREEN}[+]${NC} $*"; }
warn()  { echo -e "${YELLOW}[!]${NC} $*"; }
error() { echo -e "${RED}[✗]${NC} $*" >&2; exit 1; }

[[ $EUID -eq 0 ]] || error "Run as root: sudo bash deploy.sh"

# ── Parse args ────────────────────────────────────────────────────────────────
while [[ $# -gt 0 ]]; do
  case "$1" in
    --domain) DOMAIN="$2"; shift 2 ;;
    --email)  EMAIL="$2";  shift 2 ;;
    *)        error "Unknown argument: $1" ;;
  esac
done

# ── 1. System dependencies ────────────────────────────────────────────────────
info "Installing system dependencies..."
apt-get update -qq
apt-get install -y --no-install-recommends \
  curl nginx certbot python3-certbot-nginx \
  ca-certificates build-essential pkg-config libssl-dev

# Rust toolchain (if not present)
if ! command -v cargo &>/dev/null; then
  info "Installing Rust toolchain..."
  curl -sSf https://sh.rustup.rs | sh -s -- -y --profile minimal
  source "$HOME/.cargo/env"
fi

# Node.js for web-ui build
if ! command -v node &>/dev/null; then
  info "Installing Node.js..."
  curl -fsSL https://deb.nodesource.com/setup_22.x | bash -
  apt-get install -y nodejs
fi

# ── 2. Create confidis user & directories ───────────────────────────────────────
info "Creating confidis user and directories..."
id confidis &>/dev/null || useradd -r -s /bin/false -d "$DATA_DIR" confidis
install -d -o confidis -g confidis \
  "$DATA_DIR/store" \
  "$DATA_DIR/data" \
  "$DATA_DIR/governance" \
  "$INSTALL_DIR/bin"
install -d -o root -g root /etc/confidis

# ── 3. Build confidis binary ─────────────────────────────────────────────────────
info "Building confidis binary (this may take a few minutes)..."
cd "$REPO_DIR"
cargo build --release --quiet
install -m 755 target/release/confidis "$BINARY"
info "Binary installed: $BINARY ($(du -sh target/release/confidis | cut -f1))"

# ── 4. Public Web UI posture ─────────────────────────────────────────────────
#
# A public SPA cannot carry an operator or authority secret. Under
# production_profile the node exposes only public/signed owner browser routes;
# management and inventory routes are excluded from the public
# router. Do not inject VITE_UI_TOKEN into the public bundle.
NODE_CONFIG=/etc/confidis/node.json

# ── 4b. Build Web UI ──────────────────────────────────────────────────────────
info "Building Web UI..."
cd "$REPO_DIR/web-ui"
npm ci --silent
# VITE_NODE_URL="" → same-origin relative fetches (UI is served by the node).
VITE_NODE_URL="" npm run build --silent
install -d /var/www/confidis-ui
cp -r dist/. /var/www/confidis-ui/
# The Web UI bundle already contains the marketing landing page and the
# user/operator/admin docs; the node serves them from webui_path with SPA
# fallback. No separate static marketing site is built or copied.

# ── 5. Initialize node config (if not already present) ───────────────────────
#
# Port model (no subdomains):
#   • Public HTTPS  : https://$DOMAIN          (Nginx :443, 80→443 redirect)
#   • Node backend  : 127.0.0.1:4433           (localhost only, behind Nginx)
#   • Web UI        : https://$DOMAIN/ui/      (path on the same domain)
# Other nodes reach this one at https://$DOMAIN (default 443) — no :4433 and
# no `app.`/`node.` subdomain anywhere.
#
# $NODE_CONFIG was resolved in step 4. The public UI has no embedded bearer;
# owner/recipient signatures protect the surviving sensitive browser flows.
if [[ ! -f "$NODE_CONFIG" ]]; then
  warn "No node config found. Generating initial config..."

  # Generate a node signing key.
  WALLET_JSON=$("$BINARY" wallet create 2>/dev/null)
  PRIV_KEY=$(printf '%s' "$WALLET_JSON" | grep -oP '"private_key"\s*:\s*"\K[^"]+')

  NODE_ID="node-$(hostname -s)"
  "$BINARY" node init-config \
    --node-id "$NODE_ID" \
    --production-profile \
    --transport-policy https_reverse_proxy \
    --listen-addr "127.0.0.1:4433" \
    --public-endpoint "https://$DOMAIN" \
    --store-path "$DATA_DIR/store" \
    --region "eu-fr" \
    --failure-domain "$(hostname -s)" \
    --max-bytes $((50 * 1024 * 1024 * 1024)) \
    --private-key "$PRIV_KEY" \
    --node-ban-list-path "$DATA_DIR/governance/node_ban_list.json" \
    --packages-path "$DATA_DIR/data/packages.json" \
    --registry-path "$DATA_DIR/data/cellules.json" \
    --ui-allowed-origin "https://$DOMAIN" \
    --max-shards-per-owner-per-hour 1000 \
    --max-cellules-per-owner 100 \
    --webui-path /var/www/confidis-ui \
    --peer "https://confidis.fr" \
    "$NODE_CONFIG"

  chown root:confidis "$NODE_CONFIG"
  chmod 640 "$NODE_CONFIG"
  info "Node config written to $NODE_CONFIG (public UI has no embedded operator token)"
else
  info "Using existing node config: $NODE_CONFIG"
fi

python3 - "$NODE_CONFIG" <<'PY'
import json
import sys

with open(sys.argv[1], encoding="utf-8") as handle:
    config = json.load(handle)
if config.get("node", {}).get("production_profile") is not True:
    raise SystemExit("Existing config is not production_profile=true; refuse public deployment")
PY
"$BINARY" node check-config "$NODE_CONFIG" >/dev/null
info "Production node configuration validated"

# ── 6. Install systemd service ────────────────────────────────────────────────
info "Installing systemd service..."
install -m 644 "$REPO_DIR/deploy/systemd/confidis-node.service" /etc/systemd/system/confidis-node.service
systemctl daemon-reload
systemctl enable --now confidis-node
info "confidis-node service: $(systemctl is-active confidis-node)"

# ── 7. Configure Nginx ────────────────────────────────────────────────────────
info "Configuring Nginx..."
# Replace placeholder domain in nginx config
sed "s/confidis\.fr/$DOMAIN/g" "$REPO_DIR/deploy/nginx/confidis.conf" \
  > /etc/nginx/sites-available/confidis.conf
ln -sf /etc/nginx/sites-available/confidis.conf /etc/nginx/sites-enabled/confidis.conf
rm -f /etc/nginx/sites-enabled/default

# Test and reload (HTTP only first, TLS added after certbot)
nginx -t && systemctl reload nginx

# ── 8. TLS via Let's Encrypt ──────────────────────────────────────────────────
info "Requesting TLS certificate from Let's Encrypt..."
# Single apex domain only — no www./app./node. subdomains. Nginx adds the
# 443 TLS server and the 80→443 redirect for $DOMAIN.
certbot --nginx \
  --non-interactive \
  --agree-tos \
  --email "$EMAIL" \
  -d "$DOMAIN" \
  && systemctl reload nginx \
  || warn "Certbot failed — check DNS propagation and try again with: certbot --nginx -d $DOMAIN"

# Set up auto-renewal cron
if ! crontab -l 2>/dev/null | grep -q certbot; then
  (crontab -l 2>/dev/null; echo "0 3 * * * certbot renew --quiet && systemctl reload nginx") | crontab -
  info "Auto-renewal cron added (daily at 03:00)"
fi

# ── Summary ───────────────────────────────────────────────────────────────────
echo ""
echo -e "${GREEN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo -e "${GREEN}  CONFIDIS Deployed Successfully!${NC}"
echo -e "${GREEN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo ""
echo -e "  🌐  Landing / docs  → https://$DOMAIN"
echo -e "  📊  Web UI          → https://$DOMAIN/ui/"
echo -e "  🔗  Peer endpoint   → https://$DOMAIN  (other nodes connect here)"
echo -e "  🔌  Node backend    → http://127.0.0.1:4433 (localhost only, behind Nginx)"
echo ""
echo -e "  Logs:   journalctl -u confidis-node -f"
echo -e "  Status: systemctl status confidis-node"
echo -e "  Config: $NODE_CONFIG"
echo ""
