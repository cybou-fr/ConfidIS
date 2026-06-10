#!/usr/bin/env bash
# Refresh the stable screenshots used by promotion decks/docs.
#
# The source screenshots are produced by the Web UI smoke renderer, which waits
# for real page rendering and masks elements marked as sensitive before capture.

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

require_cmd() {
    local cmd="$1"
    local hint="$2"
    if ! command -v "$cmd" >/dev/null 2>&1; then
        echo "error: missing required command '$cmd'" >&2
        echo "hint: $hint" >&2
        exit 1
    fi
}

copy_shot() {
    local source="$1"
    local target="$2"
    if [[ ! -s "$REPO_ROOT/web-ui/dist/$source" ]]; then
        echo "error: expected screenshot missing: web-ui/dist/$source" >&2
        exit 1
    fi
    cp "$REPO_ROOT/web-ui/dist/$source" "$REPO_ROOT/promotion/screenshots/$target"
    echo "  $target"
}

verify_inventory() {
    local missing=0
    for shot in \
        home.png \
        user-dashboard.png \
        user-cellules.png \
        user-wallet.png \
        public-operator-blocked.png
    do
        if [[ ! -s "$REPO_ROOT/promotion/screenshots/$shot" ]]; then
            echo "error: promotion screenshot missing after refresh: $shot" >&2
            missing=1
        fi
    done
    if [[ "$missing" != "0" ]]; then
        exit 1
    fi
}

require_cmd npm "install Node.js + npm"
require_cmd firefox "install Firefox (macOS: brew install --cask firefox)"

cd "$REPO_ROOT"

echo "==> Building Web UI"
npm --prefix web-ui run build

echo ""
echo "==> Rendering safe smoke screenshots"
npm --prefix web-ui run smoke

mkdir -p promotion/screenshots

echo ""
echo "==> Updating promotion screenshots"
copy_shot smoke-home.png home.png
copy_shot smoke-user-overview.png user-dashboard.png
copy_shot smoke-user-cellules.png user-cellules.png
copy_shot smoke-user-wallet.png user-wallet.png
copy_shot smoke-operator-blocked.png public-operator-blocked.png
verify_inventory

echo ""
echo "✓ promotion screenshots refreshed"
