#!/usr/bin/env bash
# scripts/build-deb.sh — build the confidis .deb package
#
# Usage:
#   ./scripts/build-deb.sh [--version X.Y.Z]
#
# Requirements (on a Debian/Ubuntu build host):
#   apt install dpkg-dev build-essential pkg-config libssl-dev nodejs npm
#   cargo install cargo-auditable   # optional: embeds dependency audit info

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

require_production_root_key() {
    local key="${CONFIDIS_GENESIS_ROOT_PUBKEY_HEX:-}"
    if [[ ! "$key" =~ ^[0-9a-fA-F]{64}$ ]] || [[ "$key" =~ ^0{64}$ ]]; then
        echo "error: set CONFIDIS_GENESIS_ROOT_PUBKEY_HEX to the real 32-byte CONFIDIS root public key before building a release package" >&2
        echo "hint: generate it with 'confidis authority init-keypair' and keep the private key offline" >&2
        exit 1
    fi
}

require_production_root_key

VERSION=""
while [[ $# -gt 0 ]]; do
    case "$1" in
        --version)
            [[ $# -ge 2 ]] || { echo "error: --version requires a value" >&2; exit 1; }
            VERSION="$2"
            shift 2
            ;;
        -*)
            echo "error: unknown option '$1'" >&2
            exit 1
            ;;
        *)
            [[ -z "$VERSION" ]] || { echo "error: version specified more than once" >&2; exit 1; }
            VERSION="$1"
            shift
            ;;
    esac
done

if [[ -z "$VERSION" ]]; then
    VERSION="$(cargo metadata --no-deps --format-version 1 \
        --manifest-path "$REPO_ROOT/Cargo.toml" \
        | python3 -c "import sys,json; ws=json.load(sys.stdin); \
          print(next(p['version'] for p in ws['packages'] if p['name']=='confidis-node'))")"
fi

ARCH="$(dpkg --print-architecture 2>/dev/null || echo amd64)"
PKG="confidis_${VERSION}_${ARCH}"
BUILD_DIR="$REPO_ROOT/target/deb-build/$PKG"

echo "==> Building confidis $VERSION ($ARCH)"
echo "    repo: $REPO_ROOT"
echo "    pkg:  $BUILD_DIR.deb"

# ─── 1. Build Rust binary ────────────────────────────────────────────────────
echo "==> cargo build --release"
cargo build --release \
    --manifest-path "$REPO_ROOT/Cargo.toml" \
    -p confidis

# ─── 2. Build web-UI ─────────────────────────────────────────────────────────
echo "==> npm ci && npm run build (web-ui)"
(cd "$REPO_ROOT/web-ui" && npm ci && npm run build)
# Inject SRI hashes if the script exists.
if [[ -f "$REPO_ROOT/web-ui/scripts/inject-sri.js" ]]; then
    node "$REPO_ROOT/web-ui/scripts/inject-sri.js"
fi

# The config installed by the package must be loadable by the binary in the
# same release. This catches schema drift before a broken package is emitted.
echo "==> Validating packaged node config"
CHECK_STORE="$(mktemp -d "${TMPDIR:-/tmp}/confidis-package-config.XXXXXX")"
trap 'rm -rf "$CHECK_STORE"' EXIT
CONFIDIS_STORE_PATH="$CHECK_STORE/shards" \
    "$REPO_ROOT/target/release/confidis" node check-config "$REPO_ROOT/packaging/node-default.json" >/dev/null

# ─── 3. Assemble package tree ────────────────────────────────────────────────
echo "==> Assembling package tree"
rm -rf "$BUILD_DIR"

install -d "$BUILD_DIR/DEBIAN"
install -d "$BUILD_DIR/usr/bin"
install -d "$BUILD_DIR/usr/share/confidis/webui"
install -d "$BUILD_DIR/usr/share/confidis"
install -d "$BUILD_DIR/lib/systemd/system"
install -d "$BUILD_DIR/etc/confidis"    # owned by pkg; node.json written by postinst

# Binary
install -m 0755 "$REPO_ROOT/target/release/confidis" "$BUILD_DIR/usr/bin/confidis"

# Web-UI assets
cp -r "$REPO_ROOT/web-ui/dist/." "$BUILD_DIR/usr/share/confidis/webui/"

# Default config template (postinst copies to /etc/confidis/node.json on first install)
install -m 0644 "$REPO_ROOT/packaging/node-default.json" \
    "$BUILD_DIR/usr/share/confidis/node-default.json"

# Systemd unit
install -m 0644 "$REPO_ROOT/packaging/confidis.service" \
    "$BUILD_DIR/lib/systemd/system/confidis.service"

# ─── 4. DEBIAN control files ─────────────────────────────────────────────────
INSTALLED_SIZE=$(du -sk "$BUILD_DIR" | cut -f1)

sed \
    -e "s/\${VERSION}/$VERSION/" \
    -e "s/\${ARCHITECTURE}/$ARCH/" \
    -e "s/\${INSTALLED_SIZE}/$INSTALLED_SIZE/" \
    "$REPO_ROOT/packaging/debian/control" \
    > "$BUILD_DIR/DEBIAN/control"

install -m 0755 "$REPO_ROOT/packaging/postinst" "$BUILD_DIR/DEBIAN/postinst"
install -m 0755 "$REPO_ROOT/packaging/prerm"    "$BUILD_DIR/DEBIAN/prerm"
install -m 0755 "$REPO_ROOT/packaging/postrm"   "$BUILD_DIR/DEBIAN/postrm"

# ─── 5. Build .deb ───────────────────────────────────────────────────────────
echo "==> dpkg-deb --build"
dpkg-deb --root-owner-group --build "$BUILD_DIR" "$REPO_ROOT/target/$PKG.deb"

echo ""
echo "✓  Package ready: target/$PKG.deb"
echo ""
echo "Install on a Debian/Ubuntu host:"
echo "  scp target/$PKG.deb user@server:/tmp/"
echo "  ssh user@server 'sudo dpkg -i /tmp/$PKG.deb'"
