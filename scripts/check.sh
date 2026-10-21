#!/usr/bin/env bash
# scripts/check.sh — run the local CONFIDIS quality gate before opening a PR.
#
# Usage:
#   ./scripts/check.sh
#   CONFIDIS_SKIP_AUDIT=1 ./scripts/check.sh
#   CONFIDIS_SKIP_WASM_BROWSER=1 ./scripts/check.sh
#   CONFIDIS_SKIP_WEBUI_SMOKE=1 ./scripts/check.sh

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

run() {
    echo ""
    echo "==> $*"
    "$@"
}

require_cmd() {
    local cmd="$1"
    local hint="$2"
    if ! command -v "$cmd" >/dev/null 2>&1; then
        echo "error: missing required command '$cmd'" >&2
        echo "hint: $hint" >&2
        exit 1
    fi
}

require_cmd cargo "install Rust from https://rustup.rs/"
require_cmd node "install Node.js"
require_cmd npm "install Node.js + npm"
require_cmd wasm-pack "cargo install wasm-pack --locked"
require_cmd jq "install jq (macOS: brew install jq)"

if [[ "${CONFIDIS_SKIP_AUDIT:-0}" != "1" ]]; then
    require_cmd cargo-audit "cargo install cargo-audit --locked"
fi

if [[ "${CONFIDIS_SKIP_WASM_BROWSER:-0}" != "1" ]]; then
    require_cmd firefox "install Firefox (macOS: brew install --cask firefox)"
fi

if [[ "${CONFIDIS_SKIP_WEBUI_SMOKE:-0}" != "1" ]]; then
    require_cmd firefox "install Firefox (macOS: brew install --cask firefox)"
fi

cd "$REPO_ROOT"

run cargo fmt --all -- --check
run cargo clippy --all-targets --all-features -- -D warnings
run cargo test --workspace
run ./scripts/check-packaging.sh
# Full Cellule put/get is disabled in the current CLI (cfg(any())).
# Do not run an obsolete demo or count an unavailable upload/restore test as PASS.
echo "NOTE: end-to-end Cellule upload/restore NOT VERIFIED (put is disabled in current CLI)"

if [[ "${CONFIDIS_SKIP_AUDIT:-0}" != "1" ]]; then
    run cargo audit
else
    echo ""
    echo "==> skipping cargo audit (CONFIDIS_SKIP_AUDIT=1)"
fi

run wasm-pack test --node crates/confidis-crypto-wasm

if [[ "${CONFIDIS_SKIP_WASM_BROWSER:-0}" != "1" ]]; then
    run node ./scripts/test-wasm-browser.mjs
else
    echo ""
    echo "==> skipping WASM browser tests (CONFIDIS_SKIP_WASM_BROWSER=1)"
fi

run npm --prefix web-ui test
run npm --prefix web-ui run lint
run npm --prefix web-ui run build

if [[ "${CONFIDIS_SKIP_WEBUI_SMOKE:-0}" != "1" ]]; then
    run npm --prefix web-ui run smoke
else
    echo ""
    echo "==> skipping web-ui smoke render (CONFIDIS_SKIP_WEBUI_SMOKE=1)"
fi

echo ""
echo "✓ CONFIDIS available source/test/static-packaging checks completed"
echo "NOTE: Debian install and end-to-end backup/restore are not release-qualified"
