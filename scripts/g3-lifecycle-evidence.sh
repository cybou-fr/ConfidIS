#!/usr/bin/env bash
# Collect focused G3 lifecycle evidence for the private/public-testnet path.
#
# This bundle proves the local, synthetic-data Cellule lifecycle and discovery
# behaviours that must later be repeated on signed .deb/systemd/TLS topology.

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
STAMP="$(date -u +%Y%m%dT%H%M%SZ)"
EVIDENCE_DIR="${CONFIDIS_EVIDENCE_DIR:-$REPO_ROOT/.g3-lifecycle-evidence/$STAMP}"
LOG_DIR="$EVIDENCE_DIR/logs"

require_cmd() {
    local cmd="$1"
    local hint="$2"
    if ! command -v "$cmd" >/dev/null 2>&1; then
        echo "error: missing required command '$cmd'" >&2
        echo "hint: $hint" >&2
        exit 1
    fi
}

run_capture() {
    local name="$1"
    shift
    local log="$LOG_DIR/$name.log"
    echo ""
    echo "==> $name"
    "$@" 2>&1 | tee "$log"
}

run_cellule_test() {
    local name="$1"
    run_capture "$name" cargo test -p confidis --test cellule_flow "$name" -- --exact
}

require_cmd cargo "install Rust from https://rustup.rs/"

cd "$REPO_ROOT"
mkdir -p "$LOG_DIR"

run_cellule_test cellule_put_rejects_expiry_beyond_one_year_before_file_read
run_cellule_test cellule_put_get_round_trips_multi_segment_payload
run_cellule_test cellule_get_recovers_record_and_manifest_from_network
run_cellule_test cellule_renew_extends_expiry_and_increments_sequence
run_cellule_test cellule_expiry_closes_get_repair_and_scan
run_cellule_test cellule_delete_partial_failure_keeps_record_and_retry_converges

cat > "$EVIDENCE_DIR/SUMMARY.md" <<EOF
# CONFIDIS G3 Cellule lifecycle evidence

Generated: $STAMP

## What this bundle proves

- 365-day lifecycle bound: \`cellule put\` rejects an expiry beyond one year before reading the input file.
  Evidence: \`logs/cellule_put_rejects_expiry_beyond_one_year_before_file_read.log\`
- Multi-segment data plane: a synthetic payload is split, placed, restored and reassembled byte-identically.
  Evidence: \`logs/cellule_put_get_round_trips_multi_segment_payload.log\`
- Fresh-client recovery: \`cellule get --node ...\` restores through signed network records, manifest CID and provider registry without local registry/blob state.
  Evidence: \`logs/cellule_get_recovers_record_and_manifest_from_network.log\`
- Owner renewal: a Cellule is renewed by owner signature, increments sequence, updates expiry up to the one-year bound, and remains readable.
  Evidence: \`logs/cellule_renew_extends_expiry_and_increments_sequence.log\`
- Expiry closure: after expiry, get/repair are closed and repair-scan reports the Cellule as expired instead of pretending recovery is possible.
  Evidence: \`logs/cellule_expiry_closes_get_repair_and_scan.log\`
- Delete convergence: a partial delete keeps local record/manifest state, then a retry after node recovery converges and removes the Cellule record.
  Evidence: \`logs/cellule_delete_partial_failure_keeps_record_and_retry_converges.log\`

## Notes

This is local synthetic technical evidence. It does not replace G3 on real
signed Debian artifacts, systemd, TLS, public routable endpoints, isolated
authority signer and independent failure domains. It is the lifecycle slice that
the G3 rehearsal must reproduce.
EOF

echo ""
echo "✓ G3 lifecycle evidence collected:"
echo "  $EVIDENCE_DIR"
