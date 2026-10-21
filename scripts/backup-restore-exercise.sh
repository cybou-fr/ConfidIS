#!/usr/bin/env bash
# Real local Cellule put/get roundtrip, not a production federation test.
set -euo pipefail
umask 077
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"
for cmd in cargo python3 curl cmp mktemp; do
  command -v "$cmd" >/dev/null || { echo "ERROR: $cmd required" >&2; exit 1; }
done
WORK="$(mktemp -d)"
NODE_PID=""
cleanup() {
  if [[ -n "$NODE_PID" ]]; then kill "$NODE_PID" 2>/dev/null || true; wait "$NODE_PID" 2>/dev/null || true; fi
  rm -rf -- "$WORK"
}
trap cleanup EXIT
cargo build -p confidis --quiet
BIN="$ROOT/target/debug/confidis"
[[ -x "$BIN" ]] || { echo "ERROR: missing confidis CLI" >&2; exit 1; }
PORT="$(python3 -c "import socket; s=socket.socket(); s.bind(('127.0.0.1',0)); print(s.getsockname()[1]); s.close()")"
URL="http://127.0.0.1:$PORT"
EXPIRY="$(python3 -c "from datetime import datetime,timedelta,timezone; print((datetime.now(timezone.utc)+timedelta(days=2)).strftime('%Y-%m-%dT%H:%M:%SZ'))")"
WALLET="$("$BIN" wallet create)"
PRIVATE="$(printf "%s\n" "$WALLET" | sed -n "s/^private_key=//p")"
PUBLIC="$(printf "%s\n" "$WALLET" | sed -n "s/^public_key=//p")"
[[ -n "$PRIVATE" && -n "$PUBLIC" ]] || { echo "ERROR: wallet output missing keys" >&2; exit 1; }
printf "ConfidIS temporary integration payload\n" > "$WORK/sample.txt"
mkdir -p "$WORK/blobs" "$WORK/recovered"
"$BIN" node init-config --node-id smoke-node --store-path "$WORK/store" --registry-path "$WORK/registry.json" --listen-addr "127.0.0.1:$PORT" --max-bytes 100000000 --region local --failure-domain local-fd --output "$WORK/node.json" >/dev/null
"$BIN" node serve "$WORK/node.json" > "$WORK/node.log" 2>&1 &
NODE_PID="$!"
ready=0
for _ in $(seq 1 50); do
  if curl -fsS --max-time 1 "$URL/health" >/dev/null 2>&1; then ready=1; break; fi
  if ! kill -0 "$NODE_PID" 2>/dev/null; then echo "ERROR: test node exited" >&2; exit 1; fi
  sleep 0.2
done
[[ "$ready" -eq 1 ]] || { echo "ERROR: test node did not become healthy" >&2; exit 1; }
"$BIN" cellule record --name smoke-cellule --public-key "$PUBLIC" --private-key "$PRIVATE" --registry "$WORK/registry.json" --blob-store "$WORK/blobs" --cellule-key "$WORK/cellule.key" --expires-at "$EXPIRY" --output "$WORK/record.json" >/dev/null
CELLULE_ID="$("$BIN" cellule id --public-key "$PUBLIC")"
"$BIN" cellule put --node "$URL" --input "$WORK/sample.txt" --work-dir "$WORK/work" --registry "$WORK/registry.json" --blob-store "$WORK/blobs" --public-key "$PUBLIC" --private-key "$PRIVATE" --cellule-key "$WORK/cellule.key" --expires-at "$EXPIRY" --sequence 1 --output "$WORK/receipt.json" >/dev/null
"$BIN" cellule get --node "$URL" --cellule-id "$CELLULE_ID" --output-dir "$WORK/recovered" --registry "$WORK/registry.json" --blob-store "$WORK/blobs" --private-key "$PRIVATE" --cellule-key "$WORK/cellule.key" >/dev/null
RECOVERED="$(find "$WORK/recovered" -type f -print -quit)"
[[ -n "$RECOVERED" ]] || { echo "ERROR: no recovered file" >&2; exit 1; }
cmp -s "$WORK/sample.txt" "$RECOVERED" || { echo "ERROR: restored file mismatch" >&2; exit 1; }
echo "PASS: local synthetic Cellule upload/download with identical restored bytes"
echo "NOTE: no signed Debian install, TLS federation, independent failure-domain or delete proof covered"
