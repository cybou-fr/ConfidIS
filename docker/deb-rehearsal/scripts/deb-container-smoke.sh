#!/usr/bin/env bash
set -euo pipefail

evidence="${CONFIDIS_DEB_EVIDENCE_DIR:-/tmp/confidis-deb-evidence}"
mkdir -p "$evidence"
artifact_name="$(cat /tmp/confidis-release/artifact-name)"
artifact="/tmp/confidis-release/$artifact_name"
signature="$artifact.sig.json"
authority_set="/tmp/confidis-release/authority-set.json"
checksum="$artifact.sha256"

node_pid=""
cleanup() {
    if [[ -n "$node_pid" ]] && kill -0 "$node_pid" >/dev/null 2>&1; then
        kill "$node_pid" >/dev/null 2>&1 || true
        wait "$node_pid" >/dev/null 2>&1 || true
    fi
}
trap cleanup EXIT

capture() {
    local name="$1"
    shift
    echo "==> $name"
    "$@" 2>&1 | tee "$evidence/$name.log"
}

wait_json() {
    local name="$1"
    local url="$2"
    for _ in $(seq 1 120); do
        if curl -fsS "$url" | jq . > "$evidence/$name.json"; then
            return 0
        fi
        sleep 1
    done
    echo "timeout waiting for $url" >&2
    tail -n 200 "$evidence/node.log" >&2 || true
    return 1
}

echo "==> verifying installed package files"
capture package-query dpkg -s confidis
capture binary-help /usr/bin/confidis --help
capture config-check /usr/bin/confidis node check-config /etc/confidis/node.json

test -x /usr/bin/confidis
test -f /usr/share/confidis/node-default.json
test -f /usr/share/confidis/webui/index.html
test -f /lib/systemd/system/confidis.service
test -f /etc/confidis/node.json
test -f /var/lib/confidis/cellules.json
test -f /var/lib/confidis/packages.json
test -f /var/lib/confidis/read-access-revocations.json

jq -e '
  (.node.node_id | startswith("company-node-")) and
  (.node.production_profile == false) and
  (.network.listen_addr == "127.0.0.1:4433") and
  (.network.bootstrap_peers == []) and
    (.network.authority_spend_url == null) and
    (.network.confidis_root_pubkey == null) and
    ((.network | has("payer_mode")) | not) and
  (.storage.authority_private_key_path == null) and
    ((.usage | has("cyb_per_byte_per_day")) | not) and
    ((.usage | has("cyb_cellule_create_fee")) | not) and
  (.security.ui_token == null) and
  (.security.compliance_token == null)
' /etc/confidis/node.json | tee "$evidence/config-posture.log" >/dev/null

if grep -R "authority_private_key" /etc/confidis /var/lib/confidis 2>/dev/null | grep -v '"authority_private_key_path": null'; then
    echo "authority private key material appeared in the enterprise node install" >&2
    exit 1
fi

echo "==> verifying release artifact signature"
expected_sha="$(cut -d ' ' -f1 "$checksum")"
actual_sha="$(sha256sum "$artifact" | tee "$evidence/deb.sha256" | cut -d ' ' -f1)"
if [[ "$actual_sha" != "$expected_sha" ]]; then
    echo "deb sha256 mismatch: expected $expected_sha, got $actual_sha" >&2
    exit 1
fi
capture release-signature-verify /usr/bin/confidis authority verify-release \
    --artifact "$artifact" \
    --signature "$signature" \
    --authority-set "$authority_set"

echo "==> starting installed node as confidis user"
su -s /bin/sh -c '/usr/bin/confidis node serve /etc/confidis/node.json' confidis \
    > "$evidence/node.log" 2>&1 &
node_pid="$!"

wait_json local-health http://127.0.0.1:4433/health
wait_json local-node-info http://127.0.0.1:4433/node-info
wait_json local-peers http://127.0.0.1:4433/peers

if command -v ss >/dev/null 2>&1; then
    ss -ltnp | tee "$evidence/listeners.log" >/dev/null || true
    if ss -ltn | awk '$4 ~ /:4433$/ && $4 !~ /127\.0\.0\.1:4433$/ && $4 !~ /\[::1\]:4433$/ { found=1 } END { exit found ? 0 : 1 }'; then
        echo "confidis backend port 4433 is listening on a non-local address" >&2
        exit 1
    fi
fi

cat > "$evidence/SUMMARY.md" <<EOF
# CONFIDIS .deb container rehearsal evidence

Generated: $(date -u +%Y-%m-%dT%H:%M:%SZ)

Checks passed:
- .deb installed with dpkg in a clean Debian runtime container.
- Package created /etc/confidis/node.json with a generated company-node id.
- Package initialized local node state files under /var/lib/confidis.
- No authority private key, UI token or compliance token was created by install.
- Installed /usr/bin/confidis validated the installed config.
- Synthetic M-of-N release signature verified against the packaged artifact.
- Installed node started as the confidis system user and answered /health, /node-info and /peers.
- Backend listener stayed localhost-only on 127.0.0.1:4433.

Limit:
- This proves package build/install/use, not real host systemd boot, public TLS or independent-node G3 topology.
EOF

echo "✓ CONFIDIS .deb container rehearsal passed"
echo "  evidence: $evidence"
