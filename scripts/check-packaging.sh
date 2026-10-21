#!/usr/bin/env bash
# Static packaging gate: catches missing packaging inputs and invalid scripts.
# This does not claim that a .deb was built, installed, signed or tested.
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"
command -v python3 >/dev/null || { echo "ERROR: python3 required" >&2; exit 1; }
for f in packaging/node-default.json packaging/confidis.service packaging/debian/control packaging/postinst packaging/prerm packaging/postrm scripts/build-deb.sh; do
  [[ -s "$f" ]] || { echo "ERROR: missing or empty packaging input: $f" >&2; exit 1; }
done
bash -n scripts/build-deb.sh
for f in packaging/postinst packaging/prerm packaging/postrm; do
  bash -n "$f"
done
python3 -m json.tool packaging/node-default.json >/dev/null
python3 - <<'PY'
import json
from pathlib import Path
data = json.loads(Path('packaging/node-default.json').read_text())
for key in ('node', 'network', 'storage', 'security', 'storage_backend'):
    assert isinstance(data.get(key), dict), f'packaged default missing {key}'
assert data['node'].get('private_key') is None, 'do not ship a private key in defaults'
assert data['security'].get('ui_token') is None, 'do not ship an admin UI token in defaults'
PY
echo "PASS: packaging file layout, shell syntax, default JSON and no embedded node/UI secrets"
echo "NOTE: .deb build/install/signature and upgrades still require separate validation"
