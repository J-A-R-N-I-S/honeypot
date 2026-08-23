#!/usr/bin/env bash
# Replace the old GHCR-based jarnis-honeypot-release-sync.
# Writes /etc/jarnis/honeypot_release.php from Hub SoT:
#   https://raw.githubusercontent.com/J-A-R-N-I-S/honeypot/main/deploy/release.json
#
# After website #56, /etc is optional (API fetches release.json directly).
# Keep this only if you still want a local /etc mirror — do NOT set force=true
# unless intentionally pinning (that would race Hub again).
set -euo pipefail

OUT="${JARNIS_HONEYPOT_RELEASE_OUT:-/etc/jarnis/honeypot_release.php}"
URL="${JARNIS_HONEYPOT_RELEASE_URL:-https://raw.githubusercontent.com/J-A-R-N-I-S/honeypot/main/deploy/release.json}"
TMP="$(mktemp)"
trap 'rm -f "$TMP"' EXIT

curl -fsSL --max-time 10 -A 'jarnis-honeypot-release-sync/hub' "$URL" -o "$TMP"
python3 - "$TMP" "$OUT" <<'PY'
import json, pathlib, sys, datetime
src, out = pathlib.Path(sys.argv[1]), pathlib.Path(sys.argv[2])
doc = json.loads(src.read_text())
ver = str(doc.get("version") or "").strip()
if not ver:
    raise SystemExit("release.json missing version")
tags = doc.get("tags") or [ver]
if not isinstance(tags, list):
    tags = [ver]
# keep legacy Hub tags
for t in ("v1.0-hostinger", "v1.0"):
    if t not in tags:
        tags.append(t)
# PHP return array — no force pin (Hub API fetch wins; /etc tags only)
lines = [
    "<?php",
    "/** Auto-synced from Hub deploy/release.json — do not set force=true. */",
    "return [",
    f"    'version' => {json.dumps(ver)},",
    "    'tags' => [",
]
for t in tags:
    lines.append(f"        {json.dumps(str(t))},")
lines += [
    "    ],",
    "    'source' => 'dockerhub',",
    f"    'synced_at' => {json.dumps(datetime.datetime.utcnow().strftime('%Y-%m-%dT%H:%M:%SZ'))},",
    "];",
    "",
]
out.parent.mkdir(parents=True, exist_ok=True)
tmp = out.with_suffix(".php.tmp")
tmp.write_text("\n".join(lines))
tmp.chmod(0o644)
tmp.replace(out)
print(f"wrote {out} version={ver}")
PY
