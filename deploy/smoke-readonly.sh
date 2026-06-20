#!/usr/bin/env bash
set -euo pipefail

BASE_URL="${BASE_URL:?Set BASE_URL, e.g. https://mcptrust.example.com}"
SLUG="${SLUG:-mcp-reference-time}"

curl -fsS "$BASE_URL/healthz" | grep -q '"status":"ok"'
curl -fsS "$BASE_URL/servers" | grep -q "$SLUG"
curl -fsS "$BASE_URL/" | grep -q "MCP Server Danger Catalog"
curl -fsS "$BASE_URL/ui/servers/$SLUG" | grep -q "Automated danger grade"
curl -fsS "$BASE_URL/servers/$SLUG/badge.json" | grep -q '"schemaVersion":1'
python3 - "$BASE_URL/servers/$SLUG" <<'PY'
import json
import sys
from urllib.request import urlopen

url = sys.argv[1]
with urlopen(url, timeout=10) as response:
    payload = json.load(response)

latest_scan = payload.get("latest_scan") or {}
report_ref = latest_scan.get("report_ref")
if not report_ref:
    raise SystemExit("latest scan is missing report_ref")
if "/" in report_ref or "\\" in report_ref:
    raise SystemExit(f"report_ref must be portable, got {report_ref!r}")
PY

status="$(
  curl -sS -o /tmp/mcp-trust-scan-smoke-response.json -w '%{http_code}' \
    -X POST "$BASE_URL/servers/$SLUG/scan"
)"

if [[ "$status" != "403" ]]; then
  echo "expected POST /servers/$SLUG/scan to return 403, got $status" >&2
  cat /tmp/mcp-trust-scan-smoke-response.json >&2 || true
  exit 1
fi

echo "read-only smoke passed for $BASE_URL ($SLUG)"
