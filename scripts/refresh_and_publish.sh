#!/usr/bin/env bash
# Freshness loop for the static MCP Trust catalog:
#   re-scan the launch corpus (network-off Docker sandbox) -> rebuild the
#   static site locally.
#
# Designed to run from launchd/cron OR by hand. Re-scanning surfaces grade
# changes over time; to catch UPSTREAM server drift / rug-pull, periodically
# rebuild Dockerfile.scan with current versions (the scan image is pinned). The
# scan runtime is network-off inside Docker. This entrypoint has no publication
# authority; production deployment is a separate, explicitly authorized lane.
#
# Config (env, with safe defaults):
#   MCP_TRUST_DB                 registry SQLite path        (default ./registry.db)
#   MCP_TRUST_SITE_OUT           static output dir           (default ./site)
#   MCP_TRUST_SITE_BASE_URL      deploy URL for badge embeds (default production URL)
#   MCP_TRUST_SANDBOX_IMAGE      prebuilt scan image         (default corpus image)
#   MCP_TRUST_RECEIPTS_DIR       receipt archive dir         (default ./receipts)
set -euo pipefail

if [ "${MCP_TRUST_AUTO_DEPLOY+x}" = "x" ]; then
  printf '%s\n' \
    "ERROR: MCP_TRUST_AUTO_DEPLOY no longer authorizes deployment; use the explicit manual deployment lane." >&2
  exit 1
fi

# The refresh lane must not intentionally inherit provider deployment authority.
unset VERCEL_TOKEN VERCEL_ORG_ID VERCEL_PROJECT_ID VERCEL_SCOPE

# Resolve repo root from this script's location so launchd's bare cwd is fine.
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"
cd "${REPO_ROOT}"

DB="${MCP_TRUST_DB:-./registry.db}"
OUT="${MCP_TRUST_SITE_OUT:-./site}"
BASE_URL="${MCP_TRUST_SITE_BASE_URL:-https://mcp-trust.vercel.app}"
IMAGE="${MCP_TRUST_SANDBOX_IMAGE:-mcp-trust-scan:corpus-2026-07-03}"
RECEIPTS="${MCP_TRUST_RECEIPTS_DIR:-./receipts}"

log() { printf '%s  %s\n' "$(date -u +%Y-%m-%dT%H:%M:%SZ)" "$*"; }

# --- preflight: the sandbox needs a reachable Docker daemon + the scan image ---
if ! docker info >/dev/null 2>&1; then
  log "ERROR: Docker daemon not reachable. Start Colima/Docker before refreshing."
  exit 1
fi
if ! docker image inspect "${IMAGE}" >/dev/null 2>&1; then
  log "ERROR: scan image ${IMAGE} not found. Build it with Dockerfile.scan first."
  exit 1
fi

export MCP_TRUST_DB="${DB}"
export MCP_TRUST_ENGINE=mcpaudit
export MCP_TRUST_SANDBOX=docker
export MCP_TRUST_SANDBOX_NETWORK=none
export MCP_TRUST_SANDBOX_IMAGE="${IMAGE}"
export MCP_TRUST_RECEIPTS_DIR="${RECEIPTS}"
# Credentialed-sandboxed servers (gitlab/slack/brave-search/google-maps/everart)
# need non-functional dummy values to enumerate network-off; a no-op for servers
# without env_keys. Without this the refresh would regress those grades to errors.
export MCP_TRUST_SCAN_CREDENTIALS="${MCP_TRUST_SCAN_CREDENTIALS:-dummy}"

# Seed if empty, then re-scan every catalog server (real, sandboxed, persisted).
uv run mcp-trust seed >/dev/null
SLUGS="$(uv run python -c "
import sqlite3
c = sqlite3.connect('${DB}')
for (slug,) in c.execute('SELECT slug FROM servers ORDER BY slug'):
    print(slug)
")"

log "Re-scanning $(printf '%s\n' "${SLUGS}" | grep -c .) server(s) with mcpaudit (sandbox=${IMAGE}, network=none)"
while IFS= read -r slug; do
  [ -z "${slug}" ] && continue
  if uv run mcp-trust scan "${slug}" >/dev/null 2>&1; then
    log "  scanned ${slug}"
  else
    log "  WARN: scan failed for ${slug} (kept previous grade)"
  fi
done <<< "${SLUGS}"

# Attribute the latest grade movement on record after this run's re-scan:
# compare each server's newest stored scan against the one before it (surface
# change vs engine change vs score movement) and archive the report. A server
# whose re-scan failed above keeps its previous rows, so its entry reflects the
# movement already on record — each entry carries both scan timestamps.
# A report, not a gate: every step here is guarded so a reporting failure warns
# and the refresh continues. The report is written to a temp path and moved into
# place only on success, so a crashed run never leaves a truncated artifact.
REPORTS="${MCP_TRUST_REPORTS_DIR:-./reports}"
DRIFT_OUT="${REPORTS}/drift-$(date -u +%Y%m%dT%H%M%SZ).json"
log "Writing scan-over-scan drift report -> ${DRIFT_OUT}"
if mkdir -p "${REPORTS}" \
    && uv run mcp-trust drift --json > "${DRIFT_OUT}.tmp" \
    && mv "${DRIFT_OUT}.tmp" "${DRIFT_OUT}"; then
  # Human-readable movement summary into the launchd/cron log, rendered from the
  # archived report so the log and the artifact can never disagree.
  uv run python - "${DRIFT_OUT}" <<'PY' || log "WARN: drift summary print failed (report archived)"
import json
import sys

report = json.load(open(sys.argv[1]))
moved = [d for d in report["drifts"] if d["cause"] != "no-change"]
print(
    f"drift: compared {report['compared']} server(s), {len(moved)} with movement, "
    f"{report['skipped_single_scan']} skipped (single scan), "
    f"{report['skipped_invalid']} unreadable"
)
for d in moved:
    print(f"  {d['server_slug']}  [{d['cause']}]  {d['summary']}")
PY
else
  rm -f "${DRIFT_OUT}.tmp"
  log "WARN: drift report failed (refresh continues)"
fi

# Rebuild the static site from the freshly-scanned DB (build_site.py self-verifies).
log "Rebuilding static site -> ${OUT}"
uv run python scripts/build_site.py --db "${DB}" --out "${OUT}" --base-url "${BASE_URL}"
cp deploy/vercel.json "${OUT}/vercel.json"

log "Refresh/build complete. Local output ready in ${OUT}; this lane cannot deploy."
