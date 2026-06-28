#!/usr/bin/env bash
# Freshness loop for the static MCP Trust catalog:
#   re-scan the reference corpus (network-off Docker sandbox) -> rebuild the
#   static site -> (opt-in) deploy to Vercel.
#
# Designed to run from launchd/cron OR by hand. Re-scanning surfaces grade
# changes over time; to catch UPSTREAM server drift / rug-pull, periodically
# rebuild Dockerfile.scan with current versions (the scan image is pinned). The
# scan runtime is network-off inside Docker; only the rendered site/ is published.
#
# Deploy is OPT-IN: set MCP_TRUST_AUTO_DEPLOY=1 to publish. Off by default so a
# scheduled refresh never pushes to production without the operator opting in.
#
# Config (env, with safe defaults):
#   MCP_TRUST_DB                 registry SQLite path        (default ./registry.db)
#   MCP_TRUST_SITE_OUT           static output dir           (default ./site)
#   MCP_TRUST_SITE_BASE_URL      deploy URL for badge embeds (default placeholder)
#   MCP_TRUST_SANDBOX_IMAGE      prebuilt scan image         (default reference image)
#   MCP_TRUST_RECEIPTS_DIR       receipt archive dir         (default ./receipts)
#   MCP_TRUST_AUTO_DEPLOY        "1" to run `vercel deploy`  (default off)
set -euo pipefail

# Resolve repo root from this script's location so launchd's bare cwd is fine.
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"
cd "${REPO_ROOT}"

DB="${MCP_TRUST_DB:-./registry.db}"
OUT="${MCP_TRUST_SITE_OUT:-./site}"
BASE_URL="${MCP_TRUST_SITE_BASE_URL:-https://mcp-trust.example}"
IMAGE="${MCP_TRUST_SANDBOX_IMAGE:-mcp-trust-scan:reference-2026-06-19}"
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

# Rebuild the static site from the freshly-scanned DB (build_site.py self-verifies).
log "Rebuilding static site -> ${OUT}"
uv run python scripts/build_site.py --db "${DB}" --out "${OUT}" --base-url "${BASE_URL}"
cp deploy/vercel.json "${OUT}/vercel.json"

# Publish only when explicitly opted in.
if [ "${MCP_TRUST_AUTO_DEPLOY:-0}" = "1" ]; then
  log "MCP_TRUST_AUTO_DEPLOY=1 -> deploying ${OUT} to Vercel production"
  vercel deploy "${OUT}" --prod --yes
  log "Deploy complete."
else
  log "Refresh complete. Deploy is opt-in (set MCP_TRUST_AUTO_DEPLOY=1). Output ready in ${OUT}."
fi
