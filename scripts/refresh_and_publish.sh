#!/usr/bin/env bash
# Compatibility entrypoint for the manual refresh lane.
#
# Despite the historical filename, this command creates only an immutable local
# review candidate. It cannot publish, deploy, mutate the canonical registry DB,
# or retain an old grade while claiming a fully fresh run. Publication requires
# the separate refresh_candidate.py approve + publish commands.
set -euo pipefail

if [ "${MCP_TRUST_AUTO_DEPLOY+x}" = "x" ]; then
  printf '%s\n' \
    "ERROR: MCP_TRUST_AUTO_DEPLOY no longer authorizes deployment; refresh creates a review candidate only." >&2
  exit 1
fi

unset VERCEL_TOKEN VERCEL_ORG_ID VERCEL_PROJECT_ID VERCEL_SCOPE

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"
cd "${REPO_ROOT}"

DB="${MCP_TRUST_DB:-./registry.db}"
IMAGE="${MCP_TRUST_SANDBOX_IMAGE:-mcp-trust-scan:corpus-2026-07-03}"
CANDIDATES="${MCP_TRUST_CANDIDATES_DIR:-./dist/refresh-candidates}"
RUN_ID="$(date -u +%Y%m%dT%H%M%SZ)"
PREFLIGHT="${CANDIDATES}/preflight-${RUN_ID}.json"

# Stop before any catalog process is launched unless the exact source,
# toolchain, local Docker authority, sandbox controls, and all four catalog
# image bytes are bound. The receipt remains local and review-only.
uv run --frozen --extra engine python scripts/grade_refresh.py preflight \
  --repo-root "${REPO_ROOT}" \
  --seed "./src/mcp_trust/catalog/seed_servers.json" \
  --masked-grades "./masked-grades.json" \
  --policy "./src/mcp_trust/catalog/refresh_policy.json" \
  --out "${PREFLIGHT}"

exec uv run --frozen --extra engine python scripts/refresh_candidate.py create \
  --db "${DB}" \
  --seed "./src/mcp_trust/catalog/seed_servers.json" \
  --masked-grades "./masked-grades.json" \
  --out-dir "${CANDIDATES}" \
  --sandbox-image "${IMAGE}" \
  --qualification-receipt "${PREFLIGHT}"
