#!/usr/bin/env bash
# Compatibility entrypoint for the manual refresh lane.
#
# Despite the historical filename, this command creates only an immutable local
# review candidate. It cannot publish, deploy, mutate the canonical registry DB,
# or retain an old grade while claiming a fully fresh run. Publication requires
# the separate refresh_candidate.py approve + publish commands.
set -euo pipefail

if [ -n "${LAUNCH_JOBKEY_LABEL:-}" ] || [ "${XPC_SERVICE_NAME:-0}" != "0" ] \
    || [ "${MCP_TRUST_SCHEDULER_CONTEXT:-0}" != "0" ]; then
  printf '%s\n' \
    "ERROR: review-candidate refresh is forbidden from scheduler context." >&2
  exit 1
fi

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
PYTHON_BIN="${REPO_ROOT}/.venv/bin/python"
ENGINE_MATERIALIZATION_RECEIPT="${MCP_TRUST_ENGINE_MATERIALIZATION_RECEIPT:-./dist/grade-refresh/engine-materialization.json}"
HOST_CAPACITY_RECEIPT="${MCP_TRUST_HOST_CAPACITY_RECEIPT:-./dist/grade-refresh/host-capacity.json}"

if [ ! -x "${PYTHON_BIN}" ]; then
  printf '%s\n' \
    "ERROR: frozen engine environment is absent; prepare .venv in a separately approved dependency lane." >&2
  exit 1
fi

if [ ! -f "${ENGINE_MATERIALIZATION_RECEIPT}" ]; then
  printf '%s\n' \
    "ERROR: current engine-materialization receipt is absent; create and review it separately." >&2
  exit 1
fi

if [ ! -f "${HOST_CAPACITY_RECEIPT}" ]; then
  printf '%s\n' \
    "ERROR: pre-start host-capacity receipt is absent; create and review it before Colima start." >&2
  exit 1
fi

# Stop before any catalog process is launched unless the exact source,
# toolchain, local Docker authority, sandbox controls, and all five catalog
# image bytes are bound. The receipt remains local and review-only.
"${PYTHON_BIN}" scripts/grade_refresh.py preflight \
  --repo-root "${REPO_ROOT}" \
  --seed "./src/mcp_trust/catalog/seed_servers.json" \
  --masked-grades "./masked-grades.json" \
  --policy "./src/mcp_trust/catalog/refresh_policy.json" \
  --engine-materialization "${ENGINE_MATERIALIZATION_RECEIPT}" \
  --host-capacity "${HOST_CAPACITY_RECEIPT}" \
  --out "${PREFLIGHT}"

exec "${PYTHON_BIN}" scripts/refresh_candidate.py create \
  --db "${DB}" \
  --seed "./src/mcp_trust/catalog/seed_servers.json" \
  --masked-grades "./masked-grades.json" \
  --out-dir "${CANDIDATES}" \
  --sandbox-image "${IMAGE}" \
  --qualification-receipt "${PREFLIGHT}"
