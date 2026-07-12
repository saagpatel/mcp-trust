#!/bin/bash
# Explicit, manual-only production deployment lane for the static catalog.
set -euo pipefail

APPROVED_BRANCH="main"
APPROVED_TARGET_URL="https://mcp-trust.vercel.app"
APPROVED_PROJECT_ID="prj_ugC28dxX9xAGYnYjIkQXigxZB672"
APPROVED_ORG_ID="team_nZORCFEbaw3I8iSUrA2cWMJB"
APPROVED_ORIGIN_URL="https://github.com/saagpatel/mcp-trust.git"
CONFIRMATION="DEPLOY_MCP_TRUST_PRODUCTION"
GIT_BIN="/usr/bin/git"

die() {
  printf 'ERROR: %s\n' "$*" >&2
  exit 1
}

EXPECTED_REPO=""
EXPECTED_COMMIT=""
TARGET_URL=""
PROJECT_ID=""
ORG_ID=""
APPROVAL=""
VERCEL_BIN=""
NODE_BIN=""
EXPECTED_OUTPUT_SHA256=""

while [ "$#" -gt 0 ]; do
  case "$1" in
    --expected-repo) EXPECTED_REPO="${2:-}"; shift 2 ;;
    --expected-commit) EXPECTED_COMMIT="${2:-}"; shift 2 ;;
    --target-url) TARGET_URL="${2:-}"; shift 2 ;;
    --project-id) PROJECT_ID="${2:-}"; shift 2 ;;
    --org-id) ORG_ID="${2:-}"; shift 2 ;;
    --approval) APPROVAL="${2:-}"; shift 2 ;;
    --vercel-bin) VERCEL_BIN="${2:-}"; shift 2 ;;
    --node-bin) NODE_BIN="${2:-}"; shift 2 ;;
    --expected-output-sha256) EXPECTED_OUTPUT_SHA256="${2:-}"; shift 2 ;;
    *) die "unknown or incomplete argument: $1" ;;
  esac
done

for value in EXPECTED_REPO EXPECTED_COMMIT TARGET_URL PROJECT_ID ORG_ID APPROVAL VERCEL_BIN NODE_BIN EXPECTED_OUTPUT_SHA256; do
  [ -n "${!value}" ] || die "missing required input: ${value}"
done

if [ -n "${LAUNCH_JOBKEY_LABEL:-}" ] || [ "${XPC_SERVICE_NAME:-0}" != "0" ] \
    || [ "${MCP_TRUST_SCHEDULER_CONTEXT:-0}" != "0" ]; then
  die "production deployment is forbidden from scheduler context"
fi
if [ "${MCP_TRUST_AUTO_DEPLOY+x}" = "x" ]; then
  die "MCP_TRUST_AUTO_DEPLOY is forbidden in the manual deployment lane"
fi
while IFS='=' read -r name _; do
  case "${name}" in
    VERCEL_TOKEN) ;;
    VERCEL_*|NOW_*) die "ambient Vercel binding variable is forbidden: ${name}" ;;
  esac
done < <(/usr/bin/env)
[ "${TARGET_URL}" = "${APPROVED_TARGET_URL}" ] || die "production target is not approved"
[ "${PROJECT_ID}" = "${APPROVED_PROJECT_ID}" ] || die "Vercel project is not the approved production project"
[ "${ORG_ID}" = "${APPROVED_ORG_ID}" ] || die "Vercel organization is not the approved production organization"
[ -f "${APPROVAL}" ] || die "approval file is missing"

SCRIPT_DIR="$(cd "$(/usr/bin/dirname "${BASH_SOURCE[0]}")" && pwd -P)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd -P)"
EXPECTED_REPO_REAL="$(cd "${EXPECTED_REPO}" 2>/dev/null && pwd -P)" \
  || die "expected repository root does not exist"
[ "${REPO_ROOT}" = "${EXPECTED_REPO_REAL}" ] || die "repository root does not match explicit expectation"
GIT_ROOT="$("${GIT_BIN}" -C "${REPO_ROOT}" rev-parse --show-toplevel 2>/dev/null)" \
  || die "repository is not a Git worktree"
[ "${GIT_ROOT}" = "${REPO_ROOT}" ] || die "Git repository root is unexpected"

BRANCH="$("${GIT_BIN}" -C "${REPO_ROOT}" symbolic-ref --quiet --short HEAD 2>/dev/null)" \
  || die "detached HEAD cannot deploy"
[ "${BRANCH}" = "${APPROVED_BRANCH}" ] || die "current branch is not the approved branch ${APPROVED_BRANCH}"

HEAD_SHA="$("${GIT_BIN}" -C "${REPO_ROOT}" rev-parse HEAD)"
[ "${HEAD_SHA}" = "${EXPECTED_COMMIT}" ] || die "HEAD does not match the expected commit"

if [ -n "$("${GIT_BIN}" -C "${REPO_ROOT}" status --porcelain --untracked-files=all)" ]; then
  die "worktree is not clean (tracked and untracked files must be absent)"
fi

UPSTREAM="$("${GIT_BIN}" -C "${REPO_ROOT}" rev-parse --abbrev-ref --symbolic-full-name '@{upstream}' 2>/dev/null)" \
  || die "approved branch has no upstream"
[ "${UPSTREAM}" = "origin/${APPROVED_BRANCH}" ] \
  || die "upstream must be origin/${APPROVED_BRANCH}, found ${UPSTREAM}"
ORIGIN_FETCH_URL="$("${GIT_BIN}" -C "${REPO_ROOT}" remote get-url origin 2>/dev/null)" \
  || die "origin fetch URL is unavailable"
ORIGIN_PUSH_URL="$("${GIT_BIN}" -C "${REPO_ROOT}" remote get-url --push origin 2>/dev/null)" \
  || die "origin push URL is unavailable"
[ "${ORIGIN_FETCH_URL}" = "${APPROVED_ORIGIN_URL}" ] \
  || die "origin fetch URL is not the approved repository"
[ "${ORIGIN_PUSH_URL}" = "${APPROVED_ORIGIN_URL}" ] \
  || die "origin push URL is not the approved repository"
read -r AHEAD BEHIND < <("${GIT_BIN}" -C "${REPO_ROOT}" rev-list --left-right --count "HEAD...${UPSTREAM}")
[ "${AHEAD}" = "0" ] && [ "${BEHIND}" = "0" ] \
  || die "ahead/behind ambiguity detected (${AHEAD}/${BEHIND})"
"${GIT_BIN}" -C "${REPO_ROOT}" merge-base --is-ancestor "${EXPECTED_COMMIT}" "${UPSTREAM}" \
  || die "expected commit is not contained in the approved upstream branch"

OUT="${REPO_ROOT}/site"
[ -d "${OUT}" ] && [ -f "${OUT}/vercel.json" ] \
  || die "approved static output is missing or incomplete"
[ "${VERCEL_BIN#/}" != "${VERCEL_BIN}" ] || die "Vercel executable path must be absolute"
[ -x "${VERCEL_BIN}" ] || die "approved Vercel executable is not executable"
[ "${NODE_BIN#/}" != "${NODE_BIN}" ] || die "Node executable path must be absolute"
[ -x "${NODE_BIN}" ] || die "approved Node executable is not executable"

/usr/bin/python3 -I "${SCRIPT_DIR}/validate_deploy_authorization.py" \
  --approval "${APPROVAL}" \
  --repository "${REPO_ROOT}" \
  --branch "${BRANCH}" \
  --commit "${EXPECTED_COMMIT}" \
  --target-url "${TARGET_URL}" \
  --project-id "${PROJECT_ID}" \
  --org-id "${ORG_ID}" \
  --vercel-bin "${VERCEL_BIN}" \
  --node-bin "${NODE_BIN}" \
  --output "${OUT}" \
  --output-sha256 "${EXPECTED_OUTPUT_SHA256}" \
  || die "deployment approval validation failed"

# A live terminal confirmation is required after the exact approval validates;
# automation cannot inherit or pre-populate it through arguments or environment.
[ -t 0 ] && [ -t 1 ] || die "manual interactive TTY confirmation is required"
printf 'Type %s to authorize this production deployment: ' "${CONFIRMATION}"
IFS= read -r TYPED_CONFIRMATION
[ "${TYPED_CONFIRMATION}" = "${CONFIRMATION}" ] \
  || die "deliberate production confirmation is invalid"

# Revalidate mutable ignored output, provider link, approval, and tool bytes
# after the human confirmation to close the approval-to-deploy timing gap.
/usr/bin/python3 -I "${SCRIPT_DIR}/validate_deploy_authorization.py" \
  --approval "${APPROVAL}" \
  --repository "${REPO_ROOT}" \
  --branch "${BRANCH}" \
  --commit "${EXPECTED_COMMIT}" \
  --target-url "${TARGET_URL}" \
  --project-id "${PROJECT_ID}" \
  --org-id "${ORG_ID}" \
  --vercel-bin "${VERCEL_BIN}" \
  --node-bin "${NODE_BIN}" \
  --output "${OUT}" \
  --output-sha256 "${EXPECTED_OUTPUT_SHA256}" \
  || die "deployment approval changed after confirmation"

# Provider authority is checked only after every repository and approval gate.
[ -n "${VERCEL_TOKEN:-}" ] || die "VERCEL_TOKEN is required after local authorization passes"

printf 'Authorization complete for %s at %s -> %s\n' "${BRANCH}" "${EXPECTED_COMMIT}" "${TARGET_URL}"
umask 077
RUNTIME_ROOT="$(/usr/bin/mktemp -d /tmp/mcp-trust-vercel.XXXXXX)" \
  || die "failed to create isolated Vercel runtime root"
cleanup_runtime() {
  case "${RUNTIME_ROOT}" in
    /tmp/mcp-trust-vercel.*) /bin/rm -rf -- "${RUNTIME_ROOT}" ;;
    *) die "refusing to clean unexpected runtime root" ;;
  esac
}
trap cleanup_runtime EXIT HUP INT TERM
/bin/mkdir -p "${RUNTIME_ROOT}/home" "${RUNTIME_ROOT}/config" "${RUNTIME_ROOT}/data" \
  "${RUNTIME_ROOT}/cache" "${RUNTIME_ROOT}/tmp"

cd "${OUT}"
/usr/bin/env -i \
  HOME="${RUNTIME_ROOT}/home" \
  XDG_CONFIG_HOME="${RUNTIME_ROOT}/config" \
  XDG_DATA_HOME="${RUNTIME_ROOT}/data" \
  XDG_CACHE_HOME="${RUNTIME_ROOT}/cache" \
  TMPDIR="${RUNTIME_ROOT}/tmp" \
  PATH="/usr/bin:/bin" \
  VERCEL_TOKEN="${VERCEL_TOKEN}" \
  VERCEL_PROJECT_ID="${PROJECT_ID}" \
  VERCEL_ORG_ID="${ORG_ID}" \
  "${NODE_BIN}" "${VERCEL_BIN}" deploy . --yes \
  --cwd "${OUT}" --project "${PROJECT_ID}" --scope "${ORG_ID}" --target production
