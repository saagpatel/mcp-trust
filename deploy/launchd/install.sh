#!/usr/bin/env bash
# Install the weekly catalog-refresh launchd job for the current user.
#
# Bakes machine-specific values into a copy of the template plist:
#   - __REPO_ROOT__  -> this repo's absolute path
#   - __LOG_OUT/ERR__ -> ~/.local/share/log/<label>.{out,err}
#   - __PATH__       -> your CURRENT $PATH, so launchd (which has a minimal PATH)
#                       can find uv (mise) and docker (colima).
#
# Run from your interactive shell so $PATH includes uv + docker:
#   bash deploy/launchd/install.sh
set -euo pipefail

LABEL="com.d.mcp-trust-refresh"
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${HERE}/../.." && pwd)"
LOG_DIR="${HOME}/.local/share/log"
DEST="${HOME}/Library/LaunchAgents/${LABEL}.plist"

if ! command -v uv >/dev/null 2>&1; then
  echo "ERROR: uv not on PATH. Run from a shell where 'uv' resolves." >&2
  exit 1
fi
if ! command -v docker >/dev/null 2>&1; then
  echo "ERROR: docker not on PATH. Start Colima/Docker and retry." >&2
  exit 1
fi

mkdir -p "${LOG_DIR}" "$(dirname "${DEST}")"

# '#' delimiter avoids clashing with the slashes in paths/PATH.
sed \
  -e "s#__REPO_ROOT__#${REPO_ROOT}#g" \
  -e "s#__LOG_OUT__#${LOG_DIR}/${LABEL}.out#g" \
  -e "s#__LOG_ERR__#${LOG_DIR}/${LABEL}.err#g" \
  -e "s#__PATH__#${PATH}#g" \
  "${HERE}/${LABEL}.plist" > "${DEST}"

# Validate the generated plist before loading.
if command -v plutil >/dev/null 2>&1; then
  plutil -lint "${DEST}" >/dev/null
fi

launchctl unload "${DEST}" 2>/dev/null || true
launchctl load "${DEST}"

echo "Installed ${DEST}"
echo "Schedule: weekly, Monday 09:00 (local)."
echo "Verify:   launchctl list | grep ${LABEL}"
echo "Logs:     tail -F ${LOG_DIR}/${LABEL}.out ${LOG_DIR}/${LABEL}.err"
echo "Run now:  launchctl start ${LABEL}"
echo
echo "Deploy is OFF by default. To auto-publish, edit ${DEST}:"
echo "  - add EnvironmentVariables key MCP_TRUST_AUTO_DEPLOY = 1"
echo "  - keep MCP_TRUST_SITE_BASE_URL at https://mcp-trust.vercel.app unless changing domains"
echo "  then: bash deploy/launchd/uninstall.sh && bash deploy/launchd/install.sh"
