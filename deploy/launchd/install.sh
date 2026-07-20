#!/usr/bin/env bash
# Install the weekly catalog-refresh launchd definition for the current user.
# The label is booted out and persistently disabled; this installer never enables
# or starts the job.
#
# Bakes machine-specific values into a copy of the template plist:
#   - __REPO_ROOT__  -> this repo's absolute path
#   - __LOG_OUT/ERR__ -> ~/.local/share/log/<label>.{out,err}
#   - __PATH__       -> a fixed, repository-owned executable search path. The
#                       installed definition never inherits session-scoped or
#                       caller-controlled PATH entries.
#
# Run from an interactive shell:
#   /bin/bash deploy/launchd/install.sh
set -euo pipefail

INSTALLER_PATH="/usr/bin:/bin:/usr/sbin:/sbin"
REFRESH_PATH="/opt/homebrew/bin:/usr/local/bin:/usr/bin:/bin:/usr/sbin:/sbin"
export PATH="${INSTALLER_PATH}"

LABEL="com.d.mcp-trust-refresh"
HERE="$(cd "$(/usr/bin/dirname "${BASH_SOURCE[0]}")" && /bin/pwd)"
REPO_ROOT="$(cd "${HERE}/../.." && /bin/pwd)"
LOG_DIR="${HOME}/.local/share/log"
DEST="${HOME}/Library/LaunchAgents/${LABEL}.plist"
LAUNCHCTL_BIN="${MCP_TRUST_LAUNCHCTL_BIN:-/bin/launchctl}"
DOMAIN="gui/$(/usr/bin/id -u)"

if [ ! -x "${LAUNCHCTL_BIN}" ]; then
  echo "ERROR: launchctl unavailable at ${LAUNCHCTL_BIN}." >&2
  exit 1
fi

/bin/mkdir -p "${LOG_DIR}" "$(/usr/bin/dirname "${DEST}")"

# '#' delimiter avoids clashing with the slashes in paths/PATH.
/usr/bin/sed \
  -e "s#__REPO_ROOT__#${REPO_ROOT}#g" \
  -e "s#__LOG_OUT__#${LOG_DIR}/${LABEL}.out#g" \
  -e "s#__LOG_ERR__#${LOG_DIR}/${LABEL}.err#g" \
  -e "s#__PATH__#${REFRESH_PATH}#g" \
  "${HERE}/${LABEL}.plist" > "${DEST}"

# Validate the generated plist before loading.
if [ -x /usr/bin/plutil ]; then
  /usr/bin/plutil -lint "${DEST}" >/dev/null
fi

"${LAUNCHCTL_BIN}" bootout "${DOMAIN}/${LABEL}" 2>/dev/null || true
"${LAUNCHCTL_BIN}" disable "${DOMAIN}/${LABEL}"
if "${LAUNCHCTL_BIN}" print "${DOMAIN}/${LABEL}" >/dev/null 2>&1; then
  echo "ERROR: ${LABEL} remains loaded after bootout." >&2
  exit 1
fi
if ! "${LAUNCHCTL_BIN}" print-disabled "${DOMAIN}" \
    | /usr/bin/grep -Fq "\"${LABEL}\" => disabled"; then
  echo "ERROR: ${LABEL} is not persistently disabled." >&2
  exit 1
fi

echo "Installed ${DEST}"
echo "Defined schedule: weekly, Monday 09:00 (local)."
echo "State: verified unloaded and persistently disabled."
echo "Verify: ${LAUNCHCTL_BIN} print-disabled ${DOMAIN}"
echo "Logs:     tail -F ${LOG_DIR}/${LABEL}.out ${LOG_DIR}/${LABEL}.err"
echo
echo "Production deployment is forbidden from launchd."
echo "Do not enable this label until Docker refresh prerequisites and an explicit"
echo "operator re-enable decision have been verified."
