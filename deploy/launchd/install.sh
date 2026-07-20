#!/usr/bin/env bash
# Install the weekly catalog-refresh launchd definition for the current user.
# The label is booted out and persistently disabled; this installer never enables
# or starts the job.
#
# Bakes machine-specific values into a copy of the template plist:
#   - __REPO_ROOT__  -> this repo's absolute path
#   - __LOG_OUT/ERR__ -> ~/.local/share/log/<label>.{out,err}
#   - __PATH__       -> your current stable PATH entries, so launchd (which has a
#                       minimal PATH) can find uv (mise) and docker (colima) after
#                       a future, separately approved enablement. Session-scoped
#                       Codex runtime entries are excluded from the installed
#                       definition.
#
# Run from your interactive shell so $PATH includes uv + docker:
#   bash deploy/launchd/install.sh
set -euo pipefail

LABEL="com.d.mcp-trust-refresh"
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${HERE}/../.." && pwd)"
LOG_DIR="${HOME}/.local/share/log"
DEST="${HOME}/Library/LaunchAgents/${LABEL}.plist"
LAUNCHCTL_BIN="${MCP_TRUST_LAUNCHCTL_BIN:-/bin/launchctl}"
DOMAIN="gui/$(id -u)"

if [ ! -x "${LAUNCHCTL_BIN}" ]; then
  echo "ERROR: launchctl unavailable at ${LAUNCHCTL_BIN}." >&2
  exit 1
fi

STABLE_PATH=""
IFS=':' read -r -a PATH_ENTRIES <<< "${PATH}"
for entry in "${PATH_ENTRIES[@]}"; do
  case "${entry}" in
    "" \
      | "${HOME}/.codex/tmp/arg0/"* \
      | "${HOME}/.cache/codex-runtimes/"* \
      | /var/run/com.apple.security.cryptexd/codex.system/*)
      continue
      ;;
  esac
  if [[ "${entry}" == *'#'* || "${entry}" == *'&'* || "${entry}" == *'<'* \
    || "${entry}" == *'>'* || "${entry}" == *\\* ]]; then
    echo "ERROR: PATH contains an entry that cannot be safely embedded in a plist." >&2
    exit 1
  fi
  if [ -z "${STABLE_PATH}" ]; then
    STABLE_PATH="${entry}"
  else
    STABLE_PATH="${STABLE_PATH}:${entry}"
  fi
done
if [ -z "${STABLE_PATH}" ]; then
  echo "ERROR: PATH has no stable entries for the refresh definition." >&2
  exit 1
fi

mkdir -p "${LOG_DIR}" "$(dirname "${DEST}")"

# '#' delimiter avoids clashing with the slashes in paths/PATH.
sed \
  -e "s#__REPO_ROOT__#${REPO_ROOT}#g" \
  -e "s#__LOG_OUT__#${LOG_DIR}/${LABEL}.out#g" \
  -e "s#__LOG_ERR__#${LOG_DIR}/${LABEL}.err#g" \
  -e "s#__PATH__#${STABLE_PATH}#g" \
  "${HERE}/${LABEL}.plist" > "${DEST}"

# Validate the generated plist before loading.
if command -v plutil >/dev/null 2>&1; then
  plutil -lint "${DEST}" >/dev/null
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
