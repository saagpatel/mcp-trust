#!/usr/bin/env bash
# Remove the weekly catalog-refresh launchd job.
set -euo pipefail

LABEL="com.d.mcp-trust-refresh"
DEST="${HOME}/Library/LaunchAgents/${LABEL}.plist"

launchctl unload "${DEST}" 2>/dev/null || true
rm -f "${DEST}"
echo "Unloaded and removed ${DEST}"
echo "(Logs under ~/.local/share/log/${LABEL}.{out,err} are left in place.)"
