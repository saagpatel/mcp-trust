#!/usr/bin/env bash
set -euo pipefail

DATA_DIR="${MCP_TRUST_DATA_DIR:-/data/mcp-trust}"
DB_PATH="${MCP_TRUST_DB:-$DATA_DIR/registry.db}"
RECEIPTS_DIR="${MCP_TRUST_RECEIPTS_DIR:-$DATA_DIR/receipts}"
BACKUP_DIR="${MCP_TRUST_BACKUP_DIR:-$DATA_DIR/backups}"
STAMP="$(date -u +%Y%m%dT%H%M%SZ)"

mkdir -p "$BACKUP_DIR"

if [[ ! -f "$DB_PATH" ]]; then
  echo "missing SQLite DB: $DB_PATH" >&2
  exit 1
fi

DB_BACKUP="$BACKUP_DIR/registry-$STAMP.db"
sqlite3 "$DB_PATH" ".backup '$DB_BACKUP'"

if [[ -d "$RECEIPTS_DIR" ]]; then
  tar -C "$RECEIPTS_DIR" -czf "$BACKUP_DIR/receipts-$STAMP.tar.gz" .
else
  echo "receipts directory not found: $RECEIPTS_DIR" >&2
fi

find "$BACKUP_DIR" -type f -name 'registry-*.db' -mtime +30 -delete
find "$BACKUP_DIR" -type f -name 'receipts-*.tar.gz' -mtime +30 -delete

echo "wrote $DB_BACKUP"
