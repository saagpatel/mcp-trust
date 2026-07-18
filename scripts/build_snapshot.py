"""Bake the graded catalog into a static snapshot for the MCP server.

The published package serves trust grades over MCP without a database: this
script projects the live ``registry.db`` (the result of a real, sandboxed scan
run) into ``src/mcp_trust/catalog_snapshot.json``, which ships in the wheel and
is read read-only by ``mcp_trust.mcp_server``.

Regenerate after a scan run:
    MCP_TRUST_DB=./registry.db MCP_TRUST_VERIFIED_LOCAL_NETWORK=none \
        uv run python scripts/build_snapshot.py

Only real grades are baked: a server with no scan on record is skipped (the MCP
server never serves an invented letter grade). Dummy credential values never
appear here — the snapshot records env var NAMES only, exactly like the catalog.
"""

from __future__ import annotations

import json
import os
import sqlite3
from pathlib import Path

from mcp_trust.catalog.snapshot import build_snapshot
from mcp_trust.store.repository import ServerRepository

_OUT = Path(__file__).resolve().parents[1] / "src" / "mcp_trust" / "catalog_snapshot.json"


def main() -> None:
    db_path = os.environ.get("MCP_TRUST_DB", "./registry.db")
    verified_local_network = os.environ.get("MCP_TRUST_VERIFIED_LOCAL_NETWORK")
    if verified_local_network not in {None, "none"}:
        raise ValueError("MCP_TRUST_VERIFIED_LOCAL_NETWORK must be unset or exactly 'none'")
    masked_path = Path(os.environ.get("MCP_TRUST_MASKED_GRADES", "./masked-grades.json"))
    loaded_masked = json.loads(masked_path.read_text(encoding="utf-8"))
    if not isinstance(loaded_masked, list) or not all(
        isinstance(slug, str) for slug in loaded_masked
    ):
        raise ValueError("masked-grades must be a JSON list of slug strings")
    masked = frozenset(loaded_masked)
    db_uri = f"{Path(db_path).resolve().as_uri()}?mode=ro"
    with sqlite3.connect(db_uri, uri=True) as conn:
        conn.row_factory = sqlite3.Row
        catalog_slugs = {server.slug for server in ServerRepository(conn).list()}
    unknown_masked = sorted(masked - catalog_slugs)
    if unknown_masked:
        raise ValueError(
            "masked-grades contains unknown catalog slug(s): " + ",".join(unknown_masked)
        )
    snapshot = build_snapshot(
        db_path,
        masked_slugs=masked,
        verified_local_network=verified_local_network,
    )
    _OUT.write_text(json.dumps(snapshot, indent=2) + "\n", encoding="utf-8")
    print(f"wrote {snapshot['server_count']} servers -> {_OUT}")


if __name__ == "__main__":
    main()
