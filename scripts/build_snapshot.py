"""Bake the graded catalog into a static snapshot for the MCP server.

The published package serves trust grades over MCP without a database: this
script projects the live ``registry.db`` (the result of a real, sandboxed scan
run) into ``src/mcp_trust/catalog_snapshot.json``, which ships in the wheel and
is read read-only by ``mcp_trust.mcp_server``.

Regenerate after a scan run:
    MCP_TRUST_DB=./registry.db uv run python scripts/build_snapshot.py

Only real grades are baked: a server with no scan on record is skipped (the MCP
server never serves an invented letter grade). Dummy credential values never
appear here — the snapshot records env var NAMES only, exactly like the catalog.
"""

from __future__ import annotations

import json
import os
import sqlite3
from pathlib import Path

from mcp_trust.core import grading
from mcp_trust.core.drift import latest_grade_change
from mcp_trust.core.provenance import is_real_engine
from mcp_trust.store.repository import ScanRepository, ServerRepository

_OUT = Path(__file__).resolve().parents[1] / "src" / "mcp_trust" / "catalog_snapshot.json"
_DIMS = ("file_access", "network_access", "shell_execution", "destructive", "exfiltration")


def build_snapshot(db_path: str) -> dict[str, object]:
    conn = sqlite3.connect(db_path)
    conn.row_factory = sqlite3.Row
    server_repo = ServerRepository(conn)
    scan_repo = ScanRepository(conn)
    latest = scan_repo.latest_all()

    servers: list[dict[str, object]] = []
    newest = ""
    for server in sorted(server_repo.list(), key=lambda s: s.slug):
        scan = latest.get(server.slug)
        # Provenance boundary (core.provenance): bake ONLY real scans. A missing
        # scan, the deterministic stub engine, or any unrecognised engine must
        # never be served as a real public letter grade.
        if scan is None or not is_real_engine(scan.engine_name):
            continue
        risk = scan.risk
        # A public grade-change claim needs two real scans. A synthetic prior
        # scan must never be relabeled as a real historical grade.
        history = scan_repo.history(server.slug)
        grade_change = (
            latest_grade_change(history)
            if all(is_real_engine(item.engine_name) for item in history)
            else None
        )
        scanned_at = scan.scanned_at.isoformat()
        newest = max(newest, scanned_at)
        servers.append(
            {
                "slug": server.slug,
                "name": server.name,
                "description": server.description,
                "homepage": server.homepage,
                "grade": str(scan.grade),
                "transparency": str(scan.transparency),
                "danger_score": round(grading.danger_score(risk), 2),
                "dimensions": {d: round(getattr(risk, d), 2) for d in _DIMS},
                "annotation_coverage": round(risk.annotation_coverage, 2),
                "findings": [
                    {
                        "rule_id": f.rule_id,
                        "title": f.title,
                        "severity": str(f.severity),
                        "category": f.category,
                    }
                    for f in scan.findings
                ],
                "evidence": scan.evidence.model_dump(mode="json") if scan.evidence else None,
                "source": {
                    "kind": str(server.source.kind),
                    "reference": server.source.reference,
                    "env_keys": list(server.source.env_keys),
                },
                "engine": scan.engine_name,
                "engine_version": scan.engine_version,
                "grade_change": grade_change.model_dump(mode="json") if grade_change else None,
                # Declares required secret env vars (used to call its API). The
                # scan enumerates the tool surface network-off; servers that need
                # the credential present at startup are scanned with non-functional
                # dummy values (see the methodology tool).
                "requires_credentials": bool(server.source.env_keys),
            }
        )

    return {
        "schema_version": 2,
        "generated_from_scan_at": newest,
        "server_count": len(servers),
        "servers": servers,
    }


def main() -> None:
    db_path = os.environ.get("MCP_TRUST_DB", "./registry.db")
    snapshot = build_snapshot(db_path)
    _OUT.write_text(json.dumps(snapshot, indent=2) + "\n", encoding="utf-8")
    print(f"wrote {snapshot['server_count']} servers -> {_OUT}")


if __name__ == "__main__":
    main()
