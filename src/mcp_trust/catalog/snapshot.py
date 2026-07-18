"""Honest static projection of real, current registry scan records."""

from __future__ import annotations

import sqlite3
from datetime import UTC, datetime

from mcp_trust.core import grading
from mcp_trust.core.drift import latest_grade_change
from mcp_trust.core.provenance import is_real_engine
from mcp_trust.store.repository import ScanRepository, ServerRepository

_DIMS = ("file_access", "network_access", "shell_execution", "destructive", "exfiltration")


def build_snapshot(
    db_path: str,
    *,
    excluded_slugs: frozenset[str] = frozenset(),
    masked_slugs: frozenset[str] = frozenset(),
    now: datetime | None = None,
) -> dict[str, object]:
    """Build the public-safe snapshot without stale fallback or masked grades.

    ``excluded_slugs`` is the refresh-candidate failure boundary: a server whose
    current scan failed or lacked evidence is omitted instead of silently
    retaining its previous letter grade. Operator-masked slugs are likewise
    withheld from this grade-bearing projection.
    """
    fixed_now = now or datetime.now(tz=UTC)
    if fixed_now.tzinfo is None:
        fixed_now = fixed_now.replace(tzinfo=UTC)

    conn = sqlite3.connect(db_path)
    conn.row_factory = sqlite3.Row
    try:
        server_repo = ServerRepository(conn)
        scan_repo = ScanRepository(conn)
        latest = scan_repo.latest_all()

        servers: list[dict[str, object]] = []
        newest = ""
        for server in sorted(server_repo.list(), key=lambda item: item.slug):
            if server.slug in excluded_slugs or server.slug in masked_slugs:
                continue
            scan = latest.get(server.slug)
            if scan is None or not is_real_engine(scan.engine_name):
                continue
            risk = scan.risk
            history = scan_repo.history(server.slug)
            grade_change = (
                latest_grade_change(history)
                if all(is_real_engine(item.engine_name) for item in history)
                else None
            )
            scanned_at = scan.scanned_at
            if scanned_at.tzinfo is None:
                scanned_at = scanned_at.replace(tzinfo=UTC)
            scan_age_days = max(
                0.0,
                (fixed_now.astimezone(UTC) - scanned_at.astimezone(UTC)).total_seconds()
                / 86400,
            )
            scanned_at_text = scan.scanned_at.isoformat()
            newest = max(newest, scanned_at_text)
            servers.append(
                {
                    "slug": server.slug,
                    "name": server.name,
                    "description": server.description,
                    "homepage": server.homepage,
                    "grade": str(scan.grade),
                    "transparency": str(scan.transparency),
                    "danger_score": round(grading.danger_score(risk), 2),
                    "dimensions": {
                        dimension: round(getattr(risk, dimension), 2)
                        for dimension in _DIMS
                    },
                    "annotation_coverage": round(risk.annotation_coverage, 2),
                    "findings": [
                        {
                            "rule_id": finding.rule_id,
                            "title": finding.title,
                            "severity": str(finding.severity),
                            "category": finding.category,
                        }
                        for finding in scan.findings
                    ],
                    "evidence": (
                        scan.evidence.model_dump(mode="json") if scan.evidence else None
                    ),
                    "source": {
                        "kind": str(server.source.kind),
                        "reference": server.source.reference,
                        "env_keys": list(server.source.env_keys),
                    },
                    "engine": scan.engine_name,
                    "engine_version": scan.engine_version,
                    "scanned_at": scanned_at_text,
                    "scan_age_days": round(scan_age_days, 6),
                    "grade_change": (
                        grade_change.model_dump(mode="json") if grade_change else None
                    ),
                    "requires_credentials": bool(server.source.env_keys),
                }
            )

        return {
            "schema_version": 2,
            "generated_at": fixed_now.isoformat(),
            "generated_from_scan_at": newest,
            "server_count": len(servers),
            "servers": servers,
        }
    finally:
        conn.close()
