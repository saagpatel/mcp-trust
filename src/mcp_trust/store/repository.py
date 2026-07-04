"""Repository layer — typed access to the servers and scans tables."""

from __future__ import annotations

import json
import logging
import sqlite3

from pydantic import ValidationError

from mcp_trust.core.models import ScanRecord, Server, ServerSource

_log = logging.getLogger(__name__)


class ServerRepository:
    """Typed CRUD over the ``servers`` table."""

    def __init__(self, conn: sqlite3.Connection) -> None:
        self._conn = conn

    def upsert(self, server: Server) -> None:
        """Insert or replace a server row."""
        self._conn.execute(
            """
            INSERT INTO servers (slug, name, description, source_json, homepage, added_at)
            VALUES (?, ?, ?, ?, ?, ?)
            ON CONFLICT(slug) DO UPDATE SET
                name        = excluded.name,
                description = excluded.description,
                source_json = excluded.source_json,
                homepage    = excluded.homepage,
                added_at    = excluded.added_at
            """,
            (
                server.slug,
                server.name,
                server.description,
                server.source.model_dump_json(),
                server.homepage,
                server.added_at.isoformat(),
            ),
        )
        self._conn.commit()

    def get(self, slug: str) -> Server | None:
        """Return the server with *slug*, or ``None`` if not found or corrupt."""
        row = self._conn.execute("SELECT * FROM servers WHERE slug = ?", (slug,)).fetchone()
        if row is None:
            return None
        return self._row_to_server(row)

    def list(self) -> list[Server]:
        """Return all valid servers, ordered by slug.

        A row that fails model validation (corrupt JSON or an out-of-band write
        that bypassed the model's slug guard) is skipped rather than crashing the
        whole read, so one bad row can never poison the catalog or a site build.
        """
        rows = self._conn.execute("SELECT * FROM servers ORDER BY slug").fetchall()
        servers = [self._row_to_server(r) for r in rows]
        return [s for s in servers if s is not None]

    @staticmethod
    def _row_to_server(row: sqlite3.Row) -> Server | None:
        try:
            source = ServerSource.model_validate(json.loads(row["source_json"]))
            return Server(
                slug=row["slug"],
                name=row["name"],
                description=row["description"] or "",
                source=source,
                homepage=row["homepage"],
                added_at=row["added_at"],
            )
        except (json.JSONDecodeError, ValidationError) as exc:
            # Corrupt or schema-drifted/hostile row — drop it and surface the slug
            # rather than letting an opaque error abort the entire read.
            _log.warning("skipping invalid server row %r: %s", row["slug"], exc)
            return None


class ScanRepository:
    """Typed access to the ``scans`` table."""

    def __init__(self, conn: sqlite3.Connection) -> None:
        self._conn = conn

    def record(self, scan: ScanRecord) -> None:
        """Persist a scan record."""
        self._conn.execute(
            """
            INSERT INTO scans
                (id, server_slug, engine_name, engine_version, grade, transparency,
                 risk_json, findings_json, evidence_json, scanned_at, sandbox_image,
                 report_ref)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                scan.id,
                scan.server_slug,
                scan.engine_name,
                scan.engine_version,
                scan.grade,
                scan.transparency,
                scan.risk.model_dump_json(),
                json.dumps([f.model_dump(mode="json") for f in scan.findings]),
                scan.evidence.model_dump_json() if scan.evidence is not None else None,
                scan.scanned_at.isoformat(),
                scan.sandbox_image,
                scan.report_ref,
            ),
        )
        self._conn.commit()

    def latest(self, slug: str) -> ScanRecord | None:
        """Return the most recent scan for *slug*, or ``None``."""
        row = self._conn.execute(
            """
            SELECT * FROM scans
            WHERE server_slug = ?
            ORDER BY scanned_at DESC
            LIMIT 1
            """,
            (slug,),
        ).fetchone()
        if row is None:
            return None
        return self._row_to_scan(row)

    def latest_all(self) -> dict[str, ScanRecord]:
        """Return a slug → latest ``ScanRecord`` mapping for all servers."""
        rows = self._conn.execute(
            """
            SELECT s.*
            FROM scans s
            INNER JOIN (
                SELECT server_slug, MAX(scanned_at) AS max_at
                FROM scans
                GROUP BY server_slug
            ) latest ON s.server_slug = latest.server_slug
                     AND s.scanned_at = latest.max_at
            ORDER BY s.id ASC
            """
        ).fetchall()
        return {row["server_slug"]: self._row_to_scan(row) for row in rows}

    @staticmethod
    def _row_to_scan(row: sqlite3.Row) -> ScanRecord:
        from pydantic import ValidationError  # noqa: PLC0415

        from mcp_trust.core.models import (  # noqa: PLC0415
            Finding,
            RiskSummary,
            ScanEvidence,
            TransparencyLevel,
            TrustGrade,
        )

        try:
            risk = RiskSummary.model_validate(json.loads(row["risk_json"]))
            findings_raw = json.loads(row["findings_json"])
            findings = [Finding.model_validate(f) for f in findings_raw]
        except (json.JSONDecodeError, ValidationError) as exc:
            # Corrupt or schema-drifted row — surface the offending id rather
            # than letting an opaque error bubble up as a 500.
            raise ValueError(f"Corrupt scan record {row['id']!r}: {exc}") from exc
        # transparency column is back-compat (older rows default to 'high').
        keys = row.keys()
        transparency = (
            TransparencyLevel(row["transparency"])
            if "transparency" in keys and row["transparency"]
            else TransparencyLevel.HIGH
        )
        evidence = None
        if "evidence_json" in keys and row["evidence_json"]:
            try:
                evidence = ScanEvidence.model_validate(json.loads(row["evidence_json"]))
            except (json.JSONDecodeError, ValidationError) as exc:
                raise ValueError(f"Corrupt scan evidence {row['id']!r}: {exc}") from exc
        # sandbox_image column is back-compat (older rows predate it → None).
        sandbox_image = row["sandbox_image"] if "sandbox_image" in keys else None
        return ScanRecord(
            id=row["id"],
            server_slug=row["server_slug"],
            engine_name=row["engine_name"],
            engine_version=row["engine_version"],
            grade=TrustGrade(row["grade"]),
            transparency=transparency,
            risk=risk,
            findings=findings,
            evidence=evidence,
            scanned_at=row["scanned_at"],
            sandbox_image=sandbox_image,
            report_ref=row["report_ref"],
        )
