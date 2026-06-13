"""Repository layer — typed access to the servers and scans tables."""

from __future__ import annotations

import json
import sqlite3

from mcp_trust.core.models import ScanRecord, Server, ServerSource


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
        """Return the server with *slug*, or ``None`` if not found."""
        row = self._conn.execute("SELECT * FROM servers WHERE slug = ?", (slug,)).fetchone()
        if row is None:
            return None
        return self._row_to_server(row)

    def list(self) -> list[Server]:
        """Return all servers, ordered by slug."""
        rows = self._conn.execute("SELECT * FROM servers ORDER BY slug").fetchall()
        return [self._row_to_server(r) for r in rows]

    @staticmethod
    def _row_to_server(row: sqlite3.Row) -> Server:
        source = ServerSource.model_validate(json.loads(row["source_json"]))
        return Server(
            slug=row["slug"],
            name=row["name"],
            description=row["description"] or "",
            source=source,
            homepage=row["homepage"],
            added_at=row["added_at"],
        )


class ScanRepository:
    """Typed access to the ``scans`` table."""

    def __init__(self, conn: sqlite3.Connection) -> None:
        self._conn = conn

    def record(self, scan: ScanRecord) -> None:
        """Persist a scan record."""
        self._conn.execute(
            """
            INSERT INTO scans
                (id, server_slug, engine_name, engine_version, grade,
                 risk_json, findings_json, scanned_at, report_ref)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                scan.id,
                scan.server_slug,
                scan.engine_name,
                scan.engine_version,
                scan.grade,
                scan.risk.model_dump_json(),
                json.dumps([f.model_dump(mode="json") for f in scan.findings]),
                scan.scanned_at.isoformat(),
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

        from mcp_trust.core.models import Finding, RiskSummary, TrustGrade  # noqa: PLC0415

        try:
            risk = RiskSummary.model_validate(json.loads(row["risk_json"]))
            findings_raw = json.loads(row["findings_json"])
            findings = [Finding.model_validate(f) for f in findings_raw]
        except (json.JSONDecodeError, ValidationError) as exc:
            # Corrupt or schema-drifted row — surface the offending id rather
            # than letting an opaque error bubble up as a 500.
            raise ValueError(f"Corrupt scan record {row['id']!r}: {exc}") from exc
        return ScanRecord(
            id=row["id"],
            server_slug=row["server_slug"],
            engine_name=row["engine_name"],
            engine_version=row["engine_version"],
            grade=TrustGrade(row["grade"]),
            risk=risk,
            findings=findings,
            scanned_at=row["scanned_at"],
            report_ref=row["report_ref"],
        )
