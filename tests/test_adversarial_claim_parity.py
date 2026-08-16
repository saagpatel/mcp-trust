"""Cross-surface honesty checks using synthetic records only."""

from __future__ import annotations

import json
from datetime import UTC, datetime

import pytest
from fastapi.testclient import TestClient

from mcp_trust.api.app import create_app
from mcp_trust.catalog.snapshot import build_snapshot_from_connection
from mcp_trust.core.models import (
    RiskSummary,
    ScanRecord,
    Server,
    ServerSource,
    SourceKind,
    TransparencyLevel,
    TrustGrade,
)
from mcp_trust.engine.stub import StubEngine
from mcp_trust.site.generator import generate_site
from mcp_trust.store.db import connect, init_schema
from mcp_trust.store.repository import ScanRepository, ServerRepository


def _catalog():
    conn = connect(":memory:")
    init_schema(conn)
    server = Server(
        slug="synthetic-server",
        name="Synthetic Server",
        description="Synthetic parity fixture",
        source=ServerSource(kind=SourceKind.NPM, reference="@example/synthetic"),
        added_at=datetime(2026, 1, 1, tzinfo=UTC),
    )
    ServerRepository(conn).upsert(server)
    return conn, server


def test_stub_provenance_is_explicit_across_api_web_static_and_badge(
    tmp_path,
    monkeypatch,
) -> None:
    conn, _server = _catalog()
    monkeypatch.setenv("MCP_TRUST_ALLOW_UNAUTHENTICATED_STUB_SCANS", "1")
    client = TestClient(create_app(conn=conn, engine=StubEngine()))

    scan_response = client.post("/servers/synthetic-server/scan")
    assert scan_response.status_code == 200
    assert scan_response.json()["provenance"] == "demo"

    summary = client.get("/servers").json()[0]
    detail = client.get("/servers/synthetic-server").json()
    badge = client.get("/servers/synthetic-server/badge.json").json()
    live_html = client.get("/ui/servers/synthetic-server").text
    live_catalog = client.get("/").text
    build = generate_site(conn, tmp_path / "site", base_url="https://example.invalid")
    static_html = (build.out_dir / "ui/servers/synthetic-server/index.html").read_text()
    static_badge = json.loads(
        (build.out_dir / "servers/synthetic-server/badge.json").read_text()
    )

    assert summary["provenance"] == "demo"
    assert detail["latest_scan"]["provenance"] == "demo"
    assert "(demo)" in badge["message"]
    assert "DEMO DATA" in live_html
    assert "DEMO DATA" in live_catalog
    assert "DEMO DATA" in static_html
    assert static_badge == badge


def test_stale_state_is_explicit_across_api_web_static_and_badge(tmp_path) -> None:
    conn, server = _catalog()
    ScanRepository(conn).record(
        ScanRecord(
            id="synthetic-stale",
            server_slug=server.slug,
            engine_name="mcpaudit",
            engine_version="synthetic-record-only",
            grade=TrustGrade.B,
            transparency=TransparencyLevel.HIGH,
            risk=RiskSummary(composite=2, file_access=1),
            scanned_at=datetime(2020, 1, 1, tzinfo=UTC),
        )
    )
    client = TestClient(create_app(conn=conn, engine=StubEngine()))

    summary = client.get("/servers").json()[0]
    detail = client.get("/servers/synthetic-server").json()
    badge = client.get("/servers/synthetic-server/badge.json").json()
    live_html = client.get("/ui/servers/synthetic-server").text
    build = generate_site(
        conn,
        tmp_path / "site",
        base_url="https://example.invalid",
        now=datetime(2026, 8, 14, tzinfo=UTC),
    )
    static_html = (build.out_dir / "ui/servers/synthetic-server/index.html").read_text()
    static_badge = json.loads(
        (build.out_dir / "servers/synthetic-server/badge.json").read_text()
    )

    assert summary["provenance"] == "real"
    assert summary["stale"] is True
    assert detail["latest_scan"]["provenance"] == "real"
    assert detail["latest_scan"]["stale"] is True
    assert "(stale)" in badge["message"]
    assert "pending re-scan" in live_html
    assert "pending re-scan" in static_html
    assert static_badge["message"] == badge["message"]


def test_corrupt_latest_scan_is_unknown_everywhere_without_older_grade_fallback(
    tmp_path,
) -> None:
    conn, server = _catalog()
    ScanRepository(conn).record(
        ScanRecord(
            id="valid-older",
            server_slug=server.slug,
            engine_name="mcpaudit",
            engine_version="synthetic-record-only",
            grade=TrustGrade.A,
            transparency=TransparencyLevel.HIGH,
            risk=RiskSummary(composite=1),
            scanned_at=datetime(2026, 1, 1, tzinfo=UTC),
        )
    )
    conn.execute(
        """
        INSERT INTO scans
            (id, server_slug, engine_name, engine_version, grade, transparency,
             risk_json, findings_json, scanned_at)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (
            "corrupt-latest",
            server.slug,
            "mcpaudit",
            "synthetic-record-only",
            "A",
            "high",
            '{"token":"synthetic-secret"',
            "[]",
            datetime(2026, 1, 2, tzinfo=UTC).isoformat(),
        ),
    )
    conn.commit()
    client = TestClient(
        create_app(conn=conn, engine=StubEngine()),
        raise_server_exceptions=False,
    )

    summary_response = client.get("/servers")
    detail_response = client.get("/servers/synthetic-server")
    badge_response = client.get("/servers/synthetic-server/badge.json")
    live_response = client.get("/ui/servers/synthetic-server")
    build = generate_site(conn, tmp_path / "site", base_url="https://example.invalid")
    static_html = (build.out_dir / "ui/servers/synthetic-server/index.html").read_text()
    static_badge = json.loads(
        (build.out_dir / "servers/synthetic-server/badge.json").read_text()
    )

    assert summary_response.status_code == 200
    assert summary_response.json()[0]["grade"] == "unknown"
    assert summary_response.json()[0]["provenance"] == "unknown"
    assert detail_response.status_code == 200
    assert detail_response.json()["latest_scan"]["status"] == "UNKNOWN"
    assert detail_response.json()["latest_scan"]["reason_codes"] == [
        "SCAN_RECORD_UNREADABLE"
    ]
    assert badge_response.json()["message"] == "unknown"
    assert "UNKNOWN" in live_response.text
    assert "UNKNOWN" in static_html
    assert static_badge["message"] == "unknown"
    assert "synthetic-secret" not in " ".join(
        [
            summary_response.text,
            detail_response.text,
            badge_response.text,
            live_response.text,
            static_html,
            json.dumps(static_badge),
        ]
    )
    with pytest.raises(ValueError, match="unreadable latest scan"):
        build_snapshot_from_connection(conn)


def test_corrupt_older_history_does_not_erase_a_readable_latest_claim(tmp_path) -> None:
    conn, server = _catalog()
    scan_repo = ScanRepository(conn)
    older = ScanRecord(
        id="history-older",
        server_slug=server.slug,
        engine_name="mcpaudit",
        engine_version="synthetic-record-only",
        grade=TrustGrade.A,
        transparency=TransparencyLevel.HIGH,
        risk=RiskSummary(composite=1),
        scanned_at=datetime(2026, 1, 1, tzinfo=UTC),
    )
    latest = older.model_copy(
        update={
            "id": "history-latest",
            "grade": TrustGrade.B,
            "risk": RiskSummary(composite=3),
            "scanned_at": datetime(2026, 1, 2, tzinfo=UTC),
        }
    )
    scan_repo.record(older)
    scan_repo.record(latest)
    conn.execute(
        "UPDATE scans SET risk_json = ? WHERE id = ?",
        ('{"token":"synthetic-history-secret"', older.id),
    )
    conn.commit()
    client = TestClient(create_app(conn=conn, engine=StubEngine()))

    summary = client.get("/servers").json()[0]
    detail = client.get("/servers/synthetic-server").json()
    badge = client.get("/servers/synthetic-server/badge.json").json()
    live_html = client.get("/ui/servers/synthetic-server").text
    build = generate_site(conn, tmp_path / "site", base_url="https://example.invalid")
    static_html = (build.out_dir / "ui/servers/synthetic-server/index.html").read_text()

    assert summary["grade"] == "B"
    assert detail["latest_scan"]["grade"] == "B"
    assert detail["grade_change"] == {
        "status": "UNKNOWN",
        "reason_codes": ["SCAN_HISTORY_UNREADABLE"],
    }
    assert badge["message"].startswith("B")
    assert "SCAN HISTORY UNKNOWN" in live_html
    assert "SCAN HISTORY UNKNOWN" in static_html
    assert "synthetic-history-secret" not in " ".join(
        [json.dumps(summary), json.dumps(detail), json.dumps(badge), live_html, static_html]
    )
    with pytest.raises(ValueError):
        build_snapshot_from_connection(conn)
