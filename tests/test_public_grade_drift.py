"""Public projections of the scan-over-scan grade-drift capability."""

from __future__ import annotations

import json
from datetime import UTC, datetime, timedelta

from fastapi.testclient import TestClient

from mcp_trust.api.app import create_app
from mcp_trust.api.web import render_detail
from mcp_trust.core.drift import (
    DriftCause,
    SurfaceComparison,
    latest_grade_change,
)
from mcp_trust.core.models import (
    RiskSummary,
    ScanEvidence,
    ScanRecord,
    Server,
    ServerSource,
    SourceKind,
    ToolEvidence,
    TrustGrade,
)
from mcp_trust.site.generator import generate_site
from mcp_trust.store.db import connect, init_schema
from mcp_trust.store.repository import ScanRepository, ServerRepository


def _server() -> Server:
    return Server(
        slug="grade-change-server",
        name="Grade Change Server",
        source=ServerSource(kind=SourceKind.NPM, reference="@test/grade-change-server"),
        added_at=datetime(2026, 7, 1, tzinfo=UTC),
    )


def _scan(
    *,
    ident: str,
    grade: TrustGrade,
    scanned_at: datetime,
    engine_version: str,
    evidence: ScanEvidence | None,
) -> ScanRecord:
    return ScanRecord(
        id=ident,
        server_slug="grade-change-server",
        engine_name="mcpaudit",
        engine_version=engine_version,
        grade=grade,
        risk=RiskSummary(composite=3.0),
        evidence=evidence,
        scanned_at=scanned_at,
    )


def _history(*, evidence: ScanEvidence | None = None) -> list[ScanRecord]:
    old = _scan(
        ident="old",
        grade=TrustGrade.D,
        scanned_at=datetime(2026, 7, 1, tzinfo=UTC),
        engine_version="2.3.0",
        evidence=evidence,
    )
    new = _scan(
        ident="new",
        grade=TrustGrade.B,
        scanned_at=old.scanned_at + timedelta(days=7),
        engine_version="2.4.0",
        evidence=evidence,
    )
    return [new, old]


def test_public_grade_change_keeps_missing_evidence_unknown() -> None:
    change = latest_grade_change(_history())
    assert change is not None
    assert change.cause is DriftCause.ENGINE_CHANGED
    assert change.surface_comparison is SurfaceComparison.UNKNOWN

    html = render_detail(
        _server(),
        _history()[0],
        base_url="https://registry.example",
        grade_change=change,
    )
    assert "Grade changed 2026-07-08" in html
    assert "Cause:</strong> engine-changed" in html
    assert "comparison is unknown because evidence is missing" in html
    assert "surface was unchanged" not in html


def test_public_grade_change_survives_later_repeated_scans() -> None:
    history = _history()
    history.insert(
        0,
        history[0].model_copy(
            update={"id": "repeat", "scanned_at": datetime(2026, 7, 9, tzinfo=UTC)}
        ),
    )

    change = latest_grade_change(history)
    assert change is not None
    assert change.changed_at == datetime(2026, 7, 8, tzinfo=UTC)
    assert change.previous_grade is TrustGrade.D
    assert change.current_grade is TrustGrade.B


def test_public_api_exposes_only_the_grade_change_summary() -> None:
    conn = connect(":memory:")
    init_schema(conn)
    ServerRepository(conn).upsert(_server())
    scans = ScanRepository(conn)
    for scan in reversed(_history(evidence=ScanEvidence(tools=[ToolEvidence(name="search")]))):
        scans.record(scan)

    payload = TestClient(create_app(conn=conn)).get("/servers/grade-change-server").json()
    assert payload["grade_change"] == {
        "changed_at": "2026-07-08T00:00:00Z",
        "previous_grade": "D",
        "current_grade": "B",
        "cause": "engine-changed",
        "surface_comparison": "unchanged",
    }
    assert "previous_danger_score" not in json.dumps(payload["grade_change"])


def test_masked_api_does_not_leak_the_withheld_grade_change() -> None:
    conn = connect(":memory:")
    init_schema(conn)
    ServerRepository(conn).upsert(_server())
    scans = ScanRepository(conn)
    for scan in reversed(_history()):
        scans.record(scan)

    payload = TestClient(
        create_app(conn=conn, masked_slugs={"grade-change-server"})
    ).get("/servers/grade-change-server").json()
    assert payload["grade_change"] is None
    assert "D" not in json.dumps(payload)


def test_static_detail_surfaces_change_and_hides_it_when_masked(tmp_path) -> None:
    conn = connect(":memory:")
    init_schema(conn)
    ServerRepository(conn).upsert(_server())
    scans = ScanRepository(conn)
    for scan in reversed(_history(evidence=ScanEvidence(tools=[ToolEvidence(name="search")]))):
        scans.record(scan)

    generate_site(conn, tmp_path, base_url="https://registry.example")
    detail = (tmp_path / "ui" / "servers" / "grade-change-server" / "index.html").read_text()
    assert "Grade changed 2026-07-08" in detail
    assert "Cause:</strong> engine-changed" in detail
    assert "declared tool surface was unchanged" in detail

    generate_site(
        conn,
        tmp_path,
        base_url="https://registry.example",
        masked_slugs={"grade-change-server"},
    )
    masked_detail = (
        tmp_path / "ui" / "servers" / "grade-change-server" / "index.html"
    ).read_text()
    assert "Grade changed" not in masked_detail
    assert "D → B" not in masked_detail
