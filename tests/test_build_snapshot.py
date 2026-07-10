"""The baked snapshot must include ONLY real-engine scans (provenance boundary)."""

from __future__ import annotations

import importlib.util
import sys
from datetime import UTC, datetime, timedelta
from pathlib import Path

from mcp_trust.core.models import (
    RiskSummary,
    ScanRecord,
    Server,
    ServerSource,
    SourceKind,
    TrustGrade,
)
from mcp_trust.store.db import connect, init_schema
from mcp_trust.store.repository import ScanRepository, ServerRepository

ROOT = Path(__file__).resolve().parents[1]


def _load_build_snapshot():
    spec = importlib.util.spec_from_file_location(
        "build_snapshot", ROOT / "scripts/build_snapshot.py"
    )
    assert spec is not None and spec.loader is not None
    mod = importlib.util.module_from_spec(spec)
    sys.modules["build_snapshot"] = mod
    spec.loader.exec_module(mod)
    return mod


def _server(slug: str) -> Server:
    return Server(
        slug=slug,
        name=slug,
        source=ServerSource(kind=SourceKind.NPM, reference=slug),
        added_at=datetime(2026, 6, 28),
    )


def _scan(slug: str, engine: str) -> ScanRecord:
    return ScanRecord(
        id=slug,
        server_slug=slug,
        engine_name=engine,
        engine_version="1",
        grade=TrustGrade.C,
        risk=RiskSummary(composite=5.0),
        scanned_at=datetime(2026, 6, 28),
    )


def test_build_snapshot_bakes_only_real_engine_scans(tmp_path) -> None:
    db = str(tmp_path / "t.db")
    conn = connect(db)
    init_schema(conn)
    servers = ServerRepository(conn)
    scans = ScanRepository(conn)

    servers.upsert(_server("real-one"))
    servers.upsert(_server("stub-one"))
    scans.record(_scan("real-one", "mcpaudit"))
    scans.record(_scan("stub-one", "stub"))  # synthetic -> must be excluded

    snap = _load_build_snapshot().build_snapshot(db)
    slugs = {s["slug"] for s in snap["servers"]}
    assert "real-one" in slugs
    assert "stub-one" not in slugs
    assert snap["server_count"] == 1
    assert snap["schema_version"] == 2


def test_build_snapshot_projects_real_grade_change_without_private_deltas(tmp_path) -> None:
    db = str(tmp_path / "t.db")
    conn = connect(db)
    init_schema(conn)
    servers = ServerRepository(conn)
    scans = ScanRepository(conn)
    servers.upsert(_server("real-one"))
    old = _scan("old", "mcpaudit").model_copy(
        update={
            "server_slug": "real-one",
            "grade": TrustGrade.D,
            "scanned_at": datetime(2026, 7, 1, tzinfo=UTC),
        }
    )
    new = _scan("new", "mcpaudit").model_copy(
        update={
            "server_slug": "real-one",
            "grade": TrustGrade.B,
            "engine_version": "2",
            "scanned_at": old.scanned_at + timedelta(days=7),
        }
    )
    scans.record(old)
    scans.record(new)

    server = _load_build_snapshot().build_snapshot(db)["servers"][0]
    assert server["grade_change"] == {
        "changed_at": "2026-07-08T00:00:00Z",
        "previous_grade": "D",
        "current_grade": "B",
        "cause": "engine-changed",
        "surface_comparison": "unknown",
    }


def test_build_snapshot_does_not_relabel_a_demo_history_as_public_grade_change(tmp_path) -> None:
    db = str(tmp_path / "t.db")
    conn = connect(db)
    init_schema(conn)
    servers = ServerRepository(conn)
    scans = ScanRepository(conn)
    servers.upsert(_server("real-one"))
    demo = _scan("demo", "stub").model_copy(
        update={
            "server_slug": "real-one",
            "grade": TrustGrade.F,
            "scanned_at": datetime(2026, 7, 1, tzinfo=UTC),
        }
    )
    real = _scan("real", "mcpaudit").model_copy(
        update={
            "server_slug": "real-one",
            "grade": TrustGrade.B,
            "scanned_at": demo.scanned_at + timedelta(days=7),
        }
    )
    scans.record(demo)
    scans.record(real)

    server = _load_build_snapshot().build_snapshot(db)["servers"][0]
    assert server["grade_change"] is None
