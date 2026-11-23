"""The baked snapshot must include ONLY real-engine scans (provenance boundary)."""

from __future__ import annotations

import importlib.util
import json
import sys
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest

from mcp_trust.catalog.runtime_snapshot import parse_catalog_snapshot
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
        sandbox_image="fixture:image",
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
    assert snap["servers"][0]["scan_mode"] == "mcpaudit-local-network-unknown"
    assert snap["servers"][0]["sandbox"] == {
        "mode": "docker",
        "network": "unknown",
        "image": "fixture:image",
    }


def test_build_snapshot_compares_instants_and_emits_legacy_time_as_utc(tmp_path: Path) -> None:
    db = str(tmp_path / "registry.db")
    conn = connect(db)
    init_schema(conn)
    history = (
        ("earlier", "2026-06-28T10:00:00+02:00", TrustGrade.A),
        ("latest", "2026-06-28T09:30:00+00:00", TrustGrade.A),
        ("legacy", "2026-06-28T06:00:00", TrustGrade.B),
        ("legacy", "2026-06-28T07:00:00", TrustGrade.A),
        ("legacy", "2026-06-28T07:30:00", TrustGrade.A),
    )
    for scan_id, (slug, timestamp, grade) in enumerate(history):
        ServerRepository(conn).upsert(_server(slug))
        scan = _scan(slug, "mcpaudit").model_copy(
            update={
                "id": str(scan_id),
                "scanned_at": datetime.fromisoformat(timestamp),
                "grade": grade,
                "risk": RiskSummary(composite=0, network_access=3 if grade == TrustGrade.B else 0),
            }
        )
        ScanRepository(conn).record(scan)
    conn.close()

    snapshot = _load_build_snapshot().build_snapshot(db, now=datetime(2026, 6, 29, tzinfo=UTC))
    assert datetime.fromisoformat(snapshot["generated_from_scan_at"]) == datetime(
        2026, 6, 28, 9, 30, tzinfo=UTC
    )
    legacy = next(row for row in snapshot["servers"] if row["slug"] == "legacy")
    assert legacy["scanned_at"] == "2026-06-28T07:30:00+00:00"
    assert parse_catalog_snapshot(json.dumps(snapshot)) == snapshot
    assert datetime.fromisoformat(legacy["grade_change"]["changed_at"]) == datetime(
        2026, 6, 28, 7, tzinfo=UTC
    )


def test_build_snapshot_only_claims_network_off_with_per_scan_proof(tmp_path) -> None:
    db = str(tmp_path / "t.db")
    conn = connect(db)
    init_schema(conn)
    ServerRepository(conn).upsert(_server("real-one"))
    ScanRepository(conn).record(_scan("real-one", "mcpaudit"))

    server = _load_build_snapshot().build_snapshot(
        db,
        verified_scan_modes={"real-one": "mcpaudit-local-network-off"},
    )["servers"][0]

    assert server["scan_mode"] == "mcpaudit-local-network-off"
    assert server["sandbox"] == {
        "mode": "docker",
        "network": "none",
        "image": "fixture:image",
    }


def test_build_snapshot_discloses_remote_live_transport(tmp_path) -> None:
    db = str(tmp_path / "t.db")
    conn = connect(db)
    init_schema(conn)
    remote = _server("remote-one").model_copy(
        update={
            "source": ServerSource(
                kind=SourceKind.REMOTE,
                reference="https://example.test/mcp",
            )
        }
    )
    ServerRepository(conn).upsert(remote)
    ScanRepository(conn).record(
        _scan("remote-one", "mcpaudit").model_copy(update={"sandbox_image": None})
    )

    server = _load_build_snapshot().build_snapshot(db)["servers"][0]

    assert server["scan_mode"] == "mcpaudit-remote-live-network"
    assert server["sandbox"] == {
        "mode": "not_applicable",
        "reason": "remote_endpoint_no_local_process",
    }


def test_build_snapshot_main_rejects_unknown_mask_before_output(
    tmp_path: Path,
    monkeypatch,
) -> None:
    db = str(tmp_path / "t.db")
    conn = connect(db)
    init_schema(conn)
    ServerRepository(conn).upsert(_server("real-one"))
    conn.close()
    masked = tmp_path / "masked.json"
    masked.write_text(json.dumps(["rael-one"]), encoding="utf-8")
    output = tmp_path / "snapshot.json"
    module = _load_build_snapshot()
    monkeypatch.setattr(module, "_OUT", output)
    monkeypatch.setenv("MCP_TRUST_DB", db)
    monkeypatch.setenv("MCP_TRUST_MASKED_GRADES", str(masked))

    with pytest.raises(ValueError, match="unknown catalog slug.*rael-one"):
        module.main()

    assert not output.exists()


def test_build_snapshot_main_rejects_unbound_network_context(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    db = str(tmp_path / "t.db")
    conn = connect(db)
    init_schema(conn)
    ServerRepository(conn).upsert(_server("real-one"))
    ScanRepository(conn).record(_scan("real-one", "mcpaudit"))
    conn.close()
    masked = tmp_path / "masked.json"
    masked.write_text("[]", encoding="utf-8")
    output = tmp_path / "snapshot.json"
    module = _load_build_snapshot()
    monkeypatch.setattr(module, "_OUT", output)
    monkeypatch.setenv("MCP_TRUST_DB", db)
    monkeypatch.setenv("MCP_TRUST_MASKED_GRADES", str(masked))
    monkeypatch.setenv("MCP_TRUST_VERIFIED_LOCAL_NETWORK", "none")

    with pytest.raises(ValueError, match="cannot prove per-scan network mode"):
        module.main()

    assert not output.exists()


def test_baked_snapshot_excludes_every_reviewed_masked_slug() -> None:
    masked = set(json.loads((ROOT / "masked-grades.json").read_text(encoding="utf-8")))
    snapshot = json.loads(
        (ROOT / "src/mcp_trust/catalog_snapshot.json").read_text(encoding="utf-8")
    )
    exposed = {server["slug"] for server in snapshot["servers"]}

    assert masked
    assert masked.isdisjoint(exposed)


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
