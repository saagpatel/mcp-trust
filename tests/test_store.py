"""Tests for store/db.py and store/repository.py."""

from __future__ import annotations

import uuid
from datetime import UTC, datetime

import pytest

from mcp_trust.core.models import (
    Finding,
    RiskSummary,
    ScanRecord,
    Server,
    ServerSource,
    Severity,
    SourceKind,
    TrustGrade,
)
from mcp_trust.store.db import connect, init_schema
from mcp_trust.store.repository import ScanRepository, ServerRepository


@pytest.fixture()
def conn():
    """In-memory SQLite connection with schema initialised."""
    c = connect(":memory:")
    init_schema(c)
    return c


@pytest.fixture()
def server_repo(conn):
    return ServerRepository(conn)


@pytest.fixture()
def scan_repo(conn):
    return ScanRepository(conn)


def _make_server(slug: str = "test-server") -> Server:
    return Server(
        slug=slug,
        name="Test Server",
        description="A test MCP server.",
        source=ServerSource(
            kind=SourceKind.NPM,
            reference="@test/mcp-server",
            command="npx",
            args=["-y", "@test/mcp-server"],
            env_keys=["TEST_KEY"],
        ),
        homepage="https://example.com/test",
        added_at=datetime.now(tz=UTC),
    )


def _make_risk(composite: float = 2.5) -> RiskSummary:
    return RiskSummary(
        composite=composite,
        file_access=1.0,
        network_access=3.0,
        shell_execution=2.0,
        destructive=0.5,
        exfiltration=1.5,
        findings_by_severity={Severity.MEDIUM: 1},
    )


def _make_scan(slug: str = "test-server", composite: float = 2.5) -> ScanRecord:
    return ScanRecord(
        id=uuid.uuid4().hex,
        server_slug=slug,
        engine_name="stub",
        engine_version="0.1.0",
        grade=TrustGrade.B,
        risk=_make_risk(composite),
        findings=[
            Finding(
                rule_id="STUB001",
                title="Test finding",
                severity=Severity.MEDIUM,
                category="file_access",
                detail="Detail text.",
            )
        ],
        scanned_at=datetime.now(tz=UTC),
        report_ref=None,
    )


# ---------------------------------------------------------------------------
# Schema tests
# ---------------------------------------------------------------------------


def test_schema_creates_tables(conn) -> None:
    """init_schema must create servers and scans tables."""
    tables = {
        row[0]
        for row in conn.execute("SELECT name FROM sqlite_master WHERE type='table'").fetchall()
    }
    assert "servers" in tables
    assert "scans" in tables


def test_init_schema_idempotent(conn) -> None:
    """Calling init_schema twice must not raise."""
    init_schema(conn)  # second call
    tables = {
        row[0]
        for row in conn.execute("SELECT name FROM sqlite_master WHERE type='table'").fetchall()
    }
    assert "servers" in tables


# ---------------------------------------------------------------------------
# ServerRepository tests
# ---------------------------------------------------------------------------


def test_server_upsert_and_get(server_repo) -> None:
    server = _make_server()
    server_repo.upsert(server)
    fetched = server_repo.get(server.slug)
    assert fetched is not None
    assert fetched.slug == server.slug
    assert fetched.name == server.name
    assert fetched.source.reference == server.source.reference
    assert fetched.source.env_keys == ["TEST_KEY"]


def test_server_get_missing_returns_none(server_repo) -> None:
    assert server_repo.get("no-such-slug") is None


def test_server_list_empty(server_repo) -> None:
    assert server_repo.list() == []


def test_server_list_multiple(server_repo) -> None:
    s1 = _make_server("alpha")
    s2 = _make_server("beta")
    server_repo.upsert(s1)
    server_repo.upsert(s2)
    listed = server_repo.list()
    assert len(listed) == 2
    slugs = {s.slug for s in listed}
    assert slugs == {"alpha", "beta"}


def test_server_upsert_updates_existing(server_repo) -> None:
    server = _make_server()
    server_repo.upsert(server)

    updated = server.model_copy(update={"name": "Updated Name"})
    server_repo.upsert(updated)

    fetched = server_repo.get(server.slug)
    assert fetched is not None
    assert fetched.name == "Updated Name"
    # Only one row should exist.
    assert len(server_repo.list()) == 1


def _raw_insert(conn, slug: str) -> None:
    """Insert a row directly, bypassing the model's slug validation."""
    conn.execute(
        "INSERT INTO servers (slug, name, description, source_json, homepage, added_at) "
        "VALUES (?, ?, ?, ?, ?, ?)",
        (
            slug,
            "Evil",
            "",
            '{"kind":"npm","reference":"@x/y","command":null,"args":[],"env_keys":[]}',
            None,
            datetime.now(tz=UTC).isoformat(),
        ),
    )
    conn.commit()


def test_server_list_skips_invalid_row(conn, server_repo) -> None:
    """A hostile/corrupt row (out-of-band write) is dropped, not crashed on."""
    server_repo.upsert(_make_server("good-slug"))
    _raw_insert(conn, "../evil")  # path-traversal slug the model would reject
    listed = server_repo.list()
    assert {s.slug for s in listed} == {"good-slug"}


def test_server_get_invalid_row_returns_none(conn, server_repo) -> None:
    _raw_insert(conn, "../evil")
    assert server_repo.get("../evil") is None


# ---------------------------------------------------------------------------
# ScanRepository tests
# ---------------------------------------------------------------------------


def test_scan_record_and_latest(conn, server_repo, scan_repo) -> None:
    server = _make_server()
    server_repo.upsert(server)

    scan = _make_scan()
    scan_repo.record(scan)

    latest = scan_repo.latest(server.slug)
    assert latest is not None
    assert latest.id == scan.id
    assert latest.grade == TrustGrade.B
    assert latest.risk.composite == scan.risk.composite
    assert len(latest.findings) == 1


def test_scan_latest_returns_most_recent(conn, server_repo, scan_repo) -> None:
    """When two scans exist, latest() must return the one with the higher scanned_at."""
    server = _make_server()
    server_repo.upsert(server)

    from datetime import timedelta

    now = datetime.now(tz=UTC)
    older = _make_scan(composite=5.0)
    # Patch scanned_at to ensure ordering is deterministic.
    older = older.model_copy(update={"scanned_at": now - timedelta(hours=1)})
    newer = _make_scan(composite=1.0)
    newer = newer.model_copy(update={"scanned_at": now, "grade": TrustGrade.A})

    scan_repo.record(older)
    scan_repo.record(newer)

    latest = scan_repo.latest(server.slug)
    assert latest is not None
    assert latest.id == newer.id
    assert latest.grade == TrustGrade.A


def test_scan_latest_missing_returns_none(scan_repo) -> None:
    assert scan_repo.latest("no-such-slug") is None


def test_scan_latest_all(conn, server_repo, scan_repo) -> None:
    s1 = _make_server("alpha")
    s2 = _make_server("beta")
    server_repo.upsert(s1)
    server_repo.upsert(s2)

    scan_repo.record(_make_scan("alpha"))
    scan_repo.record(_make_scan("beta"))

    mapping = scan_repo.latest_all()
    assert set(mapping.keys()) == {"alpha", "beta"}
    assert mapping["alpha"].server_slug == "alpha"
    assert mapping["beta"].server_slug == "beta"


def test_scan_latest_all_empty(scan_repo) -> None:
    assert scan_repo.latest_all() == {}
