"""Tests for the FastAPI application."""

from __future__ import annotations

import json

import pytest
from fastapi.testclient import TestClient

from mcp_trust.api.app import create_app
from mcp_trust.engine.stub import StubEngine
from mcp_trust.store.db import connect, init_schema
from mcp_trust.store.repository import ServerRepository


class _RejectingRealEngine:
    name = "mcpaudit"
    version = "test"

    def scan(self, source):  # noqa: ANN001
        raise AssertionError("scan should not run without a valid trigger token")


class _TokenGatedRealEngine(StubEngine):
    name = "mcpaudit"


class _RejectingStubEngine:
    name = "stub"
    version = "test"

    def scan(self, source):  # noqa: ANN001
        raise AssertionError("scan should not run without explicit dev opt-in")


@pytest.fixture()
def conn():
    c = connect(":memory:")
    init_schema(c)
    return c


@pytest.fixture()
def seeded_conn(conn):
    """Connection with the seed catalog loaded."""
    from mcp_trust.catalog.seed import seed_into

    server_repo = ServerRepository(conn)
    seed_into(server_repo)
    return conn


@pytest.fixture()
def client(conn, monkeypatch):
    """TestClient backed by an in-memory DB and StubEngine."""
    monkeypatch.setenv("MCP_TRUST_ALLOW_UNAUTHENTICATED_STUB_SCANS", "1")
    application = create_app(conn=conn, engine=StubEngine())
    return TestClient(application)


@pytest.fixture()
def seeded_client(seeded_conn, monkeypatch):
    """TestClient with the seed catalog pre-loaded."""
    monkeypatch.setenv("MCP_TRUST_ALLOW_UNAUTHENTICATED_STUB_SCANS", "1")
    application = create_app(conn=seeded_conn, engine=StubEngine())
    return TestClient(application)


# ---------------------------------------------------------------------------
# /healthz
# ---------------------------------------------------------------------------


def test_healthz(client) -> None:
    resp = client.get("/healthz")
    assert resp.status_code == 200
    assert resp.json() == {"status": "ok"}


# ---------------------------------------------------------------------------
# GET /servers
# ---------------------------------------------------------------------------


def test_list_servers_empty(client) -> None:
    resp = client.get("/servers")
    assert resp.status_code == 200
    assert resp.json() == []


def test_list_servers_after_seed(seeded_client) -> None:
    resp = seeded_client.get("/servers")
    assert resp.status_code == 200
    items = resp.json()
    # The catalog reflects the bundled seed (reference + scannable-archived cohorts).
    from mcp_trust.catalog.seed import load_seed

    assert len(items) == len(load_seed())
    # Each item must have required fields.
    for item in items:
        assert "slug" in item
        assert "name" in item
        assert "grade" in item
        assert "composite" in item
        assert "scanned_at" in item


def test_list_servers_unscanned_grade(seeded_client) -> None:
    resp = seeded_client.get("/servers")
    assert resp.status_code == 200
    # Before any scan, all servers should be unscanned.
    for item in resp.json():
        assert item["grade"] == "unscanned"
        assert item["composite"] is None
        assert item["scanned_at"] is None


# ---------------------------------------------------------------------------
# GET /servers/{slug}
# ---------------------------------------------------------------------------


def test_get_server_unknown_404(client) -> None:
    resp = client.get("/servers/no-such-slug")
    assert resp.status_code == 404


def test_get_server_known(seeded_client) -> None:
    resp = seeded_client.get("/servers/mcp-reference-time")
    assert resp.status_code == 200
    body = resp.json()
    assert body["server"]["slug"] == "mcp-reference-time"
    assert body["latest_scan"] is None


# ---------------------------------------------------------------------------
# POST /servers/{slug}/scan
# ---------------------------------------------------------------------------


def test_scan_unknown_server_404(client) -> None:
    resp = client.post("/servers/no-such-slug/scan")
    assert resp.status_code == 404


def test_scan_known_server_persists(seeded_client) -> None:
    # Scan a known server.
    resp = seeded_client.post("/servers/mcp-reference-time/scan")
    assert resp.status_code == 200
    body = resp.json()

    # Response must include required ScanRecord fields.
    assert body["server_slug"] == "mcp-reference-time"
    assert "id" in body
    assert "grade" in body
    assert body["grade"] in {"A", "B", "C", "D", "F"}
    assert "risk" in body
    assert 0.0 <= body["risk"]["composite"] <= 10.0
    assert "scanned_at" in body

    # Subsequent GET must return the persisted scan.
    get_resp = seeded_client.get("/servers/mcp-reference-time")
    assert get_resp.status_code == 200
    get_body = get_resp.json()
    assert get_body["latest_scan"] is not None
    assert get_body["latest_scan"]["id"] == body["id"]


def test_scan_updates_list_grade(seeded_client) -> None:
    # Before scan, grade is unscanned.
    before = seeded_client.get("/servers")
    time_before = next(s for s in before.json() if s["slug"] == "mcp-reference-time")
    assert time_before["grade"] == "unscanned"

    # Scan it.
    seeded_client.post("/servers/mcp-reference-time/scan")

    # After scan, grade should be a real grade.
    after = seeded_client.get("/servers")
    time_after = next(s for s in after.json() if s["slug"] == "mcp-reference-time")
    assert time_after["grade"] in {"A", "B", "C", "D", "F"}
    assert time_after["composite"] is not None


def test_stub_engine_scan_without_dev_opt_in_is_disabled(seeded_conn, monkeypatch) -> None:
    monkeypatch.delenv("MCP_TRUST_ALLOW_UNAUTHENTICATED_STUB_SCANS", raising=False)
    monkeypatch.delenv("MCP_TRUST_SCAN_TOKEN", raising=False)
    application = create_app(conn=seeded_conn, engine=_RejectingStubEngine())
    client = TestClient(application)

    resp = client.post("/servers/mcp-reference-time/scan")

    assert resp.status_code == 403
    assert "MCP_TRUST_SCAN_TOKEN" in resp.json()["detail"]


def test_public_readonly_rejects_scan_before_engine_runs(seeded_conn, monkeypatch) -> None:
    monkeypatch.setenv("MCP_TRUST_PUBLIC_READONLY", "1")
    monkeypatch.setenv("MCP_TRUST_ALLOW_UNAUTHENTICATED_STUB_SCANS", "1")
    application = create_app(conn=seeded_conn, engine=_RejectingStubEngine())
    client = TestClient(application)

    resp = client.post("/servers/mcp-reference-time/scan")

    assert resp.status_code == 403
    assert "public read-only mode" in resp.json()["detail"]


def test_scan_writes_receipt_when_configured(seeded_conn, monkeypatch, tmp_path) -> None:
    monkeypatch.setenv("MCP_TRUST_ALLOW_UNAUTHENTICATED_STUB_SCANS", "1")
    monkeypatch.setenv("MCP_TRUST_RECEIPTS_DIR", str(tmp_path))
    monkeypatch.setenv("MCP_TRUST_SANDBOX", "docker")
    monkeypatch.setenv("MCP_TRUST_SANDBOX_NETWORK", "none")
    monkeypatch.setenv("MCP_TRUST_SANDBOX_IMAGE", "mcp-trust-scan:test")
    application = create_app(conn=seeded_conn, engine=StubEngine())
    client = TestClient(application)

    resp = client.post("/servers/mcp-reference-time/scan")

    assert resp.status_code == 200
    body = resp.json()
    assert body["report_ref"] is not None
    assert "/" not in body["report_ref"]
    receipt_path = tmp_path / body["report_ref"]
    assert receipt_path.exists()

    receipt = json.loads(receipt_path.read_text())
    assert receipt["format_version"] == 1
    assert receipt["scan_id"] == body["id"]
    assert receipt["server_slug"] == "mcp-reference-time"
    assert receipt["scanner"]["engine_name"] == "stub"
    assert receipt["sandbox"]["MCP_TRUST_SANDBOX_IMAGE"] == "mcp-trust-scan:test"
    assert "MCP_TRUST_SCAN_TOKEN" not in receipt

    get_body = client.get("/servers/mcp-reference-time").json()
    assert get_body["latest_scan"]["report_ref"] == body["report_ref"]


def test_real_engine_scan_without_configured_token_is_disabled(seeded_conn, monkeypatch) -> None:
    monkeypatch.delenv("MCP_TRUST_SCAN_TOKEN", raising=False)
    application = create_app(conn=seeded_conn, engine=_RejectingRealEngine())
    client = TestClient(application)

    resp = client.post("/servers/mcp-reference-time/scan")

    assert resp.status_code == 403
    assert "MCP_TRUST_SCAN_TOKEN" in resp.json()["detail"]


def test_real_engine_scan_rejects_invalid_token(seeded_conn, monkeypatch) -> None:
    monkeypatch.setenv("MCP_TRUST_SCAN_TOKEN", "correct-token")
    application = create_app(conn=seeded_conn, engine=_RejectingRealEngine())
    client = TestClient(application)

    resp = client.post(
        "/servers/mcp-reference-time/scan",
        headers={"Authorization": "Bearer wrong-token"},
    )

    assert resp.status_code == 401
    assert resp.json()["detail"] == "Valid scan trigger token required."


def test_real_engine_scan_accepts_bearer_token(seeded_conn, monkeypatch) -> None:
    monkeypatch.setenv("MCP_TRUST_SCAN_TOKEN", "correct-token")
    application = create_app(conn=seeded_conn, engine=_TokenGatedRealEngine())
    client = TestClient(application)

    resp = client.post(
        "/servers/mcp-reference-time/scan",
        headers={"Authorization": "Bearer correct-token"},
    )

    assert resp.status_code == 200
    assert resp.json()["server_slug"] == "mcp-reference-time"


def test_real_engine_scan_accepts_scan_token_header(seeded_conn, monkeypatch) -> None:
    monkeypatch.setenv("MCP_TRUST_SCAN_TOKEN", "correct-token")
    application = create_app(conn=seeded_conn, engine=_TokenGatedRealEngine())
    client = TestClient(application)

    resp = client.post(
        "/servers/mcp-reference-time/scan",
        headers={"X-MCP-Trust-Scan-Token": "correct-token"},
    )

    assert resp.status_code == 200
    assert resp.json()["server_slug"] == "mcp-reference-time"


# ---------------------------------------------------------------------------
# GET /servers/{slug}/badge.json
# ---------------------------------------------------------------------------


def test_badge_unknown_server_404(client) -> None:
    resp = client.get("/servers/no-such-slug/badge.json")
    assert resp.status_code == 404


def test_badge_unscanned_server(seeded_client) -> None:
    resp = seeded_client.get("/servers/mcp-reference-time/badge.json")
    assert resp.status_code == 200
    body = resp.json()
    assert body["schemaVersion"] == 1
    assert body["label"] == "mcp trust"
    assert body["message"] == "unscanned"
    assert body["color"] == "lightgrey"


def test_badge_after_scan(seeded_client) -> None:
    seeded_client.post("/servers/mcp-reference-time/scan")
    resp = seeded_client.get("/servers/mcp-reference-time/badge.json")
    assert resp.status_code == 200
    body = resp.json()
    assert body["schemaVersion"] == 1
    assert body["label"] == "mcp trust"
    # The seeded client scans with the stub engine, so the live badge must
    # carry the (demo) provenance label — same honesty gate as the static
    # badge files (the live route now shares site.badges.badge_payload).
    grade, suffix = body["message"].split(" ", 1)
    assert grade in {"A", "B", "C", "D", "F"}
    assert suffix == "(demo)"
    assert body["color"] in {"brightgreen", "green", "yellow", "orange", "red"}
