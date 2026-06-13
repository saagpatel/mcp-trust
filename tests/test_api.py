"""Tests for the FastAPI application."""

from __future__ import annotations

import pytest
from fastapi.testclient import TestClient

from mcp_trust.api.app import create_app
from mcp_trust.engine.stub import StubEngine
from mcp_trust.store.db import connect, init_schema
from mcp_trust.store.repository import ServerRepository


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
def client(conn):
    """TestClient backed by an in-memory DB and StubEngine."""
    application = create_app(conn=conn, engine=StubEngine())
    return TestClient(application)


@pytest.fixture()
def seeded_client(seeded_conn):
    """TestClient with the seed catalog pre-loaded."""
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
    assert len(items) >= 8
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
    resp = seeded_client.get("/servers/acme-search")
    assert resp.status_code == 200
    body = resp.json()
    assert body["server"]["slug"] == "acme-search"
    assert body["latest_scan"] is None


# ---------------------------------------------------------------------------
# POST /servers/{slug}/scan
# ---------------------------------------------------------------------------


def test_scan_unknown_server_404(client) -> None:
    resp = client.post("/servers/no-such-slug/scan")
    assert resp.status_code == 404


def test_scan_known_server_persists(seeded_client) -> None:
    # Scan a known server.
    resp = seeded_client.post("/servers/acme-search/scan")
    assert resp.status_code == 200
    body = resp.json()

    # Response must include required ScanRecord fields.
    assert body["server_slug"] == "acme-search"
    assert "id" in body
    assert "grade" in body
    assert body["grade"] in {"A", "B", "C", "D", "F"}
    assert "risk" in body
    assert 0.0 <= body["risk"]["composite"] <= 10.0
    assert "scanned_at" in body

    # Subsequent GET must return the persisted scan.
    get_resp = seeded_client.get("/servers/acme-search")
    assert get_resp.status_code == 200
    get_body = get_resp.json()
    assert get_body["latest_scan"] is not None
    assert get_body["latest_scan"]["id"] == body["id"]


def test_scan_updates_list_grade(seeded_client) -> None:
    # Before scan, grade is unscanned.
    before = seeded_client.get("/servers")
    acme_before = next(s for s in before.json() if s["slug"] == "acme-search")
    assert acme_before["grade"] == "unscanned"

    # Scan it.
    seeded_client.post("/servers/acme-search/scan")

    # After scan, grade should be a real grade.
    after = seeded_client.get("/servers")
    acme_after = next(s for s in after.json() if s["slug"] == "acme-search")
    assert acme_after["grade"] in {"A", "B", "C", "D", "F"}
    assert acme_after["composite"] is not None


# ---------------------------------------------------------------------------
# GET /servers/{slug}/badge.json
# ---------------------------------------------------------------------------


def test_badge_unknown_server_404(client) -> None:
    resp = client.get("/servers/no-such-slug/badge.json")
    assert resp.status_code == 404


def test_badge_unscanned_server(seeded_client) -> None:
    resp = seeded_client.get("/servers/acme-search/badge.json")
    assert resp.status_code == 200
    body = resp.json()
    assert body["schemaVersion"] == 1
    assert body["label"] == "mcp trust"
    assert body["message"] == "unscanned"
    assert body["color"] == "lightgrey"


def test_badge_after_scan(seeded_client) -> None:
    seeded_client.post("/servers/acme-search/scan")
    resp = seeded_client.get("/servers/acme-search/badge.json")
    assert resp.status_code == 200
    body = resp.json()
    assert body["schemaVersion"] == 1
    assert body["label"] == "mcp trust"
    assert body["message"] in {"A", "B", "C", "D", "F"}
    assert body["color"] in {"brightgreen", "green", "yellow", "orange", "red"}
