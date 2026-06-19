"""Tests for the HTML web UI routes (GET / and GET /ui/servers/{slug})."""

from __future__ import annotations

import pytest
from fastapi.testclient import TestClient

from mcp_trust.api.app import create_app
from mcp_trust.catalog.seed import seed_into
from mcp_trust.engine.stub import StubEngine
from mcp_trust.store.db import connect, init_schema
from mcp_trust.store.repository import ServerRepository

# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture()
def conn():
    c = connect(":memory:")
    init_schema(c)
    return c


@pytest.fixture()
def seeded_conn(conn):
    server_repo = ServerRepository(conn)
    seed_into(server_repo)
    return conn


@pytest.fixture()
def client(seeded_conn):
    """TestClient backed by an in-memory seeded DB and StubEngine."""
    application = create_app(conn=seeded_conn, engine=StubEngine())
    return TestClient(application)


# ---------------------------------------------------------------------------
# GET /  — catalog page
# ---------------------------------------------------------------------------


def test_catalog_returns_200(client: TestClient) -> None:
    resp = client.get("/")
    assert resp.status_code == 200


def test_catalog_content_type_html(client: TestClient) -> None:
    resp = client.get("/")
    assert "text/html" in resp.headers["content-type"]


def test_catalog_contains_seeded_server_name(client: TestClient) -> None:
    """At least one seeded server name must appear in the catalog page."""
    resp = client.get("/")
    body = resp.text
    assert "MCP Reference Time" in body
    assert "/ui/servers/" in body


def test_catalog_shows_unscanned_before_scan(client: TestClient) -> None:
    resp = client.get("/")
    assert "unscanned" in resp.text.lower()


def test_catalog_shows_grade_after_scan(client: TestClient) -> None:
    # Trigger a scan.
    client.post("/servers/mcp-reference-time/scan")
    resp = client.get("/")
    body = resp.text
    # After scan a real grade pill (A–F) must appear.
    assert any(f">{g}<" in body for g in ("A", "B", "C", "D", "F"))


# ---------------------------------------------------------------------------
# GET /ui/servers/{slug}  — detail page
# ---------------------------------------------------------------------------


def test_detail_known_server_200(client: TestClient) -> None:
    resp = client.get("/ui/servers/mcp-reference-time")
    assert resp.status_code == 200
    assert "text/html" in resp.headers["content-type"]


def test_detail_unknown_server_404(client: TestClient) -> None:
    resp = client.get("/ui/servers/no-such-server-xyz")
    assert resp.status_code == 404
    assert "text/html" in resp.headers["content-type"]


def test_detail_404_page_contains_slug(client: TestClient) -> None:
    resp = client.get("/ui/servers/no-such-server-xyz")
    assert "no-such-server-xyz" in resp.text


def test_detail_shows_grade_after_scan(client: TestClient) -> None:
    # Scan first so there's a grade to show.
    scan_resp = client.post("/servers/mcp-reference-time/scan")
    grade = scan_resp.json()["grade"]

    resp = client.get("/ui/servers/mcp-reference-time")
    assert resp.status_code == 200
    assert grade in resp.text


def test_detail_shows_transparency_after_scan(client: TestClient) -> None:
    scan_resp = client.post("/servers/mcp-reference-time/scan")
    transparency = scan_resp.json()["transparency"]

    resp = client.get("/ui/servers/mcp-reference-time")
    assert transparency in resp.text


def test_detail_contains_badge_embed_snippet(client: TestClient) -> None:
    """The detail page must contain a shields.io badge embed Markdown snippet."""
    resp = client.get("/ui/servers/mcp-reference-time")
    body = resp.text
    assert "shields.io" in body
    assert "mcp-reference-time" in body
    assert "badge.json" in body


def test_detail_badge_snippet_has_absolute_url(client: TestClient) -> None:
    """The badge snippet must include the absolute base URL (not a relative path)."""
    resp = client.get("/ui/servers/mcp-reference-time")
    body = resp.text
    # TestClient uses http://testserver as base_url by default.
    assert "http://testserver" in body


def test_detail_badge_snippet_slug_correct(client: TestClient) -> None:
    """The badge URL must include the server's own slug."""
    resp = client.get("/ui/servers/mcp-reference-time")
    body = resp.text
    # Both the badge.json URL and the detail URL should contain the slug.
    assert "/servers/mcp-reference-time/badge.json" in body
    assert "/ui/servers/mcp-reference-time" in body


# ---------------------------------------------------------------------------
# Catalog reflects scan result (integration path)
# ---------------------------------------------------------------------------


def test_catalog_shows_scanned_server_grade(client: TestClient) -> None:
    scan_resp = client.post("/servers/mcp-reference-time/scan")
    assert scan_resp.status_code == 200
    grade = scan_resp.json()["grade"]

    catalog = client.get("/")
    assert grade in catalog.text
