"""Tests for site/generator.py — the static catalog generator.

The generator turns the registry's stored scans into a low-ops static site:
``index.html`` (catalog), one detail page per server, and one shields.io
``badge.json`` per server. It is pure: it reads SQLite and writes files, never
touching the network or spawning a process.

The non-negotiable property under test is HONESTY: a grade derived from the
deterministic stub engine must be loudly labelled demo data, and an unscanned
server must never be rendered with a letter grade.
"""

from __future__ import annotations

import json
import uuid
from datetime import UTC, datetime
from pathlib import Path

import pytest

from mcp_trust.core import grading
from mcp_trust.core.models import (
    RiskSummary,
    ScanRecord,
    Server,
    ServerSource,
    SourceKind,
    TrustGrade,
)
from mcp_trust.engine.stub import StubEngine
from mcp_trust.site.generator import generate_site
from mcp_trust.store.db import connect, init_schema
from mcp_trust.store.repository import ScanRepository, ServerRepository

BASE_URL = "https://mcp-trust.example"


# ---------------------------------------------------------------------------
# Fixtures / helpers
# ---------------------------------------------------------------------------


@pytest.fixture()
def conn():
    c = connect(":memory:")
    init_schema(c)
    return c


def _server(slug: str, name: str | None = None) -> Server:
    return Server(
        slug=slug,
        name=name or slug.replace("-", " ").title(),
        description=f"Test server {slug}.",
        source=ServerSource(kind=SourceKind.NPM, reference=f"@test/{slug}"),
        homepage="https://example.com/" + slug,
        added_at=datetime.now(tz=UTC),
    )


def _stub_scan(slug: str) -> ScanRecord:
    """Build a scan record exactly as the stub-engine scan path would."""
    result = StubEngine().scan(_server(slug).source)
    return ScanRecord(
        id=uuid.uuid4().hex,
        server_slug=slug,
        engine_name=result.engine_name,  # "stub"
        engine_version=result.engine_version,
        grade=grading.grade(result.risk),
        transparency=grading.transparency(result.risk),
        risk=result.risk,
        findings=result.findings,
        scanned_at=datetime.now(tz=UTC),
        report_ref=None,
    )


def _real_scan(slug: str, grade: TrustGrade) -> ScanRecord:
    return ScanRecord(
        id=uuid.uuid4().hex,
        server_slug=slug,
        engine_name="mcpaudit",
        engine_version="2.1.0",
        grade=grade,
        risk=RiskSummary(composite=1.0),
        findings=[],
        scanned_at=datetime.now(tz=UTC),
        report_ref=None,
    )


def _seed(conn, *, scanned: list[str], unscanned: list[str]) -> None:
    servers = ServerRepository(conn)
    scans = ScanRepository(conn)
    for slug in scanned:
        servers.upsert(_server(slug))
        scans.record(_stub_scan(slug))
    for slug in unscanned:
        servers.upsert(_server(slug))


# ---------------------------------------------------------------------------
# File layout
# ---------------------------------------------------------------------------


def test_writes_catalog_index(conn, tmp_path: Path) -> None:
    _seed(conn, scanned=["alpha"], unscanned=[])
    generate_site(conn, tmp_path, base_url=BASE_URL)
    assert (tmp_path / "index.html").is_file()


def test_writes_404_page(conn, tmp_path: Path) -> None:
    _seed(conn, scanned=["alpha"], unscanned=[])
    generate_site(conn, tmp_path, base_url=BASE_URL)
    assert (tmp_path / "404.html").is_file()


def test_writes_detail_page_per_server_at_clean_url_path(conn, tmp_path: Path) -> None:
    _seed(conn, scanned=["alpha"], unscanned=["beta"])
    generate_site(conn, tmp_path, base_url=BASE_URL)
    # Layout matches the absolute links web.py emits: /ui/servers/<slug>.
    assert (tmp_path / "ui" / "servers" / "alpha" / "index.html").is_file()
    assert (tmp_path / "ui" / "servers" / "beta" / "index.html").is_file()


def test_writes_badge_json_per_server(conn, tmp_path: Path) -> None:
    _seed(conn, scanned=["alpha"], unscanned=["beta"])
    generate_site(conn, tmp_path, base_url=BASE_URL)
    # Layout matches the badge-embed URL: /servers/<slug>/badge.json.
    assert (tmp_path / "servers" / "alpha" / "badge.json").is_file()
    assert (tmp_path / "servers" / "beta" / "badge.json").is_file()


def test_returns_manifest_of_written_files(conn, tmp_path: Path) -> None:
    _seed(conn, scanned=["alpha"], unscanned=["beta"])
    build = generate_site(conn, tmp_path, base_url=BASE_URL)
    assert build.server_count == 2
    assert build.scanned_count == 1
    assert build.demo_count == 1  # alpha is a stub scan
    # Every reported page actually exists on disk.
    assert build.pages, "manifest must list written files"
    for page in build.pages:
        assert Path(page).is_file()


def test_real_scan_has_zero_demo_count(conn, tmp_path: Path) -> None:
    servers = ServerRepository(conn)
    scans = ScanRepository(conn)
    servers.upsert(_server("gamma"))
    scans.record(_real_scan("gamma", TrustGrade.A))
    build = generate_site(conn, tmp_path, base_url=BASE_URL)
    assert build.scanned_count == 1
    assert build.demo_count == 0


# ---------------------------------------------------------------------------
# SECURITY — hostile input must not escape the output directory
# ---------------------------------------------------------------------------


def _raw_insert_server(conn, slug: str) -> None:
    """Insert a server row directly, bypassing the model's slug validation.

    Simulates a corrupt or out-of-band write: the only way a hostile slug could
    ever land in the DB, since ``Server`` rejects it at construction.
    """
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


def test_hostile_slug_row_is_skipped_and_cannot_escape_out_dir(conn, tmp_path: Path) -> None:
    out = tmp_path / "site"
    servers = ServerRepository(conn)
    servers.upsert(_server("alpha"))
    # A traversal slug written out-of-band must never produce a page or escape out_dir.
    _raw_insert_server(conn, "../escape")

    build = generate_site(conn, out, base_url=BASE_URL)

    # The hostile row is dropped by the resilient repository read — no page at all.
    assert build.server_count == 1
    assert not (tmp_path / "escape").exists()
    assert not (tmp_path / "ui").exists()  # would appear if '../' resolved up a level
    # The safe server is still generated.
    assert (out / "ui" / "servers" / "alpha" / "index.html").is_file()
    # Every manifest path stays strictly within out_dir.
    resolved_out = out.resolve()
    for page in build.pages:
        assert page.resolve().is_relative_to(resolved_out)


# ---------------------------------------------------------------------------
# Catalog content
# ---------------------------------------------------------------------------


def test_catalog_lists_server_names_and_links(conn, tmp_path: Path) -> None:
    _seed(conn, scanned=["alpha"], unscanned=["beta"])
    generate_site(conn, tmp_path, base_url=BASE_URL)
    html = (tmp_path / "index.html").read_text(encoding="utf-8")
    assert "Alpha" in html
    assert "Beta" in html
    # Links use the same clean-URL path the detail files are written at.
    assert "/ui/servers/alpha" in html
    assert "/ui/servers/beta" in html


# ---------------------------------------------------------------------------
# HONESTY — the property that matters most
# ---------------------------------------------------------------------------


def test_demo_data_carries_loud_banner_on_catalog(conn, tmp_path: Path) -> None:
    _seed(conn, scanned=["alpha"], unscanned=[])
    generate_site(conn, tmp_path, base_url=BASE_URL)
    html = (tmp_path / "index.html").read_text(encoding="utf-8")
    assert "DEMO DATA" in html
    assert "stub" in html.lower()


def test_demo_data_carries_loud_banner_on_detail(conn, tmp_path: Path) -> None:
    _seed(conn, scanned=["alpha"], unscanned=[])
    generate_site(conn, tmp_path, base_url=BASE_URL)
    html = (tmp_path / "ui" / "servers" / "alpha" / "index.html").read_text(encoding="utf-8")
    assert "DEMO DATA" in html


def test_unscanned_server_shows_no_letter_grade(conn, tmp_path: Path) -> None:
    import re

    _seed(conn, scanned=[], unscanned=["beta"])
    generate_site(conn, tmp_path, base_url=BASE_URL)
    html = (tmp_path / "ui" / "servers" / "beta" / "index.html").read_text(encoding="utf-8")
    assert "unscanned" in html.lower()
    # The hero grade block must never render ANY confident A–F letter for an
    # unscanned server — assert on the grade-big element's contents directly.
    match = re.search(r'class="grade-big"[^>]*>([^<]*)<', html)
    assert match is not None, "detail page must render a grade-big hero block"
    assert match.group(1).strip() not in {"A", "B", "C", "D", "F"}


def test_real_scan_does_not_carry_demo_banner(conn, tmp_path: Path) -> None:
    servers = ServerRepository(conn)
    scans = ScanRepository(conn)
    servers.upsert(_server("gamma"))
    scans.record(_real_scan("gamma", TrustGrade.A))
    generate_site(conn, tmp_path, base_url=BASE_URL)
    html = (tmp_path / "ui" / "servers" / "gamma" / "index.html").read_text(encoding="utf-8")
    assert "DEMO DATA" not in html


# ---------------------------------------------------------------------------
# Badge JSON
# ---------------------------------------------------------------------------


def test_badge_json_is_valid_shields_endpoint(conn, tmp_path: Path) -> None:
    _seed(conn, scanned=["alpha"], unscanned=[])
    generate_site(conn, tmp_path, base_url=BASE_URL)
    payload = json.loads((tmp_path / "servers" / "alpha" / "badge.json").read_text())
    assert payload["schemaVersion"] == 1
    assert payload["label"] == "mcp trust"
    assert "color" in payload
    assert payload["message"]  # non-empty


def test_badge_json_labels_demo_grade(conn, tmp_path: Path) -> None:
    _seed(conn, scanned=["alpha"], unscanned=[])
    generate_site(conn, tmp_path, base_url=BASE_URL)
    payload = json.loads((tmp_path / "servers" / "alpha" / "badge.json").read_text())
    # A stub-derived grade must never be presented as an unqualified letter.
    assert "demo" in payload["message"].lower()


def test_badge_json_unscanned_message(conn, tmp_path: Path) -> None:
    _seed(conn, scanned=[], unscanned=["beta"])
    generate_site(conn, tmp_path, base_url=BASE_URL)
    payload = json.loads((tmp_path / "servers" / "beta" / "badge.json").read_text())
    assert payload["message"].lower() == "unscanned"


# ---------------------------------------------------------------------------
# Rebuild / staleness
# ---------------------------------------------------------------------------


def test_rebuild_removes_orphaned_detail_pages(conn, tmp_path: Path) -> None:
    _seed(conn, scanned=["alpha"], unscanned=["beta"])
    generate_site(conn, tmp_path, base_url=BASE_URL)
    assert (tmp_path / "ui" / "servers" / "beta" / "index.html").is_file()

    # Drop beta from the registry and rebuild; its stale page must not survive.
    conn.execute("DELETE FROM servers WHERE slug = 'beta'")
    conn.commit()
    generate_site(conn, tmp_path, base_url=BASE_URL)
    assert not (tmp_path / "ui" / "servers" / "beta").exists()
    assert (tmp_path / "ui" / "servers" / "alpha" / "index.html").is_file()


def test_rebuild_preserves_unmanaged_files(conn, tmp_path: Path) -> None:
    # A user's deploy config (e.g. vercel.json) at the site root must survive a rebuild.
    (tmp_path / "vercel.json").write_text("{}", encoding="utf-8")
    _seed(conn, scanned=["alpha"], unscanned=[])
    generate_site(conn, tmp_path, base_url=BASE_URL)
    generate_site(conn, tmp_path, base_url=BASE_URL)
    assert (tmp_path / "vercel.json").is_file()
