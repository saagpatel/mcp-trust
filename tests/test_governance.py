"""Tests for the public-grading governance layer (packet-008 dispositions).

Covers the four governance components:

- M1 framing floor: methodology page + opinion-vs-fact framing with the scan
  basis (artifact + date) on every detail page.
- M2 provenance: listing basis, scan-target statement, and credential
  disclosure on every detail page.
- M3 staleness: a grade past the horizon greys out and is labelled on pages,
  the catalog, and badges — it must never read as a current verdict.
- M4 dispute: dispute / right-of-reply policy page, per-entry dispute link,
  and the public corrections log.
"""

from __future__ import annotations

import json
import uuid
from datetime import UTC, datetime, timedelta

import pytest
from fastapi.testclient import TestClient

from mcp_trust.api.app import create_app
from mcp_trust.api.web import (
    render_catalog,
    render_corrections,
    render_detail,
    render_dispute,
    render_methodology,
)
from mcp_trust.core.governance import DISPUTE_URL, STALE_AFTER_DAYS, is_stale
from mcp_trust.core.models import (
    RiskSummary,
    ScanRecord,
    Server,
    ServerSource,
    SourceKind,
    TransparencyLevel,
    TrustGrade,
)
from mcp_trust.core.provenance import ScanProvenance
from mcp_trust.site.badges import badge_payload
from mcp_trust.site.generator import generate_site
from mcp_trust.store.db import connect, init_schema
from mcp_trust.store.repository import ScanRepository, ServerRepository

BASE_URL = "https://mcp-trust.example"
NOW = datetime(2026, 7, 3, 12, 0, 0, tzinfo=UTC)
FRESH_AT = NOW - timedelta(days=5)
STALE_AT = NOW - timedelta(days=STALE_AFTER_DAYS + 1)


# ---------------------------------------------------------------------------
# Fixtures / helpers
# ---------------------------------------------------------------------------


def _server(slug: str = "test-server", *, env_keys: list[str] | None = None) -> Server:
    return Server(
        slug=slug,
        name=slug.replace("-", " ").title(),
        description=f"Test server {slug}.",
        source=ServerSource(
            kind=SourceKind.NPM,
            reference=f"@test/{slug}",
            env_keys=env_keys or [],
        ),
        homepage=f"https://example.com/{slug}",
        added_at=NOW,
    )


def _real_scan(
    slug: str = "test-server",
    *,
    grade: TrustGrade = TrustGrade.F,
    scanned_at: datetime = FRESH_AT,
) -> ScanRecord:
    return ScanRecord(
        id=uuid.uuid4().hex,
        server_slug=slug,
        engine_name="mcpaudit",
        engine_version="2.4.0",
        grade=grade,
        transparency=TransparencyLevel.HIGH,
        risk=RiskSummary(composite=8.0),
        findings=[],
        scanned_at=scanned_at,
        report_ref=None,
    )


# ---------------------------------------------------------------------------
# is_stale — the staleness policy primitive
# ---------------------------------------------------------------------------


def test_is_stale_inside_horizon():
    assert not is_stale(NOW - timedelta(days=STALE_AFTER_DAYS - 1), NOW)


def test_is_stale_past_horizon():
    assert is_stale(NOW - timedelta(days=STALE_AFTER_DAYS + 1), NOW)


def test_is_stale_treats_naive_datetimes_as_utc():
    naive_old = (NOW - timedelta(days=STALE_AFTER_DAYS + 1)).replace(tzinfo=None)
    assert is_stale(naive_old, NOW)
    assert is_stale(naive_old, NOW.replace(tzinfo=None))


# ---------------------------------------------------------------------------
# M3 — badges must never present an expired scan as current
# ---------------------------------------------------------------------------


def test_badge_stale_real_grade_greys_and_labels():
    payload = badge_payload("F", ScanProvenance.REAL, stale=True)
    assert payload["message"] == "F (stale)"
    assert payload["color"] == "lightgrey"


def test_badge_fresh_real_grade_unchanged():
    payload = badge_payload("F", ScanProvenance.REAL, stale=False)
    assert payload["message"] == "F"
    assert payload["color"] == "red"


def test_badge_demo_label_wins_over_stale():
    payload = badge_payload("B", ScanProvenance.DEMO, stale=True)
    assert payload["message"] == "B (demo)"


def test_badge_unscanned_ignores_stale():
    payload = badge_payload("unscanned", ScanProvenance.UNSCANNED, stale=True)
    assert payload["message"] == "unscanned"


# ---------------------------------------------------------------------------
# M1 + M2 + M4 — detail page framing, provenance, and dispute surfaces
# ---------------------------------------------------------------------------


def test_detail_framing_states_opinion_artifact_and_date():
    html = render_detail(_server(), _real_scan(), base_url=BASE_URL, now=NOW)
    assert "automated opinion" in html
    assert '<a href="/ui/methodology">' in html
    assert "@test/test-server" in html
    assert "as scanned on" in html
    assert "may not describe later releases" in html


def test_detail_provenance_card_scan_target_and_listing_basis():
    html = render_detail(_server(), _real_scan(), base_url=BASE_URL, now=NOW)
    assert "operator-listed from a public catalog" in html
    assert "No vendor-hosted infrastructure was contacted" in html
    assert "Dispute this grade" in html
    assert '<a href="/ui/dispute">' in html


def test_detail_provenance_credentials_disclosed_when_declared():
    server = _server(env_keys=["API_TOKEN"])
    html = render_detail(server, _real_scan(), base_url=BASE_URL, now=NOW)
    assert "API_TOKEN" in html
    assert "never use real credentials" in html


def test_detail_provenance_no_credentials_line():
    html = render_detail(_server(), _real_scan(), base_url=BASE_URL, now=NOW)
    assert "none declared, none used" in html


def test_detail_fresh_grade_has_no_stale_marker():
    html = render_detail(_server(), _real_scan(scanned_at=FRESH_AT), base_url=BASE_URL, now=NOW)
    assert "(stale)" not in html
    assert "Stale grade:" not in html


def test_detail_stale_grade_greys_and_carries_caveat():
    html = render_detail(_server(), _real_scan(scanned_at=STALE_AT), base_url=BASE_URL, now=NOW)
    assert "(stale)" in html
    assert "Stale grade:" in html
    assert "pending re-scan" in html
    # The hero block greys out: the grade colour must be the unscanned grey.
    assert '<div class="grade-big" style="background:#8b949e">' in html


def test_detail_without_now_renders_no_staleness():
    html = render_detail(_server(), _real_scan(scanned_at=STALE_AT), base_url=BASE_URL)
    assert "(stale)" not in html


# ---------------------------------------------------------------------------
# M3 — catalog rows
# ---------------------------------------------------------------------------


def _catalog_row(scanned_at: datetime) -> dict:
    return {
        "slug": "test-server",
        "name": "Test Server",
        "grade": "F",
        "transparency": "high",
        "composite": 8.0,
        "scanned_at": scanned_at.isoformat(),
    }


def test_catalog_marks_stale_rows():
    html = render_catalog([_catalog_row(STALE_AT)], now=NOW)
    assert "F (STALE)" in html.upper()


def test_catalog_fresh_rows_unmarked():
    html = render_catalog([_catalog_row(FRESH_AT)], now=NOW)
    assert "(stale)" not in html


# ---------------------------------------------------------------------------
# M1 — methodology page renders from the real grading constants
# ---------------------------------------------------------------------------


def test_methodology_page_discloses_weights_bands_and_cap():
    html = render_methodology()
    assert "shell_execution" in html
    assert "2.0" in html  # the shell weight — the strongest danger signal
    assert "Critical cap" in html
    assert "cannot verify it is safe" in html
    assert "not" in html and "known dangerous" in html
    assert str(STALE_AFTER_DAYS) in html
    assert "opinion" in html


def test_methodology_page_states_scan_target_policy():
    html = render_methodology()
    assert "network-isolated sandbox" in html
    assert "No vendor-hosted infrastructure is contacted" in html
    assert "never use real credentials" in html


# ---------------------------------------------------------------------------
# M4 — dispute policy and corrections log
# ---------------------------------------------------------------------------


def test_dispute_page_names_channel_sla_and_withdrawal_rule():
    html = render_dispute()
    assert DISPUTE_URL in html
    assert "14 days" in html
    assert "re-scanned" in html
    assert "corrections log" in html
    assert "withdrawn, not defended" in html


def test_corrections_empty_state():
    html = render_corrections([])
    assert "No corrections recorded yet" in html


def test_corrections_rows_render_and_escape():
    entries = [
        {
            "date": "2026-07-03",
            "slug": "test-server",
            "summary": "Grade revised after re-scan <script>",
            "resolution": "F → C",
        }
    ]
    html = render_corrections(entries)
    assert "2026-07-03" in html
    assert '<a href="/ui/servers/test-server">' in html
    assert "<script>" not in html
    assert "&lt;script&gt;" in html


# ---------------------------------------------------------------------------
# Generator — governance pages ship with every build, staleness is wired
# ---------------------------------------------------------------------------


@pytest.fixture()
def conn():
    c = connect(":memory:")
    init_schema(c)
    return c


def test_generator_emits_governance_pages_and_stale_badges(conn, tmp_path):
    server_repo = ServerRepository(conn)
    scan_repo = ScanRepository(conn)
    server_repo.upsert(_server("stale-server"))
    server_repo.upsert(_server("fresh-server"))
    scan_repo.record(_real_scan("stale-server", scanned_at=STALE_AT))
    scan_repo.record(_real_scan("fresh-server", scanned_at=FRESH_AT))

    build = generate_site(conn, tmp_path, base_url=BASE_URL, now=NOW)

    for rel in ("ui/methodology", "ui/dispute", "ui/corrections"):
        assert (tmp_path / rel / "index.html").is_file(), f"{rel} page missing"
    assert build.stale_count == 1

    stale_badge = json.loads(
        (tmp_path / "servers" / "stale-server" / "badge.json").read_text(encoding="utf-8")
    )
    assert stale_badge["message"] == "F (stale)"
    assert stale_badge["color"] == "lightgrey"

    fresh_badge = json.loads(
        (tmp_path / "servers" / "fresh-server" / "badge.json").read_text(encoding="utf-8")
    )
    assert fresh_badge["message"] == "F"

    index_html = (tmp_path / "index.html").read_text(encoding="utf-8")
    assert "(stale)" in index_html


def test_generator_renders_corrections_entries(conn, tmp_path):
    generate_site(
        conn,
        tmp_path,
        base_url=BASE_URL,
        now=NOW,
        corrections=[{"date": "2026-07-03", "slug": "x", "summary": "s", "resolution": "r"}],
    )
    html = (tmp_path / "ui" / "corrections" / "index.html").read_text(encoding="utf-8")
    assert "2026-07-03" in html


# ---------------------------------------------------------------------------
# FastAPI parity — governance pages served by the live app too
# ---------------------------------------------------------------------------


@pytest.fixture()
def client(conn):
    return TestClient(create_app(conn=conn))


@pytest.mark.parametrize("path", ["/ui/methodology", "/ui/dispute", "/ui/corrections"])
def test_app_serves_governance_pages(client, path):
    response = client.get(path)
    assert response.status_code == 200
    assert "MCP Trust" in response.text


# ---------------------------------------------------------------------------
# M3 parity — the LIVE badge endpoint must agree with the static badge files
# ---------------------------------------------------------------------------


def test_live_badge_route_marks_stale_grades(conn, client):
    """The README-embed endpoint must never present an expired scan as current."""
    ServerRepository(conn).upsert(_server("stale-server"))
    ScanRepository(conn).record(_real_scan("stale-server", scanned_at=STALE_AT))

    payload = client.get("/servers/stale-server/badge.json").json()
    assert payload["message"] == "F (stale)"
    assert payload["color"] == "lightgrey"


def test_live_badge_route_fresh_grade_unchanged(conn, client):
    ServerRepository(conn).upsert(_server("fresh-server"))
    ScanRepository(conn).record(_real_scan("fresh-server", scanned_at=FRESH_AT))

    payload = client.get("/servers/fresh-server/badge.json").json()
    assert payload["message"] == "F"
    assert payload["color"] == "red"


def test_live_badge_route_labels_demo_scans(conn, client):
    """Provenance honesty on the live route: a stub-engine grade reads (demo)."""
    ServerRepository(conn).upsert(_server("demo-server"))
    demo_scan = _real_scan("demo-server", scanned_at=FRESH_AT).model_copy(
        update={"engine_name": "stub"}
    )
    ScanRepository(conn).record(demo_scan)

    payload = client.get("/servers/demo-server/badge.json").json()
    assert payload["message"] == "F (demo)"
