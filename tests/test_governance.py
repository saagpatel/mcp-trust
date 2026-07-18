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
from mcp_trust.core.governance import (
    DISPUTE_URL,
    MASKED_SERVER_DESCRIPTION,
    STALE_AFTER_DAYS,
    is_stale,
)
from mcp_trust.core.models import (
    Finding,
    RiskSummary,
    ScanRecord,
    Server,
    ServerSource,
    Severity,
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
    sandbox_image: str | None = "mcp-trust-scan:test",
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
        sandbox_image=sandbox_image,
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


def test_detail_floor_states_artifact_date_and_does_not_claim():
    html = render_detail(_server(), _real_scan(), base_url=BASE_URL, now=NOW)
    assert "How to read this grade" in html
    assert 'href="/ui/methodology"' in html
    assert "@test/test-server" in html
    assert "What it does not claim" in html
    assert 'href="/ui/dispute"' in html  # floor links the dispute policy page


def test_detail_provenance_card_scan_target_and_listing_basis():
    html = render_detail(_server(), _real_scan(), base_url=BASE_URL, now=NOW)
    assert "operator-listed from a public catalog" in html
    assert "does not claim network isolation for that run" in html
    assert "mcp-trust-scan:test" in html
    assert "Dispute this grade" in html
    assert '<a href="/ui/dispute">' in html


def test_detail_provenance_no_sandbox_does_not_claim_sandbox():
    html = render_detail(
        _server(), _real_scan(sandbox_image=None), base_url=BASE_URL, now=NOW
    )
    assert "network-isolated sandbox" not in html
    assert "cannot verify sandbox provenance or network isolation" in html


def test_detail_provenance_demo_wins_for_remote_sources():
    server = _server("remote-demo").model_copy(
        update={
            "source": ServerSource(
                kind=SourceKind.REMOTE,
                reference="https://example.com/mcp",
                env_keys=[],
            )
        }
    )
    record = _real_scan("remote-demo").model_copy(update={"engine_name": "StubEngine"})

    html = render_detail(server, record, base_url=BASE_URL, now=NOW)

    assert "demo data from the local stub path" in html
    assert "no real server artifact or hosted endpoint was launched" in html
    assert "a hosted endpoint (<code>https://example.com/mcp</code>)" not in html


def test_detail_provenance_remote_proxy_keeps_sandbox_context():
    server = _server("remote-proxy").model_copy(
        update={
            "source": ServerSource(
                kind=SourceKind.REMOTE,
                reference="https://example.com/mcp",
                command="remote-proxy-launcher",
                env_keys=[],
            )
        }
    )
    record = _real_scan("remote-proxy")

    html = render_detail(server, record, base_url=BASE_URL, now=NOW)

    assert "launched and scanned locally using command" in html
    assert "remote-proxy-launcher" in html
    assert "mcp-trust-scan:test" in html
    assert "a hosted endpoint (<code>https://example.com/mcp</code>)" not in html


def test_detail_provenance_hosted_remote_stays_hosted_with_sandbox_record():
    server = _server("hosted-remote").model_copy(
        update={
            "source": ServerSource(
                kind=SourceKind.REMOTE,
                reference="https://example.com/mcp",
                env_keys=[],
            )
        }
    )
    record = _real_scan("hosted-remote")

    html = render_detail(server, record, base_url=BASE_URL, now=NOW)

    assert "a hosted endpoint (<code>https://example.com/mcp</code>)" in html
    assert "installed and scanned locally" not in html
    assert "launched and scanned locally" not in html


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
    assert "Shell execution" in html
    assert "2.0" in html  # the shell weight — the strongest danger signal
    assert "Critical cap" in html
    assert "cannot verify safe" in html
    assert "known dangerous" in html
    assert str(STALE_AFTER_DAYS) in html
    assert "opinion" in html


def test_methodology_page_states_scan_target_policy():
    html = render_methodology()
    assert "hosted endpoint entries are labeled" in html
    assert "does not expose per-run network mode" in html
    assert "never use real credentials" in html
    assert 'href="/ui/corrections"' in html


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


# ---------------------------------------------------------------------------
# Grade masking — operator-withheld grades pending governance review
# ---------------------------------------------------------------------------


def test_badge_masked_shows_no_letter():
    payload = badge_payload("F", ScanProvenance.REAL, masked=True)
    assert payload["message"] == "under review"
    assert payload["color"] == "lightgrey"
    assert "F" not in payload["message"]


def test_badge_masked_wins_over_stale_and_demo():
    assert badge_payload("F", ScanProvenance.REAL, stale=True, masked=True)["message"] == (
        "under review"
    )
    assert badge_payload("F", ScanProvenance.DEMO, masked=True)["message"] == "under review"


def test_badge_unscanned_wins_over_masked():
    payload = badge_payload("unscanned", ScanProvenance.UNSCANNED, masked=True)
    assert payload["message"] == "unscanned"


def test_badge_verified_masked_scan_reads_under_review_without_grade():
    payload = badge_payload(
        "unscanned",
        ScanProvenance.UNSCANNED,
        masked=True,
        masked_scan_succeeded=True,
    )
    assert payload == {
        "schemaVersion": 1,
        "label": "mcp trust",
        "message": "under review",
        "color": "lightgrey",
    }


def test_detail_masked_withholds_grade_score_and_findings():
    server = _server().model_copy(update={"description": "The F grade should not leak."})
    record = _real_scan().model_copy(
        update={
            "findings": [
                Finding(
                    rule_id="MCP007",
                    title="Shell execution capability",
                    severity=Severity.CRITICAL,
                    category="shell",
                )
            ]
        }
    )
    html = render_detail(server, record, base_url=BASE_URL, now=NOW, masked=True)
    assert "Grade withheld:" in html
    assert "under governance review" in html
    assert ">withheld<" in html  # danger score cell
    assert "Finding detail is withheld" in html
    assert "MCP007" not in html  # finding detail really is gone
    assert "The F grade should not leak." not in html
    assert MASKED_SERVER_DESCRIPTION in html
    assert "No findings on record" not in html  # must not read as a clean scan
    assert '<div class="grade-big" style="background:#8b949e">—</div>' in html
    # Dispute path and scan metadata stay disclosed.
    assert '<a href="/ui/dispute">' in html
    assert "mcpaudit" in html


def test_detail_masked_suppresses_stale_marker():
    html = render_detail(
        _server(), _real_scan(scanned_at=STALE_AT), base_url=BASE_URL, now=NOW, masked=True
    )
    assert "Grade withheld:" in html
    assert "(stale)" not in html


def test_detail_masked_ignored_for_unscanned():
    server = _server().model_copy(update={"description": "The F grade should not leak."})
    html = render_detail(server, None, base_url=BASE_URL, now=NOW, masked=True)
    assert "Grade withheld:" not in html
    assert "UNSCANNED" in html
    assert "The F grade should not leak." not in html
    assert MASKED_SERVER_DESCRIPTION in html


def test_detail_verified_masked_scan_withholds_all_verdict_data():
    server = _server().model_copy(
        update={"description": "masked-detail-sentinel-should-not-leak"}
    )
    html = render_detail(
        server,
        None,
        base_url=BASE_URL,
        now=NOW,
        masked=True,
        masked_scan_succeeded=True,
    )
    assert "Grade withheld:" in html
    assert "successful scan" in html
    assert "grade withheld — under governance review" in html
    assert "masked-detail-sentinel-should-not-leak" not in html
    assert MASKED_SERVER_DESCRIPTION in html
    assert "Not yet scanned." not in html
    assert "No findings on record." not in html
    assert "Finding detail is withheld" in html
    assert " / 10" not in html
    assert "this page reports detected or inferred risk" not in html


def test_catalog_masked_row_hides_grade_and_score():
    row = _catalog_row(FRESH_AT) | {"masked": True}
    html = render_catalog([row], now=NOW)
    assert ">masked<" in html
    assert 'class="pill" style="background:#8b949e"' in html
    assert "8.0" not in html


def test_generator_masks_listed_slugs(conn, tmp_path):
    server_repo = ServerRepository(conn)
    scan_repo = ScanRepository(conn)
    server_repo.upsert(_server("masked-server"))
    server_repo.upsert(_server("open-server"))
    scan_repo.record(_real_scan("masked-server", scanned_at=FRESH_AT))
    scan_repo.record(_real_scan("open-server", scanned_at=FRESH_AT))

    build = generate_site(
        conn, tmp_path, base_url=BASE_URL, now=NOW, masked_slugs={"masked-server"}
    )

    assert build.masked_count == 1
    masked_badge = json.loads(
        (tmp_path / "servers" / "masked-server" / "badge.json").read_text(encoding="utf-8")
    )
    assert masked_badge["message"] == "under review"
    open_badge = json.loads(
        (tmp_path / "servers" / "open-server" / "badge.json").read_text(encoding="utf-8")
    )
    assert open_badge["message"] == "F"
    detail = (tmp_path / "ui" / "servers" / "masked-server" / "index.html").read_text(
        encoding="utf-8"
    )
    assert "Grade withheld:" in detail


def test_generator_masks_unscanned_operator_metadata(conn, tmp_path):
    server = _server("masked-server").model_copy(
        update={"description": "The F grade should not leak."}
    )
    ServerRepository(conn).upsert(server)

    generate_site(conn, tmp_path, base_url=BASE_URL, now=NOW, masked_slugs={"masked-server"})

    detail = (tmp_path / "ui" / "servers" / "masked-server" / "index.html").read_text(
        encoding="utf-8"
    )
    badge = json.loads(
        (tmp_path / "servers" / "masked-server" / "badge.json").read_text(encoding="utf-8")
    )
    assert "The F grade should not leak." not in detail
    assert MASKED_SERVER_DESCRIPTION in detail
    assert "Grade withheld:" not in detail
    assert badge["message"] == "unscanned"


def test_generator_projects_verified_masked_scan_without_grade(conn, tmp_path):
    server = _server("masked-server").model_copy(
        update={"description": "masked-generator-sentinel-should-not-leak"}
    )
    ServerRepository(conn).upsert(server)

    build = generate_site(
        conn,
        tmp_path,
        base_url=BASE_URL,
        now=NOW,
        masked_slugs={"masked-server"},
        masked_scan_succeeded_slugs={"masked-server"},
    )

    assert build.scanned_count == 1
    assert build.masked_count == 1
    badge = json.loads(
        (tmp_path / "servers" / "masked-server" / "badge.json").read_text(encoding="utf-8")
    )
    detail = (tmp_path / "ui" / "servers" / "masked-server" / "index.html").read_text(
        encoding="utf-8"
    )
    catalog = (tmp_path / "index.html").read_text(encoding="utf-8")
    assert badge["message"] == "under review"
    assert "Grade withheld:" in detail
    assert "successful scan" in detail
    assert "masked-generator-sentinel-should-not-leak" not in detail
    assert "No findings on record." not in detail
    assert ">masked<" in catalog
    assert ">unscanned<" not in catalog


def test_generator_rejects_verified_scan_without_operator_mask(conn, tmp_path):
    ServerRepository(conn).upsert(_server("not-masked"))
    with pytest.raises(ValueError, match="must also be operator-masked"):
        generate_site(
            conn,
            tmp_path,
            base_url=BASE_URL,
            masked_scan_succeeded_slugs={"not-masked"},
        )


def test_app_masks_badge_and_detail_routes(conn):
    ServerRepository(conn).upsert(_server("masked-server"))
    ScanRepository(conn).record(_real_scan("masked-server", scanned_at=FRESH_AT))
    masked_client = TestClient(create_app(conn=conn, masked_slugs={"masked-server"}))

    badge = masked_client.get("/servers/masked-server/badge.json").json()
    assert badge["message"] == "under review"

    detail = masked_client.get("/ui/servers/masked-server").text
    assert "Grade withheld:" in detail


def test_app_masks_public_json_routes(conn):
    server = _server("masked-server").model_copy(
        update={"description": "The F grade should not leak."}
    )
    ServerRepository(conn).upsert(server)
    record = _real_scan("masked-server", scanned_at=FRESH_AT).model_copy(
        update={
            "report_ref": "reports/masked-server.json",
            "findings": [
                Finding(
                    rule_id="MCP007",
                    title="Shell execution capability",
                    severity=Severity.CRITICAL,
                    category="shell",
                )
            ]
        }
    )
    ScanRepository(conn).record(record)
    masked_client = TestClient(create_app(conn=conn, masked_slugs={"masked-server"}))

    listed = masked_client.get("/servers").json()[0]
    assert listed["masked"] is True
    assert listed["grade"] == "under review"
    assert listed["composite"] is None
    assert "F" not in json.dumps(listed)

    detail = masked_client.get("/servers/masked-server").json()
    latest = detail["latest_scan"]
    assert latest["masked"] is True
    assert latest["grade"] == "under review"
    assert latest["risk"] is None
    assert latest["findings"] is None
    assert latest["evidence"] is None
    assert latest["report_ref"] is None
    assert "MCP007" not in json.dumps(detail)
    assert "reports/masked-server.json" not in json.dumps(detail)
    assert detail["server"]["description"] == MASKED_SERVER_DESCRIPTION
    assert "The F grade should not leak." not in json.dumps(detail)


def test_app_masks_public_json_server_metadata_before_scan(conn):
    server = _server("masked-server").model_copy(
        update={"description": "The F grade should not leak."}
    )
    ServerRepository(conn).upsert(server)
    masked_client = TestClient(create_app(conn=conn, masked_slugs={"masked-server"}))

    detail = masked_client.get("/servers/masked-server").json()

    assert detail["latest_scan"] is None
    assert detail["server"]["description"] == MASKED_SERVER_DESCRIPTION
    assert "The F grade should not leak." not in json.dumps(detail)
