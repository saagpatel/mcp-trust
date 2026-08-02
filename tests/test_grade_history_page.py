"""The public grade-history timeline on a server detail page.

The registry publishes grades that move between deploys. This surface is the
public record of that movement: every scan on record for one server, oldest
first, with the cause of each step attributed from the inputs the registry
already stores (engine identity and declared tool surface).

The properties under test are the honest ones. A masked entry withholds its
letters across the whole history, not just the latest row. An attribution the
data cannot support renders as undetermined rather than guessed. The corpus
aggregate on the methodology page is computed from the same primitive that
builds the table, so the two can never disagree.
"""

from __future__ import annotations

import re
from datetime import UTC, datetime
from pathlib import Path

from mcp_trust.api.web import render_detail, render_methodology
from mcp_trust.core.drift import DriftCause, corpus_history_totals, grade_timeline
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

BASE_URL = "https://registry.example"
BUILD_DATE = datetime(2026, 8, 1, 12, 0, tzinfo=UTC)

# A bare grade letter as an element's entire text content — how every grade the
# site publishes is rendered (hero tile and pill alike). A masked page must
# contain no such node anywhere in its output.
_BARE_GRADE_LETTER = re.compile(r">\s*([A-F])\s*<")


def _server(slug: str = "history-server") -> Server:
    return Server(
        slug=slug,
        name="History Server",
        description="Fixture server with a known scan history.",
        source=ServerSource(kind=SourceKind.NPM, reference=f"@test/{slug}"),
        added_at=datetime(2026, 6, 1, tzinfo=UTC),
    )


# Shared default surface. Passing ``evidence=None`` to ``_scan`` means a scan
# with NO recorded evidence — the state that makes a surface incomparable.
_DEFAULT_EVIDENCE = ScanEvidence(tools=[ToolEvidence(name="search", input_schema_sha256="a" * 64)])


def _scan(
    *,
    ident: str,
    grade: TrustGrade,
    day: int,
    month: int = 6,
    engine_version: str = "2.1.0",
    composite: float = 7.0,
    evidence: ScanEvidence | None = _DEFAULT_EVIDENCE,
    slug: str = "history-server",
) -> ScanRecord:
    return ScanRecord(
        id=ident,
        server_slug=slug,
        engine_name="mcpaudit",
        engine_version=engine_version,
        grade=grade,
        risk=RiskSummary(composite=composite),
        evidence=evidence,
        scanned_at=datetime(2026, month, day, 6, 0, tzinfo=UTC),
    )


def _three_scan_history() -> list[ScanRecord]:
    """Newest-first, as ``ScanRepository.history()`` returns it.

    Steps: first scan on record, an identical re-scan, then a grade movement
    that coincides with an engine bump and an unchanged declared surface.
    """
    return [
        _scan(
            ident="s3", grade=TrustGrade.B, day=3, month=7, engine_version="2.3.0", composite=3.0
        ),
        _scan(ident="s2", grade=TrustGrade.F, day=27),
        _scan(ident="s1", grade=TrustGrade.F, day=20),
    ]


# ---------------------------------------------------------------------------
# Core: per-pair attribution over a stored history
# ---------------------------------------------------------------------------


def test_timeline_is_oldest_first_and_attributes_every_step() -> None:
    timeline = grade_timeline(_three_scan_history())

    assert [e.scanned_at.date().isoformat() for e in timeline] == [
        "2026-06-20",
        "2026-06-27",
        "2026-07-03",
    ]
    assert [e.cause for e in timeline] == [
        None,  # nothing earlier to compare the first scan against
        DriftCause.NO_CHANGE,
        DriftCause.ENGINE_CHANGED,
    ]
    assert [e.grade_changed for e in timeline] == [False, False, True]
    assert timeline[-1].engine == "mcpaudit 2.3.0"


def test_timeline_reports_undetermined_when_no_surface_is_comparable() -> None:
    """Same engine, movement, and no evidence on one side: not attributable."""
    history = [
        _scan(ident="new", grade=TrustGrade.C, day=27, composite=5.0, evidence=None),
        _scan(ident="old", grade=TrustGrade.F, day=20, composite=7.0),
    ]
    timeline = grade_timeline(history)
    assert timeline[-1].cause is DriftCause.UNDETERMINED


def test_empty_history_has_no_timeline() -> None:
    assert grade_timeline([]) == []


# ---------------------------------------------------------------------------
# Detail page: the rendered table
# ---------------------------------------------------------------------------


def _detail(history: list[ScanRecord], **kwargs: object) -> str:
    return render_detail(
        _server(),
        history[0] if history else None,
        base_url=BASE_URL,
        now=BUILD_DATE,
        history=history,
        **kwargs,  # type: ignore[arg-type]
    )


def test_detail_renders_exact_history_rows() -> None:
    html = _detail(_three_scan_history())

    assert (
        '<tr><td class="hist-num">2026-06-20 06:00</td>'
        '<td><span class="pill" style="background:#d1242f">F</span></td>'
        '<td class="hist-num">mcpaudit 2.1.0</td>'
        "<td>First scan on record</td></tr>"
        '<tr><td class="hist-num">2026-06-27 06:00</td>'
        '<td><span class="pill" style="background:#d1242f">F</span></td>'
        '<td class="hist-num">mcpaudit 2.1.0</td>'
        '<td class="hist-quiet">No change</td></tr>'
        '<tr><td class="hist-num">2026-07-03 06:00</td>'
        '<td><span class="pill" style="background:#487500">B</span></td>'
        '<td class="hist-num">mcpaudit 2.3.0</td>'
        "<td>Scanner engine changed</td></tr>"
    ) in html


def test_history_table_headers_are_scoped_column_headers() -> None:
    html = _detail(_three_scan_history())
    assert (
        '<thead><tr><th scope="col">Scanned (UTC)</th><th scope="col">Grade</th>'
        '<th scope="col">Engine</th><th scope="col">Attributed cause</th></tr></thead>'
    ) in html


def test_history_intro_states_what_the_record_shows() -> None:
    html = _detail(_three_scan_history())
    assert (
        "3 scans on record between 2026-06-20 and 2026-07-03. The grade changed once in that time."
    ) in html


def test_history_intro_states_a_flat_record_plainly() -> None:
    history = [
        _scan(ident="s2", grade=TrustGrade.F, day=27),
        _scan(ident="s1", grade=TrustGrade.F, day=20),
    ]
    html = _detail(history)
    assert (
        "2 scans on record between 2026-06-20 and 2026-06-27. "
        "The grade has not changed across them."
    ) in html


def test_single_scan_history_reads_confident_not_apologetic() -> None:
    """One scan is a complete record of one scan, stated as such."""
    html = _detail([_scan(ident="only", grade=TrustGrade.B, day=20)])
    assert (
        "One scan on record, 2026-06-20. There is no earlier scan to compare it against."
    ) in html
    assert "<td>First scan on record</td>" in html


def test_history_carries_its_generation_date() -> None:
    html = _detail(_three_scan_history())
    assert "Generated 2026-08-01" in html


def test_history_states_attribution_is_not_proof() -> None:
    html = _detail(_three_scan_history())
    assert "attribution" in html
    assert "not proof" in html


def test_unscanned_server_renders_no_history_section() -> None:
    html = render_detail(_server(), None, base_url=BASE_URL, now=BUILD_DATE, history=[])
    assert "Grade history" not in html


def test_engine_change_with_no_comparable_surface_says_so() -> None:
    history = [
        _scan(ident="new", grade=TrustGrade.B, day=27, engine_version="2.3.0", evidence=None),
        _scan(ident="old", grade=TrustGrade.F, day=20),
    ]
    html = _detail(history)
    assert "<td>Scanner engine changed; surface not comparable</td>" in html


def test_tool_surface_change_is_named_in_words() -> None:
    history = [
        _scan(
            ident="new",
            grade=TrustGrade.F,
            day=27,
            evidence=ScanEvidence(
                tools=[
                    ToolEvidence(name="search", input_schema_sha256="a" * 64),
                    ToolEvidence(name="write_file", input_schema_sha256="b" * 64),
                ]
            ),
        ),
        _scan(ident="old", grade=TrustGrade.F, day=20),
    ]
    html = _detail(history)
    assert "<td>Tool surface changed</td>" in html


# ---------------------------------------------------------------------------
# Masking: the letters stay withheld across the whole history
# ---------------------------------------------------------------------------


def test_masked_history_withholds_letters_but_keeps_dates_and_engines() -> None:
    html = _detail(_three_scan_history(), masked=True)

    assert "Grade history" in html
    assert "2026-06-20" in html
    assert "mcpaudit 2.3.0" in html
    assert '<td class="hist-withheld">withheld</td>' in html
    assert _BARE_GRADE_LETTER.search(html) is None


def test_masked_generated_site_leaks_no_grade_letter_anywhere(tmp_path: Path) -> None:
    conn = connect(":memory:")
    init_schema(conn)
    ServerRepository(conn).upsert(_server())
    scans = ScanRepository(conn)
    for scan in reversed(_three_scan_history()):
        scans.record(scan)

    generate_site(
        conn,
        tmp_path,
        base_url=BASE_URL,
        now=BUILD_DATE,
        masked_slugs={"history-server"},
    )
    detail = (tmp_path / "ui" / "servers" / "history-server" / "index.html").read_text()

    assert _BARE_GRADE_LETTER.search(detail) is None
    assert "F</span>" not in detail
    assert "B</span>" not in detail
    # The history is still published — masking withholds the verdict, not the record.
    assert "3 scans on record" in detail
    assert "Scanner engine changed" in detail


def test_unmasked_generated_site_renders_the_history_table(tmp_path: Path) -> None:
    conn = connect(":memory:")
    init_schema(conn)
    ServerRepository(conn).upsert(_server())
    scans = ScanRepository(conn)
    for scan in reversed(_three_scan_history()):
        scans.record(scan)

    generate_site(conn, tmp_path, base_url=BASE_URL, now=BUILD_DATE)
    detail = (tmp_path / "ui" / "servers" / "history-server" / "index.html").read_text()

    assert '<td class="hist-num">2026-06-27 06:00</td>' in detail
    assert "<td>Scanner engine changed</td>" in detail
    assert "Generated 2026-08-01" in detail


# ---------------------------------------------------------------------------
# Corpus aggregate on the methodology page
# ---------------------------------------------------------------------------


def _other_history() -> list[ScanRecord]:
    return [
        _scan(ident="o2", grade=TrustGrade.A, day=27, slug="other", evidence=None),
        _scan(ident="o1", grade=TrustGrade.A, day=20, slug="other"),
    ]


def test_corpus_totals_count_scans_changes_and_comparability() -> None:
    totals = corpus_history_totals([_three_scan_history(), _other_history()])

    assert totals.servers == 2
    assert totals.scans == 5
    assert totals.grade_changes == 1
    assert totals.grade_changes_with_engine_change == 1
    assert totals.surface_changes == 0
    assert totals.comparable_pairs == 2  # the 'other' pair has evidence on one side only
    assert totals.first_scanned_at.date().isoformat() == "2026-06-20"
    assert totals.last_scanned_at.date().isoformat() == "2026-07-03"


def test_corpus_totals_are_empty_for_an_empty_registry() -> None:
    totals = corpus_history_totals([])
    assert totals.servers == 0
    assert totals.scans == 0
    assert totals.first_scanned_at is None


def test_methodology_aggregate_line_is_computed_from_the_totals() -> None:
    totals = corpus_history_totals([_three_scan_history(), _other_history()])
    html = render_methodology(history_totals=totals)

    assert (
        "Across 5 scans of 2 servers recorded between 2026-06-20 and 2026-07-03, "
        "this registry has recorded 1 grade change. "
        "It coincided with a change of scanner engine version. "
        "No declared tool surface changed in the 2 scan-to-scan comparisons "
        "where evidence was recorded on both sides."
    ) in html


def test_methodology_omits_the_aggregate_when_no_totals_are_supplied() -> None:
    assert "this registry has recorded" not in render_methodology()


def test_methodology_aggregate_makes_no_forward_looking_scan_promise() -> None:
    totals = corpus_history_totals([_three_scan_history()])
    html = render_methodology(history_totals=totals)
    aggregate = html[html.index("Across 3 scans") : html.index("Across 3 scans") + 600]
    for promise in ("will be", "weekly", "every week", "scheduled", "upcoming"):
        assert promise not in aggregate.lower()
