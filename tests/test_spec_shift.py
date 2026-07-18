"""Tests for spec-shift exposure: the dataset, its loader, and its rendering.

The load-bearing property under test is SEPARATION. Spec-shift exposure and the
danger grade answer different questions, and the moment one starts influencing
the other, every published grade silently changes meaning. Several tests here
exist only to make that fusion fail loudly.
"""

from __future__ import annotations

import ast
import json
from pathlib import Path
from types import SimpleNamespace

import pytest
from fastapi.testclient import TestClient

from mcp_trust.api.app import create_app
from mcp_trust.api.web import _spec_shift_card, _spec_shift_notice
from mcp_trust.catalog.seed import seed_into
from mcp_trust.core import spec_shift
from mcp_trust.engine.stub import StubEngine
from mcp_trust.store.db import connect, init_schema
from mcp_trust.store.repository import ServerRepository

# A ruled server whose overall verdict is adverse, and one that is clean.
BREAKING_SLUG = "com-microsoft-powerbi-modeling-mcp-0-5-0-beta-11"
CLEAN_SLUG = "mcp-archived-github"


@pytest.fixture()
def client():
    conn = connect(":memory:")
    init_schema(conn)
    seed_into(ServerRepository(conn))
    return TestClient(create_app(conn=conn, engine=StubEngine()))


# ---------------------------------------------------------------------------
# Dataset integrity
# ---------------------------------------------------------------------------


def test_every_ruled_server_has_all_five_dimensions() -> None:
    """A partial ruling is worse than none: it looks complete and isn't."""
    for slug, record in spec_shift.load()["servers"].items():
        assert set(record["dimensions"]) == {"D1", "D2", "D3", "D4", "D5"}, slug


def test_counts_match_the_records_they_summarize() -> None:
    """The disclosure quotes these counts, so drift here becomes a false claim."""
    records = spec_shift.load()["servers"].values()
    tallied: dict[str, int] = {}
    for record in records:
        tallied[record["overall"]] = tallied.get(record["overall"], 0) + 1
    assert spec_shift.load()["counts"] == tallied


def test_every_adverse_record_carries_a_remediation() -> None:
    """An adverse verdict with no remedy is an accusation, not a finding."""
    for slug, record in spec_shift.load()["servers"].items():
        if record["overall"] in spec_shift.ADVERSE_VERDICTS:
            assert record["remediations"], slug
            for remediation in record["remediations"]:
                assert remediation["effort"] in {
                    "trivial",
                    "small",
                    "substantial",
                    "upstream-blocked",
                }
                assert remediation["action"].strip()


def test_ruled_slugs_are_real_catalog_slugs() -> None:
    """Verdicts keyed to a slug the catalog does not have would render nowhere."""
    seed_file = Path(spec_shift.__file__).parent.parent / "catalog" / "seed_servers.json"
    catalog_slugs = {entry["slug"] for entry in json.loads(seed_file.read_text())}
    assert set(spec_shift.load()["servers"]) <= catalog_slugs


# ---------------------------------------------------------------------------
# Separation from grading — the invariant this module exists to protect
# ---------------------------------------------------------------------------


def _imported_modules(path: Path) -> set[str]:
    """Module names imported by ``path``, via AST rather than text search.

    A substring scan would match the module's own docstring, which discusses the
    separation in prose — the first version of this test failed for exactly that
    reason. Only real import statements count.
    """
    tree = ast.parse(path.read_text(encoding="utf-8"))
    names: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            names.update(alias.name for alias in node.names)
        elif isinstance(node, ast.ImportFrom):
            if node.module:
                names.add(node.module)
            names.update(alias.name for alias in node.names)
    return names


def test_grading_does_not_import_spec_shift() -> None:
    """Grading must not consult conformance. If it ever does, every historical
    grade silently changes meaning, so this is enforced rather than documented."""
    imported = _imported_modules(Path(spec_shift.__file__).parent / "grading.py")
    assert not any("spec_shift" in name for name in imported)


def test_spec_shift_does_not_import_grading() -> None:
    """And the reverse: a conformance verdict must never be derived from a grade."""
    imported = _imported_modules(Path(spec_shift.__file__))
    assert not any("grading" in name for name in imported)


# ---------------------------------------------------------------------------
# Loader behaviour
# ---------------------------------------------------------------------------


def test_unknown_slug_returns_none_not_a_clean_record() -> None:
    assert spec_shift.for_server("no-such-server-xyz") is None


def test_is_adverse_is_false_for_a_missing_record() -> None:
    assert spec_shift.is_adverse(None) is False


def test_summary_adverse_count_matches_counts() -> None:
    summary = spec_shift.summary()
    expected = sum(
        n for verdict, n in summary["counts"].items() if verdict in spec_shift.ADVERSE_VERDICTS
    )
    assert summary["adverse"] == expected
    assert summary["total"] == sum(summary["counts"].values())


# ---------------------------------------------------------------------------
# Catalog disclosure
# ---------------------------------------------------------------------------


def test_catalog_discloses_that_grades_are_not_conformance(client: TestClient) -> None:
    body = client.get("/").text
    assert "not conformance with the MCP" in body
    assert "spec-shift exposure" in body


def test_catalog_notice_states_the_silent_failure_mode(client: TestClient) -> None:
    """The actionable part: these do not announce themselves at runtime."""
    assert "fail silently" in client.get("/").text


def test_catalog_notice_disappears_when_nothing_rendered_is_exposed() -> None:
    """Showing only clean servers must retire the disclosure."""
    assert _spec_shift_notice([{"slug": CLEAN_SLUG}]) == ""


def test_catalog_notice_is_silent_on_an_empty_catalog() -> None:
    """Regression: the first version quoted dataset totals, so a build with an
    empty table still announced "10 of 31 servers below" with nothing below."""
    assert _spec_shift_notice([]) == ""


def test_catalog_notice_counts_only_rendered_servers() -> None:
    """The numbers must describe the page they appear on, not the whole dataset."""
    notice = _spec_shift_notice([{"slug": BREAKING_SLUG}, {"slug": CLEAN_SLUG}])
    assert "1 of 2 servers below" in notice


def test_catalog_notice_ignores_unruled_slugs_in_its_denominator() -> None:
    """An un-audited server is not evidence of anything and must not inflate
    the denominator into implying broader coverage than the audit had."""
    notice = _spec_shift_notice(
        [{"slug": BREAKING_SLUG}, {"slug": "server-added-after-the-audit"}]
    )
    assert "1 of 1 servers below" in notice


# ---------------------------------------------------------------------------
# Detail card
# ---------------------------------------------------------------------------


def test_detail_shows_spec_shift_verdict_for_a_breaking_server(client: TestClient) -> None:
    body = client.get(f"/ui/servers/{BREAKING_SLUG}").text
    assert "Spec-shift exposure" in body
    assert "BREAKS" in body
    assert "What to change" in body


def test_detail_shows_a_clean_verdict_too(client: TestClient) -> None:
    """A conformance signal that only ever appears on failures is a warning
    banner, not a signal — READY has to be visible for BREAKS to mean anything."""
    body = client.get(f"/ui/servers/{CLEAN_SLUG}").text
    assert "Spec-shift exposure" in body
    assert "READY" in body


def test_detail_card_states_the_release_candidate_caveat(client: TestClient) -> None:
    body = client.get(f"/ui/servers/{BREAKING_SLUG}").text
    assert "release candidate" in body
    assert "independent of the danger grade" in body


def test_unaudited_server_is_not_rendered_as_clean() -> None:
    """Absence of a verdict must read as unknown, never as a pass."""
    card = _spec_shift_card("some-server-added-after-the-audit")
    assert "Not audited is not" in card
    assert "READY" not in card


# ---------------------------------------------------------------------------
# Masking — api/AGENTS.md requires masked metadata to stay neutral
# ---------------------------------------------------------------------------


def _audited_source(slug: str):
    """The exact source the verdict was ruled against, as a Server would expose it."""
    return SimpleNamespace(**spec_shift.load()["servers"][slug]["audited_source"])


def test_masked_detail_card_publishes_no_verdict() -> None:
    """A spec-shift verdict is a fresh public trust claim about precisely the
    server whose claims are being withheld, so masking wins over everything."""
    card = _spec_shift_card(BREAKING_SLUG, masked=True, source=_audited_source(BREAKING_SLUG))
    assert "under review" in card
    assert "BREAKS" not in card
    assert "What to change" not in card


def test_masked_card_does_not_imply_the_server_is_clean() -> None:
    """Withholding must not read as a pass in either direction."""
    card = _spec_shift_card(BREAKING_SLUG, masked=True, source=_audited_source(BREAKING_SLUG))
    assert "says nothing about whether the server is exposed" in card
    assert "READY" not in card


def test_masked_rows_are_excluded_from_the_catalog_count() -> None:
    """Aggregating masked servers into a public exposure count republishes what
    the per-row mask withholds."""
    rows = [
        {"slug": BREAKING_SLUG, "masked": True},
        {"slug": CLEAN_SLUG, "masked": False},
    ]
    assert _spec_shift_notice(rows) == ""


def test_unmasked_rows_still_counted_when_a_masked_row_is_present() -> None:
    rows = [
        {"slug": BREAKING_SLUG, "masked": False},
        {"slug": "mcp-reference-fetch", "masked": True},
        {"slug": CLEAN_SLUG, "masked": False},
    ]
    assert "1 of 2 servers below" in _spec_shift_notice(rows)


# ---------------------------------------------------------------------------
# Source binding — a slug is not a stable identity
# ---------------------------------------------------------------------------


def test_every_record_carries_the_audited_source() -> None:
    bound = spec_shift.load()["bound_fields"]
    for slug, record in spec_shift.load()["servers"].items():
        assert set(record["audited_source"]) == set(bound), slug
        assert record["audited_source"]["reference"], slug


def test_verdict_renders_when_the_artifact_still_matches() -> None:
    card = _spec_shift_card(BREAKING_SLUG, source=_audited_source(BREAKING_SLUG))
    assert "BREAKS" in card


@pytest.mark.parametrize(
    "field,value",
    [
        ("reference", "@evil/substituted-package"),
        ("args", ["--different"]),
        ("sandbox_image", "some-other-image:latest"),
        ("command", "another-binary"),
    ],
)
def test_changed_artifact_withholds_the_verdict(field: str, value) -> None:
    """A catalog entry can keep its slug while the artifact underneath changes.
    Publishing the old verdict would be a claim about software nobody audited."""
    source = _audited_source(BREAKING_SLUG)
    setattr(source, field, value)
    card = _spec_shift_card(BREAKING_SLUG, source=source)
    assert "source has changed" in card
    assert "BREAKS" not in card
    assert "What to change" not in card


def test_missing_source_withholds_the_verdict() -> None:
    """No source to verify against is unknown, not a pass."""
    card = _spec_shift_card(BREAKING_SLUG, source=None)
    assert "source has changed" in card
    assert "BREAKS" not in card


def test_matches_audited_source_is_false_without_a_record() -> None:
    assert spec_shift.matches_audited_source(None, _audited_source(BREAKING_SLUG)) is False


def test_live_detail_page_still_publishes_for_an_unchanged_catalog(client: TestClient) -> None:
    """End-to-end: the seeded catalog is what was audited, so verdicts publish."""
    body = client.get(f"/ui/servers/{BREAKING_SLUG}").text
    assert "BREAKS" in body
    assert "source has changed" not in body
