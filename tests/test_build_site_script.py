"""Tests for ``scripts/build_site.py`` — the catalog rebuild orchestrator.

The production rebuild must be HONEST by default: a server with no real scan is
shown as ``unscanned``, never given a fabricated letter grade. Stub/demo grades
are an explicit opt-in (``--demo-fill``) and, when used, must be loudly labelled.
"""

from __future__ import annotations

import importlib.util
import json
import sys
from datetime import UTC, datetime
from pathlib import Path

import pytest

from mcp_trust.core.models import Server, ServerSource, SourceKind
from mcp_trust.store.db import connect, init_schema
from mcp_trust.store.repository import ServerRepository

ROOT = Path(__file__).resolve().parents[1]
SCRIPTS = ROOT / "scripts"


def _load_module(name: str, path: Path):
    spec = importlib.util.spec_from_file_location(name, path)
    assert spec is not None
    assert spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


build_site = _load_module("build_site_script", SCRIPTS / "build_site.py")


def test_default_build_is_honest_no_demo_fill(tmp_path: Path) -> None:
    """Default rebuild fabricates no grades: unscanned servers stay unscanned."""
    db = tmp_path / "registry.db"
    out = tmp_path / "site"

    rc = build_site.main(["--db", str(db), "--out", str(out), "--base-url", "https://x.example"])

    assert rc == 0
    index = (out / "index.html").read_text(encoding="utf-8")
    assert "DEMO DATA" not in index  # nothing was really scanned -> no demo banner
    # A seeded-but-unscanned server is reported honestly, not given a letter grade.
    badge = (out / "servers" / "mcp-reference-time" / "badge.json").read_text(encoding="utf-8")
    assert "unscanned" in badge


def test_demo_fill_opt_in_labels_demo_data(tmp_path: Path) -> None:
    """``--demo-fill`` stub-scans unscanned servers and labels them as demo."""
    db = tmp_path / "registry.db"
    out = tmp_path / "site"

    rc = build_site.main(
        [
            "--db",
            str(db),
            "--out",
            str(out),
            "--base-url",
            "https://x.example",
            "--demo-fill",
        ]
    )

    assert rc == 0
    index = (out / "index.html").read_text(encoding="utf-8")
    assert "DEMO DATA" in index  # opt-in stub fill must be loudly labelled
    badge = (out / "servers" / "mcp-reference-time" / "badge.json").read_text(encoding="utf-8")
    assert "(demo)" in badge  # the fabricated grade is marked demo, not bare


def test_build_emits_governance_pages(tmp_path: Path) -> None:
    """Every build ships the methodology, dispute, and corrections pages."""
    db = tmp_path / "registry.db"
    out = tmp_path / "site"

    rc = build_site.main(["--db", str(db), "--out", str(out), "--base-url", "https://x.example"])

    assert rc == 0
    for rel in ("ui/methodology", "ui/dispute", "ui/corrections"):
        assert (out / rel / "index.html").is_file(), f"{rel} page missing from build"


def test_load_corrections_missing_file_is_empty_log(tmp_path: Path) -> None:
    assert build_site._load_corrections(str(tmp_path / "nope.json")) == []


def test_load_corrections_valid_list_loads(tmp_path: Path) -> None:
    path = tmp_path / "corrections.json"
    path.write_text('[{"date": "2026-07-03", "slug": "x"}]', encoding="utf-8")
    assert build_site._load_corrections(str(path)) == [{"date": "2026-07-03", "slug": "x"}]


def test_load_corrections_malformed_shape_fails_loudly(tmp_path: Path) -> None:
    path = tmp_path / "corrections.json"
    path.write_text('{"not": "a list"}', encoding="utf-8")
    try:
        build_site._load_corrections(str(path))
    except ValueError as exc:
        assert "JSON list" in str(exc)
    else:
        raise AssertionError("malformed corrections log must fail the build, not pass silently")


def test_load_masked_slugs_missing_file_means_no_masking(tmp_path: Path) -> None:
    assert build_site._load_masked_slugs(str(tmp_path / "nope.json")) == set()


def test_default_masked_grades_path_is_repo_relative(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    monkeypatch.chdir(tmp_path)
    expected = ROOT / "masked-grades.json"
    assert Path(build_site._DEFAULT_MASKED) == expected
    assert build_site._load_masked_slugs(build_site._DEFAULT_MASKED) == set(
        build_site.json.loads(expected.read_text(encoding="utf-8"))
    )


def test_load_masked_slugs_rejects_non_string_entries(tmp_path: Path) -> None:
    path = tmp_path / "masked-grades.json"
    path.write_text('["ok-slug", 42]', encoding="utf-8")
    try:
        build_site._load_masked_slugs(str(path))
    except ValueError as exc:
        assert "slug strings" in str(exc)
    else:
        raise AssertionError("non-string masked entries must fail the build loudly")


def test_masked_typo_slug_fails_the_build(tmp_path: Path) -> None:
    """A mask the operator ordered must never silently not-apply."""
    db = tmp_path / "registry.db"
    out = tmp_path / "site"
    masked = tmp_path / "masked-grades.json"
    masked.write_text('["no-such-server-slug"]', encoding="utf-8")

    rc = build_site.main(
        [
            "--db",
            str(db),
            "--out",
            str(out),
            "--base-url",
            "https://x.example",
            "--masked-grades",
            str(masked),
        ]
    )

    assert rc == 1  # verify gate catches the typo


def test_masked_scanned_server_badge_reads_under_review(tmp_path: Path) -> None:
    db = tmp_path / "registry.db"
    out = tmp_path / "site"
    masked = tmp_path / "masked-grades.json"
    masked.write_text('["mcp-reference-time"]', encoding="utf-8")

    rc = build_site.main(
        [
            "--db",
            str(db),
            "--out",
            str(out),
            "--base-url",
            "https://x.example",
            "--demo-fill",
            "--masked-grades",
            str(masked),
        ]
    )

    assert rc == 0
    badge = (out / "servers" / "mcp-reference-time" / "badge.json").read_text(encoding="utf-8")
    assert "under review" in badge


def test_verified_candidate_masked_proof_projects_under_review(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    candidate = tmp_path / "candidate"
    candidate.mkdir()
    db = candidate / "registry.db"
    conn = connect(db)
    init_schema(conn)
    ServerRepository(conn).upsert(
        Server(
            slug="masked-proof-server",
            name="Masked proof server",
            description="masked-proof-grade-sentinel",
            source=ServerSource(kind=SourceKind.REMOTE, reference="https://example.test/mcp"),
            added_at=datetime(2026, 7, 18, tzinfo=UTC),
        )
    )
    conn.close()
    masked = tmp_path / "masked-grades.json"
    masked.write_text(json.dumps(["masked-proof-server"]), encoding="utf-8")
    seed = tmp_path / "seed.json"
    seed.write_text("[]", encoding="utf-8")
    out = tmp_path / "site"
    monkeypatch.setattr(
        build_site,
        "verified_masked_scan_slugs",
        lambda *args, **kwargs: frozenset({"masked-proof-server"}),
    )

    rc = build_site.main(
        [
            "--candidate",
            str(candidate),
            "--seed",
            str(seed),
            "--masked-grades",
            str(masked),
            "--out",
            str(out),
            "--base-url",
            "https://x.example",
        ]
    )

    assert rc == 0
    badge = json.loads(
        (out / "servers" / "masked-proof-server" / "badge.json").read_text(encoding="utf-8")
    )
    detail = (out / "ui" / "servers" / "masked-proof-server" / "index.html").read_text(
        encoding="utf-8"
    )
    assert badge["message"] == "under review"
    assert "Grade withheld:" in detail
    assert "masked-proof-grade-sentinel" not in detail
    assert "No findings on record." not in detail


def test_candidate_build_rejects_demo_fill(tmp_path: Path) -> None:
    with pytest.raises(SystemExit):
        build_site.main(
            [
                "--candidate",
                str(tmp_path / "candidate"),
                "--demo-fill",
            ]
        )


def test_corrections_flag_renders_entries(tmp_path: Path) -> None:
    """A committed corrections entry lands on the built corrections page."""
    db = tmp_path / "registry.db"
    out = tmp_path / "site"
    corrections = tmp_path / "corrections.json"
    corrections.write_text(
        '[{"date": "2026-07-03", "slug": "mcp-reference-time",'
        ' "summary": "test entry", "resolution": "F to C"}]',
        encoding="utf-8",
    )

    rc = build_site.main(
        [
            "--db",
            str(db),
            "--out",
            str(out),
            "--base-url",
            "https://x.example",
            "--corrections",
            str(corrections),
        ]
    )

    assert rc == 0
    html = (out / "ui" / "corrections" / "index.html").read_text(encoding="utf-8")
    assert "test entry" in html
