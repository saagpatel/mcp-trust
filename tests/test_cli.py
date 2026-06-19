"""Tests for the Typer CLI."""

from __future__ import annotations

import pytest
from typer.testing import CliRunner

from mcp_trust.cli.main import app

runner = CliRunner()


@pytest.fixture()
def db_path(tmp_path):
    """Path to a fresh temp database file."""
    return str(tmp_path / "test.db")


# ---------------------------------------------------------------------------
# seed
# ---------------------------------------------------------------------------


def test_seed_happy_path(db_path) -> None:
    result = runner.invoke(app, ["seed", "--db", db_path])
    assert result.exit_code == 0, result.output
    assert "Seeded" in result.output
    # Current launch seed contains the seven approved reference servers.
    import re

    match = re.search(r"Seeded (\d+) server", result.output)
    assert match is not None
    assert int(match.group(1)) == 7


def test_seed_idempotent(db_path) -> None:
    """Running seed twice must not raise."""
    result1 = runner.invoke(app, ["seed", "--db", db_path])
    result2 = runner.invoke(app, ["seed", "--db", db_path])
    assert result1.exit_code == 0
    assert result2.exit_code == 0


# ---------------------------------------------------------------------------
# scan
# ---------------------------------------------------------------------------


def test_scan_after_seed(db_path) -> None:
    runner.invoke(app, ["seed", "--db", db_path])
    result = runner.invoke(app, ["scan", "mcp-reference-time", "--db", db_path])
    assert result.exit_code == 0, result.output
    # Output must mention the slug and a grade letter.
    output = result.output
    assert "mcp-reference-time" in output
    import re

    assert re.search(r"\b[ABCDF]\b", output), f"No grade letter found in: {output!r}"


def test_scan_persists_computed_transparency(db_path) -> None:
    runner.invoke(app, ["seed", "--db", db_path])
    result = runner.invoke(app, ["scan", "mcp-reference-time", "--db", db_path])
    assert result.exit_code == 0, result.output

    from mcp_trust.core.models import TransparencyLevel
    from mcp_trust.store.db import connect
    from mcp_trust.store.repository import ScanRepository

    record = ScanRepository(connect(db_path)).latest("mcp-reference-time")
    assert record is not None
    assert record.transparency == TransparencyLevel.LOW


def test_scan_unknown_slug_exits_nonzero(db_path) -> None:
    runner.invoke(app, ["seed", "--db", db_path])
    result = runner.invoke(app, ["scan", "no-such-slug", "--db", db_path])
    assert result.exit_code != 0


def test_scan_without_seed_exits_nonzero(db_path) -> None:
    result = runner.invoke(app, ["scan", "mcp-reference-time", "--db", db_path])
    assert result.exit_code != 0


# ---------------------------------------------------------------------------
# check
# ---------------------------------------------------------------------------


def test_check_after_scan(db_path) -> None:
    runner.invoke(app, ["seed", "--db", db_path])
    runner.invoke(app, ["scan", "mcp-reference-time", "--db", db_path])
    result = runner.invoke(app, ["check", "mcp-reference-time", "--db", db_path])
    assert result.exit_code == 0, result.output
    import re

    assert re.search(r"\b[ABCDF]\b", result.output), f"No grade letter found in: {result.output!r}"


def test_check_no_scan_on_record(db_path) -> None:
    runner.invoke(app, ["seed", "--db", db_path])
    result = runner.invoke(app, ["check", "mcp-reference-time", "--db", db_path])
    # Non-zero exit so CI gates can distinguish "no record" from "found".
    assert result.exit_code == 1
    assert "No scan" in result.output or "no scan" in result.output.lower()


def test_check_seed_scan_check_full_loop(db_path) -> None:
    """Full happy-path: seed → scan → check."""
    r1 = runner.invoke(app, ["seed", "--db", db_path])
    assert r1.exit_code == 0

    r2 = runner.invoke(app, ["scan", "mcp-reference-git", "--db", db_path])
    assert r2.exit_code == 0

    r3 = runner.invoke(app, ["check", "mcp-reference-git", "--db", db_path])
    assert r3.exit_code == 0

    # Grade in check output must match grade in scan output.
    import re

    scan_grade = re.search(r"\b([ABCDF])\b", r2.output)
    check_grade = re.search(r"\b([ABCDF])\b", r3.output)
    assert scan_grade is not None
    assert check_grade is not None
    assert scan_grade.group(1) == check_grade.group(1)
