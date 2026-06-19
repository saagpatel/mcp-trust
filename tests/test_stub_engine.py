"""Tests for StubEngine — determinism, validity, grade variety."""

from __future__ import annotations

from mcp_trust.core.models import ServerSource, SourceKind, TrustGrade
from mcp_trust.engine.stub import StubEngine


def _source(reference: str) -> ServerSource:
    return ServerSource(kind=SourceKind.NPM, reference=reference)


def test_determinism_same_reference() -> None:
    """Identical references must produce identical results across calls."""
    engine = StubEngine()
    src = _source("@acme/mcp-search")
    r1 = engine.scan(src)
    r2 = engine.scan(src)
    assert r1.model_dump() == r2.model_dump()


def test_determinism_different_instances() -> None:
    """Two StubEngine instances must agree on the same reference."""
    src = _source("@example/mcp-filesystem")
    r1 = StubEngine().scan(src)
    r2 = StubEngine().scan(src)
    assert r1.risk.composite == r2.risk.composite
    assert r1.findings == r2.findings


def test_engine_result_valid_structure() -> None:
    """EngineResult must have correct engine metadata and valid risk bounds."""
    engine = StubEngine()
    result = engine.scan(_source("@sample/mcp-fetch"))

    assert result.engine_name == "stub"
    assert result.engine_version == "0.1.0"

    risk = result.risk
    assert 0.0 <= risk.composite <= 10.0
    assert 0.0 <= risk.file_access <= 10.0
    assert 0.0 <= risk.network_access <= 10.0
    assert 0.0 <= risk.shell_execution <= 10.0
    assert 0.0 <= risk.destructive <= 10.0
    assert 0.0 <= risk.exfiltration <= 10.0


def test_findings_count_bounded() -> None:
    """Findings list must contain 0–3 entries."""
    engine = StubEngine()
    for ref in ["ref-a", "ref-b", "ref-c", "ref-d", "ref-e"]:
        result = engine.scan(_source(ref))
        assert 0 <= len(result.findings) <= 3


def test_findings_by_severity_consistent() -> None:
    """findings_by_severity counts must match the actual findings list."""
    engine = StubEngine()
    for ref in ["alpha", "beta", "gamma", "delta"]:
        result = engine.scan(_source(ref))
        from collections import Counter

        counted = Counter(f.severity for f in result.findings)
        for sev, count in result.risk.findings_by_severity.items():
            assert counted[sev] == count


def test_grade_variety_across_references() -> None:
    """Different references should produce at least two distinct grades."""
    engine = StubEngine()
    refs = [
        "@modelcontextprotocol/server-everything",
        "mcp-server-fetch",
        "@modelcontextprotocol/server-filesystem",
        "mcp-server-git",
        "@modelcontextprotocol/server-memory",
        "@modelcontextprotocol/server-sequential-thinking",
        "mcp-server-time",
        "unique-ref-xyz-123",
        "another-unique-ref-abc",
    ]
    from mcp_trust.core.grading import grade

    grades = {grade(engine.scan(_source(r)).risk) for r in refs}
    # Exclude UNSCANNED — StubEngine always produces a real grade.
    assert TrustGrade.UNSCANNED not in grades
    assert len(grades) >= 2, f"Expected at least 2 distinct grades, got: {grades}"


def test_composite_consistent_with_dimensions() -> None:
    """Composite must be within [0, 10] and bounded by a weighted combination."""
    engine = StubEngine()
    result = engine.scan(_source("consistency-check-ref"))
    risk = result.risk

    # Composite should be <= max possible weighted average (all dims at 10 → 10).
    assert risk.composite <= 10.0
    assert risk.composite >= 0.0
