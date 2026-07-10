"""Tests for core/drift.py — scan-over-scan comparison and cause attribution."""

from __future__ import annotations

import uuid
from datetime import UTC, datetime, timedelta

import pytest

from mcp_trust.core.drift import (
    DriftCause,
    GradeDirection,
    SurfaceComparison,
    diff,
    diff_latest,
)
from mcp_trust.core.models import (
    RiskSummary,
    ScanEvidence,
    ScanRecord,
    ToolEvidence,
    TransparencyLevel,
    TrustGrade,
)


def _risk(**overrides) -> RiskSummary:
    values = {
        "composite": 3.0,
        "file_access": 1.0,
        "network_access": 2.0,
        "shell_execution": 0.5,
        "destructive": 1.0,
        "exfiltration": 0.5,
        "annotation_coverage": 0.8,
    }
    values.update(overrides)
    return RiskSummary(**values)


def _evidence(*tools: tuple[str, str], prompts: int = 0, resources: int = 0) -> ScanEvidence:
    """Evidence with (name, schema_hash) tool pairs."""
    return ScanEvidence(
        tool_count=len(tools),
        tools=[
            ToolEvidence(name=name, has_input_schema=True, input_schema_sha256=sha)
            for name, sha in tools
        ],
        prompt_count=prompts,
        resource_count=resources,
    )


def _scan(
    *,
    slug: str = "test-server",
    grade: TrustGrade = TrustGrade.B,
    transparency: TransparencyLevel = TransparencyLevel.HIGH,
    risk: RiskSummary | None = None,
    evidence: ScanEvidence | None = None,
    engine_version: str = "2.4.0",
    engine_name: str = "mcpaudit",
    at: datetime | None = None,
) -> ScanRecord:
    return ScanRecord(
        id=uuid.uuid4().hex,
        server_slug=slug,
        engine_name=engine_name,
        engine_version=engine_version,
        grade=grade,
        transparency=transparency,
        risk=risk if risk is not None else _risk(),
        findings=[],
        evidence=evidence,
        scanned_at=at if at is not None else datetime.now(tz=UTC),
    )


_BASE_EVIDENCE = (("read_file", "a" * 64), ("write_file", "b" * 64))


def _pair(previous: ScanRecord, current: ScanRecord) -> tuple[ScanRecord, ScanRecord]:
    """Order two records so current is one hour after previous."""
    now = datetime.now(tz=UTC)
    return (
        previous.model_copy(update={"scanned_at": now - timedelta(hours=1)}),
        current.model_copy(update={"scanned_at": now}),
    )


# ---------------------------------------------------------------------------
# No change
# ---------------------------------------------------------------------------


def test_identical_scans_report_no_change() -> None:
    prev, curr = _pair(
        _scan(evidence=_evidence(*_BASE_EVIDENCE)),
        _scan(evidence=_evidence(*_BASE_EVIDENCE)),
    )
    d = diff(prev, curr)
    assert d.cause == DriftCause.NO_CHANGE
    assert d.surface_comparison == SurfaceComparison.UNCHANGED
    assert d.grade_direction == GradeDirection.UNCHANGED
    assert d.danger_score_delta == pytest.approx(0.0)
    assert all(delta == pytest.approx(0.0) for delta in d.dimension_deltas.values())
    assert not d.engine_changed
    assert not d.transparency_changed


def test_engine_bump_without_movement_is_no_change() -> None:
    """An engine version bump that moves nothing is reported as no change."""
    prev, curr = _pair(
        _scan(engine_version="2.3.0", evidence=_evidence(*_BASE_EVIDENCE)),
        _scan(engine_version="2.4.0", evidence=_evidence(*_BASE_EVIDENCE)),
    )
    d = diff(prev, curr)
    assert d.cause == DriftCause.NO_CHANGE
    assert d.engine_changed  # still recorded as a fact


# ---------------------------------------------------------------------------
# Engine-changed attribution (the empirically dominant case in the registry)
# ---------------------------------------------------------------------------


def test_grade_move_with_engine_bump_and_same_surface_is_engine_changed() -> None:
    prev, curr = _pair(
        _scan(
            grade=TrustGrade.F,
            risk=_risk(shell_execution=4.0),
            engine_version="2.1.0",
            evidence=_evidence(*_BASE_EVIDENCE),
        ),
        _scan(
            grade=TrustGrade.B,
            risk=_risk(shell_execution=0.5),
            engine_version="2.3.0",
            evidence=_evidence(*_BASE_EVIDENCE),
        ),
    )
    d = diff(prev, curr)
    assert d.cause == DriftCause.ENGINE_CHANGED
    assert d.grade_direction == GradeDirection.IMPROVED
    assert d.previous_grade == TrustGrade.F
    assert d.current_grade == TrustGrade.B
    assert d.surface_comparison == SurfaceComparison.UNCHANGED
    assert "engine" in d.summary


def test_grade_decline_direction() -> None:
    prev, curr = _pair(
        _scan(grade=TrustGrade.B, engine_version="2.3.0", evidence=_evidence(*_BASE_EVIDENCE)),
        _scan(grade=TrustGrade.F, engine_version="2.4.0", evidence=_evidence(*_BASE_EVIDENCE)),
    )
    d = diff(prev, curr)
    assert d.grade_direction == GradeDirection.DECLINED
    assert d.cause == DriftCause.ENGINE_CHANGED


def test_engine_name_change_counts_as_engine_change() -> None:
    prev, curr = _pair(
        _scan(grade=TrustGrade.B, engine_name="mcpaudit", evidence=_evidence(*_BASE_EVIDENCE)),
        _scan(grade=TrustGrade.C, engine_name="other", evidence=_evidence(*_BASE_EVIDENCE)),
    )
    d = diff(prev, curr)
    assert d.engine_changed
    assert d.cause == DriftCause.ENGINE_CHANGED


# ---------------------------------------------------------------------------
# Surface-changed attribution
# ---------------------------------------------------------------------------


def test_tool_added_is_surface_changed() -> None:
    prev, curr = _pair(
        _scan(evidence=_evidence(*_BASE_EVIDENCE)),
        _scan(evidence=_evidence(*_BASE_EVIDENCE, ("run_query", "c" * 64))),
    )
    d = diff(prev, curr)
    assert d.cause == DriftCause.SURFACE_CHANGED
    assert d.surface_comparison == SurfaceComparison.CHANGED
    assert d.surface_delta is not None
    assert d.surface_delta.tools_added == ["run_query"]
    assert d.surface_delta.tools_removed == []


def test_tool_removed_and_schema_change_are_surface_changed() -> None:
    prev, curr = _pair(
        _scan(evidence=_evidence(("read_file", "a" * 64), ("write_file", "b" * 64))),
        _scan(evidence=_evidence(("read_file", "d" * 64))),
    )
    d = diff(prev, curr)
    assert d.cause == DriftCause.SURFACE_CHANGED
    assert d.surface_delta is not None
    assert d.surface_delta.tools_removed == ["write_file"]
    assert d.surface_delta.tools_changed == ["read_file"]


def test_surface_change_wins_over_engine_change() -> None:
    """When the declared surface moved, that is the attribution even if the
    engine also changed — the input to the grade demonstrably moved."""
    prev, curr = _pair(
        _scan(grade=TrustGrade.B, engine_version="2.3.0", evidence=_evidence(*_BASE_EVIDENCE)),
        _scan(
            grade=TrustGrade.D,
            engine_version="2.4.0",
            evidence=_evidence(*_BASE_EVIDENCE, ("run_shell", "e" * 64)),
        ),
    )
    d = diff(prev, curr)
    assert d.cause == DriftCause.SURFACE_CHANGED
    assert d.engine_changed  # still recorded


def test_prompt_or_resource_count_change_is_surface_changed() -> None:
    prev, curr = _pair(
        _scan(evidence=_evidence(*_BASE_EVIDENCE, prompts=1)),
        _scan(evidence=_evidence(*_BASE_EVIDENCE, prompts=3)),
    )
    d = diff(prev, curr)
    assert d.cause == DriftCause.SURFACE_CHANGED
    assert d.surface_delta is not None
    assert d.surface_delta.prompt_count_delta == 2


def test_surface_change_without_score_movement_is_still_surface_changed() -> None:
    prev, curr = _pair(
        _scan(evidence=_evidence(*_BASE_EVIDENCE)),
        _scan(evidence=_evidence(("read_file", "a" * 64), ("write_all", "b" * 64))),
    )
    d = diff(prev, curr)
    assert d.cause == DriftCause.SURFACE_CHANGED
    assert d.grade_direction == GradeDirection.UNCHANGED


# ---------------------------------------------------------------------------
# Score-moved attribution
# ---------------------------------------------------------------------------


def test_score_movement_same_engine_same_surface_is_score_moved() -> None:
    prev, curr = _pair(
        _scan(risk=_risk(network_access=2.0), evidence=_evidence(*_BASE_EVIDENCE)),
        _scan(risk=_risk(network_access=4.0), evidence=_evidence(*_BASE_EVIDENCE)),
    )
    d = diff(prev, curr)
    assert d.cause == DriftCause.SCORE_MOVED
    assert d.dimension_deltas["network_access"] == pytest.approx(2.0)
    assert d.danger_score_delta == pytest.approx(2.0)  # network weight 1.0


def test_transparency_change_alone_is_movement() -> None:
    prev, curr = _pair(
        _scan(transparency=TransparencyLevel.HIGH, evidence=_evidence(*_BASE_EVIDENCE)),
        _scan(transparency=TransparencyLevel.LOW, evidence=_evidence(*_BASE_EVIDENCE)),
    )
    d = diff(prev, curr)
    assert d.transparency_changed
    assert d.cause == DriftCause.SCORE_MOVED


# ---------------------------------------------------------------------------
# Missing evidence — honesty rules
# ---------------------------------------------------------------------------


def test_missing_evidence_is_unknown_surface_never_unchanged() -> None:
    prev, curr = _pair(
        _scan(evidence=None),
        _scan(evidence=_evidence(*_BASE_EVIDENCE)),
    )
    d = diff(prev, curr)
    assert d.surface_comparison == SurfaceComparison.UNKNOWN
    assert d.surface_delta is None
    assert d.cause == DriftCause.NO_CHANGE  # nothing moved
    assert "unavailable" in d.summary


def test_movement_with_unknown_surface_and_same_engine_is_undetermined() -> None:
    """Same engine, missing evidence, moved scores: the registry cannot name the
    cause and must say so rather than guessing environment variance."""
    prev, curr = _pair(
        _scan(grade=TrustGrade.B, risk=_risk(network_access=1.0), evidence=None),
        _scan(grade=TrustGrade.C, risk=_risk(network_access=4.5), evidence=None),
    )
    d = diff(prev, curr)
    assert d.surface_comparison == SurfaceComparison.UNKNOWN
    assert d.cause == DriftCause.UNDETERMINED


def test_movement_with_unknown_surface_and_engine_change_is_engine_changed() -> None:
    prev, curr = _pair(
        _scan(grade=TrustGrade.F, engine_version="2.1.0", evidence=None),
        _scan(grade=TrustGrade.B, engine_version="2.3.0", evidence=None),
    )
    d = diff(prev, curr)
    assert d.cause == DriftCause.ENGINE_CHANGED
    assert d.surface_comparison == SurfaceComparison.UNKNOWN
    # The summary must keep the uncertainty visible.
    assert "unavailable" in d.summary or "cannot be ruled out" in d.summary


# ---------------------------------------------------------------------------
# Input validation
# ---------------------------------------------------------------------------


def test_diff_rejects_mismatched_slugs() -> None:
    prev, curr = _pair(_scan(slug="server-one"), _scan(slug="server-two"))
    with pytest.raises(ValueError, match="slug"):
        diff(prev, curr)


def test_drift_serializes_to_json_including_computed_fields() -> None:
    prev, curr = _pair(
        _scan(evidence=_evidence(*_BASE_EVIDENCE)),
        _scan(evidence=_evidence(*_BASE_EVIDENCE)),
    )
    d = diff(prev, curr)
    dumped = d.model_dump(mode="json")
    assert dumped["server_slug"] == "test-server"
    assert dumped["cause"] == "no-change"
    # Derived fields are computed, not stored, but must still serialize so the
    # archived report is self-contained.
    assert dumped["grade_direction"] == "unchanged"
    assert dumped["danger_score_delta"] == pytest.approx(0.0)
    assert dumped["engine_changed"] is False
    assert dumped["transparency_changed"] is False
    assert "no assessment change" in dumped["summary"]


# ---------------------------------------------------------------------------
# diff_latest — the history ordering contract
# ---------------------------------------------------------------------------


def test_diff_latest_orders_newest_first_history_correctly() -> None:
    """diff_latest takes a newest-first history and must assign previous/current
    the right way round — a declining grade must not be reported as improving."""
    prev, curr = _pair(
        _scan(grade=TrustGrade.B, engine_version="2.3.0", evidence=_evidence(*_BASE_EVIDENCE)),
        _scan(grade=TrustGrade.F, engine_version="2.4.0", evidence=_evidence(*_BASE_EVIDENCE)),
    )
    d = diff_latest([curr, prev])  # newest first, as ScanRepository.history returns
    assert d is not None
    assert d.previous_grade == TrustGrade.B
    assert d.current_grade == TrustGrade.F
    assert d.grade_direction == GradeDirection.DECLINED


def test_diff_latest_returns_none_below_two_scans() -> None:
    assert diff_latest([]) is None
    assert diff_latest([_scan()]) is None
