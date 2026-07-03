"""Contract tests for trust-grade derivation. Pins the calibrated, danger-weighted
grading (2026-06-13 corpus). Engine adapters and the API honor these grades."""

from __future__ import annotations

import pytest

from mcp_trust.core.grading import danger_score, grade, transparency
from mcp_trust.core.models import RiskSummary, Severity, TransparencyLevel, TrustGrade


def _risk(score: float, **sev: int) -> RiskSummary:
    # network_access has weight 1.0, so danger_score == network value (others 0).
    return RiskSummary(
        composite=score,
        network_access=min(10.0, score),
        findings_by_severity={Severity(k): v for k, v in sev.items()},
    )


def test_danger_score_weights_match_calibration() -> None:
    # The real sqlite vector from the calibration corpus -> 9.66.
    sqlite = RiskSummary(
        composite=8.0,
        file_access=1.8,
        network_access=1.5,
        shell_execution=2.7,
        destructive=2.0,
        exfiltration=0.0,
    )
    assert danger_score(sqlite) == pytest.approx(9.66, abs=0.01)


def test_danger_score_is_clamped() -> None:
    maxed = RiskSummary(
        composite=10,
        file_access=10,
        network_access=10,
        shell_execution=10,
        destructive=10,
        exfiltration=10,
    )
    assert danger_score(maxed) == 10.0


@pytest.mark.parametrize(
    ("score", "expected"),
    [
        (1.0, TrustGrade.A),
        (2.0, TrustGrade.A),
        (2.5, TrustGrade.B),
        (3.5, TrustGrade.B),
        (4.0, TrustGrade.C),
        (5.0, TrustGrade.C),
        (6.0, TrustGrade.D),
        (7.5, TrustGrade.D),
        (8.0, TrustGrade.F),
        (9.66, TrustGrade.F),
    ],
)
def test_danger_bands(score: float, expected: TrustGrade) -> None:
    assert grade(_risk(score)) == expected


def test_critical_finding_caps_at_d() -> None:
    # A near-pristine danger score cannot earn an A if a CRITICAL finding exists.
    assert grade(_risk(0.5, critical=1)) == TrustGrade.D


def test_critical_cap_does_not_improve_a_worse_grade() -> None:
    assert grade(_risk(9.0, critical=2)) == TrustGrade.F


@pytest.mark.parametrize(
    ("coverage", "expected"),
    [
        (1.0, TransparencyLevel.HIGH),
        (0.7, TransparencyLevel.HIGH),
        (0.5, TransparencyLevel.MEDIUM),
        (0.3, TransparencyLevel.MEDIUM),
        (0.1, TransparencyLevel.LOW),
        (0.0, TransparencyLevel.LOW),
    ],
)
def test_transparency_levels(coverage: float, expected: TransparencyLevel) -> None:
    assert transparency(RiskSummary(composite=0, annotation_coverage=coverage)) == expected


def test_transparency_is_orthogonal_to_danger() -> None:
    # A low-danger but fully opaque server: grade A, transparency LOW —
    # "cannot verify safe", not "dangerous". The two axes are independent.
    risk = RiskSummary(composite=0, network_access=0.5, annotation_coverage=0.0)
    assert grade(risk) == TrustGrade.A
    assert transparency(risk) == TransparencyLevel.LOW


def test_rubric_matches_grader() -> None:
    """The published rubric must never drift from the code that grades.

    Every weight and band the methodology page exposes has to be the value
    ``grade()``/``danger_score()`` actually use; the worst-grade row must be the
    grade ``grade()`` returns above the last band.
    """
    from mcp_trust.core.grading import rubric

    spec = rubric()
    weights = spec["dimension_weights"]
    assert isinstance(weights, dict)

    # danger_score() must equal the published weighted sum for a probe vector.
    probe = RiskSummary(
        composite=0,
        file_access=1.0,
        network_access=1.0,
        shell_execution=1.0,
        destructive=1.0,
        exfiltration=1.0,
    )
    expected = sum(float(w) for w in weights.values())
    assert danger_score(probe) == pytest.approx(expected)

    # The last band's upper bound + worst_grade must reflect real banding: a
    # score just above the last bound grades as worst_grade.
    last_upper = float(spec["grade_bands"][-1][0])
    over = RiskSummary(composite=0, network_access=min(10.0, last_upper + 1.0))
    assert str(grade(over)) == spec["worst_grade"]
