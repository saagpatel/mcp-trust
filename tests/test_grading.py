"""Contract tests for the trust-grade derivation. This pins registry behavior;
engine adapters and the API are expected to honor these grades."""

from __future__ import annotations

import pytest

from mcp_trust.core.grading import grade
from mcp_trust.core.models import RiskSummary, Severity, TrustGrade


def _risk(composite: float, **sev: int) -> RiskSummary:
    return RiskSummary(
        composite=composite, findings_by_severity={Severity(k): v for k, v in sev.items()}
    )


@pytest.mark.parametrize(
    ("composite", "expected"),
    [
        (0.0, TrustGrade.A),
        (1.5, TrustGrade.A),
        (2.0, TrustGrade.B),
        (3.0, TrustGrade.B),
        (4.5, TrustGrade.C),
        (6.0, TrustGrade.D),
        (7.0, TrustGrade.D),
        (9.0, TrustGrade.F),
        (10.0, TrustGrade.F),
    ],
)
def test_composite_bands(composite: float, expected: TrustGrade) -> None:
    assert grade(_risk(composite)) == expected


def test_critical_finding_caps_at_d() -> None:
    # A pristine composite cannot earn an A if a CRITICAL finding exists.
    assert grade(_risk(0.0, critical=1)) == TrustGrade.D


def test_critical_cap_does_not_improve_a_worse_grade() -> None:
    # The cap only ever lowers; an F stays F.
    assert grade(_risk(9.0, critical=2)) == TrustGrade.F
