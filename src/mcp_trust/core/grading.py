"""Trust-grade derivation — the registry's own normalization layer.

This is registry IP, distinct from any engine's raw score. An engine gives us a
composite risk (0–10, higher = riskier) plus findings; we translate that into a
single public letter grade (A best, F worst) that a developer can read at a
glance before connecting a server.

Two rules combine:
1. Band the composite score into A–F.
2. Apply a *critical cap*: a server with any CRITICAL finding can never grade
   above D, regardless of how low its dimensional composite looks — a single
   tool-poisoning or rug-pull vector is disqualifying on its own.
"""

from __future__ import annotations

from mcp_trust.core.models import RiskSummary, Severity, TrustGrade

# Upper bound (inclusive) of composite score for each grade. Ordered best→worst.
_BANDS: list[tuple[float, TrustGrade]] = [
    (1.5, TrustGrade.A),
    (3.0, TrustGrade.B),
    (5.0, TrustGrade.C),
    (7.0, TrustGrade.D),
]

# A server with a CRITICAL finding cannot grade better than this.
_CRITICAL_CAP: TrustGrade = TrustGrade.D

# Grade ordering for "take the worse of" comparisons (lower index = better).
_ORDER: list[TrustGrade] = [
    TrustGrade.A,
    TrustGrade.B,
    TrustGrade.C,
    TrustGrade.D,
    TrustGrade.F,
]


def _band(composite: float) -> TrustGrade:
    for upper, grade in _BANDS:
        if composite <= upper:
            return grade
    return TrustGrade.F


def _worse(a: TrustGrade, b: TrustGrade) -> TrustGrade:
    """Return the lower-trust of two grades."""
    return a if _ORDER.index(a) >= _ORDER.index(b) else b


def grade(risk: RiskSummary) -> TrustGrade:
    """Derive a public trust grade from a normalized risk summary."""
    banded = _band(risk.composite)
    if risk.count(Severity.CRITICAL) > 0:
        return _worse(banded, _CRITICAL_CAP)
    return banded
