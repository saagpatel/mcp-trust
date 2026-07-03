"""Trust-grade derivation — the registry's own normalization layer.

This is registry IP, distinct from any engine's raw score. An engine reports a
multi-dimensional risk; we translate that into a single public letter grade
(A best, F worst) a developer can read at a glance before connecting a server.

WHY NOT THE ENGINE'S COMPOSITE
------------------------------
The scanning engine's ``composite`` is a SUM of capability dimensions, so it is
dominated by capability *breadth*, not *danger*. Calibrated against a corpus of
official reference servers (2026-06-13), composite-sum mis-orders badly: a no-op
reasoning server with no I/O (whose unannotated tools trip the spec-default
"assume capable") scored 8.6 — higher than a real filesystem server (7.7) and a
SQL-execution server (8.0). A grade built on that is noise.

WHAT WE DO INSTEAD
------------------
We compute a *danger-weighted* score over the dimensions, emphasizing the ones
that actually separate risk (shell execution above all, then file/network) and
down-weighting the default-inflated dimensions (destructive / exfiltration),
which appear on benign servers as often as dangerous ones. On the calibration
corpus this correctly ranks the genuinely-dangerous SQL server at the top and
the trivial clock/fetch servers at the bottom.

KNOWN LIMITATION (drives the v2 roadmap)
----------------------------------------
A fully unannotated server is indistinguishable from a capable one on every
dimension, so it is still over-graded. The real fix is a second axis —
*transparency* (annotation coverage) — surfaced as a separate caveat rather than
folded into the danger grade. Until then, a low grade on an unannotated server
means "cannot verify it's safe," not "known dangerous." See SPEC roadmap.

Two rules combine: band the danger score into A–F, then apply a *critical cap*
(any CRITICAL finding can never grade above D — one tool-poisoning or rug-pull
vector is disqualifying on its own).
"""

from __future__ import annotations

from mcp_trust.core.models import RiskSummary, Severity, TransparencyLevel, TrustGrade

# Danger weights over the engine's risk dimensions. Calibrated 2026-06-13 against
# the official reference-server corpus; see module docstring for the rationale.
_DIM_WEIGHTS: dict[str, float] = {
    "file_access": 1.2,
    "network_access": 1.0,
    "shell_execution": 2.0,
    "destructive": 0.3,
    "exfiltration": 0.4,
}

# Upper bound (inclusive) of the danger score for each grade. Ordered best→worst.
_BANDS: list[tuple[float, TrustGrade]] = [
    (2.0, TrustGrade.A),
    (3.5, TrustGrade.B),
    (5.0, TrustGrade.C),
    (7.5, TrustGrade.D),
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


def danger_score(risk: RiskSummary) -> float:
    """Registry danger score (0–10) — a danger-weighted aggregate of the risk
    dimensions, distinct from the engine's breadth-dominated ``composite``."""
    raw = sum(weight * getattr(risk, dim) for dim, weight in _DIM_WEIGHTS.items())
    return max(0.0, min(10.0, raw))


def _band(score: float) -> TrustGrade:
    for upper, grade_value in _BANDS:
        if score <= upper:
            return grade_value
    return TrustGrade.F


def _worse(a: TrustGrade, b: TrustGrade) -> TrustGrade:
    """Return the lower-trust of two grades."""
    return a if _ORDER.index(a) >= _ORDER.index(b) else b


def grade(risk: RiskSummary) -> TrustGrade:
    """Derive a public trust grade from a normalized risk summary."""
    banded = _band(danger_score(risk))
    if risk.count(Severity.CRITICAL) > 0:
        return _worse(banded, _CRITICAL_CAP)
    return banded


# Transparency thresholds on annotation coverage (fraction of tools annotated).
_TRANSPARENCY_HIGH = 0.7
_TRANSPARENCY_MEDIUM = 0.3


def transparency(risk: RiskSummary) -> TransparencyLevel:
    """Second axis: how much the server declares about its own behavior.

    This is intentionally NOT folded into the danger grade. A server can be
    genuinely low-risk yet opaque (no annotations), or high-risk and fully
    transparent. ``LOW`` transparency is a caveat — the danger grade is largely
    inferred from spec-defaults — not a verdict of danger.
    """
    coverage = risk.annotation_coverage
    if coverage >= _TRANSPARENCY_HIGH:
        return TransparencyLevel.HIGH
    if coverage >= _TRANSPARENCY_MEDIUM:
        return TransparencyLevel.MEDIUM
    return TransparencyLevel.LOW


def rubric() -> dict[str, object]:
    """Public, read-only description of the grading rubric.

    This is the single source of truth the methodology page renders from, so
    the published weights and bands can never drift from the code that grades.
    Values are copies; mutating the result does not affect grading.
    """
    return {
        "dimension_weights": dict(_DIM_WEIGHTS),
        "grade_bands": [(upper, str(grade_value)) for upper, grade_value in _BANDS],
        # Grade for any score above the last band's upper bound — the terminal
        # value _band() returns. Sourced here so the published table can't drift.
        "worst_grade": str(_ORDER[-1]),
        "critical_cap": str(_CRITICAL_CAP),
        "transparency_thresholds": {
            "high": _TRANSPARENCY_HIGH,
            "medium": _TRANSPARENCY_MEDIUM,
        },
    }
