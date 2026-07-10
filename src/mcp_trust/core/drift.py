"""Scan-over-scan drift — comparison and cause attribution for grade movement.

The registry re-scans its corpus on a schedule, and every re-scan can move a
published grade. A grade that moves without an explanation is a data-quality
defect: a consumer (or the graded server's author) cannot tell "the server's
declared surface changed" apart from "the grading input changed". This module
compares two persisted scans of the same server and attributes the movement to
the best-supported cause, so every published change carries its explanation.

ATTRIBUTION MODEL
-----------------
The comparison looks at three recorded inputs and one output:

- the declared tool surface (readback evidence: tool names, schema hashes,
  annotation flags, prompt/resource counts),
- the engine identity (name + version),
- the risk numbers / transparency the engine reported,
- the resulting grade.

Precedence: an observed surface change wins (the input to the grade
demonstrably moved), then an engine change (no observed surface change, so the
movement tracks the grader version — though when evidence is missing the
surface is unknown, not known-same), then same-engine/same-surface score
movement (scan-environment variance). Movement with no comparable surface and
no engine change is ``UNDETERMINED`` — the registry names what it cannot
attribute rather than guessing.

HONESTY RULE (inherited from the review guidance)
-------------------------------------------------
Missing evidence on either side is an *unknown* surface comparison, never
"unchanged". Summaries keep that uncertainty visible. A present-but-empty
evidence capture is different: the real engine raises rather than persisting a
failed readback, so empty evidence records an *observed* empty surface and
compares normally.
"""

from __future__ import annotations

from collections.abc import Sequence
from datetime import datetime
from enum import StrEnum

from pydantic import BaseModel, Field, computed_field

from mcp_trust.core import grading
from mcp_trust.core.models import (
    ScanEvidence,
    ScanRecord,
    TransparencyLevel,
    TrustGrade,
)

# Float tolerance for "did a 0-10 score move": far below any engine-meaningful
# delta, far above JSON round-trip noise.
_EPSILON = 1e-6

# Best-to-worst grade order for direction, from the grading rubric. Persisted
# scans always carry a letter grade; UNSCANNED is appended so the comparison
# stays total even for an out-of-band row.
_GRADE_ORDER_TOTAL: tuple[TrustGrade, ...] = (*grading.GRADE_ORDER, TrustGrade.UNSCANNED)


class DriftCause(StrEnum):
    """Best-supported attribution for movement between two scans."""

    SURFACE_CHANGED = "surface-changed"  # the declared tool surface moved
    ENGINE_CHANGED = "engine-changed"  # engine changed, no observed surface change
    SCORE_MOVED = "score-moved"  # same surface + engine → scan-environment variance
    UNDETERMINED = "undetermined"  # movement, but no comparable surface and same engine
    NO_CHANGE = "no-change"


class GradeDirection(StrEnum):
    IMPROVED = "improved"
    DECLINED = "declined"
    UNCHANGED = "unchanged"


class SurfaceComparison(StrEnum):
    """Outcome of comparing declared tool surfaces. ``UNKNOWN`` when evidence
    is missing on either side — deliberately distinct from ``UNCHANGED``."""

    UNCHANGED = "unchanged"
    CHANGED = "changed"
    UNKNOWN = "unknown"


class ToolSurfaceDelta(BaseModel):
    """Per-tool differences between two evidence captures."""

    tools_added: list[str] = Field(default_factory=list)
    tools_removed: list[str] = Field(default_factory=list)
    tools_changed: list[str] = Field(
        default_factory=list,
        description="Tools present in both scans whose schema hash or annotation flags differ.",
    )
    prompt_count_delta: int = 0
    resource_count_delta: int = 0

    def any_change(self) -> bool:
        return bool(
            self.tools_added
            or self.tools_removed
            or self.tools_changed
            or self.prompt_count_delta
            or self.resource_count_delta
        )


class ScanDrift(BaseModel):
    """The attributed comparison of two scans of one server.

    Everything derivable from the stored fields (deltas, direction, summary) is
    computed, not stored, so a serialized report can never carry a delta that
    disagrees with its own before/after values.
    """

    server_slug: str
    previous_scan_id: str
    current_scan_id: str
    previous_scanned_at: datetime
    current_scanned_at: datetime
    previous_grade: TrustGrade
    current_grade: TrustGrade
    previous_transparency: TransparencyLevel
    current_transparency: TransparencyLevel
    previous_danger_score: float
    current_danger_score: float
    dimension_deltas: dict[str, float]
    previous_engine: str
    current_engine: str
    surface_comparison: SurfaceComparison
    surface_delta: ToolSurfaceDelta | None = Field(
        default=None, description="None when the surface comparison is unknown."
    )
    cause: DriftCause

    @computed_field  # type: ignore[prop-decorator]
    @property
    def grade_direction(self) -> GradeDirection:
        if self.previous_grade == self.current_grade:
            return GradeDirection.UNCHANGED
        current = _GRADE_ORDER_TOTAL.index(self.current_grade)
        previous = _GRADE_ORDER_TOTAL.index(self.previous_grade)
        return GradeDirection.IMPROVED if current < previous else GradeDirection.DECLINED

    @computed_field  # type: ignore[prop-decorator]
    @property
    def transparency_changed(self) -> bool:
        return self.previous_transparency != self.current_transparency

    @computed_field  # type: ignore[prop-decorator]
    @property
    def danger_score_delta(self) -> float:
        return self.current_danger_score - self.previous_danger_score

    @computed_field  # type: ignore[prop-decorator]
    @property
    def engine_changed(self) -> bool:
        return self.previous_engine != self.current_engine

    @computed_field  # type: ignore[prop-decorator]
    @property
    def summary(self) -> str:
        return _summarize(self)


class DriftReport(BaseModel):
    """The corpus-wide drift report — the shape the weekly lane archives.

    Owning this as a typed model (rather than an ad-hoc dict at the emit site)
    keeps the archived artifact's contract in core, next to ``ScanDrift``.
    """

    generated_at: datetime
    compared: int
    skipped_single_scan: int = Field(
        description="Servers with fewer than two scans on record — nothing to compare."
    )
    skipped_invalid: int = Field(
        default=0,
        description="Servers whose scan history could not be read (corrupt rows).",
    )
    drifts: list[ScanDrift] = Field(default_factory=list)


def _surface_delta(previous: ScanEvidence, current: ScanEvidence) -> ToolSurfaceDelta:
    prev_tools = {t.name: t for t in previous.tools}
    curr_tools = {t.name: t for t in current.tools}
    changed = [
        name
        for name in sorted(prev_tools.keys() & curr_tools.keys())
        if (
            prev_tools[name].input_schema_sha256 != curr_tools[name].input_schema_sha256
            or prev_tools[name].has_input_schema != curr_tools[name].has_input_schema
            or prev_tools[name].has_annotations != curr_tools[name].has_annotations
        )
    ]
    return ToolSurfaceDelta(
        tools_added=sorted(curr_tools.keys() - prev_tools.keys()),
        tools_removed=sorted(prev_tools.keys() - curr_tools.keys()),
        tools_changed=changed,
        prompt_count_delta=current.prompt_count - previous.prompt_count,
        resource_count_delta=current.resource_count - previous.resource_count,
    )


def _compare_surfaces(
    previous: ScanEvidence | None, current: ScanEvidence | None
) -> tuple[SurfaceComparison, ToolSurfaceDelta | None]:
    if previous is None or current is None:
        return SurfaceComparison.UNKNOWN, None
    delta = _surface_delta(previous, current)
    if delta.any_change():
        return SurfaceComparison.CHANGED, delta
    return SurfaceComparison.UNCHANGED, delta


def _surface_note(comparison: SurfaceComparison, delta: ToolSurfaceDelta | None) -> str:
    if comparison == SurfaceComparison.UNKNOWN:
        return "tool-surface comparison unavailable (evidence missing on at least one scan)"
    if comparison == SurfaceComparison.UNCHANGED:
        return "declared tool surface unchanged"
    assert delta is not None
    parts = [
        f"+{len(delta.tools_added)}/-{len(delta.tools_removed)} tools",
        f"{len(delta.tools_changed)} changed",
    ]
    if delta.prompt_count_delta:
        parts.append(f"prompts {delta.prompt_count_delta:+d}")
    if delta.resource_count_delta:
        parts.append(f"resources {delta.resource_count_delta:+d}")
    return f"declared tool surface changed ({', '.join(parts)})"


def _summarize(d: ScanDrift) -> str:
    note = _surface_note(d.surface_comparison, d.surface_delta)
    grade_part = f"grade {d.previous_grade} -> {d.current_grade}"
    engine_part = f"{d.previous_engine} -> {d.current_engine}"

    if d.cause == DriftCause.NO_CHANGE:
        return f"no assessment change ({grade_part}); {note}"
    if d.cause == DriftCause.SURFACE_CHANGED:
        summary = f"{note}; {grade_part}"
        if d.engine_changed:
            summary += f"; engine also changed ({engine_part})"
        return summary
    if d.cause == DriftCause.ENGINE_CHANGED:
        prefix = f"{grade_part} under engine change ({engine_part}); {note} — "
        if d.surface_comparison == SurfaceComparison.UNCHANGED:
            return (
                prefix + "re-evaluation of the same declared surface, not an observed server change"
            )
        return prefix + (
            "engine re-evaluation is the likely cause, but a surface change cannot be ruled out"
        )
    if d.cause == DriftCause.SCORE_MOVED:
        return (
            f"scores moved under the same engine and unchanged declared surface "
            f"(danger {d.previous_danger_score:.2f} -> "
            f"{d.current_danger_score:.2f}; {grade_part})"
        )
    return (
        f"assessment moved ({grade_part}) with the same engine and no comparable "
        f"surface evidence — cause cannot be attributed; {note}"
    )


def diff(previous: ScanRecord, current: ScanRecord) -> ScanDrift:
    """Compare two scans of the same server and attribute any movement.

    *previous* and *current* are caller-ordered (oldest first); the function
    validates only that both records grade the same server. Prefer
    :func:`diff_latest` when starting from a stored history, so the ordering
    contract lives in one place.
    """
    if previous.server_slug != current.server_slug:
        raise ValueError(
            f"cannot diff scans of different servers: slug "
            f"{previous.server_slug!r} vs {current.server_slug!r}"
        )

    surface_comparison, surface_delta = _compare_surfaces(previous.evidence, current.evidence)

    previous_danger = grading.danger_score(previous.risk)
    current_danger = grading.danger_score(current.risk)
    dimension_deltas = {
        dim: getattr(current.risk, dim) - getattr(previous.risk, dim)
        for dim in grading.DANGER_DIMENSIONS
    }

    engine_changed = (
        previous.engine_name != current.engine_name
        or previous.engine_version != current.engine_version
    )
    moved = (
        previous.grade != current.grade
        or previous.transparency != current.transparency
        or abs(current_danger - previous_danger) > _EPSILON
        or any(abs(delta) > _EPSILON for delta in dimension_deltas.values())
    )

    if surface_comparison == SurfaceComparison.CHANGED:
        cause = DriftCause.SURFACE_CHANGED
    elif not moved:
        cause = DriftCause.NO_CHANGE
    elif engine_changed:
        cause = DriftCause.ENGINE_CHANGED
    elif surface_comparison == SurfaceComparison.UNCHANGED:
        cause = DriftCause.SCORE_MOVED
    else:
        cause = DriftCause.UNDETERMINED

    return ScanDrift(
        server_slug=current.server_slug,
        previous_scan_id=previous.id,
        current_scan_id=current.id,
        previous_scanned_at=previous.scanned_at,
        current_scanned_at=current.scanned_at,
        previous_grade=previous.grade,
        current_grade=current.grade,
        previous_transparency=previous.transparency,
        current_transparency=current.transparency,
        previous_danger_score=previous_danger,
        current_danger_score=current_danger,
        dimension_deltas=dimension_deltas,
        previous_engine=f"{previous.engine_name} {previous.engine_version}",
        current_engine=f"{current.engine_name} {current.engine_version}",
        surface_comparison=surface_comparison,
        surface_delta=surface_delta,
        cause=cause,
    )


def diff_latest(history: Sequence[ScanRecord]) -> ScanDrift | None:
    """Compare the newest scan in a newest-first *history* against the one
    before it, or return ``None`` when there are fewer than two scans.

    This owns the ordering contract between ``ScanRepository.history()``
    (newest first) and :func:`diff` (oldest first), so callers cannot invert it.
    """
    if len(history) < 2:
        return None
    return diff(history[1], history[0])
