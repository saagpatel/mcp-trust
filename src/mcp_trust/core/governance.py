"""Public-grading governance policy — staleness, dispute, and correction rules.

This module is the single source for the registry's published-grade governance
posture (adopted from the packet-008 dispositions): a grade is a dated,
versioned, reproducible *opinion*, so it must decay visibly instead of silently
overstaying its evidence, and every graded party gets a standing dispute path.

Policy constants live here — presentation layers render them, they never
redefine them.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from enum import StrEnum

# A published grade older than this is rendered as stale ("pending re-scan"):
# the letter grade greys out on pages and badges. Vendors ship fixes; a grade
# that outlives its scan stops being a supportable opinion.
STALE_AFTER_DAYS = 90

# Committed first-response window for grade disputes.
DISPUTE_SLA_DAYS = 14

# Public dispute channel. The repo is public; issues are open to graded vendors.
DISPUTE_URL = "https://github.com/saagpatel/mcp-trust/issues/new?labels=grade-dispute"

# Badge message for an entry whose published grade is temporarily withheld
# (operator-listed in masked-grades.json) pending provenance verification and
# governance review. Neutral, vendor-facing wording by design.
MASKED_BADGE_MESSAGE = "under review"

# Public description for entries whose grade-bearing catalog metadata is
# temporarily withheld alongside the grade.
MASKED_SERVER_DESCRIPTION = (
    "Server metadata is temporarily withheld while this grade is under governance review."
)


class FreshnessState(StrEnum):
    """Public freshness states; UNKNOWN is deliberately not false/fresh."""

    FRESH = "FRESH"
    STALE = "STALE"
    UNKNOWN = "UNKNOWN"
    NOT_APPLICABLE = "NOT_APPLICABLE"


@dataclass(frozen=True)
class ScanFreshness:
    """Deterministic assessment of one scan timestamp at one evaluation time."""

    state: FreshnessState
    reason: str
    scanned_at: datetime | None
    evaluated_at: datetime
    scan_age_days: float | None
    stale_after: datetime | None

    @property
    def reason_code(self) -> str:
        """Compatibility alias for contracts that name this a reason code."""
        return self.reason


def _as_utc(value: datetime) -> datetime:
    if value.tzinfo is None:
        value = value.replace(tzinfo=UTC)
    return value.astimezone(UTC)


def assess_scan_freshness(
    scanned_at: datetime | str | None,
    now: datetime,
    *,
    scan_exists: bool = True,
    horizon_days: int = STALE_AFTER_DAYS,
) -> ScanFreshness:
    """Assess scan freshness without clamping malformed or future evidence.

    A scan exactly on the horizon remains fresh. Missing required evidence,
    malformed evidence, and future evidence are UNKNOWN. A genuinely absent
    scan is NOT_APPLICABLE.
    """
    evaluated_at = _as_utc(now)
    if not scan_exists:
        return ScanFreshness(
            state=FreshnessState.NOT_APPLICABLE,
            reason="no_scan",
            scanned_at=None,
            evaluated_at=evaluated_at,
            scan_age_days=None,
            stale_after=None,
        )
    if scanned_at is None:
        return ScanFreshness(
            state=FreshnessState.UNKNOWN,
            reason="missing_scanned_at",
            scanned_at=None,
            evaluated_at=evaluated_at,
            scan_age_days=None,
            stale_after=None,
        )
    if isinstance(scanned_at, str):
        try:
            parsed = datetime.fromisoformat(scanned_at.replace("Z", "+00:00"))
        except ValueError:
            return ScanFreshness(
                state=FreshnessState.UNKNOWN,
                reason="malformed_scanned_at",
                scanned_at=None,
                evaluated_at=evaluated_at,
                scan_age_days=None,
                stale_after=None,
            )
    elif isinstance(scanned_at, datetime):
        parsed = scanned_at
    else:
        return ScanFreshness(
            state=FreshnessState.UNKNOWN,
            reason="malformed_scanned_at",
            scanned_at=None,
            evaluated_at=evaluated_at,
            scan_age_days=None,
            stale_after=None,
        )
    parsed = _as_utc(parsed)
    age_seconds = (evaluated_at - parsed).total_seconds()
    if age_seconds < 0:
        return ScanFreshness(
            state=FreshnessState.UNKNOWN,
            reason="future_scanned_at",
            scanned_at=parsed,
            evaluated_at=evaluated_at,
            scan_age_days=None,
            stale_after=None,
        )
    stale_after = parsed + timedelta(days=horizon_days)
    age_days = round(age_seconds / 86400, 6)
    if evaluated_at == stale_after:
        state = FreshnessState.FRESH
        reason = "fresh"
    elif evaluated_at > stale_after:
        state = FreshnessState.STALE
        reason = "age_exceeds_90_days"
    else:
        state = FreshnessState.FRESH
        reason = "fresh"
    return ScanFreshness(
        state=state,
        reason=reason,
        scanned_at=parsed,
        evaluated_at=evaluated_at,
        scan_age_days=age_days,
        stale_after=stale_after,
    )


def is_stale(
    scanned_at: datetime,
    now: datetime,
    *,
    horizon_days: int = STALE_AFTER_DAYS,
) -> bool:
    """True when a scan timestamp is past the staleness horizon.

    Naive datetimes are interpreted as UTC — stored ``scanned_at`` values are
    UTC ISO strings, but SQLite round-trips may drop the offset.
    """
    return (
        assess_scan_freshness(scanned_at, now, horizon_days=horizon_days).state
        is FreshnessState.STALE
    )
