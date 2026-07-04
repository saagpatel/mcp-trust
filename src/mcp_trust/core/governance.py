"""Public-grading governance policy — staleness, dispute, and correction rules.

This module is the single source for the registry's published-grade governance
posture (adopted from the packet-008 dispositions): a grade is a dated,
versioned, reproducible *opinion*, so it must decay visibly instead of silently
overstaying its evidence, and every graded party gets a standing dispute path.

Policy constants live here — presentation layers render them, they never
redefine them.
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

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
    if scanned_at.tzinfo is None:
        scanned_at = scanned_at.replace(tzinfo=UTC)
    if now.tzinfo is None:
        now = now.replace(tzinfo=UTC)
    return now - scanned_at > timedelta(days=horizon_days)
