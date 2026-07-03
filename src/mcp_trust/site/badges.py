"""shields.io endpoint badges for the static catalog.

A badge must never overstate confidence: a stub-derived grade is suffixed
``(demo)`` and an unscanned server reads ``unscanned``, so a badge embedded in a
README can't silently imply a real scan happened.
"""

from __future__ import annotations

from typing import Any

from mcp_trust.core.governance import MASKED_BADGE_MESSAGE
from mcp_trust.core.provenance import ScanProvenance

# shields.io named colours per grade. Single source of truth: the live badge
# route (api.app) and the static badge files both build payloads here.
_BADGE_COLORS: dict[str, str] = {
    "A": "brightgreen",
    "B": "green",
    "C": "yellow",
    "D": "orange",
    "F": "red",
    "unscanned": "lightgrey",
}


def badge_payload(
    grade: str,
    provenance: ScanProvenance,
    *,
    stale: bool = False,
    masked: bool = False,
) -> dict[str, Any]:
    """Build a shields.io *endpoint* JSON payload for one server's grade.

    The ``message`` is honesty-gated by *provenance*: ``UNSCANNED`` → ``unscanned``,
    ``DEMO`` → ``"<grade> (demo)"``, ``REAL`` → the bare grade letter. A *stale*
    real grade is suffixed ``(stale)`` and greys out — a badge embedded in a
    README must never present an expired scan as a current verdict. A *masked*
    grade (operator-withheld pending governance review) shows no letter at all.
    """
    grade_str = str(grade)

    if provenance is ScanProvenance.UNSCANNED:
        return {
            "schemaVersion": 1,
            "label": "mcp trust",
            "message": "unscanned",
            "color": "lightgrey",
        }

    if masked:
        return {
            "schemaVersion": 1,
            "label": "mcp trust",
            "message": MASKED_BADGE_MESSAGE,
            "color": "lightgrey",
        }

    color = _BADGE_COLORS.get(grade_str, "lightgrey")
    message = grade_str.upper()
    if provenance is ScanProvenance.DEMO:
        message = f"{message} (demo)"
    elif stale:
        message = f"{message} (stale)"
        color = "lightgrey"

    return {"schemaVersion": 1, "label": "mcp trust", "message": message, "color": color}
