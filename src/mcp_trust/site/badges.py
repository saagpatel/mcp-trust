"""shields.io endpoint badges for the static catalog.

A badge must never overstate confidence: a stub-derived grade is suffixed
``(demo)`` and an unscanned server reads ``unscanned``, so a badge embedded in a
README can't silently imply a real scan happened.
"""

from __future__ import annotations

from typing import Any

from mcp_trust.core.provenance import ScanProvenance

# shields.io named colours per grade. Mirrors ``api.app._BADGE_COLORS`` — the
# live badge route and the static badge files agree on colour by grade.
_BADGE_COLORS: dict[str, str] = {
    "A": "brightgreen",
    "B": "green",
    "C": "yellow",
    "D": "orange",
    "F": "red",
    "unscanned": "lightgrey",
}


def badge_payload(grade: str, provenance: ScanProvenance) -> dict[str, Any]:
    """Build a shields.io *endpoint* JSON payload for one server's grade.

    The ``message`` is honesty-gated by *provenance*: ``UNSCANNED`` → ``unscanned``,
    ``DEMO`` → ``"<grade> (demo)"``, ``REAL`` → the bare grade letter.
    """
    grade_str = str(grade)

    if provenance is ScanProvenance.UNSCANNED:
        return {
            "schemaVersion": 1,
            "label": "mcp trust",
            "message": "unscanned",
            "color": "lightgrey",
        }

    color = _BADGE_COLORS.get(grade_str, "lightgrey")
    message = grade_str.upper()
    if provenance is ScanProvenance.DEMO:
        message = f"{message} (demo)"

    return {"schemaVersion": 1, "label": "mcp trust", "message": message, "color": color}
