"""Scan-mode provenance — the registry's honesty boundary.

A trust grade is only as trustworthy as the scan that produced it. The
deterministic ``StubEngine`` exists so the whole system runs and demos without
``mcp-audits`` installed, but its grades are *synthetic* — derived from a hash of
the source reference, not from inspecting a real server. Presenting a stub grade
as if it were a real scan would be a lie the public site must never tell.

This module is the single source of truth for that distinction. Both the live
API's scan-trigger authorization and the static-site renderer key off the same
``REAL_ENGINE_NAMES`` set, so "what counts as a real scan" can never drift
between the security path and the presentation path.

Classification is deliberately *conservative*: anything that is not a recognised
real engine collapses to :data:`ScanProvenance.DEMO`, never silently to ``REAL``.
A brand-new engine we have not vetted is treated as demo until it is added here.
"""

from __future__ import annotations

from enum import StrEnum

from mcp_trust.core.models import ScanRecord

# Canonical set of engine names whose output is a real scan, not a demo.
# Lowercased; matching is case-insensitive via :func:`is_real_engine`.
REAL_ENGINE_NAMES: frozenset[str] = frozenset({"mcpaudit"})


class ScanProvenance(StrEnum):
    """How much confidence a stored grade deserves.

    - ``REAL``: produced by a recognised real scan engine.
    - ``DEMO``: synthetic stub output (or any unrecognised engine) — not a real
      scan, must be labelled loudly.
    - ``UNSCANNED``: no scan on record.
    """

    REAL = "real"
    DEMO = "demo"
    UNSCANNED = "unscanned"


def is_real_engine(name: str) -> bool:
    """Return ``True`` if *name* identifies a recognised real scan engine."""
    return name.strip().lower() in REAL_ENGINE_NAMES


def classify(record: ScanRecord | None) -> ScanProvenance:
    """Classify the provenance of a server's latest scan record.

    ``None`` (no scan) → ``UNSCANNED``. A recognised real engine → ``REAL``.
    Everything else — the stub engine, an unknown engine — → ``DEMO``.
    """
    if record is None:
        return ScanProvenance.UNSCANNED
    if is_real_engine(record.engine_name):
        return ScanProvenance.REAL
    return ScanProvenance.DEMO
