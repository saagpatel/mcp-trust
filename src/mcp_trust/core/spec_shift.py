"""Spec-shift exposure — a second, independent axis alongside the danger grade.

A danger grade answers "what can this server do to me?" It is derived from a
sandboxed capability scan. Spec-shift exposure answers a different question:
"will this server still work once the MCP 2026-07-28 specification lands?"
The two are orthogonal. A server can be perfectly safe and still break, and a
dangerous server can be entirely spec-clean.

**This module never assigns, modifies, or influences a danger grade.** It reads
a frozen verdict set and reports it. Grading logic lives in ``grading.py`` and
has no dependency on anything here. Keeping the axes separate is deliberate:
folding conformance into the grade would quietly redefine what a grade means to
every consumer already relying on it.

The verdicts are a point-in-time ruling against a RELEASE CANDIDATE, not the
final specification. They were produced by an external audit (the spec-shift
tribunal) that pinned every finding to quoted RC text, so the post-publication
re-check is a delta against those quotes rather than a fresh audit. Read
``ruled_at`` and ``spec_version`` before relying on any verdict here.
"""

from __future__ import annotations

import json
from functools import lru_cache
from pathlib import Path
from typing import Any

_VERDICTS_FILE = Path(__file__).parent / "spec_shift_verdicts.json"

# Worst-first, matching the order a reader should triage in.
VERDICT_ORDER = ("BREAKS", "EXPOSED", "UNRULEABLE", "READY")

#: Verdicts that mean "this server needs work before the spec lands".
ADVERSE_VERDICTS = frozenset({"BREAKS", "EXPOSED"})


@lru_cache(maxsize=1)
def load() -> dict[str, Any]:
    """Return the frozen verdict document, parsed once and cached."""
    return json.loads(_VERDICTS_FILE.read_text(encoding="utf-8"))


def for_server(slug: str) -> dict[str, Any] | None:
    """Return the spec-shift record for ``slug``, or None if it was not ruled.

    A missing record is the normal case for any server added to the catalog
    after the ruling date — it means "not yet audited", never "clean".
    """
    return load()["servers"].get(slug)


def summary() -> dict[str, Any]:
    """Return catalog-level provenance and counts for the disclosure notice."""
    doc = load()
    counts = doc["counts"]
    return {
        "spec_version": doc["spec_version"],
        "ruled_at": doc["ruled_at"],
        "source": doc["source"],
        "total": sum(counts.values()),
        "counts": counts,
        "adverse": sum(n for v, n in counts.items() if v in ADVERSE_VERDICTS),
    }


def dimension_title(unit: str) -> str:
    """Human-readable title for a rubric dimension id (``D1``..``D5``)."""
    return load()["dimension_titles"].get(unit, unit)


def is_adverse(record: dict[str, Any] | None) -> bool:
    """True when a record carries a verdict that needs action before the spec lands."""
    return bool(record) and record.get("overall") in ADVERSE_VERDICTS
