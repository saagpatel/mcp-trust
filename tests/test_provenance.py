"""Tests for core/provenance.py — scan-mode honesty classification.

Provenance answers a single question a renderer must never get wrong: *how much
confidence does this stored grade deserve?* A grade synthesised by the
deterministic stub engine is demo data, not a real scan, and the public site has
to say so loudly. This module is the single source of truth for that decision.
"""

from __future__ import annotations

import uuid
from datetime import UTC, datetime

from mcp_trust.core.models import RiskSummary, ScanRecord, TrustGrade
from mcp_trust.core.provenance import (
    REAL_ENGINE_NAMES,
    ScanProvenance,
    classify,
    is_real_engine,
)


def _record(engine_name: str) -> ScanRecord:
    return ScanRecord(
        id=uuid.uuid4().hex,
        server_slug="example",
        engine_name=engine_name,
        engine_version="9.9.9",
        grade=TrustGrade.B,
        risk=RiskSummary(composite=2.0),
        findings=[],
        scanned_at=datetime.now(tz=UTC),
        report_ref=None,
    )


# ---------------------------------------------------------------------------
# is_real_engine
# ---------------------------------------------------------------------------


def test_mcpaudit_is_real_engine() -> None:
    assert is_real_engine("mcpaudit") is True


def test_real_engine_match_is_case_insensitive() -> None:
    assert is_real_engine("MCPAudit") is True


def test_stub_is_not_real_engine() -> None:
    assert is_real_engine("stub") is False


def test_unknown_engine_is_not_real() -> None:
    assert is_real_engine("totally-new-scanner") is False


def test_empty_engine_name_is_not_real() -> None:
    assert is_real_engine("") is False


def test_real_engine_names_contains_mcpaudit() -> None:
    # The catalog's authz and the renderer must agree on the canonical set.
    assert "mcpaudit" in REAL_ENGINE_NAMES


# ---------------------------------------------------------------------------
# classify
# ---------------------------------------------------------------------------


def test_classify_none_is_unscanned() -> None:
    assert classify(None) is ScanProvenance.UNSCANNED


def test_classify_stub_record_is_demo() -> None:
    assert classify(_record("stub")) is ScanProvenance.DEMO


def test_classify_real_record_is_real() -> None:
    assert classify(_record("mcpaudit")) is ScanProvenance.REAL


def test_classify_unknown_engine_is_demo_not_real() -> None:
    # Conservative by design: an unrecognised engine must never be presented as
    # a trustworthy real scan. Unknown collapses to DEMO, never REAL.
    assert classify(_record("mystery-engine")) is ScanProvenance.DEMO


def test_classify_real_match_is_case_insensitive() -> None:
    assert classify(_record("MCPAUDIT")) is ScanProvenance.REAL
