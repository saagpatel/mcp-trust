"""V50 canonical freshness and public-projection contract."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

import pytest

from mcp_trust.core.governance import (
    STALE_AFTER_DAYS,
    FreshnessState,
    assess_scan_freshness,
)
from mcp_trust.core.models import (
    Finding,
    RiskSummary,
    ScanEvidence,
    ScanRecord,
    Server,
    ServerSource,
    Severity,
    SourceKind,
    ToolEvidence,
    TransparencyLevel,
    TrustGrade,
)
from mcp_trust.core.public_projection import (
    project_public_scan,
    project_public_server,
    project_public_summary,
    semantic_projection_digest,
)

NOW = datetime(2026, 8, 25, 12, 0, tzinfo=UTC)


@pytest.mark.parametrize(
    ("case_id", "scanned_at", "scan_exists", "state", "reason"),
    [
        ("F01", NOW - timedelta(days=89), True, FreshnessState.FRESH, "fresh"),
        ("F02", NOW - timedelta(days=90), True, FreshnessState.FRESH, "fresh"),
        (
            "F03",
            NOW - timedelta(days=90, microseconds=1),
            True,
            FreshnessState.STALE,
            "age_exceeds_90_days",
        ),
        ("F04", NOW + timedelta(seconds=1), True, FreshnessState.UNKNOWN, "future_scanned_at"),
        ("F05", "not-a-time", True, FreshnessState.UNKNOWN, "malformed_scanned_at"),
        ("F06", None, True, FreshnessState.UNKNOWN, "missing_scanned_at"),
        ("F07", None, False, FreshnessState.NOT_APPLICABLE, "no_scan"),
        (
            "F08",
            (NOW - timedelta(days=1)).replace(tzinfo=None),
            True,
            FreshnessState.FRESH,
            "fresh",
        ),
    ],
    ids=lambda value: value if isinstance(value, str) and value.startswith("F") else None,
)
def test_freshness_contract(
    case_id: str,
    scanned_at: datetime | str | None,
    scan_exists: bool,
    state: FreshnessState,
    reason: str,
) -> None:
    assessment = assess_scan_freshness(scanned_at, NOW, scan_exists=scan_exists)

    assert case_id.startswith("F")
    assert assessment.state is state
    assert assessment.reason == reason
    if state in {FreshnessState.UNKNOWN, FreshnessState.NOT_APPLICABLE}:
        assert assessment.scan_age_days is None
    else:
        assert assessment.scan_age_days is not None
        assert assessment.scan_age_days >= 0
        assert assessment.stale_after is not None


def test_f09_fixed_now_is_canonically_repeatable() -> None:
    scanned_at = NOW - timedelta(days=4, seconds=3)

    first = assess_scan_freshness(scanned_at, NOW)
    second = assess_scan_freshness(scanned_at, NOW)

    assert first == second


def _server() -> Server:
    return Server(
        slug="masked-server",
        name="Masked Server",
        description="grade-bearing catalog prose",
        source=ServerSource(
            kind=SourceKind.NPM,
            reference="@example/masked-server",
            command="masked-server",
        ),
        added_at=NOW,
    )


def _scan(*, scanned_at: datetime = NOW) -> ScanRecord:
    return ScanRecord(
        id="scan-1",
        server_slug="masked-server",
        engine_name="mcpaudit",
        engine_version="1.2.3",
        grade=TrustGrade.F,
        transparency=TransparencyLevel.LOW,
        risk=RiskSummary(composite=9.0, network_access=9.0, annotation_coverage=0.1),
        findings=[
            Finding(
                rule_id="MCP001",
                title="sensitive finding",
                severity=Severity.HIGH,
                category="network_access",
            )
        ],
        evidence=ScanEvidence(tools=[ToolEvidence(name="sensitive-tool")]),
        scanned_at=scanned_at,
        report_ref="reports/private.json",
    )


def test_m01_operator_masking_is_independent_of_scan_existence() -> None:
    projected = project_public_server(_server(), operator_masked=True)

    assert projected["operator_masked"] is True
    assert projected["description"] != "grade-bearing catalog prose"

    summary = project_public_summary(
        _server(),
        None,
        now=NOW,
        operator_masked=True,
    )
    assert summary["grade"] == "under review"
    assert summary["masked"] is True
    assert summary["grade_withheld"] is True


def test_m05_masked_scan_withholds_every_verdict_field() -> None:
    projected = project_public_scan(_scan(), now=NOW, operator_masked=True)

    assert projected is not None
    assert projected["grade_withheld"] is True
    assert projected["grade"] == "under review"
    for field in ("transparency", "risk", "findings", "evidence", "report_ref"):
        assert projected[field] is None
    assert projected["scanned_at"] == NOW.isoformat().replace("+00:00", "Z")
    assert projected["engine_name"] == "mcpaudit"


def test_m07_unknown_timestamp_never_exposes_a_verdict() -> None:
    projected = project_public_scan(
        _scan(scanned_at=NOW + timedelta(seconds=1)),
        now=NOW,
        operator_masked=False,
    )

    assert projected is not None
    assert projected["freshness_state"] == "UNKNOWN"
    assert projected["stale"] is None
    assert projected["grade"] == "unknown"
    assert projected["grade_withheld"] is True


def test_projection_digest_is_stable_and_sensitive() -> None:
    first = project_public_scan(_scan(), now=NOW, operator_masked=False)
    second = project_public_scan(_scan(), now=NOW, operator_masked=False)
    masked = project_public_scan(_scan(), now=NOW, operator_masked=True)

    assert semantic_projection_digest(first) == semantic_projection_digest(second)
    assert semantic_projection_digest(first) != semantic_projection_digest(masked)
    assert STALE_AFTER_DAYS == 90
