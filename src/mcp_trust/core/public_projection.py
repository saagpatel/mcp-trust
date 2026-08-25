"""Canonical provider-free projection for every public MCP Trust surface."""

from __future__ import annotations

import hashlib
import json
from datetime import datetime
from typing import Any, TypedDict, cast

from mcp_trust.core.governance import (
    MASKED_BADGE_MESSAGE,
    MASKED_SERVER_DESCRIPTION,
    FreshnessState,
    assess_scan_freshness,
)
from mcp_trust.core.models import ScanRecord, Server
from mcp_trust.core.provenance import ScanProvenance, classify


class PublicScanProjection(TypedDict, total=False):
    """Stable public scan fields shared by API, HTML, static, and MCP adapters."""

    status: str
    grade: str
    provenance: str
    freshness_state: str
    freshness_reason: str
    scan_age_days: float | None
    stale_after: str | None
    stale: bool | None
    masked: bool
    operator_masked: bool
    grade_withheld: bool


class PublicServerProjection(TypedDict, total=False):
    """Stable public catalog metadata after operator policy masking."""

    slug: str
    name: str
    description: str
    operator_masked: bool


def _canonical_bytes(value: object) -> bytes:
    return (
        json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("utf-8")
        + b"\n"
    )


def semantic_projection_digest(value: object) -> str:
    """Digest only the canonical public projection, never ambient state."""
    return "sha256:" + hashlib.sha256(_canonical_bytes(value)).hexdigest()


def project_public_server(server: Server, *, operator_masked: bool) -> PublicServerProjection:
    """Project catalog metadata; operator masking applies before any scan exists."""
    payload = server.model_dump(mode="json")
    if operator_masked:
        payload["description"] = MASKED_SERVER_DESCRIPTION
    payload["operator_masked"] = operator_masked
    return cast(PublicServerProjection, payload)


def project_public_scan(
    scan: ScanRecord | None,
    *,
    now: datetime,
    operator_masked: bool,
    unreadable: bool = False,
) -> PublicScanProjection | None:
    """Project one scan with fail-closed freshness and verdict withholding."""
    if scan is None and not unreadable:
        return None
    if unreadable:
        freshness = assess_scan_freshness(None, now, scan_exists=True)
        return cast(
            PublicScanProjection,
            {
                "status": "UNKNOWN",
                "reason_codes": ["SCAN_RECORD_UNREADABLE"],
                "provenance": str(ScanProvenance.UNKNOWN),
                "freshness_state": str(freshness.state),
                "freshness_reason": freshness.reason,
                "scan_age_days": None,
                "stale_after": None,
                "stale": None,
                "masked": False,
                "operator_masked": operator_masked,
                "grade_withheld": True,
                "grade": "unknown",
                "transparency": None,
                "risk": None,
                "findings": None,
                "evidence": None,
                "report_ref": None,
            },
        )
    assert scan is not None
    freshness = assess_scan_freshness(scan.scanned_at, now)
    freshness_unknown = freshness.state is FreshnessState.UNKNOWN
    grade_withheld = operator_masked or freshness_unknown
    payload = scan.model_dump(mode="json")
    payload.update(
        {
            "provenance": str(classify(scan)),
            "freshness_state": str(freshness.state),
            "freshness_reason": freshness.reason,
            "scan_age_days": freshness.scan_age_days,
            "stale_after": (
                freshness.stale_after.isoformat() if freshness.stale_after is not None else None
            ),
            "stale": (
                freshness.state is FreshnessState.STALE
                if freshness.state in {FreshnessState.FRESH, FreshnessState.STALE}
                else None
            ),
            "masked": operator_masked,
            "operator_masked": operator_masked,
            "grade_withheld": grade_withheld,
        }
    )
    if grade_withheld:
        payload.update(
            {
                "grade": MASKED_BADGE_MESSAGE if operator_masked else "unknown",
                "transparency": None,
                "risk": None,
                "findings": None,
                "evidence": None,
                "report_ref": None,
                "withheld_reason": (
                    "grade_under_governance_review" if operator_masked else "scan_freshness_unknown"
                ),
            }
        )
    return cast(PublicScanProjection, payload)


def project_public_summary(
    server: Server,
    scan: ScanRecord | None,
    *,
    now: datetime,
    operator_masked: bool,
    unreadable: bool = False,
) -> dict[str, Any]:
    """Build the stable list/catalog summary from the same canonical projection."""
    projected_scan = project_public_scan(
        scan,
        now=now,
        operator_masked=operator_masked,
        unreadable=unreadable,
    )
    if projected_scan is None:
        return {
            "slug": server.slug,
            "name": server.name,
            "grade": MASKED_BADGE_MESSAGE if operator_masked else "unscanned",
            "transparency": None,
            "composite": None,
            "scanned_at": None,
            "provenance": str(ScanProvenance.UNSCANNED),
            "freshness_state": str(FreshnessState.NOT_APPLICABLE),
            "freshness_reason": "no_scan",
            "scan_age_days": None,
            "stale_after": None,
            "stale": None,
            "masked": operator_masked,
            "operator_masked": operator_masked,
            "grade_withheld": operator_masked,
        }
    risk = projected_scan.get("risk")
    return {
        "slug": server.slug,
        "name": server.name,
        "grade": projected_scan.get("grade", "unknown"),
        "transparency": projected_scan.get("transparency"),
        "composite": risk.get("composite") if isinstance(risk, dict) else None,
        "scanned_at": projected_scan.get("scanned_at"),
        "provenance": projected_scan.get("provenance", str(ScanProvenance.UNKNOWN)),
        "freshness_state": projected_scan["freshness_state"],
        "freshness_reason": projected_scan["freshness_reason"],
        "scan_age_days": projected_scan["scan_age_days"],
        "stale_after": projected_scan["stale_after"],
        "stale": projected_scan["stale"],
        "masked": bool(projected_scan["masked"]),
        "operator_masked": operator_masked,
        "grade_withheld": bool(projected_scan["grade_withheld"]),
    }
