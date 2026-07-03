from __future__ import annotations

import json

import pytest
from pydantic import ValidationError

from mcp_trust.core.models import TransparencyLevel, TrustGrade
from mcp_trust.corpus.records import (
    CorpusRecordSet,
    CorpusRecordStatus,
    PackageSource,
    PublicCorpusRecord,
    ReceiptEvidenceRef,
    summarize_corpus_records,
)
from mcp_trust.corpus.registry import CandidateMode, Freshness


def _package(version: str = "1.2.3") -> PackageSource:
    return PackageSource(
        registry_type="npm",
        identifier="@example/server",
        version=version,
        repository_url="https://github.com/example/server",
    )


def _receipt(mode: CandidateMode = CandidateMode.NO_AUTH_SANDBOXED) -> ReceiptEvidenceRef:
    return ReceiptEvidenceRef(
        receipt_ref="example-server-abc123.json",
        approval_ref="first-batch-approval",
        scanned_at="2026-07-03T00:00:00+00:00",
        scan_mode=mode,
        sandbox_image="mcp-trust-live-batch:20260628",
        sandbox_network="none",
        grade=TrustGrade.C,
        transparency=TransparencyLevel.LOW,
        tool_count=3,
    )


def test_public_corpus_record_requires_receipt_for_published_status() -> None:
    with pytest.raises(ValidationError, match="published corpus records require"):
        PublicCorpusRecord(
            record_id="example-server",
            registry_name="com.example/server",
            display_name="Example Server",
            status=CorpusRecordStatus.PUBLISHED,
            recommended_mode=CandidateMode.NO_AUTH_SANDBOXED,
            package=_package(),
        )


def test_public_corpus_record_allows_unscanned_proposed_record() -> None:
    record = PublicCorpusRecord(
        record_id="example-server",
        registry_name="com.example/server",
        display_name="Example Server",
        status=CorpusRecordStatus.PROPOSED,
        recommended_mode=CandidateMode.NO_AUTH_SANDBOXED,
        package=_package(),
        freshness=Freshness.FRESH,
    )

    assert record.has_public_grade is False
    assert record.receipt is None


def test_public_corpus_record_accepts_receipt_backed_grade() -> None:
    record = PublicCorpusRecord(
        record_id="example-server",
        registry_name="com.example/server",
        display_name="Example Server",
        status=CorpusRecordStatus.PUBLISHED,
        recommended_mode=CandidateMode.NO_AUTH_SANDBOXED,
        package=_package(),
        freshness=Freshness.FRESH,
        receipt=_receipt(),
    )

    assert record.has_public_grade is True
    assert record.receipt is not None
    assert record.receipt.grade == TrustGrade.C
    assert record.receipt.grade_source == "controlled-live-scan"


def test_receipt_mode_must_match_reviewed_mode() -> None:
    with pytest.raises(ValidationError, match="receipt scan_mode must match"):
        PublicCorpusRecord(
            record_id="example-server",
            registry_name="com.example/server",
            display_name="Example Server",
            status=CorpusRecordStatus.SCANNED_TEMP,
            recommended_mode=CandidateMode.NO_AUTH_SANDBOXED,
            package=_package(),
            receipt=_receipt(CandidateMode.CREDENTIALED_SANDBOXED),
        )


def test_summary_counts_records_without_inventing_grades() -> None:
    record_set = CorpusRecordSet(
        records=[
            PublicCorpusRecord(
                record_id="proposed",
                registry_name="com.example/proposed",
                display_name="Proposed",
                status=CorpusRecordStatus.PROPOSED,
                recommended_mode=CandidateMode.NO_AUTH_SANDBOXED,
                package=_package(),
                freshness=Freshness.FRESH,
            ),
            PublicCorpusRecord(
                record_id="scanned",
                registry_name="com.example/scanned",
                display_name="Scanned",
                status=CorpusRecordStatus.SCANNED_TEMP,
                recommended_mode=CandidateMode.NO_AUTH_SANDBOXED,
                package=_package(),
                freshness=Freshness.AGING,
                receipt=_receipt(),
            ),
        ]
    )

    summary = summarize_corpus_records(record_set)

    assert summary["records"] == 2
    assert summary["with_receipt_grade"] == 1
    assert summary["grades"] == {"C": 1}
    assert summary["statuses"] == {"proposed": 1, "scanned-temp": 1}
    assert summary["published_without_receipts"] == []
    assert "grade" not in json.dumps(record_set.records[0].model_dump(mode="json"))
