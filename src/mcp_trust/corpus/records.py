"""Reviewed corpus record models.

Registry manifests are discovery inputs. Public corpus records are the reviewed
bridge between those candidates and MCP Trust's public catalog lane: they carry
source/provenance, scan-mode decisions, stale markers, approval references, and
optional receipt-backed scan evidence. They do not launch scans or infer grades.
"""

from __future__ import annotations

import json
from collections import Counter
from enum import StrEnum
from pathlib import Path
from typing import Any

from pydantic import BaseModel, Field, model_validator

from mcp_trust.core.models import TransparencyLevel, TrustGrade
from mcp_trust.corpus.registry import CandidateMode, Freshness


class CorpusRecordStatus(StrEnum):
    """Lifecycle state for a reviewed corpus candidate."""

    PROPOSED = "proposed"
    APPROVED_FOR_SCAN = "approved-for-scan"
    SCANNED_TEMP = "scanned-temp"
    PUBLISHED = "published"
    DEFERRED = "deferred"


class GradeSource(StrEnum):
    """Where a public grade came from."""

    CONTROLLED_LIVE_SCAN = "controlled-live-scan"


class PackageSource(BaseModel):
    """Exact package/source identity for one corpus record."""

    registry_type: str
    identifier: str
    version: str
    repository_url: str | None = None


class ReceiptEvidenceRef(BaseModel):
    """Public-safe receipt/evidence pointer for a completed scan."""

    receipt_ref: str = Field(description="Portable receipt filename or reviewed artifact path.")
    approval_ref: str
    scanned_at: str
    scan_mode: CandidateMode
    sandbox_image: str | None = None
    sandbox_network: str | None = None
    grade: TrustGrade
    transparency: TransparencyLevel
    tool_count: int = Field(ge=0)
    schema_hash_algorithm: str = "sha256"
    grade_source: GradeSource = GradeSource.CONTROLLED_LIVE_SCAN


class PublicCorpusRecord(BaseModel):
    """Reviewed public-corpus candidate or record.

    A record can exist before scanning, but public grade fields must come from a
    receipt-backed controlled live scan. Registry metadata alone is never enough.
    """

    record_id: str
    registry_name: str
    display_name: str
    status: CorpusRecordStatus = CorpusRecordStatus.PROPOSED
    recommended_mode: CandidateMode
    package: PackageSource | None = None
    freshness: Freshness = Freshness.UNKNOWN
    dedupe_keys: list[str] = Field(default_factory=list)
    source_caveats: list[str] = Field(default_factory=list)
    receipt: ReceiptEvidenceRef | None = None
    publish_caveats: list[str] = Field(default_factory=list)

    @model_validator(mode="after")
    def _validate_public_boundaries(self) -> PublicCorpusRecord:
        if self.status == CorpusRecordStatus.PUBLISHED and self.receipt is None:
            raise ValueError("published corpus records require receipt-backed scan evidence")
        if self.receipt is not None and self.receipt.scan_mode != self.recommended_mode:
            raise ValueError("receipt scan_mode must match the reviewed recommended_mode")
        if (
            self.recommended_mode == CandidateMode.NO_AUTH_SANDBOXED
            and self.package is not None
            and not self.package.version
        ):
            raise ValueError("no-auth sandboxed records require an exact package version")
        return self

    @property
    def has_public_grade(self) -> bool:
        """Whether this record carries receipt-backed grade evidence."""
        return self.receipt is not None


class CorpusRecordSet(BaseModel):
    """Versioned collection of reviewed corpus records."""

    format_version: int = 1
    records: list[PublicCorpusRecord] = Field(default_factory=list)


def load_corpus_records(path: str | Path) -> CorpusRecordSet:
    """Load and validate a corpus record set from JSON."""
    payload = json.loads(Path(path).read_text(encoding="utf-8"))
    return CorpusRecordSet.model_validate(payload)


def summarize_corpus_records(record_set: CorpusRecordSet) -> dict[str, Any]:
    """Return an operator summary without exposing raw receipt contents."""
    status_counts = Counter(str(record.status) for record in record_set.records)
    mode_counts = Counter(str(record.recommended_mode) for record in record_set.records)
    freshness_counts = Counter(str(record.freshness) for record in record_set.records)
    grade_counts = Counter(
        str(record.receipt.grade) for record in record_set.records if record.receipt
    )
    return {
        "format_version": record_set.format_version,
        "records": len(record_set.records),
        "with_receipt_grade": sum(1 for record in record_set.records if record.receipt),
        "statuses": dict(sorted(status_counts.items())),
        "modes": dict(sorted(mode_counts.items())),
        "freshness": dict(sorted(freshness_counts.items())),
        "grades": dict(sorted(grade_counts.items())),
        "published_without_receipts": [
            record.record_id
            for record in record_set.records
            if record.status == CorpusRecordStatus.PUBLISHED and record.receipt is None
        ],
    }
