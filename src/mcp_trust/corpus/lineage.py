"""Fail-closed evidence lineage for MCP corpus decisions.

The ledger is metadata-only. It binds identities, digests, evidence references,
freshness, publication state, and lineage without storing scan payloads, raw
logs, credentials, or private source material. Assessments are deterministic:
callers must supply the observation time and may proceed only on an explicit
``ALLOWED`` result.
"""

from __future__ import annotations

import hashlib
import json
from datetime import UTC, datetime
from enum import StrEnum
from pathlib import Path, PurePosixPath
from typing import Annotated, Any, Literal
from urllib.parse import urlsplit

from pydantic import (
    AfterValidator,
    AwareDatetime,
    BaseModel,
    ConfigDict,
    Field,
    model_validator,
)

SCHEMA = "mcp-trust-evidence-lineage-ledger.v1"
ASSESSMENT_SCHEMA = "mcp-trust-evidence-lineage-assessment.v1"

Sha256 = Annotated[str, Field(pattern=r"^[0-9a-f]{64}$")]
StableId = Annotated[
    str,
    Field(min_length=1, max_length=160, pattern=r"^[A-Za-z0-9][A-Za-z0-9._/@:+-]*$"),
]
PackageId = Annotated[
    str,
    Field(min_length=1, max_length=200, pattern=r"^[A-Za-z0-9@][A-Za-z0-9._/@:+-]*$"),
]
ReasonCode = Annotated[
    str,
    Field(min_length=3, max_length=80, pattern=r"^[A-Z][A-Z0-9_]*$"),
]


def _portable_reference(value: str) -> str:
    """Reject references that can smuggle local paths, credentials, or query values."""
    if value != value.strip() or not value or any(char in value for char in ("\n", "\r", "\0")):
        raise ValueError("reference must be a single non-empty line")
    if "?" in value:
        raise ValueError("reference query strings are not allowed")
    if value.startswith(("/", "~", "file:")) or "\\" in value:
        raise ValueError("reference must not expose a local filesystem path")

    parsed = urlsplit(value)
    if parsed.scheme:
        if parsed.scheme != "https" or not parsed.netloc:
            raise ValueError("absolute references must use HTTPS")
        if parsed.username is not None or parsed.password is not None:
            raise ValueError("reference must not contain credentials")
    else:
        relative_path = value.split("#", 1)[0]
        if any(part == ".." for part in PurePosixPath(relative_path).parts):
            raise ValueError("reference must not traverse parent directories")
    return value


PortableReference = Annotated[
    str,
    Field(min_length=1, max_length=512),
    AfterValidator(_portable_reference),
]


class _StrictModel(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True, populate_by_name=True)


class RightsStatus(StrEnum):
    DOCUMENTED = "documented"
    UNKNOWN = "unknown"
    RESTRICTED = "restricted"


class EvidenceKind(StrEnum):
    SCAN_RECEIPT = "scan-receipt"


class PublicationState(StrEnum):
    DRAFT = "draft"
    PUBLISHED = "published"
    WITHDRAWN = "withdrawn"


class LineageDecision(StrEnum):
    ADMIT = "admit"
    REFRESH = "refresh"
    PUBLISH = "publish"
    WITHDRAW = "withdraw"


class AssessmentStatus(StrEnum):
    ALLOWED = "ALLOWED"
    BLOCKED = "BLOCKED"
    UNKNOWN = "UNKNOWN"
    REQUIRED = "REQUIRED"
    COMPLETE = "COMPLETE"
    NOT_REQUIRED = "NOT_REQUIRED"


class SandboxMode(StrEnum):
    DOCKER = "docker"
    UNKNOWN = "unknown"
    NOT_APPLICABLE = "not_applicable"


class NetworkMode(StrEnum):
    NONE = "none"
    UNKNOWN = "unknown"
    LIVE = "live"


class SubjectIdentity(_StrictModel):
    name: str = Field(min_length=1, max_length=200)
    package_id: PackageId
    version: str | None = Field(default=None, min_length=1, max_length=100)
    source_ref: PortableReference


class SourceEvidence(_StrictModel):
    origin: StableId
    artifact_sha256: Sha256
    observed_at: AwareDatetime
    evidence_ref: PortableReference


class RightsEvidence(_StrictModel):
    status: RightsStatus
    basis: StableId | None = None
    scope: StableId | None = None
    custodian: StableId | None = None
    evidence_ref: PortableReference | None = None

    @model_validator(mode="after")
    def _validate_evidence(self) -> RightsEvidence:
        details = (self.basis, self.scope, self.custodian, self.evidence_ref)
        if self.status == RightsStatus.UNKNOWN and any(item is not None for item in details):
            raise ValueError("unknown rights must not carry unsupported evidence details")
        if self.status != RightsStatus.UNKNOWN and any(item is None for item in details):
            raise ValueError("documented or restricted rights require complete evidence details")
        return self


class ScanEvidence(_StrictModel):
    engine: StableId
    engine_version: str = Field(min_length=1, max_length=100)
    artifact_sha256: Sha256 | None = None
    scan_mode: StableId
    sandbox_mode: SandboxMode
    sandbox_ref: str | None = Field(
        default=None,
        min_length=1,
        max_length=200,
        pattern=r"^[A-Za-z0-9][A-Za-z0-9._:@/+\-]*$",
    )
    network: NetworkMode
    started_at: AwareDatetime
    ended_at: AwareDatetime

    @model_validator(mode="after")
    def _validate_interval(self) -> ScanEvidence:
        if self.ended_at < self.started_at:
            raise ValueError("scan ended_at must not precede started_at")
        if self.sandbox_mode == SandboxMode.DOCKER and self.sandbox_ref is None:
            raise ValueError("docker scan evidence requires a sandbox_ref")
        if self.sandbox_mode != SandboxMode.DOCKER and self.sandbox_ref is not None:
            raise ValueError("only docker scan evidence may carry a sandbox_ref")
        return self


class EvidenceReference(_StrictModel):
    kind: EvidenceKind
    ref: PortableReference
    sha256: Sha256


class FreshnessEvidence(_StrictModel):
    policy: StableId
    expires_at: AwareDatetime


class PublicationEvidence(_StrictModel):
    state: PublicationState
    public_record_id: StableId | None = None
    published_at: AwareDatetime | None = None
    withdrawn_at: AwareDatetime | None = None
    projections: tuple[PortableReference, ...] = ()

    @model_validator(mode="after")
    def _validate_state(self) -> PublicationEvidence:
        if tuple(sorted(set(self.projections))) != self.projections:
            raise ValueError("publication projections must be unique and sorted")
        if self.state == PublicationState.DRAFT:
            if self.published_at is not None or self.withdrawn_at is not None or self.projections:
                raise ValueError("draft publication must not claim published surfaces")
        elif self.state == PublicationState.PUBLISHED:
            if self.public_record_id is None or self.published_at is None or not self.projections:
                raise ValueError("published evidence requires identity, time, and projections")
            if self.withdrawn_at is not None:
                raise ValueError("published evidence must not carry withdrawn_at")
        else:
            if (
                self.public_record_id is None
                or self.published_at is None
                or self.withdrawn_at is None
            ):
                raise ValueError(
                    "withdrawn evidence requires prior publication and withdrawal times"
                )
            if self.withdrawn_at < self.published_at:
                raise ValueError("withdrawn_at must not precede published_at")
            if self.projections:
                raise ValueError("withdrawn evidence must have no remaining public projections")
        return self


class LineageLinks(_StrictModel):
    predecessor: StableId | None = None
    successor: StableId | None = None
    supersedes: tuple[StableId, ...] = ()

    @model_validator(mode="after")
    def _validate_links(self) -> LineageLinks:
        if tuple(sorted(set(self.supersedes))) != self.supersedes:
            raise ValueError("supersedes must be unique and sorted")
        return self


class QualityEvidence(_StrictModel):
    blocking_reason_codes: tuple[ReasonCode, ...] = ()

    @model_validator(mode="after")
    def _validate_codes(self) -> QualityEvidence:
        if tuple(sorted(set(self.blocking_reason_codes))) != self.blocking_reason_codes:
            raise ValueError("blocking reason codes must be unique and sorted")
        return self


class RetentionEvidence(_StrictModel):
    retention_class: StableId
    source_retention_ref: PortableReference
    tombstone: bool


class EvidenceLineageRecord(_StrictModel):
    schema_version: Literal[SCHEMA] = Field(default=SCHEMA, alias="schema")
    record_id: StableId
    subject: SubjectIdentity
    source: SourceEvidence
    rights: RightsEvidence
    scan: ScanEvidence
    receipts: tuple[EvidenceReference, ...] = ()
    freshness: FreshnessEvidence
    publication: PublicationEvidence
    lineage: LineageLinks = Field(default_factory=LineageLinks)
    quality: QualityEvidence = Field(default_factory=QualityEvidence)
    retention: RetentionEvidence

    @model_validator(mode="after")
    def _validate_boundaries(self) -> EvidenceLineageRecord:
        codes = set(self.quality.blocking_reason_codes)
        if self.subject.version is None and "SUBJECT_VERSION_UNKNOWN" not in codes:
            raise ValueError("missing subject version requires SUBJECT_VERSION_UNKNOWN")
        if not self.receipts and "RECEIPT_MISSING" not in codes:
            raise ValueError("missing receipt requires RECEIPT_MISSING")
        if self.scan.artifact_sha256 is None and "SCAN_ARTIFACT_DIGEST_UNKNOWN" not in codes:
            raise ValueError("missing scan artifact digest requires SCAN_ARTIFACT_DIGEST_UNKNOWN")
        if any(ref.kind != EvidenceKind.SCAN_RECEIPT for ref in self.receipts):
            raise ValueError("receipts may contain only scan-receipt references")
        if self.scan.network == NetworkMode.UNKNOWN and "SANDBOX_NETWORK_UNKNOWN" not in codes:
            raise ValueError("unknown network evidence requires SANDBOX_NETWORK_UNKNOWN")
        if self.publication.state == PublicationState.WITHDRAWN and not self.retention.tombstone:
            raise ValueError("withdrawn publication requires an audit tombstone")
        return self


class EvidenceLineageLedger(_StrictModel):
    schema_version: Literal[SCHEMA] = Field(default=SCHEMA, alias="schema")
    ledger_id: StableId
    records: tuple[EvidenceLineageRecord, ...] = Field(min_length=1)

    @model_validator(mode="after")
    def _validate_ledger(self) -> EvidenceLineageLedger:
        record_ids = tuple(record.record_id for record in self.records)
        if tuple(sorted(set(record_ids))) != record_ids:
            raise ValueError("ledger records must have unique, sorted record_id values")

        by_id = {record.record_id: record for record in self.records}
        derived_successors: dict[str, str] = {}
        for record in self.records:
            predecessor_id = record.lineage.predecessor
            successor_id = record.lineage.successor
            if predecessor_id is not None:
                predecessor = by_id.get(predecessor_id)
                if predecessor is None:
                    raise ValueError("predecessor links must be closed within the ledger")
                if predecessor.subject.package_id != record.subject.package_id:
                    raise ValueError("lineage links must retain package identity")
                if predecessor_id in derived_successors:
                    raise ValueError("one lineage record must not have multiple successors")
                derived_successors[predecessor_id] = record.record_id
                if (
                    predecessor.lineage.successor is not None
                    and predecessor.lineage.successor != record.record_id
                ):
                    raise ValueError("declared successor does not match the derived successor")
            if successor_id is not None:
                successor = by_id.get(successor_id)
                if successor is None or successor.lineage.predecessor != record.record_id:
                    raise ValueError("successor links must be closed and reciprocal")
                if successor.subject.package_id != record.subject.package_id:
                    raise ValueError("lineage links must retain package identity")

        for start in self.records:
            seen: set[str] = set()
            current: EvidenceLineageRecord | None = start
            while current is not None and current.record_id in derived_successors:
                if current.record_id in seen:
                    raise ValueError("lineage successor links must not form a cycle")
                seen.add(current.record_id)
                current = by_id[derived_successors[current.record_id]]
        return self


class EvidenceLineageAssessment(_StrictModel):
    schema_version: Literal[ASSESSMENT_SCHEMA] = Field(default=ASSESSMENT_SCHEMA, alias="schema")
    record_id: StableId
    record_sha256: Sha256
    decision: LineageDecision
    status: AssessmentStatus
    assessed_at: AwareDatetime
    expected_version: str | None
    reason_codes: tuple[ReasonCode, ...]


_KNOWN_BLOCKERS = {
    "PUBLICATION_WITHDRAWN",
    "RIGHTS_RESTRICTED",
    "SUBJECT_VERSION_MISMATCH",
}


def canonical_payload_sha256(value: BaseModel | dict[str, Any] | list[Any]) -> str:
    """Hash canonical JSON bytes for a model or already-parsed JSON value."""
    if isinstance(value, BaseModel):
        payload: Any = value.model_dump(mode="json", exclude_none=False, by_alias=True)
    else:
        payload = value
    encoded = json.dumps(
        payload,
        ensure_ascii=False,
        separators=(",", ":"),
        sort_keys=True,
    ).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


def _aware_utc(value: datetime) -> datetime:
    if value.tzinfo is None or value.utcoffset() is None:
        raise ValueError("assessment time must be timezone-aware")
    return value.astimezone(UTC)


def _base_reason_codes(
    record: EvidenceLineageRecord,
    *,
    now: datetime,
    expected_version: str | None,
) -> set[str]:
    reasons = set(record.quality.blocking_reason_codes)
    if not record.receipts:
        reasons.add("RECEIPT_MISSING")
    if now >= record.freshness.expires_at.astimezone(UTC):
        reasons.add("EVIDENCE_EXPIRED")
    if expected_version is not None:
        if record.subject.version is None:
            reasons.add("SUBJECT_VERSION_UNKNOWN")
        elif record.subject.version != expected_version:
            reasons.add("SUBJECT_VERSION_MISMATCH")
    return reasons


def _allow_status(reasons: set[str]) -> AssessmentStatus:
    if reasons & _KNOWN_BLOCKERS:
        return AssessmentStatus.BLOCKED
    if reasons:
        return AssessmentStatus.UNKNOWN
    return AssessmentStatus.ALLOWED


def assess_lineage(
    record: EvidenceLineageRecord,
    decision: LineageDecision,
    *,
    now: datetime,
    expected_version: str | None = None,
) -> EvidenceLineageAssessment:
    """Assess one decision without mutating evidence or consulting ambient state."""
    assessed_at = _aware_utc(now)
    reasons = _base_reason_codes(record, now=assessed_at, expected_version=expected_version)

    if decision == LineageDecision.ADMIT:
        if record.publication.state == PublicationState.WITHDRAWN:
            reasons.add("PUBLICATION_WITHDRAWN")
        status = _allow_status(reasons)
    elif decision == LineageDecision.REFRESH:
        status = AssessmentStatus.REQUIRED if reasons else AssessmentStatus.NOT_REQUIRED
    elif decision == LineageDecision.PUBLISH:
        if record.rights.status == RightsStatus.UNKNOWN:
            reasons.add("RIGHTS_UNKNOWN")
        elif record.rights.status == RightsStatus.RESTRICTED:
            reasons.add("RIGHTS_RESTRICTED")
        if record.publication.state == PublicationState.WITHDRAWN:
            reasons.add("PUBLICATION_WITHDRAWN")
        status = _allow_status(reasons)
    else:
        if record.publication.state == PublicationState.WITHDRAWN:
            reasons.clear()
            status = AssessmentStatus.COMPLETE
        elif record.publication.state == PublicationState.DRAFT:
            reasons.clear()
            reasons.add("NOT_PUBLISHED")
            status = AssessmentStatus.NOT_REQUIRED
        else:
            if record.rights.status == RightsStatus.UNKNOWN:
                reasons.add("RIGHTS_UNKNOWN")
            elif record.rights.status == RightsStatus.RESTRICTED:
                reasons.add("RIGHTS_RESTRICTED")
            status = AssessmentStatus.REQUIRED if reasons else AssessmentStatus.NOT_REQUIRED

    return EvidenceLineageAssessment(
        record_id=record.record_id,
        record_sha256=canonical_payload_sha256(record),
        decision=decision,
        status=status,
        assessed_at=assessed_at,
        expected_version=expected_version,
        reason_codes=tuple(sorted(reasons)),
    )


def load_evidence_lineage_ledger(path: str | Path) -> EvidenceLineageLedger:
    """Load and validate one immutable ledger JSON document."""
    payload = json.loads(Path(path).read_text(encoding="utf-8"))
    return EvidenceLineageLedger.model_validate(payload)
