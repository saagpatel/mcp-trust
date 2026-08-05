from __future__ import annotations

import json
import subprocess
import sys
from datetime import UTC, datetime
from pathlib import Path

import pytest
from pydantic import ValidationError

from mcp_trust.corpus.lineage import (
    AssessmentStatus,
    EvidenceLineageLedger,
    EvidenceLineageRecord,
    LineageDecision,
    assess_lineage,
    canonical_payload_sha256,
    load_evidence_lineage_ledger,
)

ROOT = Path(__file__).resolve().parents[1]
PILOT = ROOT / "tests" / "fixtures" / "evidence-lineage-pilot-v1.json"
SNAPSHOT = ROOT / "src" / "mcp_trust" / "catalog_snapshot.json"
NOW = datetime(2026, 8, 5, 12, tzinfo=UTC)


def _valid_record_payload() -> dict[str, object]:
    return {
        "schema": "mcp-trust-evidence-lineage-ledger.v1",
        "record_id": "example-server-1-2-3",
        "subject": {
            "name": "Example Server",
            "package_id": "example-server",
            "version": "1.2.3",
            "source_ref": "registry/npm/example-server",
        },
        "source": {
            "origin": "reviewed-registry-record",
            "artifact_sha256": "1" * 64,
            "observed_at": "2026-08-01T00:00:00+00:00",
            "evidence_ref": "evidence/example-server-source.json",
        },
        "rights": {
            "status": "documented",
            "basis": "license-file-observed",
            "scope": "public-metadata-record",
            "custodian": "example-maintainer",
            "evidence_ref": "https://example.test/LICENSE",
        },
        "scan": {
            "engine": "mcpaudit",
            "engine_version": "2.4.0",
            "artifact_sha256": "2" * 64,
            "scan_mode": "mcpaudit-local-network-off",
            "sandbox_mode": "docker",
            "sandbox_ref": "mcp-trust-live-batch:20260628",
            "network": "none",
            "started_at": "2026-08-01T00:01:00+00:00",
            "ended_at": "2026-08-01T00:02:00+00:00",
        },
        "receipts": [
            {
                "kind": "scan-receipt",
                "ref": "receipts/example-server.json",
                "sha256": "3" * 64,
            }
        ],
        "freshness": {
            "policy": "scan-30d",
            "expires_at": "2026-08-31T00:02:00+00:00",
        },
        "publication": {
            "state": "published",
            "public_record_id": "example-server-1-2-3",
            "published_at": "2026-08-01T01:00:00+00:00",
            "withdrawn_at": None,
            "projections": ["catalog/example-server-1-2-3.json"],
        },
        "lineage": {"predecessor": None, "successor": None, "supersedes": []},
        "quality": {"blocking_reason_codes": []},
        "retention": {
            "retention_class": "catalog-audit",
            "source_retention_ref": "evidence/example-server-source.json#retention",
            "tombstone": False,
        },
    }


def _record(payload: dict[str, object] | None = None) -> EvidenceLineageRecord:
    return EvidenceLineageRecord.model_validate(payload or _valid_record_payload())


def test_complete_record_allows_admit_and_publish() -> None:
    record = _record()

    admitted = assess_lineage(record, LineageDecision.ADMIT, now=NOW)
    published = assess_lineage(record, LineageDecision.PUBLISH, now=NOW)
    refreshed = assess_lineage(record, LineageDecision.REFRESH, now=NOW)
    withdrawn = assess_lineage(record, LineageDecision.WITHDRAW, now=NOW)

    assert admitted.status == AssessmentStatus.ALLOWED
    assert published.status == AssessmentStatus.ALLOWED
    assert admitted.reason_codes == published.reason_codes == ()
    assert refreshed.status == AssessmentStatus.NOT_REQUIRED
    assert withdrawn.status == AssessmentStatus.NOT_REQUIRED


def test_expired_evidence_never_renders_current() -> None:
    record = _record()
    expired_at = datetime(2026, 9, 1, tzinfo=UTC)

    admitted = assess_lineage(record, LineageDecision.ADMIT, now=expired_at)
    refreshed = assess_lineage(record, LineageDecision.REFRESH, now=expired_at)
    published = assess_lineage(record, LineageDecision.PUBLISH, now=expired_at)

    assert admitted.status == AssessmentStatus.UNKNOWN
    assert refreshed.status == AssessmentStatus.REQUIRED
    assert published.status == AssessmentStatus.UNKNOWN
    assert admitted.reason_codes == published.reason_codes == ("EVIDENCE_EXPIRED",)


def test_version_mismatch_is_a_stable_known_blocker() -> None:
    result = assess_lineage(
        _record(),
        LineageDecision.PUBLISH,
        now=NOW,
        expected_version="2.0.0",
    )

    assert result.status == AssessmentStatus.BLOCKED
    assert result.reason_codes == ("SUBJECT_VERSION_MISMATCH",)


def test_unknown_rights_block_publication_and_require_withdrawal() -> None:
    payload = _valid_record_payload()
    payload["rights"] = {"status": "unknown"}
    record = _record(payload)

    published = assess_lineage(record, LineageDecision.PUBLISH, now=NOW)
    withdrawn = assess_lineage(record, LineageDecision.WITHDRAW, now=NOW)

    assert published.status == AssessmentStatus.UNKNOWN
    assert published.reason_codes == ("RIGHTS_UNKNOWN",)
    assert withdrawn.status == AssessmentStatus.REQUIRED
    assert withdrawn.reason_codes == ("RIGHTS_UNKNOWN",)


def test_withdrawal_requires_empty_projections_and_a_tombstone() -> None:
    payload = _valid_record_payload()
    publication = dict(payload["publication"])
    publication.update(
        {
            "state": "withdrawn",
            "withdrawn_at": "2026-08-05T00:00:00+00:00",
        }
    )
    payload["publication"] = publication

    with pytest.raises(ValidationError, match="no remaining public projections"):
        _record(payload)

    publication["projections"] = []
    with pytest.raises(ValidationError, match="requires an audit tombstone"):
        _record(payload)

    retention = dict(payload["retention"])
    retention["tombstone"] = True
    payload["retention"] = retention
    result = assess_lineage(_record(payload), LineageDecision.WITHDRAW, now=NOW)

    assert result.status == AssessmentStatus.COMPLETE
    assert result.reason_codes == ()


def test_metadata_only_schema_rejects_raw_logs_and_unsafe_references() -> None:
    payload = _valid_record_payload()
    source = dict(payload["source"])
    source["raw_log"] = "private scan output"
    payload["source"] = source
    with pytest.raises(ValidationError, match="raw_log"):
        _record(payload)

    payload = _valid_record_payload()
    subject = dict(payload["subject"])
    subject["source_ref"] = "/Users/example/private/source.json"
    payload["subject"] = subject
    with pytest.raises(ValidationError, match="local filesystem path"):
        _record(payload)

    payload = _valid_record_payload()
    rights = dict(payload["rights"])
    rights["evidence_ref"] = "https://example.test/license?token=secret"
    payload["rights"] = rights
    with pytest.raises(ValidationError, match="query strings"):
        _record(payload)


def test_ledger_requires_sorted_records_and_reciprocal_lineage() -> None:
    first_payload = _valid_record_payload()
    first_payload["record_id"] = "example-server-1-2-2"
    first_publication = dict(first_payload["publication"])
    first_publication["public_record_id"] = "example-server-1-2-2"
    first_payload["publication"] = first_publication
    first_payload["lineage"] = {
        "predecessor": None,
        "successor": None,
        "supersedes": [],
    }
    second_payload = _valid_record_payload()
    second_payload["lineage"] = {
        "predecessor": "example-server-1-2-2",
        "successor": None,
        "supersedes": ["example-server-1-2-2"],
    }

    ledger = EvidenceLineageLedger(
        ledger_id="example-lineage",
        records=(_record(first_payload), _record(second_payload)),
    )
    assert len(ledger.records) == 2

    second_payload["lineage"] = {
        "predecessor": "missing-record",
        "successor": None,
        "supersedes": [],
    }
    with pytest.raises(ValidationError, match="closed within the ledger"):
        EvidenceLineageLedger(
            ledger_id="example-lineage",
            records=(_record(first_payload), _record(second_payload)),
        )


def test_pilot_binds_three_packaged_rows_and_surfaces_current_gaps() -> None:
    ledger = load_evidence_lineage_ledger(PILOT)
    snapshot = json.loads(SNAPSHOT.read_text(encoding="utf-8"))
    rows = {row["slug"]: row for row in snapshot["servers"]}

    assert len(ledger.records) == 3
    for record in ledger.records:
        assert record.source.artifact_sha256 == canonical_payload_sha256(rows[record.record_id])
        assert record.scan.artifact_sha256 is None

        admitted = assess_lineage(record, LineageDecision.ADMIT, now=NOW)
        refreshed = assess_lineage(record, LineageDecision.REFRESH, now=NOW)
        published = assess_lineage(record, LineageDecision.PUBLISH, now=NOW)
        withdrawn = assess_lineage(record, LineageDecision.WITHDRAW, now=NOW)

        assert admitted.status == AssessmentStatus.UNKNOWN
        assert refreshed.status == AssessmentStatus.REQUIRED
        assert published.status == AssessmentStatus.UNKNOWN
        assert withdrawn.status == AssessmentStatus.REQUIRED
        assert published.reason_codes == (
            "EVIDENCE_EXPIRED",
            "RECEIPT_MISSING",
            "RIGHTS_UNKNOWN",
            "SANDBOX_NETWORK_UNKNOWN",
            "SCAN_ARTIFACT_DIGEST_UNKNOWN",
            "SUBJECT_VERSION_UNKNOWN",
        )


def test_read_only_cli_returns_nonzero_for_fail_closed_pilot() -> None:
    result = subprocess.run(
        [
            sys.executable,
            "scripts/assess_evidence_lineage.py",
            str(PILOT),
            "--decision",
            "publish",
            "--now",
            "2026-08-05T12:00:00Z",
        ],
        cwd=ROOT,
        check=False,
        capture_output=True,
        text=True,
    )

    payload = json.loads(result.stdout)
    assert result.returncode == 1
    assert payload["schema"] == "mcp-trust-evidence-lineage-assessment-set.v1"
    assert {record["status"] for record in payload["records"]} == {"UNKNOWN"}


def test_cli_validation_error_is_content_free(tmp_path: Path) -> None:
    secret_marker = "do-not-echo-this-value"
    invalid = tmp_path / "invalid-ledger.json"
    payload = json.loads(PILOT.read_text(encoding="utf-8"))
    payload["records"][0]["raw_log"] = secret_marker
    invalid.write_text(json.dumps(payload), encoding="utf-8")

    result = subprocess.run(
        [
            sys.executable,
            "scripts/assess_evidence_lineage.py",
            str(invalid),
            "--decision",
            "publish",
            "--now",
            "2026-08-05T12:00:00Z",
        ],
        cwd=ROOT,
        check=False,
        capture_output=True,
        text=True,
    )

    assert result.returncode == 2
    assert secret_marker not in result.stdout
    assert secret_marker not in result.stderr
    assert json.loads(result.stdout) == {
        "reason_codes": ["LEDGER_INVALID"],
        "schema": "mcp-trust-evidence-lineage-error.v1",
        "status": "UNKNOWN",
    }
