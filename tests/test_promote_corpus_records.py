from __future__ import annotations

import importlib.util
import json
import sys
from pathlib import Path

import pytest

from mcp_trust.core.models import TransparencyLevel, TrustGrade
from mcp_trust.corpus.records import (
    CorpusRecordSet,
    CorpusRecordStatus,
    PackageSource,
    PublicCorpusRecord,
    ReceiptEvidenceRef,
    load_corpus_records,
)
from mcp_trust.corpus.registry import CandidateMode, Freshness

ROOT = Path(__file__).resolve().parents[1]
SCRIPTS = ROOT / "scripts"


def _load_module(name: str, path: Path):
    spec = importlib.util.spec_from_file_location(name, path)
    assert spec is not None
    assert spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


def _package(name: str = "@example/server") -> PackageSource:
    return PackageSource(
        registry_type="npm",
        identifier=name,
        version="1.2.3",
        repository_url="https://github.com/example/server",
    )


def _receipt(record_id: str) -> ReceiptEvidenceRef:
    return ReceiptEvidenceRef(
        receipt_ref=f"receipts/{record_id}.json",
        approval_ref="first-batch-approval",
        scanned_at="2026-07-03T00:00:00+00:00",
        scan_mode=CandidateMode.NO_AUTH_SANDBOXED,
        sandbox_image="mcp-trust-live-batch:test",
        sandbox_network="none",
        grade=TrustGrade.C,
        transparency=TransparencyLevel.LOW,
        tool_count=3,
    )


def _record(record_id: str, *, receipt: bool = True) -> PublicCorpusRecord:
    return PublicCorpusRecord(
        record_id=record_id,
        registry_name=f"com.example/{record_id}",
        display_name=record_id,
        status=CorpusRecordStatus.SCANNED_TEMP,
        recommended_mode=CandidateMode.NO_AUTH_SANDBOXED,
        package=_package(f"@example/{record_id}"),
        freshness=Freshness.UNKNOWN,
        receipt=_receipt(record_id) if receipt else None,
        publish_caveats=["Registry metadata is not tool-surface truth."],
    )


def _write_record_set(path: Path, records: list[PublicCorpusRecord]) -> None:
    path.write_text(
        json.dumps(CorpusRecordSet(records=records).model_dump(mode="json")),
        encoding="utf-8",
    )


def test_promote_record_set_only_promotes_named_receipt_backed_records(tmp_path: Path) -> None:
    input_path = tmp_path / "records.json"
    _write_record_set(input_path, [_record("alpha"), _record("beta")])
    module = _load_module("promote_corpus_records", SCRIPTS / "promote_corpus_records.py")

    record_set = module.promote_record_set(
        input_path,
        promote_ids={"alpha"},
        promotion_ref="promotion-review-1",
    )

    by_id = {record.record_id: record for record in record_set.records}
    assert by_id["alpha"].status == "published"
    assert by_id["alpha"].receipt is not None
    assert by_id["alpha"].receipt.grade == "C"
    assert "Review-only promotion artifact: promotion-review-1." in by_id[
        "alpha"
    ].publish_caveats
    assert by_id["beta"].status == "scanned-temp"


def test_promote_record_set_can_defer_unpromoted_records(tmp_path: Path) -> None:
    input_path = tmp_path / "records.json"
    _write_record_set(input_path, [_record("alpha"), _record("beta")])
    module = _load_module("promote_corpus_records_defer", SCRIPTS / "promote_corpus_records.py")

    record_set = module.promote_record_set(
        input_path,
        promote_ids={"alpha"},
        promotion_ref="promotion-review-1",
        defer_unpromoted=True,
        defer_reason="source mapping needs review",
    )

    by_id = {record.record_id: record for record in record_set.records}
    assert by_id["alpha"].status == "published"
    assert by_id["beta"].status == "deferred"
    assert "Deferred: source mapping needs review." in by_id["beta"].publish_caveats


def test_promote_record_set_refuses_missing_or_unbacked_records(tmp_path: Path) -> None:
    input_path = tmp_path / "records.json"
    _write_record_set(input_path, [_record("alpha", receipt=False)])
    module = _load_module("promote_corpus_records_guard", SCRIPTS / "promote_corpus_records.py")

    with pytest.raises(ValueError, match="cannot be promoted without receipt evidence"):
        module.promote_record_set(
            input_path,
            promote_ids={"alpha"},
            promotion_ref="promotion-review-1",
        )

    with pytest.raises(ValueError, match="not found"):
        module.promote_record_set(
            input_path,
            promote_ids={"missing"},
            promotion_ref="promotion-review-1",
        )


def test_promote_corpus_records_cli_writes_valid_json(tmp_path: Path, capsys) -> None:
    input_path = tmp_path / "records.json"
    out = tmp_path / "published.json"
    _write_record_set(input_path, [_record("alpha"), _record("beta")])
    module = _load_module("promote_corpus_records_cli", SCRIPTS / "promote_corpus_records.py")

    rc = module.main(
        [
            "--input",
            str(input_path),
            "--promote",
            "alpha",
            "--promotion-ref",
            "promotion-review-1",
            "--defer-unpromoted",
            "--out",
            str(out),
        ]
    )

    assert rc == 0
    loaded = load_corpus_records(out)
    statuses = {record.record_id: record.status for record in loaded.records}
    assert statuses == {"alpha": "published", "beta": "deferred"}
    summary = json.loads(capsys.readouterr().out)
    assert summary["statuses"] == {"deferred": 1, "published": 1}
    assert summary["published_without_receipts"] == []
