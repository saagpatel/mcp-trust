from __future__ import annotations

import importlib.util
import json
import sqlite3
import sys
from pathlib import Path

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


def _receipt(record_id: str) -> ReceiptEvidenceRef:
    return ReceiptEvidenceRef(
        receipt_ref=f"receipts/{record_id}.json",
        approval_ref="promotion-review-1",
        scanned_at="2026-07-03T00:00:00+00:00",
        scan_mode=CandidateMode.NO_AUTH_SANDBOXED,
        sandbox_image="mcp-trust-live-batch:test",
        sandbox_network="none",
        grade=TrustGrade.C,
        transparency=TransparencyLevel.LOW,
        tool_count=2,
    )


def _record(record_id: str, status: CorpusRecordStatus) -> PublicCorpusRecord:
    return PublicCorpusRecord(
        record_id=record_id,
        registry_name=f"com.example/{record_id}",
        display_name=f"Example {record_id}",
        status=status,
        recommended_mode=CandidateMode.NO_AUTH_SANDBOXED,
        package=PackageSource(
            registry_type="npm",
            identifier=f"@example/{record_id}",
            version="1.2.3",
            repository_url=f"https://github.com/example/{record_id}",
        ),
        freshness=Freshness.UNKNOWN,
        receipt=_receipt(record_id),
    )


def _write_record_set(path: Path) -> None:
    record_set = CorpusRecordSet(
        records=[
            _record("alpha", CorpusRecordStatus.PUBLISHED),
            _record("beta", CorpusRecordStatus.DEFERRED),
        ]
    )
    path.write_text(json.dumps(record_set.model_dump(mode="json")), encoding="utf-8")


def _write_seed(path: Path, *, include_alpha: bool = False) -> None:
    seed = []
    if include_alpha:
        seed.append(
            {
                "slug": "alpha",
                "name": "Existing alpha",
                "description": "Already seeded",
                "source": {
                    "kind": "npm",
                    "reference": "@example/alpha",
                    "command": "alpha-server",
                    "args": [],
                    "env_keys": [],
                },
                "homepage": "https://github.com/example/alpha",
            }
        )
    path.write_text(json.dumps(seed), encoding="utf-8")


def _write_source_db(path: Path) -> None:
    conn = sqlite3.connect(path)
    try:
        conn.execute(
            """
            CREATE TABLE servers (
                slug TEXT PRIMARY KEY,
                name TEXT NOT NULL,
                description TEXT NOT NULL DEFAULT '',
                source_json TEXT NOT NULL,
                homepage TEXT,
                added_at TEXT NOT NULL
            )
            """
        )
        conn.execute(
            """
            INSERT INTO servers (slug, name, description, source_json, homepage, added_at)
            VALUES (?, ?, ?, ?, ?, ?)
            """,
            (
                "alpha",
                "com.example/alpha",
                "Alpha",
                json.dumps(
                    {
                        "kind": "npm",
                        "reference": "@example/alpha",
                        "command": "alpha-server",
                        "args": [],
                        "env_keys": [],
                    }
                ),
                "https://github.com/example/alpha",
                "2026-07-03T00:00:00+00:00",
            ),
        )
        conn.commit()
    finally:
        conn.close()


def test_build_integration_plan_adds_only_published_records_with_source_specs(
    tmp_path: Path,
) -> None:
    input_path = tmp_path / "records.json"
    seed_path = tmp_path / "seed.json"
    source_db = tmp_path / "source.db"
    _write_record_set(input_path)
    _write_seed(seed_path)
    _write_source_db(source_db)
    module = _load_module(
        "plan_corpus_catalog_integration",
        SCRIPTS / "plan_corpus_catalog_integration.py",
    )

    plan = module.build_integration_plan(input_path, seed_path=seed_path, source_db=source_db)

    assert plan["summary"]["published_records"] == 1
    assert plan["summary"]["deferred_records"] == 1
    assert plan["summary"]["actions"] == {"add-seed-entry": 1}
    assert plan["deferred_record_ids"] == ["beta"]
    action = plan["actions"][0]
    assert action["record_id"] == "alpha"
    assert action["seed_preview"]["source"]["command"] == "alpha-server"
    assert action["receipt_ref"] == "receipts/alpha.json"
    assert "does not edit seed_servers.json" in plan["non_mutation_boundaries"]


def test_build_integration_plan_blocks_without_source_command(tmp_path: Path) -> None:
    input_path = tmp_path / "records.json"
    seed_path = tmp_path / "seed.json"
    _write_record_set(input_path)
    _write_seed(seed_path)
    module = _load_module(
        "plan_corpus_catalog_integration_blocked",
        SCRIPTS / "plan_corpus_catalog_integration.py",
    )

    plan = module.build_integration_plan(input_path, seed_path=seed_path)

    assert plan["summary"]["actions"] == {"blocked": 1}
    assert "missing source spec readback" in plan["actions"][0]["blockers"][0]
    assert "missing launch command" in plan["actions"][0]["blockers"][1]


def test_build_integration_plan_marks_existing_seed_entry(tmp_path: Path) -> None:
    input_path = tmp_path / "records.json"
    seed_path = tmp_path / "seed.json"
    source_db = tmp_path / "source.db"
    _write_record_set(input_path)
    _write_seed(seed_path, include_alpha=True)
    _write_source_db(source_db)
    module = _load_module(
        "plan_corpus_catalog_integration_existing",
        SCRIPTS / "plan_corpus_catalog_integration.py",
    )

    plan = module.build_integration_plan(input_path, seed_path=seed_path, source_db=source_db)

    assert plan["summary"]["actions"] == {"already-seeded": 1}


def test_plan_corpus_catalog_integration_cli_writes_optional_output(
    tmp_path: Path,
    capsys,
) -> None:
    input_path = tmp_path / "records.json"
    seed_path = tmp_path / "seed.json"
    source_db = tmp_path / "source.db"
    out = tmp_path / "plan.json"
    _write_record_set(input_path)
    _write_seed(seed_path)
    _write_source_db(source_db)
    module = _load_module(
        "plan_corpus_catalog_integration_cli",
        SCRIPTS / "plan_corpus_catalog_integration.py",
    )

    rc = module.main(
        [
            "--input",
            str(input_path),
            "--seed",
            str(seed_path),
            "--source-db",
            str(source_db),
            "--out",
            str(out),
        ]
    )

    assert rc == 0
    assert json.loads(capsys.readouterr().out)["summary"]["actions"] == {
        "add-seed-entry": 1
    }
    loaded = json.loads(out.read_text(encoding="utf-8"))
    assert loaded["actions"][0]["record_id"] == "alpha"
    assert load_corpus_records(input_path).records[0].status == "published"
