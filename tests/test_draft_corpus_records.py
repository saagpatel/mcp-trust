from __future__ import annotations

import importlib.util
import json
import sqlite3
import sys
from pathlib import Path

from mcp_trust.corpus.records import load_corpus_records

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


def _write_db(path: Path) -> None:
    conn = sqlite3.connect(path)
    try:
        conn.execute(
            """
            CREATE TABLE servers (
                slug TEXT PRIMARY KEY,
                name TEXT NOT NULL,
                homepage TEXT,
                source_json TEXT NOT NULL
            )
            """
        )
        conn.execute(
            "INSERT INTO servers (slug, name, homepage, source_json) VALUES (?, ?, ?, ?)",
            (
                "com-example-server-1-2-3",
                "com.example/server",
                "https://github.com/example/server",
                json.dumps(
                    {
                        "kind": "npm",
                        "reference": "@example/server",
                        "command": "example-server",
                        "args": [],
                        "env_keys": [],
                    }
                ),
            ),
        )
        conn.commit()
    finally:
        conn.close()


def _write_receipt(path: Path) -> None:
    path.parent.mkdir(parents=True)
    path.write_text(
        json.dumps(
            {
                "server_slug": "com-example-server-1-2-3",
                "server": {
                    "slug": "com-example-server-1-2-3",
                    "name": "com.example/server",
                    "description": "Example",
                    "homepage": "https://github.com/example/server",
                    "added_at": "2026-07-03T00:00:00+00:00",
                    "source": {
                        "kind": "npm",
                        "reference": "@example/server",
                        "command": "example-server",
                        "args": [],
                        "env_keys": [],
                    },
                },
                "scan": {
                    "id": "scan1",
                    "server_slug": "com-example-server-1-2-3",
                    "engine_name": "mcpaudit",
                    "engine_version": "2.1.0",
                    "grade": "C",
                    "transparency": "low",
                    "risk": {"composite": 5.0},
                    "findings": [],
                    "evidence": None,
                    "scanned_at": "2026-07-03T00:00:00+00:00",
                    "report_ref": path.name,
                },
                "approval": {"approval_ref": "test-approval"},
                "sandbox": {
                    "MCP_TRUST_SANDBOX_IMAGE": "mcp-trust-live-batch:test",
                    "MCP_TRUST_SANDBOX_NETWORK": "none",
                },
                "evidence": {
                    "tool_count": 4,
                    "tools": [],
                    "prompt_count": 0,
                    "resource_count": 0,
                    "schema_hash_algorithm": "sha256",
                },
            }
        ),
        encoding="utf-8",
    )


def test_build_record_set_from_temp_db_and_receipt(tmp_path: Path) -> None:
    db = tmp_path / "scan.db"
    receipts = tmp_path / "receipts"
    receipt = receipts / "com-example-server-1-2-3-scan1.json"
    _write_db(db)
    _write_receipt(receipt)
    module = _load_module("draft_corpus_records", SCRIPTS / "draft_corpus_records.py")

    record_set = module.build_record_set(db, receipts)

    assert len(record_set.records) == 1
    record = record_set.records[0]
    assert record.record_id == "com-example-server-1-2-3"
    assert record.status == "scanned-temp"
    assert record.package is not None
    assert record.package.version == "1.2.3"
    assert record.receipt is not None
    assert record.receipt.grade == "C"
    assert record.receipt.tool_count == 4
    assert record.receipt.receipt_ref == "receipts/com-example-server-1-2-3-scan1.json"


def test_version_from_slug_handles_release_and_prerelease() -> None:
    module = _load_module("draft_corpus_records_ver", SCRIPTS / "draft_corpus_records.py")

    assert module._version_from_slug("com-example-server-1-2-3") == "1.2.3"
    assert module._version_from_slug("com-kogcat-kogcat-mcp-0-46-2") == "0.46.2"
    # Prerelease tails are dot-separated identifiers after the release core,
    # never part of it (npm resolves 0.5.0-beta.11, not 0.5.0.beta.11).
    assert (
        module._version_from_slug("com-microsoft-powerbi-modeling-mcp-0-5-0-beta-11")
        == "0.5.0-beta.11"
    )
    assert module._version_from_slug("com-example-server-2-0-0-rc-1") == "2.0.0-rc.1"


def test_version_from_slug_preserves_non_npm_numeric_release_segments() -> None:
    module = _load_module("draft_corpus_records_pypi", SCRIPTS / "draft_corpus_records.py")

    assert (
        module._version_from_slug("org-example-server-1-2-3-4", registry_type="pypi")
        == "1.2.3.4"
    )


def test_draft_corpus_records_cli_writes_valid_json(tmp_path: Path, capsys) -> None:
    db = tmp_path / "scan.db"
    receipts = tmp_path / "receipts"
    out = tmp_path / "draft.json"
    _write_db(db)
    _write_receipt(receipts / "com-example-server-1-2-3-scan1.json")
    module = _load_module("draft_corpus_records_cli", SCRIPTS / "draft_corpus_records.py")

    rc = module.main(["--db", str(db), "--receipts-dir", str(receipts), "--out", str(out)])

    assert rc == 0
    assert out.is_file()
    loaded = load_corpus_records(out)
    assert len(loaded.records) == 1
    summary = json.loads(capsys.readouterr().out)
    assert summary["records"] == 1
    assert summary["with_receipt_grade"] == 1
    assert summary["grades"] == {"C": 1}
