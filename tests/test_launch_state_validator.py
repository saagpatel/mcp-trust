from __future__ import annotations

import importlib.util
import json
import sqlite3
import sys
from datetime import UTC, datetime
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SCRIPTS = ROOT / "scripts"


def _load_validator():
    spec = importlib.util.spec_from_file_location(
        "validate_launch_state", SCRIPTS / "validate_launch_state.py"
    )
    assert spec is not None
    assert spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules["validate_launch_state"] = module
    spec.loader.exec_module(module)
    return module


def _write_seed(path: Path, slugs: list[str]) -> None:
    payload = [
        {"slug": slug, "name": slug, "source": {"kind": "npm", "reference": slug}}
        for slug in slugs
    ]
    path.write_text(json.dumps(payload), encoding="utf-8")


def _init_db(path: Path) -> sqlite3.Connection:
    conn = sqlite3.connect(path)
    conn.execute(
        """
        CREATE TABLE scans (
            id TEXT PRIMARY KEY,
            server_slug TEXT NOT NULL,
            engine_name TEXT NOT NULL,
            engine_version TEXT NOT NULL,
            grade TEXT NOT NULL,
            transparency TEXT NOT NULL,
            risk_json TEXT NOT NULL,
            findings_json TEXT NOT NULL,
            scanned_at TEXT NOT NULL,
            report_ref TEXT
        )
        """
    )
    return conn


def _insert_scan(
    conn: sqlite3.Connection,
    *,
    slug: str,
    scan_id: str,
    report_ref: str,
    engine_name: str = "mcpaudit",
) -> None:
    conn.execute(
        """
        INSERT INTO scans
            (id, server_slug, engine_name, engine_version, grade, transparency,
             risk_json, findings_json, scanned_at, report_ref)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (
            scan_id,
            slug,
            engine_name,
            "2.1.0",
            "A",
            "high",
            '{"composite": 1.0}',
            "[]",
            datetime.now(tz=UTC).isoformat(),
            report_ref,
        ),
    )
    conn.commit()


def _write_receipt(
    receipts_dir: Path,
    *,
    filename: str,
    slug: str,
    scan_id: str,
    engine_name: str = "mcpaudit",
) -> None:
    receipts_dir.mkdir()
    (receipts_dir / filename).write_text(
        json.dumps(
            {
                "server_slug": slug,
                "scan_id": scan_id,
                "scanner": {"engine_name": engine_name, "engine_version": "2.1.0"},
            }
        ),
        encoding="utf-8",
    )


def test_validate_launch_state_accepts_portable_receipts(tmp_path) -> None:
    validator = _load_validator()
    db_path = tmp_path / "registry.db"
    receipts_dir = tmp_path / "receipts"
    seed_path = tmp_path / "seed.json"
    _write_seed(seed_path, ["alpha"])
    conn = _init_db(db_path)
    _insert_scan(conn, slug="alpha", scan_id="scan-alpha", report_ref="alpha-scan.json")
    _write_receipt(receipts_dir, filename="alpha-scan.json", slug="alpha", scan_id="scan-alpha")

    errors, summary = validator.validate_launch_state(
        db_path=db_path,
        receipts_dir=receipts_dir,
        seed_path=seed_path,
    )

    assert errors == []
    assert summary["latest_scans"] == 1
    assert summary["receipts_checked"] == 1
    assert summary["engines"] == {"mcpaudit": 1}


def test_validate_launch_state_rejects_absolute_report_ref(tmp_path) -> None:
    validator = _load_validator()
    db_path = tmp_path / "registry.db"
    receipts_dir = tmp_path / "receipts"
    seed_path = tmp_path / "seed.json"
    _write_seed(seed_path, ["alpha"])
    receipts_dir.mkdir()
    conn = _init_db(db_path)
    _insert_scan(
        conn,
        slug="alpha",
        scan_id="scan-alpha",
        report_ref="/tmp/receipts/alpha-scan.json",
    )

    errors, _summary = validator.validate_launch_state(
        db_path=db_path,
        receipts_dir=receipts_dir,
        seed_path=seed_path,
    )

    assert any("report_ref is not portable" in error for error in errors)


def test_validate_launch_state_rejects_stub_latest_scan(tmp_path) -> None:
    validator = _load_validator()
    db_path = tmp_path / "registry.db"
    receipts_dir = tmp_path / "receipts"
    seed_path = tmp_path / "seed.json"
    _write_seed(seed_path, ["alpha"])
    conn = _init_db(db_path)
    _insert_scan(
        conn,
        slug="alpha",
        scan_id="scan-alpha",
        report_ref="alpha-scan.json",
        engine_name="stub",
    )
    _write_receipt(
        receipts_dir,
        filename="alpha-scan.json",
        slug="alpha",
        scan_id="scan-alpha",
        engine_name="stub",
    )

    errors, _summary = validator.validate_launch_state(
        db_path=db_path,
        receipts_dir=receipts_dir,
        seed_path=seed_path,
    )

    assert any("latest scan uses stub engine" in error for error in errors)
