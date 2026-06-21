from __future__ import annotations

import importlib.util
import json
import sqlite3
import sys
import tarfile
from datetime import UTC, datetime, timedelta
from pathlib import Path

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
    scanned_at: datetime,
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
            "mcpaudit",
            "2.1.0",
            "A",
            "high",
            '{"composite": 1.0}',
            "[]",
            scanned_at.isoformat(),
            report_ref,
        ),
    )
    conn.commit()


def _write_receipt(receipts_dir: Path, *, filename: str, slug: str, scan_id: str) -> None:
    receipts_dir.mkdir(exist_ok=True)
    (receipts_dir / filename).write_text(
        json.dumps(
            {
                "server_slug": slug,
                "scan_id": scan_id,
                "scanner": {"engine_name": "mcpaudit", "engine_version": "2.1.0"},
            }
        ),
        encoding="utf-8",
    )


def test_build_deploy_bundle_sanitizes_historical_scan_rows(tmp_path) -> None:
    _load_module("validate_launch_state", SCRIPTS / "validate_launch_state.py")
    builder = _load_module("build_deploy_bundle", SCRIPTS / "build_deploy_bundle.py")
    db_path = tmp_path / "registry.db"
    receipts_dir = tmp_path / "receipts"
    seed_path = tmp_path / "seed.json"
    out_dir = tmp_path / "dist"
    _write_seed(seed_path, ["alpha"])

    conn = _init_db(db_path)
    now = datetime.now(tz=UTC)
    _insert_scan(
        conn,
        slug="alpha",
        scan_id="old-scan",
        report_ref="/Users/d/Projects/mcp-trust/receipts/old-alpha.json",
        scanned_at=now - timedelta(hours=1),
    )
    _insert_scan(
        conn,
        slug="alpha",
        scan_id="new-scan",
        report_ref="new-alpha.json",
        scanned_at=now,
    )
    _write_receipt(receipts_dir, filename="new-alpha.json", slug="alpha", scan_id="new-scan")

    bundle_path = builder.build_deploy_bundle(
        db_path=db_path,
        receipts_dir=receipts_dir,
        seed_path=seed_path,
        out_dir=out_dir,
        bundle_name="bundle",
    )

    assert bundle_path.exists()
    extract_dir = tmp_path / "extract"
    with tarfile.open(bundle_path, "r:gz") as tar:
        tar.extractall(extract_dir, filter="data")

    bundle_root = extract_dir / "bundle"
    manifest = json.loads((bundle_root / "MANIFEST.json").read_text())
    assert manifest["bundle"]["scan_rows"] == 1
    assert manifest["bundle"]["receipts"][0]["receipt"] == "new-alpha.json"
    assert (bundle_root / "receipts/new-alpha.json").exists()

    bundle_conn = sqlite3.connect(bundle_root / "registry.db")
    bundle_conn.row_factory = sqlite3.Row
    rows = bundle_conn.execute("select id, report_ref from scans").fetchall()
    assert [(row["id"], row["report_ref"]) for row in rows] == [("new-scan", "new-alpha.json")]
