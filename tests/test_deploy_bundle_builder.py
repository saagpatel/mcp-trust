from __future__ import annotations

import importlib.util
import json
import sqlite3
import sys
import tarfile
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest

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


def _admitted_candidate_verifier(*_args, **_kwargs) -> dict[str, object]:
    return {
        "publication_ready": True,
        "manifest_sha256": "a" * 64,
        "errors": [],
    }


def test_build_deploy_bundle_rejects_unverified_candidate(tmp_path) -> None:
    _load_module("validate_launch_state", SCRIPTS / "validate_launch_state.py")
    builder = _load_module("build_deploy_bundle", SCRIPTS / "build_deploy_bundle.py")
    candidate = tmp_path / "candidate"
    candidate.mkdir()
    seed_path = tmp_path / "seed.json"
    masked_path = tmp_path / "masked.json"
    _write_seed(seed_path, ["alpha"])
    masked_path.write_text("[]\n", encoding="utf-8")

    with pytest.raises(ValueError, match="not complete, current, and publication-ready"):
        builder.build_deploy_bundle(
            candidate_path=candidate,
            seed_path=seed_path,
            masked_path=masked_path,
            out_dir=tmp_path / "dist",
        )


def test_build_deploy_bundle_sanitizes_historical_scan_rows(tmp_path) -> None:
    _load_module("validate_launch_state", SCRIPTS / "validate_launch_state.py")
    builder = _load_module("build_deploy_bundle", SCRIPTS / "build_deploy_bundle.py")
    candidate_path = tmp_path / "candidate"
    candidate_path.mkdir()
    db_path = candidate_path / "registry.db"
    receipts_dir = candidate_path / "receipts"
    seed_path = tmp_path / "seed.json"
    masked_path = tmp_path / "masked.json"
    out_dir = tmp_path / "dist"
    _write_seed(seed_path, ["alpha"])
    masked_path.write_text("[]\n", encoding="utf-8")

    conn = _init_db(db_path)
    now = datetime.now(tz=UTC)
    _insert_scan(
        conn,
        slug="alpha",
        scan_id="old-scan",
        report_ref="~/Projects/mcp-trust/receipts/old-alpha.json",
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
        candidate_path=candidate_path,
        seed_path=seed_path,
        masked_path=masked_path,
        out_dir=out_dir,
        bundle_name="bundle",
        candidate_verifier=_admitted_candidate_verifier,
    )

    assert bundle_path.exists()
    extract_dir = tmp_path / "extract"
    with tarfile.open(bundle_path, "r:gz") as tar:
        tar.extractall(extract_dir, filter="data")

    bundle_root = extract_dir / "bundle"
    manifest = json.loads((bundle_root / "MANIFEST.json").read_text())
    assert manifest["bundle"]["scan_rows"] == 1
    assert manifest["source"]["candidate_manifest_sha256"] == "a" * 64
    assert manifest["source"]["db"] == "registry.db"
    assert manifest["source"]["receipts_dir"] == "receipts"
    assert manifest["bundle"]["receipts"][0]["receipt"] == "new-alpha.json"
    assert (bundle_root / "receipts/new-alpha.json").exists()
    assert json.loads((bundle_root / "masked-grades.json").read_text()) == []

    bundle_conn = sqlite3.connect(bundle_root / "registry.db")
    bundle_conn.row_factory = sqlite3.Row
    rows = bundle_conn.execute("select id, report_ref from scans").fetchall()
    assert [(row["id"], row["report_ref"]) for row in rows] == [("new-scan", "new-alpha.json")]


def test_build_deploy_bundle_removes_masked_scan_rows_and_receipts(tmp_path) -> None:
    _load_module("validate_launch_state", SCRIPTS / "validate_launch_state.py")
    builder = _load_module("build_deploy_bundle", SCRIPTS / "build_deploy_bundle.py")
    candidate_path = tmp_path / "candidate"
    candidate_path.mkdir()
    db_path = candidate_path / "registry.db"
    receipts_dir = candidate_path / "receipts"
    seed_path = tmp_path / "seed.json"
    masked_path = tmp_path / "masked.json"
    out_dir = tmp_path / "dist"
    _write_seed(seed_path, ["alpha", "masked"])
    masked_path.write_text(json.dumps(["masked"]), encoding="utf-8")
    conn = _init_db(db_path)
    now = datetime.now(tz=UTC)
    for slug in ("alpha", "masked"):
        _insert_scan(
            conn,
            slug=slug,
            scan_id=f"{slug}-scan",
            report_ref=f"{slug}.json",
            scanned_at=now,
        )
        _write_receipt(
            receipts_dir,
            filename=f"{slug}.json",
            slug=slug,
            scan_id=f"{slug}-scan",
        )

    bundle_path = builder.build_deploy_bundle(
        candidate_path=candidate_path,
        seed_path=seed_path,
        masked_path=masked_path,
        out_dir=out_dir,
        bundle_name="bundle-masked",
        candidate_verifier=_admitted_candidate_verifier,
    )
    extract_dir = tmp_path / "extract"
    with tarfile.open(bundle_path, "r:gz") as tar:
        tar.extractall(extract_dir, filter="data")
    root = extract_dir / "bundle-masked"
    bundle_conn = sqlite3.connect(root / "registry.db")
    assert bundle_conn.execute("select server_slug from scans").fetchall() == [("alpha",)]
    assert (root / "receipts/alpha.json").is_file()
    assert not (root / "receipts/masked.json").exists()
    assert json.loads((root / "masked-grades.json").read_text()) == ["masked"]
