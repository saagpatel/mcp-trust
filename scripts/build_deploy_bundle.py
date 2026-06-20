"""Build a sanitized VM deploy bundle from a launch-ready DB.

The working registry DB may contain older scan rows from local rehearsals. This
script validates the latest launch state, copies only the latest scan rows into a
deploy DB, copies only referenced receipt artifacts, writes a manifest, and
packs the result as a tarball ready to upload to `/data/mcp-trust/` on the VM.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import shutil
import sqlite3
import subprocess
import tarfile
import tempfile
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from validate_launch_state import _latest_scan_rows, validate_launch_state


def _default_db_path() -> Path:
    return Path(os.environ.get("MCP_TRUST_DB", "registry.db"))


def _default_receipts_dir() -> Path:
    return Path(os.environ.get("MCP_TRUST_RECEIPTS_DIR", "receipts"))


def _default_seed_path() -> Path:
    return Path("src/mcp_trust/catalog/seed_servers.json")


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _git_value(args: list[str]) -> str | None:
    result = subprocess.run(["git", *args], text=True, capture_output=True, check=False)
    if result.returncode != 0:
        return None
    return result.stdout.strip()


def _copy_sanitized_db(source_db: Path, destination_db: Path) -> list[sqlite3.Row]:
    shutil.copy2(source_db, destination_db)
    conn = sqlite3.connect(destination_db)
    conn.row_factory = sqlite3.Row
    rows = _latest_scan_rows(conn)
    latest_ids = {row["id"] for row in rows}
    if not latest_ids:
        raise ValueError("no latest scan rows found")

    placeholders = ",".join("?" for _ in latest_ids)
    conn.execute(f"DELETE FROM scans WHERE id NOT IN ({placeholders})", tuple(latest_ids))
    conn.commit()
    conn.execute("VACUUM")
    conn.close()

    conn = sqlite3.connect(destination_db)
    conn.row_factory = sqlite3.Row
    sanitized_rows = _latest_scan_rows(conn)
    conn.close()
    return sanitized_rows


def _write_manifest(
    *,
    manifest_path: Path,
    db_path: Path,
    receipts_dir: Path,
    rows: list[sqlite3.Row],
    source_db: Path,
    source_receipts_dir: Path,
) -> dict[str, Any]:
    receipts: list[dict[str, Any]] = []
    for row in rows:
        receipt_name = row["report_ref"]
        receipt_path = receipts_dir / receipt_name
        receipts.append(
            {
                "server_slug": row["server_slug"],
                "scan_id": row["id"],
                "grade": row["grade"],
                "transparency": row["transparency"],
                "engine_name": row["engine_name"],
                "engine_version": row["engine_version"],
                "receipt": receipt_name,
                "sha256": _sha256(receipt_path),
            }
        )

    manifest = {
        "format_version": 1,
        "created_at": datetime.now(tz=UTC).isoformat(),
        "git": {
            "head": _git_value(["rev-parse", "HEAD"]),
            "branch": _git_value(["branch", "--show-current"]),
            "status_short": _git_value(["status", "--short"]),
        },
        "source": {
            "db": str(source_db),
            "receipts_dir": str(source_receipts_dir),
        },
        "bundle": {
            "db": "registry.db",
            "db_sha256": _sha256(db_path),
            "receipts_dir": "receipts",
            "scan_rows": len(rows),
            "receipts": receipts,
        },
    }
    manifest_path.write_text(
        json.dumps(manifest, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    return manifest


def build_deploy_bundle(
    *,
    db_path: Path,
    receipts_dir: Path,
    seed_path: Path,
    out_dir: Path,
    bundle_name: str | None = None,
) -> Path:
    """Build and return the deploy bundle tarball path."""

    errors, _summary = validate_launch_state(
        db_path=db_path,
        receipts_dir=receipts_dir,
        seed_path=seed_path,
    )
    if errors:
        raise ValueError("launch state is not deployable:\n- " + "\n- ".join(errors))

    timestamp = datetime.now(tz=UTC).strftime("%Y%m%dT%H%M%SZ")
    name = bundle_name or f"mcp-trust-deploy-bundle-{timestamp}"
    out_dir.mkdir(parents=True, exist_ok=True)
    bundle_path = out_dir / f"{name}.tar.gz"

    with tempfile.TemporaryDirectory(prefix="mcp-trust-bundle.") as tmp:
        root = Path(tmp) / name
        bundle_receipts_dir = root / "receipts"
        bundle_receipts_dir.mkdir(parents=True)
        bundle_db = root / "registry.db"

        rows = _copy_sanitized_db(db_path, bundle_db)
        for row in rows:
            receipt_ref = row["report_ref"]
            shutil.copy2(receipts_dir / receipt_ref, bundle_receipts_dir / receipt_ref)

        errors, _summary = validate_launch_state(
            db_path=bundle_db,
            receipts_dir=bundle_receipts_dir,
            seed_path=seed_path,
        )
        if errors:
            raise ValueError("sanitized bundle failed validation:\n- " + "\n- ".join(errors))

        _write_manifest(
            manifest_path=root / "MANIFEST.json",
            db_path=bundle_db,
            receipts_dir=bundle_receipts_dir,
            rows=rows,
            source_db=db_path,
            source_receipts_dir=receipts_dir,
        )

        with tarfile.open(bundle_path, "w:gz") as tar:
            tar.add(root, arcname=name)

    return bundle_path


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--db", type=Path, default=_default_db_path())
    parser.add_argument("--receipts-dir", type=Path, default=_default_receipts_dir())
    parser.add_argument("--seed", type=Path, default=_default_seed_path())
    parser.add_argument("--out-dir", type=Path, default=Path("dist"))
    parser.add_argument("--name", help="Bundle directory/tarball basename.")
    return parser


def main(argv: list[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    bundle_path = build_deploy_bundle(
        db_path=args.db,
        receipts_dir=args.receipts_dir,
        seed_path=args.seed,
        out_dir=args.out_dir,
        bundle_name=args.name,
    )
    print(bundle_path)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
