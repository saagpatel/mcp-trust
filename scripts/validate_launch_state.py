"""Validate a launch-ready registry DB and receipt bundle.

This is a local/offline preflight. It does not run scans or start the API.
Use it before copying `registry.db` + `receipts/` to a VM, and again on the VM
before public smoke testing.
"""

from __future__ import annotations

import argparse
import json
import os
import sqlite3
import sys
from collections import Counter
from pathlib import Path
from typing import Any

_VALID_GRADES = {"A", "B", "C", "D", "F"}
_VALID_TRANSPARENCY = {"high", "medium", "low"}


def _default_db_path() -> Path:
    return Path(os.environ.get("MCP_TRUST_DB", "registry.db"))


def _default_receipts_dir() -> Path:
    return Path(os.environ.get("MCP_TRUST_RECEIPTS_DIR", "receipts"))


def _default_seed_path() -> Path:
    return Path("src/mcp_trust/catalog/seed_servers.json")


def _load_json(path: Path) -> Any:
    return json.loads(path.read_text(encoding="utf-8"))


def _is_portable_ref(report_ref: str) -> bool:
    return bool(report_ref) and "/" not in report_ref and "\\" not in report_ref


def _latest_scan_rows(conn: sqlite3.Connection) -> list[sqlite3.Row]:
    return conn.execute(
        """
        SELECT s.*
        FROM scans s
        INNER JOIN (
            SELECT server_slug, MAX(scanned_at) AS max_at
            FROM scans
            GROUP BY server_slug
        ) latest ON s.server_slug = latest.server_slug
                 AND s.scanned_at = latest.max_at
        ORDER BY s.server_slug
        """
    ).fetchall()


def validate_launch_state(
    *,
    db_path: Path,
    receipts_dir: Path,
    seed_path: Path,
    allow_stub: bool = False,
) -> tuple[list[str], dict[str, Any]]:
    """Return validation errors and a compact launch-state summary."""

    errors: list[str] = []
    if not db_path.exists():
        return [f"missing registry DB: {db_path}"], {}
    if not receipts_dir.exists():
        return [f"missing receipts directory: {receipts_dir}"], {}
    if not seed_path.exists():
        return [f"missing seed catalog: {seed_path}"], {}

    seed = _load_json(seed_path)
    expected_slugs = {row["slug"] for row in seed}

    conn = sqlite3.connect(db_path)
    conn.row_factory = sqlite3.Row
    rows = _latest_scan_rows(conn)

    latest_slugs = {row["server_slug"] for row in rows}
    missing = sorted(expected_slugs - latest_slugs)
    extras = sorted(latest_slugs - expected_slugs)
    if missing:
        errors.append(f"missing latest scans for seeded slugs: {', '.join(missing)}")
    if extras:
        errors.append(f"latest scans include unseeded slugs: {', '.join(extras)}")

    receipt_count = 0
    grades: Counter[str] = Counter()
    transparencies: Counter[str] = Counter()
    engines: Counter[str] = Counter()

    for row in rows:
        slug = row["server_slug"]
        scan_id = row["id"]
        grade = row["grade"]
        transparency = row["transparency"]
        engine_name = row["engine_name"]
        report_ref = row["report_ref"]

        grades[grade] += 1
        transparencies[transparency] += 1
        engines[engine_name] += 1

        if grade not in _VALID_GRADES:
            errors.append(f"{slug}: invalid grade {grade!r}")
        if transparency not in _VALID_TRANSPARENCY:
            errors.append(f"{slug}: invalid transparency {transparency!r}")
        if engine_name == "stub" and not allow_stub:
            errors.append(f"{slug}: latest scan uses stub engine")
        if not report_ref:
            errors.append(f"{slug}: missing report_ref")
            continue
        if not _is_portable_ref(report_ref):
            errors.append(f"{slug}: report_ref is not portable: {report_ref!r}")
            continue

        receipt_path = receipts_dir / report_ref
        if not receipt_path.exists():
            errors.append(f"{slug}: receipt file missing: {receipt_path}")
            continue

        receipt_count += 1
        try:
            receipt = _load_json(receipt_path)
        except json.JSONDecodeError as exc:
            errors.append(f"{slug}: receipt JSON is invalid: {exc}")
            continue

        if receipt.get("server_slug") != slug:
            errors.append(f"{slug}: receipt server_slug mismatch")
        if receipt.get("scan_id") != scan_id:
            errors.append(f"{slug}: receipt scan_id mismatch")
        scanner = receipt.get("scanner") or {}
        if scanner.get("engine_name") != engine_name:
            errors.append(f"{slug}: receipt engine_name mismatch")
        if scanner.get("engine_version") != row["engine_version"]:
            errors.append(f"{slug}: receipt engine_version mismatch")

    summary = {
        "seeded_servers": len(expected_slugs),
        "latest_scans": len(rows),
        "receipts_checked": receipt_count,
        "grades": dict(sorted(grades.items())),
        "transparency": dict(sorted(transparencies.items())),
        "engines": dict(sorted(engines.items())),
    }
    return errors, summary


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--db", type=Path, default=_default_db_path())
    parser.add_argument("--receipts-dir", type=Path, default=_default_receipts_dir())
    parser.add_argument("--seed", type=Path, default=_default_seed_path())
    parser.add_argument(
        "--allow-stub",
        action="store_true",
        help="Allow latest scans from StubEngine. Never use this for public launch.",
    )
    return parser


def main(argv: list[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    errors, summary = validate_launch_state(
        db_path=args.db,
        receipts_dir=args.receipts_dir,
        seed_path=args.seed,
        allow_stub=args.allow_stub,
    )
    if summary:
        print(json.dumps(summary, indent=2, sort_keys=True))
    if errors:
        print("launch-state validation failed:", file=sys.stderr)
        for error in errors:
            print(f"- {error}", file=sys.stderr)
        return 1
    print("launch-state validation passed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
