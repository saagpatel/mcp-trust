"""Build a sanitized VM deploy bundle from a verified refresh candidate.

The review-only candidate may contain historical rows. This script first runs
the independent candidate verifier, then copies only latest unmasked scan rows
and referenced receipts into a manifest-bound transfer artifact. Creating a
bundle does not authorize upload or deployment.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import shutil
import sqlite3
import subprocess
import tarfile
import tempfile
from collections.abc import Callable
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from validate_launch_state import _latest_scan_rows, validate_launch_state

from mcp_trust.refresh import verify_refresh_candidate


def _default_seed_path() -> Path:
    return Path("src/mcp_trust/catalog/seed_servers.json")


def _default_masked_path() -> Path:
    return Path("masked-grades.json")


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


def _copy_sanitized_db(
    source_db: Path, destination_db: Path, *, masked_slugs: set[str]
) -> list[sqlite3.Row]:
    shutil.copy2(source_db, destination_db)
    conn = sqlite3.connect(destination_db)
    conn.row_factory = sqlite3.Row
    rows = _latest_scan_rows(conn)
    latest_ids = {row["id"] for row in rows}
    if not latest_ids:
        raise ValueError("no latest scan rows found")

    placeholders = ",".join("?" for _ in latest_ids)
    conn.execute(f"DELETE FROM scans WHERE id NOT IN ({placeholders})", tuple(latest_ids))
    if masked_slugs:
        masked_placeholders = ",".join("?" for _ in masked_slugs)
        conn.execute(
            f"DELETE FROM scans WHERE server_slug IN ({masked_placeholders})",  # noqa: S608
            tuple(sorted(masked_slugs)),
        )
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
    candidate_path: Path,
    candidate_manifest_sha256: str,
    masked_path: Path,
    masked_slugs: set[str],
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
            "candidate": str(candidate_path),
            "candidate_manifest_sha256": candidate_manifest_sha256,
            "db": str(source_db.relative_to(candidate_path)),
            "receipts_dir": str(source_receipts_dir.relative_to(candidate_path)),
        },
        "masking": {
            "path": "masked-grades.json",
            "sha256": _sha256(masked_path),
            "masked_servers": len(masked_slugs),
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
    candidate_path: Path,
    seed_path: Path,
    masked_path: Path,
    out_dir: Path,
    bundle_name: str | None = None,
    candidate_verifier: Callable[..., dict[str, object]] = verify_refresh_candidate,
) -> Path:
    """Build and return a bundle bound to one independently verified candidate."""

    verification = candidate_verifier(
        candidate_path,
        expected_seed_path=seed_path,
        expected_masked_path=masked_path,
    )
    if verification.get("publication_ready") is not True:
        errors = verification.get("errors")
        detail = ",".join(str(item) for item in errors) if isinstance(errors, list) else ""
        raise ValueError(
            "refresh candidate is not complete, current, and publication-ready"
            + (f": {detail}" if detail else "")
        )
    candidate_manifest_sha256 = verification.get("manifest_sha256")
    if not isinstance(candidate_manifest_sha256, str) or len(candidate_manifest_sha256) != 64:
        raise ValueError("refresh candidate verification omitted its manifest digest")

    db_path = candidate_path / "registry.db"
    receipts_dir = candidate_path / "receipts"

    errors, _summary = validate_launch_state(
        db_path=db_path,
        receipts_dir=receipts_dir,
        seed_path=seed_path,
        masked_path=masked_path,
    )
    if errors:
        raise ValueError("launch state is not deployable:\n- " + "\n- ".join(errors))

    loaded_masked = json.loads(masked_path.read_text(encoding="utf-8"))
    if (
        not isinstance(loaded_masked, list)
        or not all(isinstance(slug, str) and slug for slug in loaded_masked)
        or len(loaded_masked) != len(set(loaded_masked))
    ):
        raise ValueError("masked-grades input must be a unique string list")
    masked_slugs = set(loaded_masked)

    timestamp = datetime.now(tz=UTC).strftime("%Y%m%dT%H%M%SZ")
    name = bundle_name or f"mcp-trust-deploy-bundle-{timestamp}"
    out_dir.mkdir(parents=True, exist_ok=True)
    bundle_path = out_dir / f"{name}.tar.gz"

    with tempfile.TemporaryDirectory(prefix="mcp-trust-bundle.") as tmp:
        root = Path(tmp) / name
        bundle_receipts_dir = root / "receipts"
        bundle_receipts_dir.mkdir(parents=True)
        bundle_db = root / "registry.db"

        rows = _copy_sanitized_db(db_path, bundle_db, masked_slugs=masked_slugs)
        for row in rows:
            receipt_ref = row["report_ref"]
            shutil.copy2(receipts_dir / receipt_ref, bundle_receipts_dir / receipt_ref)

        errors, _summary = validate_launch_state(
            db_path=bundle_db,
            receipts_dir=bundle_receipts_dir,
            seed_path=seed_path,
            masked_path=masked_path,
        )
        if errors:
            raise ValueError("sanitized bundle failed validation:\n- " + "\n- ".join(errors))

        shutil.copy2(masked_path, root / "masked-grades.json")
        _write_manifest(
            manifest_path=root / "MANIFEST.json",
            db_path=bundle_db,
            receipts_dir=bundle_receipts_dir,
            rows=rows,
            source_db=db_path,
            source_receipts_dir=receipts_dir,
            candidate_path=candidate_path,
            candidate_manifest_sha256=candidate_manifest_sha256,
            masked_path=root / "masked-grades.json",
            masked_slugs=masked_slugs,
        )

        with tarfile.open(bundle_path, "w:gz") as tar:
            tar.add(root, arcname=name)

    return bundle_path


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--candidate",
        type=Path,
        required=True,
        help="Complete review-only refresh candidate to verify and package.",
    )
    parser.add_argument("--seed", type=Path, default=_default_seed_path())
    parser.add_argument("--masked-grades", type=Path, default=_default_masked_path())
    parser.add_argument("--out-dir", type=Path, default=Path("dist"))
    parser.add_argument("--name", help="Bundle directory/tarball basename.")
    return parser


def main(argv: list[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    bundle_path = build_deploy_bundle(
        candidate_path=args.candidate,
        seed_path=args.seed,
        masked_path=args.masked_grades,
        out_dir=args.out_dir,
        bundle_name=args.name,
    )
    print(bundle_path)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
