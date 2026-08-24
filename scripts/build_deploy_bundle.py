"""Gate a sanitized VM deploy bundle behind verified publication authority.

The review-only candidate may contain historical rows. This script first runs
the independent candidate and publication-review verifiers. The current pending
review always fails closed; no supported promotion path exists in this lane.
If a future separately authorized state is admitted, only latest unmasked scan
rows and referenced receipts are copied. A bundle still does not authorize
upload or deployment.
"""

from __future__ import annotations

import argparse
import gzip
import hashlib
import json
import os
import re
import sqlite3
import stat
import subprocess
import tarfile
import tempfile
from collections.abc import Callable
from pathlib import Path
from typing import Any

from validate_launch_state import _latest_scan_rows, validate_launch_state

from mcp_trust.refresh import verify_refresh_candidate
from mcp_trust.site.candidate import verify_site_candidate_review

ROOT = Path(__file__).resolve().parents[1]


def _default_seed_path() -> Path:
    return Path("src/mcp_trust/catalog/seed_servers.json")


def _default_masked_path() -> Path:
    return Path("masked-grades.json")


def _sha256(path: Path) -> str:
    return _stable_file_digest(path, str(path))


def _stat_identity(value: os.stat_result) -> tuple[int, int, int, int, int]:
    return (
        value.st_dev,
        value.st_ino,
        value.st_mode,
        value.st_size,
        value.st_mtime_ns,
    )


def _stable_file_bytes(path: Path, label: str) -> bytes:
    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(path, flags)
    except OSError as exc:
        raise ValueError(f"{label} cannot be opened safely: {exc}") from exc
    try:
        before = os.fstat(descriptor)
        if not stat.S_ISREG(before.st_mode):
            raise ValueError(f"{label} must be a regular file")
        chunks: list[bytes] = []
        while chunk := os.read(descriptor, 1024 * 1024):
            chunks.append(chunk)
        after = os.fstat(descriptor)
        current = os.stat(path, follow_symlinks=False)
    finally:
        os.close(descriptor)
    if _stat_identity(before) != _stat_identity(after) or _stat_identity(after) != _stat_identity(
        current
    ):
        raise ValueError(f"{label} changed while it was read")
    return b"".join(chunks)


def _stable_file_digest(path: Path, label: str) -> str:
    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(path, flags)
    except OSError as exc:
        raise ValueError(f"{label} cannot be opened safely: {exc}") from exc
    digest = hashlib.sha256()
    try:
        before = os.fstat(descriptor)
        if not stat.S_ISREG(before.st_mode):
            raise ValueError(f"{label} must be a regular file")
        while chunk := os.read(descriptor, 1024 * 1024):
            digest.update(chunk)
        after = os.fstat(descriptor)
        current = os.stat(path, follow_symlinks=False)
    finally:
        os.close(descriptor)
    if _stat_identity(before) != _stat_identity(after) or _stat_identity(after) != _stat_identity(
        current
    ):
        raise ValueError(f"{label} changed while it was read")
    return digest.hexdigest()


def _stable_copy_file(source: Path, destination: Path, label: str) -> tuple[str, int]:
    source_flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    destination_flags = (
        os.O_WRONLY
        | os.O_CREAT
        | os.O_EXCL
        | getattr(os, "O_CLOEXEC", 0)
        | getattr(os, "O_NOFOLLOW", 0)
    )
    source_descriptor = -1
    destination_descriptor = -1
    destination_created = False
    digest = hashlib.sha256()
    size = 0
    try:
        source_descriptor = os.open(source, source_flags)
        before = os.fstat(source_descriptor)
        if not stat.S_ISREG(before.st_mode):
            raise ValueError(f"{label} must be a regular file")
        destination_descriptor = os.open(destination, destination_flags, 0o600)
        destination_created = True
        while chunk := os.read(source_descriptor, 1024 * 1024):
            view = memoryview(chunk)
            while view:
                written = os.write(destination_descriptor, view)
                if written <= 0:
                    raise OSError("short write while copying verified input")
                view = view[written:]
            digest.update(chunk)
            size += len(chunk)
        os.fsync(destination_descriptor)
        after = os.fstat(source_descriptor)
        current = os.stat(source, follow_symlinks=False)
        if _stat_identity(before) != _stat_identity(after) or _stat_identity(
            after
        ) != _stat_identity(current):
            raise ValueError(f"{label} changed while it was copied")
    except Exception:
        if destination_created:
            destination.unlink(missing_ok=True)
        raise
    finally:
        if destination_descriptor >= 0:
            os.close(destination_descriptor)
        if source_descriptor >= 0:
            os.close(source_descriptor)
    return digest.hexdigest(), size


def _canonical_bytes(value: object) -> bytes:
    return (
        json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode() + b"\n"
    )


def _implementation_binding() -> dict[str, str]:
    status = subprocess.run(
        ["git", "status", "--porcelain", "--untracked-files=all"],
        cwd=ROOT,
        check=True,
        text=True,
        capture_output=True,
    ).stdout
    if status:
        raise ValueError("deployment bundle build requires a clean committed worktree")
    revision = subprocess.run(
        ["git", "rev-parse", "HEAD"],
        cwd=ROOT,
        check=True,
        text=True,
        capture_output=True,
    ).stdout.strip()
    tree = subprocess.run(
        ["git", "ls-tree", "-r", "--full-tree", "HEAD"],
        cwd=ROOT,
        check=True,
        capture_output=True,
    ).stdout
    return {
        "state": "CLEAN_COMMITTED",
        "revision": revision,
        "source_tree_digest": "sha256:" + hashlib.sha256(tree).hexdigest(),
    }


def _copy_sanitized_db(
    source_db: Path, destination_db: Path, *, masked_slugs: set[str]
) -> tuple[list[sqlite3.Row], str, int]:
    source_digest, source_size = _stable_copy_file(source_db, destination_db, "candidate database")
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
    return sanitized_rows, source_digest, source_size


def _validated_implementation_binding(payload: object) -> dict[str, str]:
    if (
        not isinstance(payload, dict)
        or set(payload) != {"state", "revision", "source_tree_digest"}
        or payload.get("state") != "CLEAN_COMMITTED"
        or re.fullmatch(r"[0-9a-f]{40}", str(payload.get("revision", ""))) is None
        or re.fullmatch(r"sha256:[0-9a-f]{64}", str(payload.get("source_tree_digest", ""))) is None
    ):
        raise ValueError("deployment bundle implementation binding is invalid")
    return dict(payload)


def _write_manifest(
    *,
    manifest_path: Path,
    db_path: Path,
    receipts_dir: Path,
    rows: list[sqlite3.Row],
    candidate_manifest_sha256: str,
    source_db_sha256: str,
    source_receipts: list[dict[str, Any]],
    implementation_binding: dict[str, str],
    review_binding: dict[str, Any],
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

    content_files = [
        {
            "path": "registry.db",
            "bytes": db_path.stat().st_size,
            "sha256": _sha256(db_path),
        },
        {
            "path": "masked-grades.json",
            "bytes": masked_path.stat().st_size,
            "sha256": _sha256(masked_path),
        },
        *[
            {
                "path": f"receipts/{item['receipt']}",
                "bytes": (receipts_dir / item["receipt"]).stat().st_size,
                "sha256": item["sha256"],
            }
            for item in receipts
        ],
    ]
    content_files.sort(key=lambda item: item["path"])
    manifest: dict[str, Any] = {
        "schema": "McpTrustVmDeployBundleV2",
        "format_version": 2,
        "source_max_scanned_at": max(str(row["scanned_at"]) for row in rows),
        "implementation_binding": implementation_binding,
        "source": {
            "candidate_manifest_sha256": candidate_manifest_sha256,
            "db_sha256": source_db_sha256,
            "receipts": source_receipts,
        },
        "publication_review": review_binding,
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
        "content": {
            "files": content_files,
            "digest": "sha256:" + hashlib.sha256(_canonical_bytes(content_files)).hexdigest(),
        },
    }
    manifest["receipt_digest"] = "sha256:" + hashlib.sha256(_canonical_bytes(manifest)).hexdigest()
    manifest_path.write_bytes(_canonical_bytes(manifest))
    return manifest


def _verified_artifact_map(verification: dict[str, object]) -> dict[str, dict[str, object]]:
    artifacts = verification.get("_artifact_manifest")
    if not isinstance(artifacts, list):
        raise ValueError("refresh candidate verification omitted its artifact manifest")
    result: dict[str, dict[str, object]] = {}
    for item in artifacts:
        if (
            not isinstance(item, dict)
            or set(item) != {"path", "bytes", "sha256"}
            or not isinstance(item.get("path"), str)
            or not isinstance(item.get("bytes"), int)
            or not isinstance(item.get("sha256"), str)
        ):
            raise ValueError("refresh candidate artifact manifest is invalid")
        result[item["path"]] = item
    return result


def _require_copied_artifact(
    artifacts: dict[str, dict[str, object]],
    *,
    relative: str,
    digest: str,
    size: int,
) -> None:
    expected = artifacts.get(relative)
    if expected != {"path": relative, "bytes": size, "sha256": digest}:
        raise ValueError(f"copied candidate artifact does not match manifest: {relative}")


def _write_deterministic_archive(descriptor: int, *, root: Path, archive_name: str) -> None:
    with os.fdopen(os.dup(descriptor), "wb") as raw:
        with gzip.GzipFile(filename="", mode="wb", fileobj=raw, mtime=0) as compressed:
            with tarfile.open(fileobj=compressed, mode="w", format=tarfile.PAX_FORMAT) as archive:
                paths = [root, *sorted(root.rglob("*"), key=lambda path: path.relative_to(root))]
                for path in paths:
                    if path.is_symlink():
                        raise ValueError("deployment bundle staging tree contains a symlink")
                    relative = path.relative_to(root).as_posix()
                    arcname = archive_name if relative == "." else f"{archive_name}/{relative}"
                    info = archive.gettarinfo(str(path), arcname=arcname)
                    info.uid = 0
                    info.gid = 0
                    info.uname = ""
                    info.gname = ""
                    info.mtime = 0
                    info.mode = 0o755 if path.is_dir() else 0o644
                    if path.is_dir():
                        archive.addfile(info)
                    elif path.is_file():
                        with path.open("rb") as handle:
                            archive.addfile(info, handle)
                    else:
                        raise ValueError("deployment bundle staging tree contains a special file")


def _fsync_directory(path: Path) -> None:
    directory_descriptor = os.open(path, os.O_RDONLY)
    try:
        os.fsync(directory_descriptor)
    finally:
        os.close(directory_descriptor)


def _publish_archive_atomically(*, root: Path, bundle_path: Path, archive_name: str) -> None:
    descriptor, temporary_name = tempfile.mkstemp(
        prefix=f".{archive_name}.", suffix=".tmp", dir=bundle_path.parent
    )
    temporary_path = Path(temporary_name)
    try:
        _write_deterministic_archive(descriptor, root=root, archive_name=archive_name)
        os.fsync(descriptor)
        os.close(descriptor)
        descriptor = -1
        os.link(temporary_path, bundle_path)
        try:
            _fsync_directory(bundle_path.parent)
        except OSError as exc:
            try:
                temporary_identity = temporary_path.stat()
                published_identity = bundle_path.lstat()
                if not os.path.samestat(temporary_identity, published_identity):
                    raise RuntimeError(
                        "deployment bundle final path changed after atomic publication"
                    )
                bundle_path.unlink()
            except FileNotFoundError:
                pass
            except OSError as cleanup_exc:
                raise RuntimeError(
                    "deployment bundle directory sync failed and final cleanup is unknown"
                ) from cleanup_exc
            raise OSError(
                "deployment bundle directory sync failed; final archive was removed"
            ) from exc
    finally:
        if descriptor >= 0:
            os.close(descriptor)
        temporary_path.unlink(missing_ok=True)


def build_deploy_bundle(
    *,
    candidate_path: Path,
    seed_path: Path,
    masked_path: Path,
    policy_path: Path,
    review_path: Path,
    disposition_path: Path,
    out_dir: Path,
    bundle_name: str | None = None,
    candidate_verifier: Callable[..., dict[str, object]] = verify_refresh_candidate,
    review_verifier: Callable[..., dict[str, Any]] = verify_site_candidate_review,
    implementation_binding_provider: Callable[[], dict[str, str]] = _implementation_binding,
) -> Path:
    """Build and return a bundle bound to one independently verified candidate."""

    implementation_binding = _validated_implementation_binding(implementation_binding_provider())
    verification = candidate_verifier(
        candidate_path,
        expected_seed_path=seed_path,
        expected_masked_path=masked_path,
        _include_artifact_manifest=True,
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
    candidate_artifacts = _verified_artifact_map(verification)
    review_binding = review_verifier(
        review_path=review_path,
        disposition_path=disposition_path,
        candidate_path=candidate_path,
        seed_path=seed_path,
        masked_path=masked_path,
        policy_path=policy_path,
        candidate_verifier=candidate_verifier,
    )
    if (
        review_binding.get("publication_allowed") is not True
        or review_binding.get("deployment_allowed") is not True
        or review_binding.get("rollback_state") != "BOUND"
    ):
        raise ValueError(
            "publication review does not authorize a deployment-shaped bundle; "
            f"state={review_binding.get('state', 'UNKNOWN')}"
        )
    if review_binding.get("candidate_manifest_digest") != ("sha256:" + candidate_manifest_sha256):
        raise ValueError("publication review candidate binding changed")

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

    masked_content = _stable_file_bytes(masked_path, "masked-grades input")
    masked_digest = hashlib.sha256(masked_content).hexdigest()
    if review_binding.get("masking_digest") != "sha256:" + masked_digest:
        raise ValueError("publication review masking binding changed")
    try:
        loaded_masked = json.loads(masked_content)
    except json.JSONDecodeError as exc:
        raise ValueError(f"masked-grades input is invalid JSON: {exc}") from exc
    if (
        not isinstance(loaded_masked, list)
        or not all(isinstance(slug, str) and slug for slug in loaded_masked)
        or len(loaded_masked) != len(set(loaded_masked))
    ):
        raise ValueError("masked-grades input must be a unique string list")
    masked_slugs = set(loaded_masked)

    name = bundle_name or f"mcp-trust-deploy-bundle-{candidate_manifest_sha256[:12]}"
    if name in {".", ".."} or re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._-]{0,127}", name) is None:
        raise ValueError("deployment bundle name is unsafe")
    out_dir.mkdir(parents=True, exist_ok=True)
    if out_dir.is_symlink():
        raise ValueError("deployment bundle output directory must not be a symlink")
    bundle_path = out_dir / f"{name}.tar.gz"
    if bundle_path.exists() or bundle_path.is_symlink():
        raise ValueError(f"deployment bundle output already exists: {bundle_path}")

    with tempfile.TemporaryDirectory(prefix="mcp-trust-bundle.") as tmp:
        root = Path(tmp) / name
        bundle_receipts_dir = root / "receipts"
        bundle_receipts_dir.mkdir(parents=True)
        bundle_db = root / "registry.db"

        rows, source_db_sha256, source_db_size = _copy_sanitized_db(
            db_path, bundle_db, masked_slugs=masked_slugs
        )
        _require_copied_artifact(
            candidate_artifacts,
            relative="registry.db",
            digest=source_db_sha256,
            size=source_db_size,
        )
        source_receipts: list[dict[str, Any]] = []
        for row in rows:
            receipt_ref = row["report_ref"]
            digest, size = _stable_copy_file(
                receipts_dir / receipt_ref,
                bundle_receipts_dir / receipt_ref,
                f"candidate receipt {receipt_ref}",
            )
            _require_copied_artifact(
                candidate_artifacts,
                relative=f"receipts/{receipt_ref}",
                digest=digest,
                size=size,
            )
            source_receipts.append({"receipt": receipt_ref, "bytes": size, "sha256": digest})
        source_receipts.sort(key=lambda item: item["receipt"])

        errors, _summary = validate_launch_state(
            db_path=bundle_db,
            receipts_dir=bundle_receipts_dir,
            seed_path=seed_path,
            masked_path=masked_path,
        )
        if errors:
            raise ValueError("sanitized bundle failed validation:\n- " + "\n- ".join(errors))

        (root / "masked-grades.json").write_bytes(masked_content)
        _write_manifest(
            manifest_path=root / "MANIFEST.json",
            db_path=bundle_db,
            receipts_dir=bundle_receipts_dir,
            rows=rows,
            candidate_manifest_sha256=candidate_manifest_sha256,
            source_db_sha256=source_db_sha256,
            source_receipts=source_receipts,
            implementation_binding=implementation_binding,
            review_binding=review_binding,
            masked_path=root / "masked-grades.json",
            masked_slugs=masked_slugs,
        )

        final_review_binding = review_verifier(
            review_path=review_path,
            disposition_path=disposition_path,
            candidate_path=candidate_path,
            seed_path=seed_path,
            masked_path=masked_path,
            policy_path=policy_path,
            candidate_verifier=candidate_verifier,
        )
        if final_review_binding != review_binding:
            raise ValueError("deployment bundle inputs changed during construction")
        final_verification = candidate_verifier(
            candidate_path,
            expected_seed_path=seed_path,
            expected_masked_path=masked_path,
            _include_artifact_manifest=True,
        )
        if (
            final_verification.get("structural_valid") is not True
            or final_verification.get("publication_ready") is not True
            or final_verification.get("manifest_sha256") != candidate_manifest_sha256
            or final_verification.get("_artifact_manifest")
            != verification.get("_artifact_manifest")
        ):
            raise ValueError("refresh candidate inputs changed during construction")

        _publish_archive_atomically(root=root, bundle_path=bundle_path, archive_name=name)

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
    parser.add_argument(
        "--policy",
        type=Path,
        default=Path("src/mcp_trust/catalog/refresh_policy.json"),
    )
    parser.add_argument(
        "--review",
        type=Path,
        required=True,
        help="Receipt-bound publication review for this exact candidate.",
    )
    parser.add_argument(
        "--disposition",
        type=Path,
        default=Path("src/mcp_trust/catalog/refresh_disposition_policy.json"),
    )
    parser.add_argument("--out-dir", type=Path, default=Path("dist"))
    parser.add_argument("--name", help="Bundle directory/tarball basename.")
    return parser


def main(argv: list[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    bundle_path = build_deploy_bundle(
        candidate_path=args.candidate,
        seed_path=args.seed,
        masked_path=args.masked_grades,
        policy_path=args.policy,
        review_path=args.review,
        disposition_path=args.disposition,
        out_dir=args.out_dir,
        bundle_name=args.name,
    )
    print(bundle_path)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
