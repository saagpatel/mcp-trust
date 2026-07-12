#!/usr/bin/env python3
"""Validate an exact, short-lived mcp-trust production deployment approval."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import stat
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

SCHEMA = "McpTrustProductionDeployAuthorizationV2"
MAX_VALIDITY = timedelta(minutes=15)
MAX_FUTURE_SKEW = timedelta(seconds=60)
SHA_RE = re.compile(r"[0-9a-f]{40}")
UTC = timezone.utc  # noqa: UP017 - /usr/bin/python3 is 3.9 on supported macOS hosts.


def _fail(message: str) -> None:
    raise ValueError(message)


def _parse_time(value: Any, field: str) -> datetime:
    if not isinstance(value, str):
        _fail(f"{field} must be an ISO-8601 string")
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as exc:
        _fail(f"{field} is invalid: {exc}")
    if parsed.tzinfo is None:
        _fail(f"{field} must include a timezone")
    return parsed.astimezone(UTC)


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _tree_sha256(root: Path) -> str:
    if not root.is_dir():
        _fail(f"deployment output is not a directory: {root}")
    digest = hashlib.sha256()
    files = 0
    for path in sorted(root.rglob("*"), key=lambda item: item.relative_to(root).as_posix()):
        relative = path.relative_to(root).as_posix()
        if path.is_symlink():
            _fail(f"deployment output contains a symlink: {relative}")
        if path.is_dir():
            continue
        if not path.is_file():
            _fail(f"deployment output contains a special file: {relative}")
        digest.update(relative.encode("utf-8"))
        digest.update(b"\0")
        digest.update(_sha256(path).encode("ascii"))
        digest.update(b"\0")
        files += 1
    if files == 0:
        _fail("deployment output contains no files")
    return digest.hexdigest()


def _regular_file(path: Path, label: str) -> Path:
    if path.is_symlink() or path.parent.is_symlink():
        _fail(f"{label} must not be symlinked: {path}")
    try:
        metadata = path.stat()
    except FileNotFoundError:
        _fail(f"{label} is missing: {path}")
    if not stat.S_ISREG(metadata.st_mode):
        _fail(f"{label} must be a regular file: {path}")
    return path


def _project_link(path: Path, label: str, project_id: str, org_id: str) -> None:
    _regular_file(path, label)
    try:
        link = json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        _fail(f"{label} is invalid JSON: {exc}")
    if not isinstance(link, dict):
        _fail(f"{label} must be a JSON object")
    if link.get("projectId") != project_id or link.get("orgId") != org_id:
        _fail(f"{label} does not match the approved project and organization")


def _validate_project_bindings(
    repository: Path, output_path: Path, project_id: str, org_id: str
) -> None:
    if output_path != repository / "site":
        _fail("deployment output must be the repository site directory")
    root_link = repository / ".vercel/project.json"
    output_link = output_path / ".vercel/project.json"
    _project_link(root_link, "repository Vercel project link", project_id, org_id)
    _project_link(output_link, "output Vercel project link", project_id, org_id)

    forbidden = [
        repository / ".now/project.json",
        output_path / ".now/project.json",
        repository / ".vercel/repo.json",
        output_path / ".vercel/repo.json",
    ]
    current = repository.parent
    while current != current.parent:
        forbidden.extend(
            [
                current / ".vercel/project.json",
                current / ".vercel/repo.json",
                current / ".now/project.json",
            ]
        )
        current = current.parent
    present = [str(path) for path in forbidden if path.exists() or path.is_symlink()]
    if present:
        _fail("unexpected ambient Vercel binding source: " + ", ".join(present))


def validate(
    *,
    approval_path: Path,
    repository: Path,
    branch: str,
    commit: str,
    target_url: str,
    project_id: str,
    org_id: str,
    vercel_bin: Path,
    node_bin: Path,
    output_path: Path,
    output_sha256: str,
    now: datetime | None = None,
) -> None:
    if output_path.is_symlink():
        _fail("deployment output root must not be a symlink")
    if approval_path.is_symlink():
        _fail("approval must not be a symlink")
    approval_path = approval_path.resolve(strict=True)
    mode = stat.S_IMODE(approval_path.stat().st_mode)
    if mode != 0o600:
        _fail(f"approval permissions must be 0600, found {mode:04o}")
    if approval_path.stat().st_uid != os.getuid():
        _fail("approval must be owned by the executing user")

    try:
        payload = json.loads(approval_path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        _fail(f"approval JSON is invalid: {exc}")
    if not isinstance(payload, dict):
        _fail("approval JSON must be an object")

    vercel_invocation_path = vercel_bin.absolute()
    node_invocation_path = node_bin.absolute()
    vercel_resolved = vercel_bin.resolve(strict=True)
    node_resolved = node_bin.resolve(strict=True)
    expected = {
        "schema": SCHEMA,
        "repository": str(repository.resolve(strict=True)),
        "branch": branch,
        "commit": commit,
        "target_url": target_url,
        "vercel_project_id": project_id,
        "vercel_org_id": org_id,
        "vercel_invocation_path": str(vercel_invocation_path),
        "vercel_bin": str(vercel_resolved),
        "node_invocation_path": str(node_invocation_path),
        "node_bin": str(node_resolved),
        "output_path": str(output_path.resolve(strict=True)),
        "output_sha256": output_sha256,
        "approval_path": str(approval_path),
    }
    for field, value in expected.items():
        if payload.get(field) != value:
            _fail(f"approval {field} mismatch")

    receipt_id = payload.get("receipt_id")
    if not isinstance(receipt_id, str) or not receipt_id.strip():
        _fail("approval receipt_id is required")
    if not SHA_RE.fullmatch(commit):
        _fail("approved commit must be a full lowercase Git SHA")

    issued_at = _parse_time(payload.get("issued_at"), "issued_at")
    expires_at = _parse_time(payload.get("expires_at"), "expires_at")
    if expires_at <= issued_at:
        _fail("approval expiry must be after issuance")
    if expires_at - issued_at > MAX_VALIDITY:
        _fail("approval validity window exceeds 15 minutes")
    now = (now or datetime.now(tz=UTC)).astimezone(UTC)
    if issued_at > now + MAX_FUTURE_SKEW:
        _fail("approval issuance is too far in the future")
    if now < issued_at:
        _fail("approval is not yet valid")
    if now >= expires_at:
        _fail("approval is expired")

    expected_digest = payload.get("vercel_sha256")
    if not isinstance(expected_digest, str) or expected_digest != _sha256(vercel_resolved):
        _fail("approval vercel_sha256 mismatch")
    expected_node_digest = payload.get("node_sha256")
    if not isinstance(expected_node_digest, str) or expected_node_digest != _sha256(
        node_resolved
    ):
        _fail("approval node_sha256 mismatch")
    if not re.fullmatch(r"[0-9a-f]{64}", output_sha256):
        _fail("approved output SHA-256 must be 64 lowercase hex characters")
    if _tree_sha256(output_path.resolve(strict=True)) != output_sha256:
        _fail("deployment output tree SHA-256 mismatch")

    _validate_project_bindings(repository, output_path, project_id, org_id)


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--approval", type=Path, required=True)
    parser.add_argument("--repository", type=Path, required=True)
    parser.add_argument("--branch", required=True)
    parser.add_argument("--commit", required=True)
    parser.add_argument("--target-url", required=True)
    parser.add_argument("--project-id", required=True)
    parser.add_argument("--org-id", required=True)
    parser.add_argument("--vercel-bin", type=Path, required=True)
    parser.add_argument("--node-bin", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--output-sha256", required=True)
    return parser


def main(argv: list[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    try:
        validate(
            approval_path=args.approval,
            repository=args.repository,
            branch=args.branch,
            commit=args.commit,
            target_url=args.target_url,
            project_id=args.project_id,
            org_id=args.org_id,
            vercel_bin=args.vercel_bin,
            node_bin=args.node_bin,
            output_path=args.output,
            output_sha256=args.output_sha256,
        )
    except (OSError, ValueError) as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 1
    print("Deployment authorization is valid and current.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
