#!/usr/bin/env python3
"""Validate an exact, short-lived mcp-trust production deployment approval."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import stat
import subprocess
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

SCHEMA = "McpTrustProductionDeployAuthorizationV4"
SITE_SCHEMA = "McpTrustSiteCandidateV2"
SITE_MANIFEST = "SITE_CANDIDATE.json"
SITE_REVIEW_STATE = "REVIEW_ONLY_ACCEPTED_FOR_SOURCE_REVIEW"
DEPLOYABLE_SITE_STATE = "PUBLICATION_APPROVED_ROLLBACK_BOUND"  # legacy rejection helper
PACKAGE_SCHEMA = "McpTrustPublicationPackageV1"
PACKAGE_STATE = "PUBLICATION_PACKAGE_READY_FOR_DEPLOY_REVIEW"
PACKAGE_MANIFEST = "PUBLICATION_PACKAGE.json"
PUBLICATION_APPROVAL_SCHEMA = "McpTrustPublicationApprovalV1"
PUBLICATION_APPROVAL_STATE = "PUBLICATION_CONTENT_APPROVED_LOCAL_ONLY"
READBACK_SCHEMA = "WebReleaseSentinelManifestV1"
READBACK_CONTRACT_VERSION = "1.0.0"
READBACK_MISSING_ROUTE = "/__mcp_trust_candidate_missing__"
READBACK_MAX_ROUTES = 128
READBACK_MAX_BODY_BYTES = 16 * 1024 * 1024
READBACK_NON_PUBLIC_FILES = frozenset({"vercel.json"})
MAX_VALIDITY = timedelta(minutes=15)
MAX_FUTURE_SKEW = timedelta(seconds=60)
SHA_RE = re.compile(r"[0-9a-f]{40}")
SHA256_RE = re.compile(r"sha256:[0-9a-f]{64}")
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


def _stable_file_bytes(path: Path, label: str) -> bytes:
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(path, flags)
    except OSError as exc:
        _fail(f"{label} cannot be opened safely: {exc}")
    try:
        before = os.fstat(descriptor)
        if not stat.S_ISREG(before.st_mode):
            _fail(f"{label} must be a regular file")
        with os.fdopen(descriptor, "rb", closefd=False) as handle:
            content = handle.read()
        after = os.fstat(descriptor)
        current = os.stat(path, follow_symlinks=False)
    finally:
        os.close(descriptor)

    def identity(value: os.stat_result) -> tuple[int, int, int, int, int]:
        return (
            value.st_dev,
            value.st_ino,
            value.st_mode,
            value.st_size,
            value.st_mtime_ns,
        )

    if identity(before) != identity(after) or identity(after) != identity(current):
        _fail(f"{label} changed while it was read")
    return content


def _sha256(path: Path) -> str:
    return hashlib.sha256(_stable_file_bytes(path, str(path))).hexdigest()


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


def _canonical_bytes(value: object) -> bytes:
    return (
        json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode() + b"\n"
    )


def _prefixed_digest(value: bytes) -> str:
    return "sha256:" + hashlib.sha256(value).hexdigest()


def _strict_json(value: bytes, label: str) -> Any:
    def reject_duplicates(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
        result: dict[str, Any] = {}
        for key, item in pairs:
            if key in result:
                _fail(f"{label} contains duplicate key: {key}")
            result[key] = item
        return result

    try:
        return json.loads(value, object_pairs_hook=reject_duplicates)
    except json.JSONDecodeError as exc:
        _fail(f"{label} is invalid JSON: {exc}")


def _git_tree_digest(repository: Path, commit: str) -> str:
    if SHA_RE.fullmatch(commit) is None:
        _fail("approved commit must be a full lowercase Git SHA")
    result = subprocess.run(
        ["/usr/bin/git", "-C", str(repository), "ls-tree", "-r", "--full-tree", commit],
        check=False,
        capture_output=True,
    )
    if result.returncode != 0:
        _fail("approved commit Git tree cannot be read")
    return _prefixed_digest(result.stdout)


def _public_route(relative: str) -> tuple[str, int]:
    if relative == "index.html":
        route, expected_status = "/", 200
    elif relative == "404.html":
        route, expected_status = READBACK_MISSING_ROUTE, 404
    elif relative.startswith("ui/") and relative.endswith("/index.html"):
        route, expected_status = "/" + relative[: -len("/index.html")], 200
    elif relative.startswith("servers/") and relative.endswith("/badge.json"):
        route, expected_status = "/" + relative, 200
    else:
        _fail(f"site candidate file has no public route mapping: {relative}")
    if (
        not route.startswith("/")
        or route.startswith("//")
        or "#" in route
        or any(character.isspace() for character in route)
    ):
        _fail(f"site candidate file maps to an invalid public route: {relative}")
    return route, expected_status


def _public_readback_manifest(files: list[dict[str, object]]) -> dict[str, object]:
    public_files = [item for item in files if item["path"] not in READBACK_NON_PUBLIC_FILES]
    if not 1 <= len(public_files) <= READBACK_MAX_ROUTES:
        _fail(f"site candidate exact readback requires between 1 and {READBACK_MAX_ROUTES} routes")
    routes: list[dict[str, object]] = []
    largest_body = 1
    for index, item in enumerate(public_files):
        relative = item["path"]
        body_bytes = item["bytes"]
        body_digest = item["sha256"]
        if not isinstance(relative, str) or not isinstance(body_bytes, int):
            _fail("site candidate exact readback file metadata is invalid")
        if not isinstance(body_digest, str) or not body_digest.startswith("sha256:"):
            _fail("site candidate exact readback file digest is invalid")
        route, expected_status = _public_route(relative)
        largest_body = max(largest_body, body_bytes)
        routes.append(
            {
                "id": f"route-{index:03d}",
                "method": "GET",
                "route": route,
                "expected_status": expected_status,
                "body_sha256": body_digest[len("sha256:") :],
            }
        )
    if largest_body > READBACK_MAX_BODY_BYTES:
        _fail("site candidate file exceeds exact readback body limit")
    return {
        "schema": READBACK_SCHEMA,
        "contract_version": READBACK_CONTRACT_VERSION,
        "name": "mcp-trust-site-candidate-exact",
        "defaults": {
            "timeout_seconds": 10,
            "max_body_bytes": largest_body,
            "follow_same_origin_redirects": False,
        },
        "denied_methods": ["POST", "PUT", "PATCH", "DELETE", "CONNECT", "TRACE"],
        "routes": routes,
    }


def _validate_site_candidate(output_path: Path) -> dict[str, str]:
    """Require a receipt-bound, rollback-bound artifact before deploy approval."""
    manifest_path = _regular_file(output_path / SITE_MANIFEST, "site candidate manifest")
    manifest = _strict_json(
        _stable_file_bytes(manifest_path, "site candidate manifest"),
        "site candidate manifest",
    )
    if not isinstance(manifest, dict) or manifest.get("schema") != SITE_SCHEMA:
        _fail("site candidate manifest schema is invalid")
    unsigned = dict(manifest)
    claimed = unsigned.pop("receipt_digest", None)
    if not isinstance(claimed, str) or claimed != _prefixed_digest(_canonical_bytes(unsigned)):
        _fail("site candidate manifest receipt integrity is invalid")
    if (
        manifest.get("state") != DEPLOYABLE_SITE_STATE
        or manifest.get("publication_allowed") is not True
        or manifest.get("deployment_allowed") is not True
        or manifest.get("blocking_gates", []) != []
    ):
        _fail("site candidate is not publication-approved and deployment-eligible")
    implementation = manifest.get("implementation_binding")
    if (
        not isinstance(implementation, dict)
        or implementation.get("state") != "CLEAN_COMMITTED"
        or re.fullmatch(r"[0-9a-f]{40}", str(implementation.get("revision", ""))) is None
        or re.fullmatch(r"sha256:[0-9a-f]{64}", str(implementation.get("source_tree_digest", "")))
        is None
    ):
        _fail("site candidate implementation binding is invalid")
    rollback = manifest.get("rollback")
    if (
        not isinstance(rollback, dict)
        or rollback.get("state") != "BOUND"
        or not isinstance(rollback.get("site_receipt_digest"), str)
        or re.fullmatch(r"sha256:[0-9a-f]{64}", rollback["site_receipt_digest"]) is None
        or not isinstance(rollback.get("content_digest"), str)
        or re.fullmatch(r"sha256:[0-9a-f]{64}", rollback["content_digest"]) is None
    ):
        _fail("site candidate rollback lineage is not exact and complete")
    bindings = manifest.get("bindings")
    required_bindings = {
        "candidate_manifest_digest",
        "review_artifact_sha256",
        "review_receipt_digest",
        "disposition_policy_sha256",
        "seed_digest",
        "masking_digest",
        "policy_digest",
        "source_revision",
        "source_tree_digest",
        "state",
        "publication_allowed",
        "deployment_allowed",
        "rollback_state",
    }
    if not isinstance(bindings, dict) or not required_bindings <= set(bindings):
        _fail("site candidate provenance bindings are incomplete")
    if (
        bindings.get("state") != DEPLOYABLE_SITE_STATE
        or bindings.get("publication_allowed") is not True
        or bindings.get("deployment_allowed") is not True
        or bindings.get("rollback_state") != "BOUND"
    ):
        _fail("site candidate review authority binding is invalid")
    digest_bindings = required_bindings - {
        "source_revision",
        "state",
        "publication_allowed",
        "deployment_allowed",
        "rollback_state",
    }
    if (
        any(
            not isinstance(bindings.get(field), str)
            or re.fullmatch(r"sha256:[0-9a-f]{64}", bindings[field]) is None
            for field in digest_bindings
        )
        or re.fullmatch(r"[0-9a-f]{40}", str(bindings.get("source_revision", ""))) is None
    ):
        _fail("site candidate provenance binding format is invalid")

    content = manifest.get("content")
    expected_files = content.get("files") if isinstance(content, dict) else None
    if not isinstance(expected_files, list) or not expected_files:
        _fail("site candidate content manifest is missing")
    actual_files: list[dict[str, object]] = []
    paths = sorted(
        output_path.rglob("*"),
        key=lambda item: item.relative_to(output_path).as_posix(),
    )
    for path in paths:
        relative = path.relative_to(output_path).as_posix()
        if path.is_symlink():
            _fail(f"site candidate contains a symlink: {relative}")
        if path.is_dir():
            continue
        if not path.is_file():
            _fail(f"site candidate contains a special file: {relative}")
        if relative in {SITE_MANIFEST, ".vercel/project.json"}:
            continue
        file_content = _stable_file_bytes(path, f"site candidate file {relative}")
        actual_files.append(
            {
                "path": relative,
                "bytes": len(file_content),
                "sha256": "sha256:" + hashlib.sha256(file_content).hexdigest(),
            }
        )
    content_digest = _prefixed_digest(_canonical_bytes(actual_files))
    if expected_files != actual_files or content.get("digest") != content_digest:
        _fail("site candidate content manifest changed")
    expected_readback = _public_readback_manifest(actual_files)
    if manifest.get("public_readback") != expected_readback:
        _fail("site candidate exact public readback binding is invalid")
    return {
        "receipt_digest": claimed,
        "content_digest": content_digest,
        "rollback_receipt_digest": rollback["site_receipt_digest"],
        "rollback_content_digest": rollback["content_digest"],
        "implementation_revision": implementation["revision"],
        "implementation_source_tree_digest": implementation["source_tree_digest"],
        "public_readback_manifest_digest": _prefixed_digest(_canonical_bytes(expected_readback)),
    }


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
    link = _strict_json(_stable_file_bytes(path, label), label)
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


def _receipt_digest(payload: dict[str, Any], label: str) -> str:
    unsigned = dict(payload)
    claimed = unsigned.pop("receipt_digest", None)
    expected = _prefixed_digest(_canonical_bytes(unsigned))
    if not isinstance(claimed, str) or claimed != expected:
        _fail(f"{label} receipt integrity is invalid")
    return claimed


def _candidate_files(root: Path, *, deployment_envelope: bool = False) -> list[dict[str, object]]:
    files: list[dict[str, object]] = []
    for path in sorted(root.rglob("*"), key=lambda item: item.relative_to(root).as_posix()):
        relative = path.relative_to(root).as_posix()
        if path.is_symlink():
            _fail(f"publication candidate contains a symlink: {relative}")
        if path.is_dir():
            continue
        if deployment_envelope and relative == ".vercel/project.json":
            continue
        content = _stable_file_bytes(path, f"publication candidate file {relative}")
        files.append(
            {
                "path": relative,
                "bytes": len(content),
                "sha256": _prefixed_digest(content),
            }
        )
    if not files:
        _fail("publication candidate contains no files")
    return files


def _validate_publication_inputs(
    *,
    package_path: Path,
    publication_approval_path: Path,
    output_path: Path,
) -> dict[str, str]:
    if package_path.is_symlink() or not package_path.is_dir():
        _fail("publication package must be a real directory")
    package_manifest_path = _regular_file(
        package_path / PACKAGE_MANIFEST, "publication package manifest"
    )
    package = _strict_json(
        _stable_file_bytes(package_manifest_path, "publication package manifest"),
        "publication package manifest",
    )
    package_keys = {
        "schema",
        "state",
        "created_at",
        "candidate_path_name",
        "candidate_manifest_sha256",
        "candidate_receipt_digest",
        "candidate_content_digest",
        "publication_approval_sha256",
        "publication_approval_receipt_digest",
        "provider_revalidation_receipt_digest",
        "content_files",
        "content_digest",
        "authority",
        "claim_ceiling",
        "receipt_digest",
    }
    if not isinstance(package, dict) or set(package) != package_keys:
        _fail("publication package fields are invalid")
    package_receipt = _receipt_digest(package, "publication package")
    if (
        package.get("schema") != PACKAGE_SCHEMA
        or package.get("state") != PACKAGE_STATE
        or package.get("authority")
        != {
            "public_mutation_allowed": False,
            "deployment_allowed": False,
            "rollback_execution_allowed": False,
            "scheduler_activation_allowed": False,
        }
    ):
        _fail("publication package authority is invalid")
    candidate_name = package.get("candidate_path_name")
    if (
        not isinstance(candidate_name, str)
        or not candidate_name
        or Path(candidate_name).name != candidate_name
    ):
        _fail("publication package candidate name is invalid")
    candidate_root = package_path / candidate_name
    package_files = _candidate_files(candidate_root)
    if (
        package.get("content_files") != package_files
        or package.get("content_digest") != _prefixed_digest(_canonical_bytes(package_files))
    ):
        _fail("publication package content changed")

    publication_approval_path = _regular_file(
        publication_approval_path, "publication content approval"
    )
    publication_approval_bytes = _stable_file_bytes(
        publication_approval_path, "publication content approval"
    )
    publication_approval = _strict_json(
        publication_approval_bytes, "publication content approval"
    )
    if not isinstance(publication_approval, dict):
        _fail("publication content approval must be a JSON object")
    publication_receipt = _receipt_digest(
        publication_approval, "publication content approval"
    )
    authority = publication_approval.get("authority")
    if (
        publication_approval.get("schema") != PUBLICATION_APPROVAL_SCHEMA
        or publication_approval.get("state") != PUBLICATION_APPROVAL_STATE
        or not isinstance(authority, dict)
        or authority.get("publication_content_approved") is not True
        or authority.get("publication_package_build_allowed") is not True
        or any(
            authority.get(field) is not False
            for field in (
                "public_mutation_allowed",
                "deployment_allowed",
                "rollback_execution_allowed",
                "scheduler_activation_allowed",
                "outreach_allowed",
            )
        )
    ):
        _fail("publication content approval authority is invalid")
    provider = publication_approval.get("provider_prepublication")
    operator = publication_approval.get("operator_acceptance")
    candidate = publication_approval.get("candidate")
    if not isinstance(provider, dict) or not isinstance(operator, dict) or not isinstance(
        candidate, dict
    ):
        _fail("publication content approval lineage is incomplete")
    provider_receipt = _receipt_digest(provider, "provider prepublication")
    operator_statement = operator.get("statement_sha256")
    if not isinstance(operator_statement, str) or SHA256_RE.fullmatch(operator_statement) is None:
        _fail("operator acceptance statement digest is invalid")
    site_manifest_path = _regular_file(
        candidate_root / SITE_MANIFEST, "packaged site candidate manifest"
    )
    site_manifest_bytes = _stable_file_bytes(
        site_manifest_path, "packaged site candidate manifest"
    )
    site_manifest = _strict_json(site_manifest_bytes, "packaged site candidate manifest")
    if not isinstance(site_manifest, dict):
        _fail("packaged site candidate manifest must be an object")
    site_receipt = _receipt_digest(site_manifest, "packaged site candidate")
    implementation = site_manifest.get("implementation_binding")
    content = site_manifest.get("content")
    if (
        site_manifest.get("schema") != SITE_SCHEMA
        or site_manifest.get("state") != SITE_REVIEW_STATE
        or site_manifest.get("publication_allowed") is not False
        or site_manifest.get("deployment_allowed") is not False
        or not isinstance(implementation, dict)
        or not isinstance(content, dict)
    ):
        _fail("packaged site candidate is not an accepted V2 review artifact")
    if (
        candidate.get("manifest_sha256") != _prefixed_digest(site_manifest_bytes)
        or candidate.get("manifest_receipt_digest") != site_receipt
        or candidate.get("content_digest") != content.get("digest")
        or package.get("candidate_manifest_sha256") != candidate.get("manifest_sha256")
        or package.get("candidate_receipt_digest") != site_receipt
        or package.get("candidate_content_digest") != content.get("digest")
        or package.get("publication_approval_sha256")
        != _prefixed_digest(publication_approval_bytes)
        or package.get("publication_approval_receipt_digest") != publication_receipt
        or package.get("provider_revalidation_receipt_digest") != provider_receipt
    ):
        _fail("publication package approval binding changed")
    if _candidate_files(output_path, deployment_envelope=True) != package_files:
        _fail("deployment output does not match the exact publication package")
    return {
        "package_receipt_digest": package_receipt,
        "package_manifest_sha256": _prefixed_digest(
            _stable_file_bytes(package_manifest_path, "publication package manifest")
        ),
        "publication_approval_receipt_digest": publication_receipt,
        "publication_approval_sha256": _prefixed_digest(publication_approval_bytes),
        "provider_prepublication_receipt_digest": provider_receipt,
        "operator_acceptance_statement_sha256": operator_statement,
        "site_candidate_receipt_digest": site_receipt,
        "site_candidate_content_digest": str(content["digest"]),
        "implementation_revision": str(implementation.get("revision")),
        "implementation_source_tree_digest": str(implementation.get("source_tree_digest")),
    }


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
    python_bin: Path,
    publication_verifier: Path,
    output_path: Path,
    output_sha256: str,
    publication_package: Path,
    publication_approval: Path,
    rollback_artifact: Path,
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

    payload = _strict_json(_stable_file_bytes(approval_path, "approval"), "approval")
    if not isinstance(payload, dict):
        _fail("approval JSON must be an object")

    vercel_invocation_path = vercel_bin.absolute()
    node_invocation_path = node_bin.absolute()
    vercel_resolved = vercel_bin.resolve(strict=True)
    node_resolved = node_bin.resolve(strict=True)
    python_invocation_path = python_bin.absolute()
    python_resolved = python_bin.resolve(strict=True)
    publication_verifier = _regular_file(
        publication_verifier.resolve(strict=True), "publication package verifier"
    )
    publication_identity = _validate_publication_inputs(
        package_path=publication_package.resolve(strict=True),
        publication_approval_path=publication_approval.resolve(strict=True),
        output_path=output_path.resolve(strict=True),
    )
    current_component = rollback_artifact
    while current_component != current_component.parent:
        if current_component.is_symlink():
            _fail("rollback artifact path must not contain a symlink")
        current_component = current_component.parent
    rollback_artifact = rollback_artifact.resolve(strict=True)
    resolved_output = output_path.resolve(strict=True)
    if (
        rollback_artifact == resolved_output
        or resolved_output in rollback_artifact.parents
        or rollback_artifact in resolved_output.parents
    ):
        _fail("rollback artifact must be distinct from and outside current output")
    rollback_manifest = _strict_json(
        _stable_file_bytes(
            _regular_file(rollback_artifact / SITE_MANIFEST, "rollback site manifest"),
            "rollback site manifest",
        ),
        "rollback site manifest",
    )
    if not isinstance(rollback_manifest, dict):
        _fail("rollback site manifest must be a JSON object")
    rollback_receipt = _receipt_digest(rollback_manifest, "rollback site manifest")
    rollback_content = rollback_manifest.get("content")
    if (
        not isinstance(rollback_content, dict)
        or not isinstance(rollback_content.get("digest"), str)
        or not isinstance(rollback_content.get("files"), list)
    ):
        _fail("rollback site content binding is invalid")
    rollback_files = [
        item
        for item in _candidate_files(rollback_artifact, deployment_envelope=True)
        if item["path"] != SITE_MANIFEST
    ]
    rollback_content_digest = _prefixed_digest(_canonical_bytes(rollback_files))
    if (
        rollback_content["files"] != rollback_files
        or rollback_content["digest"] != rollback_content_digest
    ):
        _fail("rollback artifact content digest mismatch")
    expected_tree_digest = _git_tree_digest(repository.resolve(strict=True), commit)
    if (
        publication_identity["implementation_revision"] != commit
        or publication_identity["implementation_source_tree_digest"] != expected_tree_digest
    ):
        _fail("publication package implementation binding does not match approved commit")
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
        "python_invocation_path": str(python_invocation_path),
        "python_bin": str(python_resolved),
        "publication_verifier_path": str(publication_verifier),
        "output_path": str(output_path.resolve(strict=True)),
        "output_sha256": output_sha256,
        "site_candidate_receipt_digest": publication_identity[
            "site_candidate_receipt_digest"
        ],
        "site_candidate_content_digest": publication_identity[
            "site_candidate_content_digest"
        ],
        "publication_package_path": str(publication_package.resolve(strict=True)),
        "publication_package_manifest_sha256": publication_identity[
            "package_manifest_sha256"
        ],
        "publication_package_receipt_digest": publication_identity[
            "package_receipt_digest"
        ],
        "publication_approval_path": str(publication_approval.resolve(strict=True)),
        "publication_approval_sha256": publication_identity[
            "publication_approval_sha256"
        ],
        "publication_approval_receipt_digest": publication_identity[
            "publication_approval_receipt_digest"
        ],
        "provider_prepublication_receipt_digest": publication_identity[
            "provider_prepublication_receipt_digest"
        ],
        "operator_acceptance_statement_sha256": publication_identity[
            "operator_acceptance_statement_sha256"
        ],
        "rollback_artifact_path": str(rollback_artifact),
        "rollback_site_candidate_receipt_digest": rollback_receipt,
        "rollback_site_candidate_content_digest": rollback_content["digest"],
        "implementation_revision": publication_identity["implementation_revision"],
        "implementation_source_tree_digest": publication_identity[
            "implementation_source_tree_digest"
        ],
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
    if not isinstance(expected_node_digest, str) or expected_node_digest != _sha256(node_resolved):
        _fail("approval node_sha256 mismatch")
    expected_python_digest = payload.get("python_sha256")
    if (
        not isinstance(expected_python_digest, str)
        or expected_python_digest != _sha256(python_resolved)
    ):
        _fail("approval python_sha256 mismatch")
    if payload.get("publication_verifier_sha256") != _sha256(publication_verifier):
        _fail("approval publication_verifier_sha256 mismatch")
    unsigned = dict(payload)
    claimed_approval_receipt = unsigned.pop("approval_receipt_digest", None)
    if claimed_approval_receipt != _prefixed_digest(_canonical_bytes(unsigned)):
        _fail("deployment approval receipt integrity is invalid")
    exact_keys = set(expected) | {
        "receipt_id",
        "issued_at",
        "expires_at",
        "vercel_sha256",
        "node_sha256",
        "python_sha256",
        "publication_verifier_sha256",
        "approval_receipt_digest",
    }
    if set(payload) != exact_keys:
        _fail("deployment approval fields are invalid")
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
    parser.add_argument("--python-bin", type=Path, required=True)
    parser.add_argument("--publication-verifier", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--output-sha256", required=True)
    parser.add_argument("--publication-package", type=Path, required=True)
    parser.add_argument("--publication-approval", type=Path, required=True)
    parser.add_argument("--rollback-artifact", type=Path, required=True)
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
            python_bin=args.python_bin,
            publication_verifier=args.publication_verifier,
            output_path=args.output,
            output_sha256=args.output_sha256,
            publication_package=args.publication_package,
            publication_approval=args.publication_approval,
            rollback_artifact=args.rollback_artifact,
        )
    except (OSError, ValueError) as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 1
    print("Deployment authorization is valid and current.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
