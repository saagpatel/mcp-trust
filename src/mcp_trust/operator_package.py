"""Deterministic, review-only operator package construction and verification."""

from __future__ import annotations

import errno
import json
import os
import re
import shutil
import stat
import sys
import tempfile
from collections.abc import Callable
from ctypes import CDLL, c_char_p, c_int, c_uint, get_errno
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from mcp_trust.grade_refresh import (
    GradeRefreshError,
    build_operator_package_lineage,
    build_preflight_receipt,
    build_resume_capsule,
    build_state_card,
    canonical_bytes,
    catalog_inventory,
    digest_bytes,
    source_binding,
    triage_candidate,
)

OPERATOR_PACKAGE_SCHEMA = "McpTrustOperatorReviewPackageV2"
OPERATOR_PACKAGE_STATE = "LOCAL_REVIEW_ONLY"
OPERATOR_PACKAGE_MANIFEST = "OPERATOR_PACKAGE.json"
_CONTENT_FILES = frozenset(
    {
        "state-card.json",
        "HumanGateResumeCapsuleV1.json",
        "operator-review.md",
        "rollback.md",
    }
)
_MANIFEST_KEYS = frozenset(
    {
        "schema",
        "state",
        "evidence_as_of",
        "task_identity_digest",
        "lineage",
        "content_files",
        "content_digest",
        "rollback_lineage_digest",
        "authority",
        "privacy",
        "claim_ceiling",
        "receipt_digest",
    }
)
_AUTHORITY = {
    "publication_allowed": False,
    "deployment_allowed": False,
    "scheduler_change_allowed": False,
    "third_party_execution_allowed": False,
}
_PRIVACY = {
    "validated": True,
    "host_specific_paths_allowed": False,
    "credential_values_allowed": False,
    "raw_masked_evidence_allowed": False,
}
_CLAIM_CEILING = (
    "Local deterministic review package only; no MCP runtime proof, publication, "
    "deployment, rollback execution, scheduler change, or endorsement authority."
)
_FORBIDDEN_KEYS = frozenset(
    {
        "credential",
        "credential_value",
        "password",
        "private_key",
        "raw_chat",
        "report_ref",
        "secret",
        "token",
        "worker.hostname",
        "containerd.uuid",
    }
)
_MAX_FILE_BYTES = 2 * 1024 * 1024
_AT_FDCWD = -100 if sys.platform.startswith("linux") else -2
_RENAME_EXCL = 0x00000004
_RENAME_NOREPLACE = 1


class OperatorPackageError(GradeRefreshError):
    """One operator-package integrity control failed closed."""


def _stable_bytes(path: Path, label: str) -> bytes:
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(path, flags)
    except OSError as exc:
        raise OperatorPackageError(f"{label} cannot be opened safely") from exc
    try:
        before = os.fstat(descriptor)
        if not stat.S_ISREG(before.st_mode):
            raise OperatorPackageError(f"{label} must be a regular file")
        if before.st_size > _MAX_FILE_BYTES:
            raise OperatorPackageError(f"{label} exceeds the size limit")
        with os.fdopen(descriptor, "rb", closefd=False) as handle:
            content = handle.read(_MAX_FILE_BYTES + 1)
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

    if len(content) > _MAX_FILE_BYTES:
        raise OperatorPackageError(f"{label} exceeds the size limit")
    if identity(before) != identity(after) or identity(after) != identity(current):
        raise OperatorPackageError(f"{label} changed while it was read")
    return content


def _reject_duplicate_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    payload: dict[str, Any] = {}
    for key, value in pairs:
        if key in payload:
            raise OperatorPackageError(f"duplicate JSON key is forbidden: {key}")
        payload[key] = value
    return payload


def _strict_json(path: Path, label: str) -> tuple[dict[str, Any], bytes]:
    content = _stable_bytes(path, label)
    try:
        payload = json.loads(content, object_pairs_hook=_reject_duplicate_keys)
    except (UnicodeError, json.JSONDecodeError, RecursionError) as exc:
        raise OperatorPackageError(f"{label} is invalid JSON") from exc
    if not isinstance(payload, dict):
        raise OperatorPackageError(f"{label} must be a JSON object")
    return payload, content


def _privacy_walk(value: object, *, key: str = "") -> None:
    lowered = key.lower()
    normalized_key = re.sub(r"[^a-z0-9]", "", lowered)
    forbidden_normalized = {re.sub(r"[^a-z0-9]", "", item) for item in _FORBIDDEN_KEYS}
    if (
        lowered in _FORBIDDEN_KEYS
        or normalized_key in forbidden_normalized
        or normalized_key.endswith(("token", "password", "secret", "apikey"))
    ):
        raise OperatorPackageError(f"privacy-forbidden field: {key}")
    if isinstance(value, dict):
        for child_key, child in value.items():
            _privacy_walk(child, key=str(child_key))
    elif isinstance(value, list):
        for child in value:
            _privacy_walk(child, key=key)
    elif isinstance(value, str):
        if re.search(r"/(?:Users|home)/", value):
            raise OperatorPackageError("host-specific absolute path is forbidden")
        if re.search(r"(?i)(?:token|secret|password|credential)\s*[:=]", value):
            raise OperatorPackageError("credential-like value is forbidden")
        if re.search(
            r"(?<![0-9])(?:10(?:\.[0-9]{1,3}){3}|192\.168(?:\.[0-9]{1,3}){2}|"
            r"172\.(?:1[6-9]|2[0-9]|3[01])(?:\.[0-9]{1,3}){2})(?![0-9])",
            value,
        ):
            raise OperatorPackageError("private network address is forbidden")


def _write_file(path: Path, content: bytes) -> None:
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    try:
        written = os.write(descriptor, content)
        if written != len(content):
            raise OperatorPackageError(f"short package write: {path.name}")
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def _fsync_directory(path: Path) -> None:
    flags = os.O_RDONLY | getattr(os, "O_DIRECTORY", 0)
    try:
        descriptor = os.open(path, flags)
        try:
            os.fsync(descriptor)
        finally:
            os.close(descriptor)
    except OSError as exc:
        raise OperatorPackageError(f"operator package directory fsync failed: {path.name}") from exc


def _rename_no_replace(source: Path, destination: Path) -> None:
    try:
        libc = CDLL(None, use_errno=True)
    except OSError as exc:
        raise OperatorPackageError("atomic no-replace runtime is unavailable") from exc
    source_bytes = os.fsencode(source)
    destination_bytes = os.fsencode(destination)
    if sys.platform == "darwin" and hasattr(libc, "renamex_np"):
        rename = libc.renamex_np
        rename.argtypes = [c_char_p, c_char_p, c_uint]
        rename.restype = c_int
        result = rename(source_bytes, destination_bytes, _RENAME_EXCL)
    elif sys.platform.startswith("linux") and hasattr(libc, "renameat2"):
        rename = libc.renameat2
        rename.argtypes = [c_int, c_char_p, c_int, c_char_p, c_uint]
        rename.restype = c_int
        result = rename(
            _AT_FDCWD,
            source_bytes,
            _AT_FDCWD,
            destination_bytes,
            _RENAME_NOREPLACE,
        )
    else:
        raise OperatorPackageError("atomic no-replace rename is unavailable")
    if result != 0:
        error = get_errno()
        if error == errno.EEXIST:
            raise OperatorPackageError("operator package output collision detected")
        raise OperatorPackageError(f"operator package atomic rename failed: errno {error}")


def _directory_identity(path: Path) -> tuple[int, int]:
    current = os.stat(path, follow_symlinks=False)
    if not stat.S_ISDIR(current.st_mode) or path.is_symlink():
        raise OperatorPackageError("operator package output ownership is invalid")
    return current.st_dev, current.st_ino


def _remove_owned_directory(path: Path) -> None:
    if path.is_symlink() or not path.is_dir():
        raise OperatorPackageError("refusing to remove a non-directory package path")
    path.chmod(0o700)
    for child in path.iterdir():
        if child.is_symlink():
            child.unlink()
        elif child.is_dir():
            raise OperatorPackageError("refusing to remove unexpected nested package data")
        else:
            child.chmod(0o600)
    shutil.rmtree(path)


def _receipt_valid(payload: dict[str, Any]) -> bool:
    unsigned = dict(payload)
    claimed = unsigned.pop("receipt_digest", None)
    return isinstance(claimed, str) and claimed == digest_bytes(canonical_bytes(unsigned))


def _current_preflight_evidence(
    *,
    supplied_preflight: dict[str, Any],
    repo_root: Path,
    seed_path: Path,
    masked_path: Path,
    policy_path: Path,
    now: datetime | None,
) -> dict[str, Any]:
    return build_preflight_receipt(
        repo_root=repo_root,
        seed_path=seed_path,
        masked_path=masked_path,
        policy_path=policy_path,
        engine_materialization_receipt=supplied_preflight.get("engine_materialization"),
        now=now,
        include_scheduler_readback=True,
    )


def _content_inventory(root: Path) -> list[dict[str, Any]]:
    files: list[dict[str, Any]] = []
    for path in sorted(root.iterdir(), key=lambda item: item.name):
        if path.is_symlink():
            raise OperatorPackageError(f"operator package contains a symlink: {path.name}")
        if path.is_dir():
            raise OperatorPackageError(f"operator package contains a directory: {path.name}")
        if path.name == OPERATOR_PACKAGE_MANIFEST:
            continue
        content = _stable_bytes(path, f"operator package file {path.name}")
        files.append(
            {
                "path": path.name,
                "bytes": len(content),
                "sha256": digest_bytes(content),
            }
        )
    if {item["path"] for item in files} != _CONTENT_FILES:
        raise OperatorPackageError("operator package content file set is invalid")
    return files


def _review_markdown(state: dict[str, Any]) -> str:
    gates = state.get("outstanding_gates")
    gate_lines = (
        "\n".join(f"- {gate}" for gate in gates)
        if isinstance(gates, list) and gates
        else "- none"
    )
    findings = state.get("findings")
    finding_lines = (
        "\n".join(
            f"- {finding.get('severity', 'UNKNOWN')}: "
            f"`{finding.get('code', 'unknown')}` "
            f"({finding.get('scope', finding.get('slug', 'catalog'))})"
            for finding in findings
            if isinstance(finding, dict)
        )
        if isinstance(findings, list) and findings
        else "- none"
    )
    return f"""# MCP Trust grade-refresh operator review

This package is review-only. It grants no publication, deployment, scheduler,
credential, third-party execution, or outreach authority. A danger grade is a
technical capability assessment, not an endorsement.

## Current decision

- Source revision: `{state.get('source_revision', 'UNKNOWN')}`
- Source tree digest: `{state.get('source_tree_digest', 'UNKNOWN')}`
- Catalog denominator: `{state.get('catalog_denominator', 0)}`
- Catalog execution ready: `{state.get('safe_to_execute_catalog', False)}`
- Fixture repeatability: `{state.get('fixture_repeatability', 'UNKNOWN')}`
- Production freshness: `{state.get('production_freshness', 'UNKNOWN')}`
- Publication state: `{state.get('publication_state', 'UNKNOWN')}`

## Findings (Critical, High, Medium, Low)

{finding_lines}

## Outstanding gates

{gate_lines}

## Next action

{state.get('next_action', 'UNKNOWN')}
"""


def _validate_state_card(state: dict[str, Any]) -> None:
    counts = state.get("catalog_counts")
    severity = state.get("severity_findings")
    if (
        state.get("schema") != "McpTrustGradeRefreshStateCardV1"
        or not isinstance(state.get("source_revision"), str)
        or not isinstance(state.get("source_tree_digest"), str)
        or type(state.get("catalog_denominator")) is not int
        or not isinstance(counts, dict)
        or not all(isinstance(key, str) and type(value) is int for key, value in counts.items())
        or not isinstance(state.get("scheduler_state"), dict)
        or type(state.get("safe_to_execute_catalog")) is not bool
        or not isinstance(state.get("fixture_repeatability"), str)
        or not isinstance(severity, dict)
        or set(severity) != {"Critical", "High", "Medium", "Low"}
        or not all(type(value) is int for value in severity.values())
        or not isinstance(state.get("findings"), list)
        or not isinstance(state.get("completed_controls"), list)
        or not all(isinstance(value, str) for value in state["completed_controls"])
        or not isinstance(state.get("outstanding_gates"), list)
        or not all(isinstance(value, str) for value in state["outstanding_gates"])
        or state.get("publication_state") != "WAITING_FOR_EXPLICIT_APPROVAL"
        or state.get("production_freshness") != "UNKNOWN"
        or not isinstance(state.get("next_action"), str)
    ):
        raise OperatorPackageError("operator package state-card semantics are invalid")


def _rollback_markdown(lineage: dict[str, Any]) -> str:
    triage = lineage.get("triage")
    candidate_digest = (
        triage.get("candidate_manifest_digest") if isinstance(triage, dict) else "UNKNOWN"
    )
    repeat_digest = (
        triage.get("repeat_candidate_manifest_digest")
        if isinstance(triage, dict)
        else "UNKNOWN"
    )
    catalog = lineage["catalog"]
    execution_boundary = catalog["execution_boundary"]
    counts_digest = digest_bytes(canonical_bytes(catalog["counts"]))
    boundary_summary = (
        f"{len(execution_boundary['scannable'])} scannable / "
        f"{len(execution_boundary['blocked'])} blocked"
    )
    return f"""# Future publication rollback procedure

This review-only rollback plan is bound to operator-package lineage
`{lineage['lineage_digest']}`. It grants no rollback, publication, deployment,
scheduler, credential, or provider mutation authority.

## Exact reviewed lineage

- Source revision: `{lineage['source_revision']}`
- Source tree digest: `{lineage['source_tree_digest']}`
- Preflight receipt: `{lineage['preflight']['receipt_digest']}`
- Repeatability receipt: `{lineage['repeatability']['receipt_digest']}`
- Triage receipt: `{triage.get('receipt_digest') if isinstance(triage, dict) else 'UNKNOWN'}`
- Candidate manifest: `{candidate_digest}`
- Repeat candidate manifest: `{repeat_digest}`
- Policy digest: `{catalog['policy_digest']}`
- Seed digest: `{catalog['seed_digest']}`
- Masking digest: `{catalog['masking_digest']}`
- Inventory digest: `{catalog['inventory_digest']}`
- Catalog denominator: `{catalog['denominator']}`
- Inventory counts digest: `{counts_digest}`
- Execution boundary: `{boundary_summary}`

Before a separately approved first publication, bind the exact prior provider
deployment identifier, immutable prior artifact digest, target project/team,
and public readback receipt to this lineage. If post-publication readback fails:

1. Stop; preserve the failed artifact and all receipts.
2. Mark the new publication `WITHDRAWN_PENDING_REVIEW` without rescanning.
3. Re-authorize only the exact retained prior deployment and artifact.
4. Use the provider-native rollback lane with its independent confirmation.
5. Read back source identity, catalog denominator, masking, grade/staleness
   semantics, badges, health, and denied scan POST behavior.
6. Record failed and restored deployment identifiers, artifact digests, and
   public readback receipt digests.

Candidate deletion, scheduler enablement, force pushes, provider rollback, and
public mutation are not authorized by this document.
"""


def _inputs(
    *,
    preflight_path: Path,
    repeatability_path: Path,
    triage_path: Path | None,
    candidate_path: Path | None,
    repeat_candidate_path: Path | None,
    seed_path: Path,
    masked_path: Path,
    policy_path: Path | None,
    repo_root: Path | None,
    candidate_verifier: Callable[..., dict[str, Any]] | None,
    source_binding_reader: Callable[[Path], dict[str, Any]] | None,
    now: datetime | None,
) -> tuple[dict[str, Any], dict[str, Any], dict[str, Any] | None, dict[str, Any]]:
    effective_policy = policy_path or seed_path.parent / "refresh_policy.json"
    effective_repo_root = repo_root or effective_policy.resolve().parents[3]
    preflight, preflight_bytes = _strict_json(preflight_path, "preflight receipt")
    repeatability, repeatability_bytes = _strict_json(
        repeatability_path, "repeatability receipt"
    )
    triage: dict[str, Any] | None = None
    triage_bytes: bytes | None = None
    if triage_path is None:
        if candidate_path is not None or repeat_candidate_path is not None:
            raise OperatorPackageError("candidate paths require a triage receipt")
    else:
        if candidate_path is None or repeat_candidate_path is None:
            raise OperatorPackageError(
                "triage package requires candidate and repeat candidate paths"
            )
        triage, triage_bytes = _strict_json(triage_path, "triage receipt")
        try:
            recomputed = triage_candidate(
                candidate=candidate_path,
                repeat_candidate=repeat_candidate_path,
                preflight=preflight,
                repeatability=repeatability,
                seed_path=seed_path,
                masked_path=masked_path,
                repo_root=effective_repo_root,
                candidate_verifier=candidate_verifier,
            )
        except GradeRefreshError as exc:
            raise OperatorPackageError(str(exc)) from exc
        if triage != recomputed:
            raise OperatorPackageError(
                "triage receipt differs from independently recomputed evidence"
            )
    try:
        seed_bytes = _stable_bytes(seed_path, "catalog seed")
        masked_bytes = _stable_bytes(masked_path, "masked grade policy")
        policy_bytes = _stable_bytes(effective_policy, "refresh policy")
        inventory = catalog_inventory(
            seed_path=seed_path,
            masked_path=masked_path,
            policy_path=effective_policy,
        )
        if (
            _stable_bytes(seed_path, "catalog seed") != seed_bytes
            or _stable_bytes(masked_path, "masked grade policy") != masked_bytes
            or _stable_bytes(effective_policy, "refresh policy") != policy_bytes
        ):
            raise OperatorPackageError("operator package catalog inputs changed while read")
    except GradeRefreshError as exc:
        raise OperatorPackageError(str(exc)) from exc
    scannable = sorted(
        row["slug"] for row in inventory["entries"] if row.get("scannable") is True
    )
    blocked = sorted(
        row["slug"] for row in inventory["entries"] if row.get("scannable") is not True
    )
    catalog_inputs = {
        "seed_digest": digest_bytes(seed_bytes),
        "masking_digest": digest_bytes(masked_bytes),
        "policy_digest": digest_bytes(policy_bytes),
        "inventory_digest": digest_bytes(canonical_bytes(inventory)),
        "denominator": inventory["catalog_denominator"],
        "counts": inventory["counts"],
        "execution_boundary": {
            "schema": "McpTrustRefreshExecutionBoundaryV1",
            "scannable": scannable,
            "blocked": blocked,
        },
        "image_references": sorted(
            {
                row["sandbox_image"]
                for row in inventory["entries"]
                if row.get("scannable") is True
                and isinstance(row.get("sandbox_image"), str)
            }
        ),
    }
    reader = source_binding_reader or source_binding
    try:
        current_source = reader(effective_repo_root)
    except (OSError, GradeRefreshError) as exc:
        raise OperatorPackageError("operator package current source read failed") from exc
    if preflight.get("status") == "READY":
        try:
            current_preflight = _current_preflight_evidence(
                supplied_preflight=preflight,
                repo_root=effective_repo_root,
                seed_path=seed_path,
                masked_path=masked_path,
                policy_path=effective_policy,
                now=now,
            )
        except (OSError, GradeRefreshError) as exc:
            raise OperatorPackageError(
                "operator package current preflight revalidation failed"
            ) from exc
        critical_fields = (
            "schema",
            "status",
            "safe_to_execute_catalog",
            "exit_classification",
            "source_binding",
            "engine_materialization",
            "catalog",
            "sandbox",
            "tool_versions",
            "scheduler",
            "reasons",
            "authority",
        )
        if (
            not isinstance(current_preflight, dict)
            or set(current_preflight) != set(preflight)
            or not _receipt_valid(current_preflight)
            or any(
                current_preflight.get(key) != preflight.get(key)
                for key in critical_fields
            )
        ):
            raise OperatorPackageError(
                "operator package current preflight evidence changed"
            )
    try:
        lineage = build_operator_package_lineage(
            preflight=preflight,
            repeatability=repeatability,
            triage=triage,
            preflight_file_sha256=digest_bytes(preflight_bytes),
            repeatability_file_sha256=digest_bytes(repeatability_bytes),
            triage_file_sha256=(
                digest_bytes(triage_bytes) if triage_bytes is not None else None
            ),
            catalog_inputs=catalog_inputs,
            current_source=current_source,
            now=now,
        )
    except GradeRefreshError as exc:
        raise OperatorPackageError(str(exc)) from exc
    return preflight, repeatability, triage, lineage


def _expected_content(
    *,
    task_id: str,
    preflight: dict[str, Any],
    repeatability: dict[str, Any],
    triage: dict[str, Any] | None,
    lineage: dict[str, Any],
) -> dict[str, bytes]:
    try:
        state = build_state_card(
            preflight=preflight,
            repeatability=repeatability,
            triage=triage,
        )
        _validate_state_card(state)
        evidence_time = datetime.fromisoformat(lineage["evidence_as_of"]).astimezone(UTC)
        capsule = build_resume_capsule(
            task_id=task_id, state_card=state, now=evidence_time
        )
    except (AttributeError, KeyError, TypeError, ValueError) as exc:
        raise OperatorPackageError("operator package input semantics are invalid") from exc
    review = _review_markdown(state)
    rollback = _rollback_markdown(lineage)
    for payload in (state, capsule, review, rollback, lineage, task_id):
        _privacy_walk(payload)
    return {
        "state-card.json": canonical_bytes(state),
        "HumanGateResumeCapsuleV1.json": canonical_bytes(capsule),
        "operator-review.md": review.encode("utf-8"),
        "rollback.md": rollback.encode("utf-8"),
    }


def _manifest(
    *, task_id: str, lineage: dict[str, Any], files: list[dict[str, Any]], rollback: bytes
) -> dict[str, Any]:
    payload: dict[str, Any] = {
        "schema": OPERATOR_PACKAGE_SCHEMA,
        "state": OPERATOR_PACKAGE_STATE,
        "evidence_as_of": lineage["evidence_as_of"],
        "task_identity_digest": digest_bytes(task_id.encode("utf-8")),
        "lineage": lineage,
        "content_files": files,
        "content_digest": digest_bytes(canonical_bytes(files)),
        "rollback_lineage_digest": digest_bytes(rollback),
        "authority": dict(_AUTHORITY),
        "privacy": dict(_PRIVACY),
        "claim_ceiling": _CLAIM_CEILING,
    }
    _privacy_walk(payload)
    payload["receipt_digest"] = digest_bytes(canonical_bytes(payload))
    return payload


def build_operator_review_package(
    *,
    output_path: Path,
    task_id: str,
    preflight_path: Path,
    repeatability_path: Path,
    seed_path: Path,
    masked_path: Path,
    policy_path: Path | None = None,
    repo_root: Path | None = None,
    triage_path: Path | None = None,
    candidate_path: Path | None = None,
    repeat_candidate_path: Path | None = None,
    candidate_verifier: Callable[..., dict[str, Any]] | None = None,
    source_binding_reader: Callable[[Path], dict[str, Any]] | None = None,
    now: datetime | None = None,
) -> Path:
    """Build and independently verify one atomic local operator package."""
    if output_path.exists() or output_path.is_symlink():
        raise OperatorPackageError("operator package output must not already exist")
    output_path.parent.mkdir(parents=True, exist_ok=True)
    if output_path.parent.is_symlink() or not output_path.parent.is_dir():
        raise OperatorPackageError("operator package parent must be a real directory")
    output_resolved = output_path.resolve()
    for protected in (candidate_path, repeat_candidate_path):
        if protected is None:
            continue
        protected_resolved = protected.resolve()
        if (
            output_resolved == protected_resolved
            or protected_resolved in output_resolved.parents
            or output_resolved in protected_resolved.parents
        ):
            raise OperatorPackageError("operator package output overlaps a candidate")
    preflight, repeatability, triage, lineage = _inputs(
        preflight_path=preflight_path,
        repeatability_path=repeatability_path,
        triage_path=triage_path,
        candidate_path=candidate_path,
        repeat_candidate_path=repeat_candidate_path,
        seed_path=seed_path,
        masked_path=masked_path,
        policy_path=policy_path,
        repo_root=repo_root,
        candidate_verifier=candidate_verifier,
        source_binding_reader=source_binding_reader,
        now=now,
    )
    expected = _expected_content(
        task_id=task_id,
        preflight=preflight,
        repeatability=repeatability,
        triage=triage,
        lineage=lineage,
    )
    temporary = Path(
        tempfile.mkdtemp(prefix=f".{output_path.name}.tmp-", dir=output_path.parent)
    )
    finalized_identity: tuple[int, int] | None = None
    try:
        for name, content in expected.items():
            _write_file(temporary / name, content)
        files = _content_inventory(temporary)
        manifest = _manifest(
            task_id=task_id,
            lineage=lineage,
            files=files,
            rollback=expected["rollback.md"],
        )
        _write_file(temporary / OPERATOR_PACKAGE_MANIFEST, canonical_bytes(manifest))
        _fsync_directory(temporary)
        verify_operator_review_package(
            temporary,
            task_id=task_id,
            preflight_path=preflight_path,
            repeatability_path=repeatability_path,
            triage_path=triage_path,
            candidate_path=candidate_path,
            repeat_candidate_path=repeat_candidate_path,
            seed_path=seed_path,
            masked_path=masked_path,
            policy_path=policy_path,
            repo_root=repo_root,
            candidate_verifier=candidate_verifier,
            source_binding_reader=source_binding_reader,
            now=now,
        )
        for path in temporary.iterdir():
            path.chmod(0o400)
        temporary.chmod(0o500)
        _rename_no_replace(temporary, output_path)
        finalized_identity = _directory_identity(output_path)
        _fsync_directory(output_path.parent)
        verify_operator_review_package(
            output_path,
            task_id=task_id,
            preflight_path=preflight_path,
            repeatability_path=repeatability_path,
            triage_path=triage_path,
            candidate_path=candidate_path,
            repeat_candidate_path=repeat_candidate_path,
            seed_path=seed_path,
            masked_path=masked_path,
            policy_path=policy_path,
            repo_root=repo_root,
            candidate_verifier=candidate_verifier,
            source_binding_reader=source_binding_reader,
            now=now,
        )
    except Exception as exc:
        if temporary.exists():
            _remove_owned_directory(temporary)
        if finalized_identity is not None and output_path.exists():
            if _directory_identity(output_path) != finalized_identity:
                raise OperatorPackageError(
                    "operator package final readback failed after ownership changed"
                ) from exc
            _remove_owned_directory(output_path)
        raise
    return output_path


def verify_operator_review_package(
    root: Path,
    *,
    task_id: str,
    preflight_path: Path,
    repeatability_path: Path,
    seed_path: Path,
    masked_path: Path,
    policy_path: Path | None = None,
    repo_root: Path | None = None,
    triage_path: Path | None = None,
    candidate_path: Path | None = None,
    repeat_candidate_path: Path | None = None,
    candidate_verifier: Callable[..., dict[str, Any]] | None = None,
    source_binding_reader: Callable[[Path], dict[str, Any]] | None = None,
    now: datetime | None = None,
) -> dict[str, Any]:
    """Re-read all inputs and package bytes; reject drift, aliases, extras, or leaks."""
    if root.is_symlink() or not root.is_dir():
        raise OperatorPackageError("operator package root must be a real directory")
    preflight, repeatability, triage, lineage = _inputs(
        preflight_path=preflight_path,
        repeatability_path=repeatability_path,
        triage_path=triage_path,
        candidate_path=candidate_path,
        repeat_candidate_path=repeat_candidate_path,
        seed_path=seed_path,
        masked_path=masked_path,
        policy_path=policy_path,
        repo_root=repo_root,
        candidate_verifier=candidate_verifier,
        source_binding_reader=source_binding_reader,
        now=now,
    )
    expected = _expected_content(
        task_id=task_id,
        preflight=preflight,
        repeatability=repeatability,
        triage=triage,
        lineage=lineage,
    )
    manifest, _ = _strict_json(
        root / OPERATOR_PACKAGE_MANIFEST, "operator package manifest"
    )
    if set(manifest) != _MANIFEST_KEYS or not _receipt_valid(manifest):
        raise OperatorPackageError("operator package manifest receipt is invalid")
    files = _content_inventory(root)
    rollback = _stable_bytes(root / "rollback.md", "operator rollback")
    if (
        manifest["schema"] != OPERATOR_PACKAGE_SCHEMA
        or manifest["state"] != OPERATOR_PACKAGE_STATE
        or manifest["evidence_as_of"] != lineage["evidence_as_of"]
        or manifest["task_identity_digest"] != digest_bytes(task_id.encode("utf-8"))
        or manifest["lineage"] != lineage
        or manifest["content_files"] != files
        or manifest["content_digest"] != digest_bytes(canonical_bytes(files))
        or manifest["rollback_lineage_digest"] != digest_bytes(rollback)
        or manifest["authority"] != _AUTHORITY
        or manifest["privacy"] != _PRIVACY
        or manifest["claim_ceiling"] != _CLAIM_CEILING
    ):
        raise OperatorPackageError("operator package binding changed")
    for name, content in expected.items():
        if _stable_bytes(root / name, f"operator package file {name}") != content:
            raise OperatorPackageError(f"operator package generated content changed: {name}")
    _privacy_walk(manifest)
    return {
        "schema": manifest["schema"],
        "state": manifest["state"],
        "receipt_digest": manifest["receipt_digest"],
        "content_digest": manifest["content_digest"],
        "lineage_digest": lineage["lineage_digest"],
        "file_count": len(files),
        "privacy_validated": True,
        "publication_allowed": False,
        "deployment_allowed": False,
    }
