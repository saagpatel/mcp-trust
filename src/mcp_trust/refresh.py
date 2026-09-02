"""Manual, approval-gated refresh candidates with no deployment authority."""

from __future__ import annotations

import hashlib
import json
import math
import os
import re
import shutil
import sqlite3
import stat
import subprocess
import sys
import tempfile
import unicodedata
import uuid
from collections.abc import Callable, Iterator
from contextlib import contextmanager
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

from pydantic import ValidationError

from mcp_trust.core import grading
from mcp_trust.core.drift import ScanDrift, diff_latest
from mcp_trust.core.governance import (
    STALE_AFTER_DAYS,
    FreshnessState,
    assess_scan_freshness,
)
from mcp_trust.core.models import ScanRecord, Server, SourceKind
from mcp_trust.engine.base import EngineResult, ScanTimeoutError
from mcp_trust.engine.mcpaudit import (
    MCPAuditEngine,
    docker_launch_spec,
    repository_outer_timeout_seconds,
)
from mcp_trust.engine.runtime import (
    MCP_AUDIT_RUNTIME_MODULES,
    modules_belong_to_distribution,
)
from mcp_trust.engine.sandbox import (
    SANDBOX_RUNTIME_READBACK_SCHEMA,
    SANDBOX_RUNTIME_READBACK_TIMEOUT_SECONDS,
    DockerSandbox,
    normalize_local_docker_host,
    sandbox_server_process_digests,
    valid_sandbox_runtime_readback,
)
from mcp_trust.host_capacity import HostCapacityError, require_current_host_capacity
from mcp_trust.receipts import build_scan_receipt
from mcp_trust.store.db import connect, init_schema
from mcp_trust.store.repository import ScanRepository, ServerRepository

CANDIDATE_SCHEMA_V1 = "RefreshCandidateV1"
CANDIDATE_SCHEMA = "RefreshCandidateV2"
SCAN_EXECUTION_BINDING_SCHEMA = "McpTrustScanExecutionBindingV2"
APPROVAL_SCHEMA = "RefreshCandidateApprovalV1"
PUBLICATION_SCHEMA = "RefreshCandidatePublicationV1"
MANIFEST_NAME = "MANIFEST.json"
MANIFEST_DIGEST_NAME = "MANIFEST.sha256"
DEFAULT_MAX_AGE_HOURS = 24
SCAN_TIMEOUT_SECONDS = 90.0
MAX_APPROVAL_TTL_HOURS = 4
_DEPLOYMENT_ENV = ("VERCEL_TOKEN", "VERCEL_ORG_ID", "VERCEL_PROJECT_ID", "VERCEL_SCOPE")
_DOCKER_HOST_ENV = "MCP_TRUST_DOCKER_HOST"
_SANDBOX_FLAGS = (
    "--network",
    "none",
    "--read-only",
    "--cap-drop",
    "ALL",
    "--security-opt",
    "no-new-privileges",
    "--memory",
    "--pids-limit",
    "--cpus",
)
_SAFE_CANDIDATE_NAME = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]*$")
_SAFE_ARTIFACT_COMPONENT = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,254}$")
_SHA256_TEXT = re.compile(r"^[0-9a-f]{64}$")
_MAX_JSON_ARTIFACT_BYTES = 16 * 1024 * 1024
_MAX_DATABASE_ARTIFACT_BYTES = 64 * 1024 * 1024
_MAX_CANDIDATE_BYTES = 128 * 1024 * 1024
_MAX_CANDIDATE_FILES = 4096
_MAX_CATALOG_ROWS = 10_000
_MAX_ARTIFACT_PATH_BYTES = 1024
_MAX_ARTIFACT_PATH_DEPTH = 16
_MAX_JSON_STRING_CHARS = 65_536
_MAX_JSON_NODES = 100_000
_MAX_JSON_NUMBER_CHARS = 256
_CANDIDATE_STATES = frozenset({"fixture", "partial", "complete"})
_MANIFEST_KEYS_V1 = frozenset(
    {
        "schema",
        "created_at",
        "expires_at",
        "candidate_state",
        "publication_allowed",
        "scan_mode",
        "catalog",
        "masking",
        "sandbox",
        "qualification",
        "scan_counts",
        "engine_versions",
        "artifacts",
        "authority",
    }
)
_MANIFEST_KEYS = _MANIFEST_KEYS_V1 | {
    "freshness",
    "semantic_digests",
    "source_tree_digest",
    "tool_versions",
}
_RECEIPT_KEYS_V1 = frozenset(
    {
        "format_version",
        "server_slug",
        "scan_id",
        "server",
        "scan",
        "evidence",
        "danger_score",
        "scanner",
        "sandbox",
        "approval",
        "caveats",
    }
)
_RECEIPT_KEYS = _RECEIPT_KEYS_V1 | {"execution_binding", "receipt_digest"}
_SCANNER_KEYS = frozenset({"engine_name", "engine_version", "scanner_git_ref"})
_LOCAL_RECEIPT_SANDBOX_KEYS = frozenset(
    {
        "MCP_TRUST_SANDBOX",
        "MCP_TRUST_SANDBOX_IMAGE",
        "MCP_TRUST_SANDBOX_NETWORK",
        "MCP_TRUST_SCAN_CREDENTIALS",
    }
)
_REMOTE_RECEIPT_SANDBOX_KEYS = frozenset({"mode", "reason"})
_FIXTURE_RECEIPT_SANDBOX_KEYS = _LOCAL_RECEIPT_SANDBOX_KEYS - {"MCP_TRUST_SANDBOX_IMAGE"}
_BASE_RECEIPT_CAVEATS = (
    "Automated scan output is not an endorsement.",
    "Danger grade and transparency are separate signals.",
    "Low transparency means cannot verify safe, not known dangerous.",
    "Network-off sandboxing may suppress behavior that requires live egress.",
)
_DUMMY_CREDENTIAL_CAVEAT = (
    "Scanned with injected non-functional dummy credentials (network-off): "
    "the enumerated tool surface is real; no live authentication or egress "
    "occurred, and dummy credential values are never recorded."
)
_REMOTE_TRANSPORT_CAVEAT = (
    "Remote transport used the live network; no local process sandbox was applicable."
)
_SUCCESS_RESULT_KEYS_V1 = frozenset(
    {
        "server_slug",
        "state",
        "fresh_grade",
        "grade_visibility",
        "transparency",
        "scanned_at",
        "scan_age_days",
        "scan_id",
        "engine_name",
        "engine_version",
        "receipt",
        "receipt_visibility",
        "scan_proof",
        "scan_proof_visibility",
        "drift",
    }
)
_SUCCESS_RESULT_KEYS = _SUCCESS_RESULT_KEYS_V1 | {
    "freshness_state",
    "freshness_reason",
    "stale_after",
}
_BLOCKED_RESULT_KEYS = frozenset(
    {
        "server_slug",
        "state",
        "fresh_grade",
        "execution_disposition",
        "reason",
        "previous_grade",
        "previous_scanned_at",
        "previous_scan_age_days",
    }
)
_TIMEOUT_RESULT_KEYS = frozenset(
    {
        "server_slug",
        "state",
        "fresh_grade",
        "reason",
        "configured_timeout_seconds",
        "timeout_outcome",
        "hard_termination_evidence",
        "previous_grade",
        "previous_scanned_at",
        "previous_scan_age_days",
    }
)
_SANDBOX_PROFILE_KEYS = frozenset(
    {
        "kind",
        "image",
        "image_digest",
        "network",
        "read_only_root",
        "capabilities",
        "no_new_privileges",
        "memory",
        "pids_limit",
        "cpus",
        "user",
        "tmpfs",
        "runtime_attestor",
    }
)
_APPROVAL_KEYS = frozenset(
    {
        "schema",
        "candidate_manifest_sha256",
        "approved_at",
        "expires_at",
        "actor",
        "reason",
        "publication_target",
        "reviewed_seed_sha256",
        "reviewed_masked_sha256",
        "deployment_authority",
    }
)


class RefreshCandidateError(RuntimeError):
    """A fail-closed refresh-candidate contract violation."""


@dataclass(frozen=True)
class _CandidateSnapshot:
    files: dict[str, bytes]
    file_metadata: dict[str, tuple[int, ...]]
    tree_metadata: dict[str, tuple[int, ...]]
    root_metadata: tuple[int, ...]
    errors: tuple[str, ...]


@dataclass(frozen=True)
class _ReviewedInputs:
    catalog_slugs: frozenset[str]
    catalog_rows: list[dict[str, Any]]
    seed_sha256: str
    masked_slugs: frozenset[str]
    masked_sha256: str


class _CandidateSnapshotError(RefreshCandidateError):
    """A candidate could not be captured as one bounded filesystem snapshot."""

    def __init__(self, code: str) -> None:
        super().__init__(code)
        self.code = code


class _DuplicateJSONKeyError(ValueError):
    """A JSON object repeated a key and therefore has ambiguous meaning."""


class _NonFiniteJSONNumberError(ValueError):
    """A JSON payload used a non-standard non-finite numeric constant."""


class _UnsafeJSONValueError(ValueError):
    """A JSON payload exceeded bounded or display-safe value semantics."""


def _reject_duplicate_json_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    payload: dict[str, Any] = {}
    for key, value in pairs:
        if key in payload:
            raise _DuplicateJSONKeyError(key)
        payload[key] = value
    return payload


def _reject_nonfinite_json_number(value: str) -> None:
    raise _NonFiniteJSONNumberError(value)


def _parse_bounded_json_int(value: str) -> int:
    if len(value) > _MAX_JSON_NUMBER_CHARS:
        raise _UnsafeJSONValueError
    return int(value)


def _parse_bounded_json_float(value: str) -> float:
    if len(value) > _MAX_JSON_NUMBER_CHARS:
        raise _UnsafeJSONValueError
    parsed = float(value)
    if not math.isfinite(parsed):
        raise _NonFiniteJSONNumberError(value)
    return parsed


def _json_values_are_bounded_and_display_safe(payload: Any) -> bool:
    pending = [payload]
    visited = 0
    while pending:
        value = pending.pop()
        visited += 1
        if visited > _MAX_JSON_NODES:
            return False
        if isinstance(value, dict):
            pending.extend(value.keys())
            pending.extend(value.values())
        elif isinstance(value, list):
            pending.extend(value)
        elif isinstance(value, str):
            if len(value) > _MAX_JSON_STRING_CHARS or any(
                unicodedata.category(character) in {"Cc", "Cf"} for character in value
            ):
                return False
        elif isinstance(value, float) and not math.isfinite(value):
            return False
    return True


def _strict_json_loads(content: bytes) -> Any:
    payload = json.loads(
        content.decode("utf-8"),
        object_pairs_hook=_reject_duplicate_json_keys,
        parse_constant=_reject_nonfinite_json_number,
        parse_float=_parse_bounded_json_float,
        parse_int=_parse_bounded_json_int,
    )
    if not _json_values_are_bounded_and_display_safe(payload):
        raise _UnsafeJSONValueError
    return payload


def _stat_signature(value: os.stat_result) -> tuple[int, ...]:
    return (
        value.st_dev,
        value.st_ino,
        value.st_mode,
        value.st_size,
        value.st_mtime_ns,
        value.st_ctime_ns,
        value.st_uid,
        value.st_gid,
        value.st_nlink,
    )


def _safe_artifact_component(value: object) -> bool:
    return isinstance(value, str) and _SAFE_ARTIFACT_COMPONENT.fullmatch(value) is not None


def _safe_artifact_path(value: object) -> bool:
    return bool(
        isinstance(value, str)
        and len(value.encode("utf-8")) <= _MAX_ARTIFACT_PATH_BYTES
        and not value.startswith("/")
        and "\\" not in value
        and len(value.split("/")) <= _MAX_ARTIFACT_PATH_DEPTH
        and all(_safe_artifact_component(part) for part in value.split("/"))
    )


def _safe_error_label(value: object) -> str:
    return str(value) if _safe_artifact_component(value) else "invalid"


def _receipt_metadata_shape_valid(receipt: dict[str, Any]) -> bool:
    scanner = receipt.get("scanner")
    sandbox = receipt.get("sandbox")
    if (
        not isinstance(scanner, dict)
        or set(scanner) != _SCANNER_KEYS
        or scanner.get("scanner_git_ref") is not None
        or not isinstance(sandbox, dict)
    ):
        return False
    sandbox_keys = frozenset(sandbox)
    return bool(
        sandbox_keys == _REMOTE_RECEIPT_SANDBOX_KEYS
        or sandbox_keys == _LOCAL_RECEIPT_SANDBOX_KEYS
        or sandbox_keys == _FIXTURE_RECEIPT_SANDBOX_KEYS
    )


def _read_descriptor(descriptor: int, *, limit: int) -> bytes:
    try:
        content = bytearray()
        while len(content) <= limit:
            chunk = os.read(descriptor, min(1024 * 1024, limit + 1 - len(content)))
            if not chunk:
                break
            content.extend(chunk)
    except MemoryError as exc:
        raise RefreshCandidateError("artifact exceeds available verification memory") from exc
    if len(content) > limit:
        raise RefreshCandidateError("artifact exceeds the bounded read limit")
    return bytes(content)


def _read_stable_external_file(path: Path, *, limit: int) -> bytes:
    """Read one reviewed input once, without following links or accepting aliases."""
    try:
        before = path.lstat()
        if not stat.S_ISREG(before.st_mode) or path.is_symlink():
            raise RefreshCandidateError(f"reviewed input is not a regular file: {path.name}")
        if before.st_uid != os.geteuid() or before.st_nlink != 1:
            raise RefreshCandidateError(
                f"reviewed input has unsafe ownership or links: {path.name}"
            )
        flags = os.O_RDONLY
        if hasattr(os, "O_CLOEXEC"):
            flags |= os.O_CLOEXEC
        if hasattr(os, "O_NOFOLLOW"):
            flags |= os.O_NOFOLLOW
        descriptor = os.open(path, flags)
        try:
            opened = os.fstat(descriptor)
            content = _read_descriptor(descriptor, limit=limit)
            after_read = os.fstat(descriptor)
        finally:
            os.close(descriptor)
        after_path = path.lstat()
        if (
            len(
                {
                    _stat_signature(before),
                    _stat_signature(opened),
                    _stat_signature(after_read),
                    _stat_signature(after_path),
                }
            )
            != 1
        ):
            raise RefreshCandidateError(f"reviewed input changed during read: {path.name}")
        return content
    except RefreshCandidateError:
        raise
    except OSError as exc:
        raise RefreshCandidateError(f"unreadable reviewed input: {path.name}") from exc


def _capture_candidate(candidate: Path) -> _CandidateSnapshot:
    """Capture candidate bytes through directory descriptors as one bounded view."""
    try:
        before_root = candidate.lstat()
        flags = os.O_RDONLY
        if hasattr(os, "O_CLOEXEC"):
            flags |= os.O_CLOEXEC
        if hasattr(os, "O_DIRECTORY"):
            flags |= os.O_DIRECTORY
        if hasattr(os, "O_NOFOLLOW"):
            flags |= os.O_NOFOLLOW
        root_descriptor = os.open(candidate, flags)
    except OSError as exc:
        raise _CandidateSnapshotError("candidate_snapshot_unavailable") from exc

    files: dict[str, bytes] = {}
    file_metadata: dict[str, tuple[int, ...]] = {}
    tree_metadata: dict[str, tuple[int, ...]] = {}
    errors: list[str] = []
    total_bytes = 0
    file_count = 0
    entry_count = 0

    def walk(directory_descriptor: int, relative_parent: str) -> None:
        nonlocal entry_count, file_count, total_bytes
        try:
            before_directory = os.fstat(directory_descriptor)
            remaining_entries = max(0, _MAX_CANDIDATE_FILES - entry_count)
            discovered_names: list[str] = []
            with os.scandir(directory_descriptor) as entries:
                for entry in entries:
                    discovered_names.append(entry.name)
                    if len(discovered_names) > remaining_entries:
                        break
        except (MemoryError, OSError) as exc:
            raise _CandidateSnapshotError("candidate_snapshot_unavailable") from exc
        if len(discovered_names) > remaining_entries:
            errors.append("candidate_entry_count_exceeded")
            discovered_names = sorted(discovered_names)[:remaining_entries]
        names = sorted(discovered_names)
        entry_count += len(names)
        directory_label = relative_parent or "."
        tree_metadata[directory_label] = _stat_signature(before_directory)
        if before_directory.st_uid != os.geteuid():
            errors.append(f"unsafe_owner:{directory_label}")
        if before_directory.st_mode & 0o222:
            if relative_parent:
                errors.append(f"writable_directory:{relative_parent}")
            else:
                errors.append("writable_candidate_root")

        for name in names:
            relative = f"{relative_parent}/{name}" if relative_parent else name
            if not _safe_artifact_component(name):
                errors.append("unsafe_artifact_name")
                continue
            try:
                before = os.stat(
                    name,
                    dir_fd=directory_descriptor,
                    follow_symlinks=False,
                )
            except OSError:
                errors.append(f"artifact_unreadable:{relative}")
                continue
            signature = _stat_signature(before)
            tree_metadata[relative] = signature
            if stat.S_ISLNK(before.st_mode):
                errors.append(f"symlink:{relative}")
                continue
            if stat.S_ISDIR(before.st_mode):
                child_flags = os.O_RDONLY
                if hasattr(os, "O_CLOEXEC"):
                    child_flags |= os.O_CLOEXEC
                if hasattr(os, "O_DIRECTORY"):
                    child_flags |= os.O_DIRECTORY
                if hasattr(os, "O_NOFOLLOW"):
                    child_flags |= os.O_NOFOLLOW
                child_descriptor: int | None = None
                try:
                    child_descriptor = os.open(
                        name,
                        child_flags,
                        dir_fd=directory_descriptor,
                    )
                    opened = os.fstat(child_descriptor)
                    if opened.st_dev != before.st_dev or opened.st_ino != before.st_ino:
                        errors.append(f"artifact_unstable:{relative}")
                    else:
                        walk(child_descriptor, relative)
                except OSError:
                    errors.append(f"artifact_unreadable:{relative}")
                finally:
                    if child_descriptor is not None:
                        os.close(child_descriptor)
                try:
                    after = os.stat(
                        name,
                        dir_fd=directory_descriptor,
                        follow_symlinks=False,
                    )
                    if _stat_signature(after) != signature:
                        errors.append(f"artifact_unstable:{relative}")
                except OSError:
                    errors.append(f"artifact_unstable:{relative}")
                continue
            if not stat.S_ISREG(before.st_mode):
                errors.append(f"special_artifact:{relative}")
                continue

            file_count += 1
            file_metadata[relative] = signature
            if file_count > _MAX_CANDIDATE_FILES:
                errors.append("candidate_file_count_exceeded")
                continue
            if before.st_uid != os.geteuid():
                errors.append(f"unsafe_owner:{relative}")
            if before.st_mode & 0o222:
                errors.append(f"writable_artifact:{relative}")
            if before.st_nlink != 1:
                errors.append(f"hardlinked_artifact:{relative}")
            file_limit = (
                _MAX_DATABASE_ARTIFACT_BYTES
                if relative == "registry.db"
                else _MAX_JSON_ARTIFACT_BYTES
            )
            if before.st_size > file_limit:
                errors.append(f"artifact_too_large:{relative}")
                continue
            total_bytes += before.st_size
            if total_bytes > _MAX_CANDIDATE_BYTES:
                errors.append("candidate_size_exceeded")
                continue

            file_flags = os.O_RDONLY
            if hasattr(os, "O_CLOEXEC"):
                file_flags |= os.O_CLOEXEC
            if hasattr(os, "O_NOFOLLOW"):
                file_flags |= os.O_NOFOLLOW
            descriptor: int | None = None
            try:
                descriptor = os.open(
                    name,
                    file_flags,
                    dir_fd=directory_descriptor,
                )
                opened = os.fstat(descriptor)
                content = _read_descriptor(descriptor, limit=file_limit)
                after_read = os.fstat(descriptor)
            except (OSError, RefreshCandidateError):
                errors.append(f"artifact_unreadable:{relative}")
                continue
            finally:
                if descriptor is not None:
                    os.close(descriptor)
            try:
                after_path = os.stat(
                    name,
                    dir_fd=directory_descriptor,
                    follow_symlinks=False,
                )
            except OSError:
                errors.append(f"artifact_unstable:{relative}")
                continue
            if (
                len(
                    {
                        signature,
                        _stat_signature(opened),
                        _stat_signature(after_read),
                        _stat_signature(after_path),
                    }
                )
                != 1
            ):
                errors.append(f"artifact_unstable:{relative}")
                continue
            files[relative] = content

        try:
            after_directory = os.fstat(directory_descriptor)
            if _stat_signature(after_directory) != _stat_signature(before_directory):
                errors.append(f"directory_changed:{directory_label}")
        except OSError:
            errors.append(f"directory_changed:{directory_label}")

    try:
        opened_root = os.fstat(root_descriptor)
        if (
            opened_root.st_dev != before_root.st_dev
            or opened_root.st_ino != before_root.st_ino
            or not stat.S_ISDIR(opened_root.st_mode)
        ):
            raise _CandidateSnapshotError("candidate_snapshot_unavailable")
        walk(root_descriptor, "")
        after_root_path = candidate.lstat()
        if _stat_signature(after_root_path) != _stat_signature(opened_root):
            errors.append("candidate_root_replaced")
        root_metadata = _stat_signature(opened_root)
    except _CandidateSnapshotError:
        raise
    except (MemoryError, OSError) as exc:
        raise _CandidateSnapshotError("candidate_snapshot_unavailable") from exc
    finally:
        os.close(root_descriptor)

    return _CandidateSnapshot(
        files=files,
        file_metadata=file_metadata,
        tree_metadata=tree_metadata,
        root_metadata=root_metadata,
        errors=tuple(sorted(set(errors))),
    )


def _captured_json(snapshot: _CandidateSnapshot, relative: str) -> Any:
    content = snapshot.files.get(relative)
    if content is None:
        raise RefreshCandidateError(f"unreadable JSON artifact: {relative}")
    try:
        return _strict_json_loads(content)
    except (
        _DuplicateJSONKeyError,
        _NonFiniteJSONNumberError,
        _UnsafeJSONValueError,
        json.JSONDecodeError,
        MemoryError,
        RecursionError,
        UnicodeError,
        ValueError,
    ) as exc:
        raise RefreshCandidateError(f"unreadable JSON artifact: {relative}") from exc


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _sha256_bytes(content: bytes) -> str:
    return hashlib.sha256(content).hexdigest()


def _json_bytes(payload: object) -> bytes:
    return (
        json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=True) + "\n"
    ).encode("utf-8")


def _write_private(path: Path, payload: object) -> None:
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    if hasattr(os, "O_CLOEXEC"):
        flags |= os.O_CLOEXEC
    fd = os.open(path, flags, 0o600)
    try:
        view = memoryview(_json_bytes(payload))
        while view:
            written = os.write(fd, view)
            if written <= 0:
                raise OSError("short refresh-candidate write")
            view = view[written:]
        os.fsync(fd)
    finally:
        os.close(fd)


def _write_private_text(path: Path, text: str) -> None:
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    fd = os.open(path, flags, 0o600)
    try:
        encoded = text.encode("utf-8")
        view = memoryview(encoded)
        while view:
            written = os.write(fd, view)
            if written <= 0:
                raise OSError("short refresh-candidate text write")
            view = view[written:]
        os.fsync(fd)
    finally:
        os.close(fd)


def _write_private_bytes(path: Path, content: bytes) -> None:
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    if hasattr(os, "O_CLOEXEC"):
        flags |= os.O_CLOEXEC
    descriptor = os.open(path, flags, 0o600)
    try:
        view = memoryview(content)
        while view:
            written = os.write(descriptor, view)
            if written <= 0:
                raise OSError("short refresh-candidate byte write")
            view = view[written:]
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def _fsync_directory(path: Path) -> None:
    """Commit directory metadata before immutable readback."""
    flags = os.O_RDONLY
    if hasattr(os, "O_CLOEXEC"):
        flags |= os.O_CLOEXEC
    if hasattr(os, "O_DIRECTORY"):
        flags |= os.O_DIRECTORY
    descriptor = os.open(path, flags)
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def _sqlite_online_copy(source: Path, destination: Path) -> None:
    if not source.is_file():
        raise RefreshCandidateError(f"registry database is missing: {source}")
    source_db = sqlite3.connect(f"{source.resolve().as_uri()}?mode=ro", uri=True)
    destination_db = sqlite3.connect(destination)
    try:
        source_db.backup(destination_db)
    finally:
        destination_db.close()
        source_db.close()
    os.chmod(destination, 0o600)


def _load_json(path: Path) -> Any:
    try:
        content = _read_stable_external_file(path, limit=_MAX_JSON_ARTIFACT_BYTES)
        return _strict_json_loads(content)
    except (
        _DuplicateJSONKeyError,
        _NonFiniteJSONNumberError,
        _UnsafeJSONValueError,
        OSError,
        json.JSONDecodeError,
        MemoryError,
        RecursionError,
        UnicodeError,
        ValueError,
    ) as exc:
        raise RefreshCandidateError(f"unreadable JSON artifact: {path.name}") from exc


def _load_json_with_digest(path: Path) -> tuple[Any, str]:
    try:
        content = _read_stable_external_file(path, limit=_MAX_JSON_ARTIFACT_BYTES)
        return _strict_json_loads(content), _sha256_bytes(content)
    except RefreshCandidateError:
        raise
    except (
        _DuplicateJSONKeyError,
        _NonFiniteJSONNumberError,
        _UnsafeJSONValueError,
        json.JSONDecodeError,
        MemoryError,
        RecursionError,
        UnicodeError,
        ValueError,
    ) as exc:
        raise RefreshCandidateError(f"unreadable JSON artifact: {path.name}") from exc


def _load_read_only_json_with_digest(path: Path) -> tuple[Any, str]:
    """Read one owner-private immutable JSON artifact without following links."""
    try:
        before = path.lstat()
        if not stat.S_ISREG(before.st_mode) or path.is_symlink():
            raise RefreshCandidateError(f"immutable JSON artifact is not regular: {path.name}")
        if before.st_uid != os.geteuid() or before.st_mode & 0o277 or before.st_nlink != 1:
            raise RefreshCandidateError(
                f"immutable JSON artifact has unsafe ownership or permissions: {path.name}"
            )
        flags = os.O_RDONLY
        if hasattr(os, "O_CLOEXEC"):
            flags |= os.O_CLOEXEC
        if hasattr(os, "O_NOFOLLOW"):
            flags |= os.O_NOFOLLOW
        descriptor = os.open(path, flags)
        try:
            opened = os.fstat(descriptor)
            content = _read_descriptor(
                descriptor,
                limit=_MAX_JSON_ARTIFACT_BYTES,
            )
            after_read = os.fstat(descriptor)
        finally:
            os.close(descriptor)
        after_path = path.lstat()
        signatures = {_stat_signature(item) for item in (before, opened, after_read, after_path)}
        if len(signatures) != 1:
            raise RefreshCandidateError(f"immutable JSON artifact changed during read: {path.name}")
        return _strict_json_loads(content), _sha256_bytes(content)
    except RefreshCandidateError:
        raise
    except (
        _DuplicateJSONKeyError,
        _NonFiniteJSONNumberError,
        _UnsafeJSONValueError,
        OSError,
        json.JSONDecodeError,
        MemoryError,
        RecursionError,
        UnicodeError,
        ValueError,
    ) as exc:
        raise RefreshCandidateError(f"unreadable immutable JSON artifact: {path.name}") from exc


def _load_string_list(path: Path) -> frozenset[str]:
    loaded, _digest = _load_json_with_digest(path)
    if (
        not isinstance(loaded, list)
        or len(loaded) > _MAX_CATALOG_ROWS
        or not all(_safe_artifact_component(item) for item in loaded)
    ):
        raise RefreshCandidateError(f"{path.name} must be a JSON string list")
    return frozenset(loaded)


def _catalog_slugs(seed_path: Path) -> tuple[frozenset[str], list[dict[str, Any]]]:
    loaded, _digest = _load_json_with_digest(seed_path)
    if not isinstance(loaded, list) or len(loaded) > _MAX_CATALOG_ROWS:
        raise RefreshCandidateError("catalog identity must be a JSON list")
    rows: list[dict[str, Any]] = []
    slugs: set[str] = set()
    for item in loaded:
        if not isinstance(item, dict) or not _safe_artifact_component(item.get("slug")):
            raise RefreshCandidateError("catalog identity contains an invalid row")
        slug = item["slug"]
        if slug in slugs:
            raise RefreshCandidateError(f"catalog identity contains duplicate slug {slug}")
        slugs.add(slug)
        rows.append(item)
    return frozenset(slugs), rows


def _reviewed_inputs(seed_path: Path, masked_path: Path) -> _ReviewedInputs:
    catalog_payload, seed_digest = _load_json_with_digest(seed_path)
    if not isinstance(catalog_payload, list) or len(catalog_payload) > _MAX_CATALOG_ROWS:
        raise RefreshCandidateError("catalog identity must be a JSON list")
    catalog_rows: list[dict[str, Any]] = []
    catalog_slugs: set[str] = set()
    for item in catalog_payload:
        if not isinstance(item, dict) or not _safe_artifact_component(item.get("slug")):
            raise RefreshCandidateError("catalog identity contains an invalid row")
        slug = item["slug"]
        if slug in catalog_slugs:
            raise RefreshCandidateError(f"catalog identity contains duplicate slug {slug}")
        catalog_slugs.add(slug)
        catalog_rows.append(item)

    masked_payload, masked_digest = _load_json_with_digest(masked_path)
    if (
        not isinstance(masked_payload, list)
        or len(masked_payload) > _MAX_CATALOG_ROWS
        or not all(_safe_artifact_component(item) for item in masked_payload)
    ):
        raise RefreshCandidateError(f"{masked_path.name} must be a JSON string list")
    return _ReviewedInputs(
        catalog_slugs=frozenset(catalog_slugs),
        catalog_rows=catalog_rows,
        seed_sha256=seed_digest,
        masked_slugs=frozenset(masked_payload),
        masked_sha256=masked_digest,
    )


def _reviewed_server_from_seed(row: dict[str, Any], *, added_at: datetime) -> Server:
    try:
        return Server.model_validate({**row, "added_at": added_at})
    except (RecursionError, ValidationError) as exc:
        slug = row.get("slug")
        raise RefreshCandidateError(
            f"catalog identity contains invalid server metadata: {slug!r}"
        ) from exc


def _server_identity(server: Server) -> dict[str, Any]:
    return server.model_dump(mode="json", exclude={"added_at"})


def _sandbox_profile(
    image: str,
    *,
    image_digest: str = "UNKNOWN",
    docker_host: str | None = None,
) -> dict[str, object]:
    execution_image = image_digest if image_digest != "UNKNOWN" else image
    sandbox = DockerSandbox(image=execution_image, network="none", host=docker_host)
    command, args = sandbox.wrap("server-command", ["--probe"])
    joined = [command, *args]
    for required in _SANDBOX_FLAGS:
        if required not in joined:
            raise RefreshCandidateError(f"sandbox profile missing required control: {required}")
    if any(token in joined for token in ("--volume", "-v", "--mount")):
        raise RefreshCandidateError("sandbox profile unexpectedly exposes a host mount")
    return {
        "kind": "docker",
        "image": image,
        "image_digest": image_digest,
        "network": "none",
        "read_only_root": True,
        "capabilities": "dropped-all",
        "no_new_privileges": True,
        "memory": sandbox.memory,
        "pids_limit": sandbox.pids_limit,
        "cpus": sandbox.cpus,
        "user": sandbox.user,
        "tmpfs": sandbox.workdir,
        "runtime_attestor": sandbox.attestor_command,
    }


def _requires_local_sandbox(server: Server) -> bool:
    return not (server.source.kind == SourceKind.REMOTE and server.source.command is None)


def _required_local_sandbox_images(servers: list[Server], *, default_image: str) -> list[str]:
    local_servers = [server for server in servers if _requires_local_sandbox(server)]
    return sorted(
        {server.source.sandbox_image or default_image for server in local_servers}
        | ({default_image} if local_servers else set())
    )


def _catalog_row_requires_local_sandbox(row: object) -> bool:
    if not isinstance(row, dict):
        return False
    source = row.get("source")
    return not (
        isinstance(source, dict)
        and source.get("kind") == "remote"
        and source.get("command") is None
    )


def _real_scan_mode(*, local_count: int, total_count: int) -> str:
    if total_count == 0:
        return "no-execution-policy-blocked"
    if local_count == total_count:
        return "mcpaudit-local-network-off"
    if local_count == 0:
        return "mcpaudit-remote-live-network"
    return "mcpaudit-mixed-transport"


def _resolve_local_docker_host(
    *,
    runner: Callable[..., subprocess.CompletedProcess[str]],
) -> str:
    """Resolve and validate the one local Docker endpoint used by this refresh."""
    configured = os.environ.get("DOCKER_HOST")
    if configured is None:
        inspected = runner(
            [
                "docker",
                "context",
                "inspect",
                "--format",
                "{{json .Endpoints.docker.Host}}",
            ],
            text=True,
            capture_output=True,
            check=False,
        )
        if inspected.returncode != 0:
            raise RefreshCandidateError("required Docker context endpoint is unavailable")
        try:
            configured = json.loads(inspected.stdout.strip())
        except (json.JSONDecodeError, TypeError) as exc:
            raise RefreshCandidateError("required Docker context endpoint is unreadable") from exc
    try:
        return normalize_local_docker_host(configured)
    except ValueError as exc:
        raise RefreshCandidateError(
            "Docker daemon authority must use one absolute local Unix socket"
        ) from exc


def preflight_real_refresh(
    servers: list[Server],
    *,
    default_image: str,
    host_capacity_receipt: object,
    capacity_anchor: Path,
    runner: Callable[..., subprocess.CompletedProcess[str]] = subprocess.run,
) -> dict[str, object]:
    """Prove the network-off Docker controls and every pinned image locally."""
    try:
        require_current_host_capacity(
            host_capacity_receipt,
            anchor=capacity_anchor,
            now=datetime.now(tz=UTC),
        )
    except HostCapacityError as exc:
        raise RefreshCandidateError("required host capacity is not READY") from exc
    local_servers = [server for server in servers if _requires_local_sandbox(server)]
    images = _required_local_sandbox_images(servers, default_image=default_image)
    profiles: list[dict[str, object]] = []
    image_bindings: dict[str, str] = {}
    if local_servers:
        if shutil.which("docker") is None:
            raise RefreshCandidateError("required Docker executable is unavailable")
        docker_host = _resolve_local_docker_host(runner=runner)
        docker_command = ["docker", "--host", docker_host]
        info = runner(
            [*docker_command, "info"],
            text=True,
            capture_output=True,
            check=False,
        )
        if info.returncode != 0:
            raise RefreshCandidateError("required Docker daemon is unavailable")
        for image in images:
            inspected = runner(
                [*docker_command, "image", "inspect", image],
                text=True,
                capture_output=True,
                check=False,
            )
            if inspected.returncode != 0:
                raise RefreshCandidateError(f"required local sandbox image is unavailable: {image}")
            try:
                inspected_payload = json.loads(inspected.stdout)
                image_digest = inspected_payload[0]["Id"]
            except (IndexError, KeyError, TypeError, json.JSONDecodeError) as exc:
                raise RefreshCandidateError(
                    f"required local sandbox image provenance is unreadable: {image}"
                ) from exc
            if (
                not isinstance(image_digest, str)
                or re.fullmatch(r"sha256:[0-9a-f]{64}", image_digest) is None
            ):
                raise RefreshCandidateError(
                    f"required local sandbox image digest is invalid: {image}"
                )
            image_bindings[image] = image_digest
            profiles.append(
                _sandbox_profile(
                    image,
                    image_digest=image_digest,
                    docker_host=docker_host,
                )
            )
    if not modules_belong_to_distribution("mcp-audits", MCP_AUDIT_RUNTIME_MODULES):
        raise RefreshCandidateError("required MCPAudit engine package is unavailable")
    evidence: dict[str, object] = {
        "docker_daemon": "available" if local_servers else "not_required",
        "profiles": profiles,
        "default_image": default_image,
        "remote_transport_count": len(servers) - len(local_servers),
    }
    if local_servers:
        # Private execution binding: removed before the candidate manifest is
        # written, then supplied to every DockerSandbox through a dedicated
        # mcp-trust variable. This is authority, not a public trust claim.
        evidence["_execution_docker_host"] = docker_host
        evidence["_execution_image_bindings"] = image_bindings
    return evidence


def _qualification_metadata(
    receipt: dict[str, Any],
    *,
    seed_sha256: str,
    masked_sha256: str,
    expected_catalog_counts: object,
    expected_catalog_inventory_digest: object,
    sandbox_evidence: dict[str, object],
    now: datetime,
    current_source_binding: dict[str, Any] | None = None,
) -> dict[str, str]:
    required_keys = {
        "schema",
        "observed_at",
        "status",
        "safe_to_execute_catalog",
        "exit_classification",
        "source_binding",
        "engine_materialization",
        "host_capacity",
        "catalog",
        "sandbox",
        "tool_versions",
        "scheduler",
        "reasons",
        "authority",
        "receipt_digest",
    }
    if set(receipt) != required_keys or receipt.get("schema") != "McpTrustGradeRefreshPreflightV3":
        raise RefreshCandidateError("qualification receipt schema is invalid")
    claimed_digest = receipt.get("receipt_digest")
    unsigned = dict(receipt)
    unsigned.pop("receipt_digest", None)
    actual_digest = "sha256:" + _sha256_bytes(_json_bytes(unsigned))
    if claimed_digest != actual_digest:
        raise RefreshCandidateError("qualification receipt digest is invalid")
    try:
        observed_at = _parse_utc_datetime(receipt["observed_at"])
    except (KeyError, OverflowError, TypeError, ValueError) as exc:
        raise RefreshCandidateError("qualification timestamp is invalid") from exc
    age_seconds = (now.astimezone(UTC) - observed_at).total_seconds()
    if age_seconds < 0 or age_seconds >= DEFAULT_MAX_AGE_HOURS * 3600:
        raise RefreshCandidateError("qualification receipt is stale or future-dated")
    expected_build_source_images = sorted(
        {
            profile.get("image")
            for profile in sandbox_evidence.get("profiles", [])
            if isinstance(profile, dict) and isinstance(profile.get("image"), str)
        }
    )
    try:
        from mcp_trust.grade_refresh import (  # noqa: PLC0415
            GradeRefreshError,
            validate_ready_preflight_contract,
        )

        validate_ready_preflight_contract(
            receipt,
            expected_image_references=expected_build_source_images,
            expected_catalog_counts=expected_catalog_counts,
            expected_catalog_inventory_digest=expected_catalog_inventory_digest,
        )
    except GradeRefreshError as exc:
        raise RefreshCandidateError(f"qualification receipt {exc}") from exc
    source = receipt.get("source_binding")
    catalog = receipt.get("catalog")
    sandbox = receipt.get("sandbox")
    tools = receipt.get("tool_versions")
    authority = receipt.get("authority")
    if (
        receipt.get("status") != "READY"
        or receipt.get("safe_to_execute_catalog") is not True
        or receipt.get("exit_classification") != "ready"
        or receipt.get("reasons") != []
        or not isinstance(source, dict)
        or not isinstance(source.get("revision"), str)
        or re.fullmatch(r"[0-9a-f]{40}", source["revision"]) is None
        or source.get("worktree_state") != "clean"
        or not isinstance(source.get("source_tree_digest"), str)
        or re.fullmatch(r"sha256:[0-9a-f]{64}", source["source_tree_digest"]) is None
        or not isinstance(catalog, dict)
        or catalog.get("seed_digest") != "sha256:" + seed_sha256
        or catalog.get("masking_digest") != "sha256:" + masked_sha256
        or not isinstance(catalog.get("policy_digest"), str)
        or re.fullmatch(r"sha256:[0-9a-f]{64}", catalog["policy_digest"]) is None
        or not isinstance(tools, dict)
        or any(
            not isinstance(tools.get(key), str) or tools[key] in {"", "UNKNOWN"}
            for key in (
                "python",
                "python_executable",
                "mcp_audits",
                "mcp_trust",
                "docker_client",
                "docker_server",
            )
        )
        or authority
        != {
            "candidate_build": True,
            "publication": False,
            "deployment": False,
            "scheduler_change": False,
        }
    ):
        raise RefreshCandidateError("qualification receipt is not execution-ready")
    build_sources = catalog.get("image_build_sources")
    boundary_counts = catalog.get("counts")
    execution_boundary = catalog.get("execution_boundary")
    boundary_scannable = (
        execution_boundary.get("scannable") if isinstance(execution_boundary, dict) else None
    )
    boundary_blocked = (
        execution_boundary.get("blocked") if isinstance(execution_boundary, dict) else None
    )
    if (
        not isinstance(execution_boundary, dict)
        or set(execution_boundary) != {"schema", "scannable", "blocked"}
        or execution_boundary.get("schema") != "McpTrustRefreshExecutionBoundaryV1"
        or not isinstance(boundary_scannable, list)
        or not isinstance(boundary_blocked, list)
        or not all(_safe_artifact_component(slug) for slug in boundary_scannable)
        or not all(_safe_artifact_component(slug) for slug in boundary_blocked)
        or len(set(boundary_scannable)) != len(boundary_scannable)
        or len(set(boundary_blocked)) != len(boundary_blocked)
        or set(boundary_scannable) & set(boundary_blocked)
        or len(boundary_scannable) + len(boundary_blocked) != catalog.get("denominator")
        or not isinstance(boundary_counts, dict)
        or boundary_counts.get("scannable") != len(boundary_scannable)
        or boundary_counts.get("blocked") != len(boundary_blocked)
    ):
        raise RefreshCandidateError("qualification execution boundary is invalid")
    if (
        not isinstance(build_sources, dict)
        or any(
            not isinstance(binding, dict)
            or binding.get("state") != "BOUND"
            or not isinstance(binding.get("path"), str)
            or not isinstance(binding.get("sha256"), str)
            or re.fullmatch(r"sha256:[0-9a-f]{64}", binding["sha256"]) is None
            for binding in build_sources.values()
        )
        or set(build_sources) != set(expected_build_source_images)
    ):
        raise RefreshCandidateError("qualification image build provenance is incomplete")
    source_files = source.get("file_digests")
    if (
        not isinstance(source_files, dict)
        or source_files.get("src/mcp_trust/catalog/refresh_policy.json")
        != catalog.get("policy_digest")
        or any(
            source_files.get(binding["path"]) != binding["sha256"]
            for binding in build_sources.values()
        )
    ):
        raise RefreshCandidateError(
            "qualification policy or image build provenance is not source-bound"
        )
    if current_source_binding is not None and source != current_source_binding:
        raise RefreshCandidateError(
            "qualification source binding differs from the execution source"
        )
    sandbox_rows = sandbox.get("image_bindings", []) if isinstance(sandbox, dict) else []
    receipt_bindings = {
        row.get("reference"): row.get("image_id")
        for row in sandbox_rows
        if isinstance(row, dict) and row.get("state") == "BOUND"
    }
    profile_bindings = {
        row.get("image"): row.get("image_digest")
        for row in sandbox_evidence.get("profiles", [])
        if isinstance(row, dict)
    }
    if receipt_bindings != profile_bindings:
        raise RefreshCandidateError("qualification image bindings differ from execution preflight")
    return {
        "mode": "grade-refresh-preflight",
        "receipt": "qualification_receipt.json",
        "receipt_sha256": _sha256_bytes(_json_bytes(receipt)),
        "preflight_receipt_digest": actual_digest,
        "policy_digest": catalog["policy_digest"],
        "source_revision": source["revision"],
        "source_tree_digest": source["source_tree_digest"],
    }


@contextmanager
def _scan_environment(
    default_image: str,
    docker_host: str | None = None,
) -> Iterator[None]:
    keys = {
        "MCP_TRUST_ENGINE",
        "MCP_TRUST_SANDBOX",
        "MCP_TRUST_SANDBOX_NETWORK",
        "MCP_TRUST_SANDBOX_IMAGE",
        "MCP_TRUST_SCAN_CREDENTIALS",
        _DOCKER_HOST_ENV,
        *_DEPLOYMENT_ENV,
    }
    previous = {key: os.environ.get(key) for key in keys}
    try:
        os.environ["MCP_TRUST_ENGINE"] = "mcpaudit"
        os.environ["MCP_TRUST_SANDBOX"] = "docker"
        os.environ["MCP_TRUST_SANDBOX_NETWORK"] = "none"
        os.environ["MCP_TRUST_SANDBOX_IMAGE"] = default_image
        os.environ["MCP_TRUST_SCAN_CREDENTIALS"] = "dummy"
        if docker_host is None:
            os.environ.pop(_DOCKER_HOST_ENV, None)
        else:
            os.environ[_DOCKER_HOST_ENV] = normalize_local_docker_host(docker_host)
        for key in _DEPLOYMENT_ENV:
            os.environ.pop(key, None)
        yield
    finally:
        for key, value in previous.items():
            if value is None:
                os.environ.pop(key, None)
            else:
                os.environ[key] = value


@contextmanager
def _remote_transport_environment() -> Iterator[None]:
    """Prevent remote endpoints from inheriting local-process sandbox claims."""
    keys = {
        "MCP_TRUST_SANDBOX",
        "MCP_TRUST_SANDBOX_NETWORK",
        "MCP_TRUST_SANDBOX_IMAGE",
        "MCP_TRUST_SCAN_CREDENTIALS",
    }
    previous = {key: os.environ.get(key) for key in keys}
    try:
        for key in keys:
            os.environ.pop(key, None)
        yield
    finally:
        for key, value in previous.items():
            if value is None:
                os.environ.pop(key, None)
            else:
                os.environ[key] = value


def _scan_receipt_payload(
    server: Server,
    scan: ScanRecord,
    *,
    execution_binding: dict[str, Any] | None = None,
) -> dict[str, Any]:
    if not _requires_local_sandbox(server):
        with _remote_transport_environment():
            payload = build_scan_receipt(server, scan)
        payload["sandbox"] = {
            "mode": "not_applicable",
            "reason": "remote_endpoint_no_local_process",
        }
        caveats = payload.get("caveats")
        if isinstance(caveats, list):
            payload["caveats"] = [
                caveat
                for caveat in caveats
                if isinstance(caveat, str) and not caveat.startswith("Network-off sandboxing")
            ] + ["Remote transport used the live network; no local process sandbox was applicable."]
    else:
        payload = build_scan_receipt(server, scan)
    if execution_binding is not None:
        payload["format_version"] = 2
        payload["execution_binding"] = execution_binding
        payload["receipt_digest"] = "sha256:" + _sha256_bytes(_json_bytes(payload))
    return payload


def _write_receipt(
    server: Server,
    scan: ScanRecord,
    receipts_dir: Path,
    *,
    execution_binding: dict[str, Any] | None = None,
) -> str:
    name = f"{scan.server_slug}-{scan.id}.json"
    payload = _scan_receipt_payload(server, scan, execution_binding=execution_binding)
    _write_private(receipts_dir / name, payload)
    return name


def _candidate_execution_binding(
    server: Server,
    *,
    qualification: dict[str, object],
    sandbox_evidence: dict[str, object],
    default_image: str,
    expected_image: str | None,
    fixture_mode: bool,
    cleanup_evidence: str | None,
    runtime_readback: dict[str, object] | None,
) -> dict[str, Any]:
    local_process = _requires_local_sandbox(server)
    requested_image = server.source.sandbox_image or default_image if local_process else None
    configured_profile = next(
        (
            profile
            for profile in sandbox_evidence.get("profiles", [])
            if isinstance(profile, dict) and profile.get("image") == requested_image
        ),
        None,
    )
    if local_process and configured_profile is None:
        raise RefreshCandidateError("scan execution profile is unavailable")
    try:
        server_command, server_args = docker_launch_spec(server.source)
        expected_server_process_digests = sandbox_server_process_digests(
            server_command,
            server_args,
            allow_python_console_script=(
                server.source.kind == SourceKind.PYPI and server.source.command is not None
            ),
        )
    except Exception as exc:  # normalized below; no execution occurs here
        if local_process:
            raise RefreshCandidateError("scan execution command binding is unavailable") from exc
        expected_server_process_digests = ("NOT_APPLICABLE",)
    if fixture_mode:
        source = {
            "revision": None,
            "source_tree_digest": None,
            "policy_digest": None,
            "preflight_receipt_digest": None,
        }
        bound_runtime_readback: dict[str, object] = {
            "state": "NOT_APPLICABLE",
            "reason": "deterministic fixture did not execute a server process",
        }
        immutable_image_id = None
        sandbox_mode = "deterministic-fixture"
        container_cleanup_evidence = "NOT_APPLICABLE"
    else:
        source = {
            "revision": qualification.get("source_revision"),
            "source_tree_digest": qualification.get("source_tree_digest"),
            "policy_digest": qualification.get("policy_digest"),
            "preflight_receipt_digest": qualification.get("preflight_receipt_digest"),
        }
        if local_process:
            if (
                not isinstance(expected_image, str)
                or not valid_sandbox_runtime_readback(
                    runtime_readback,
                    expected_image_id=expected_image,
                    expected_profile=configured_profile,
                    expected_dummy_env_names=list(server.source.env_keys),
                    expected_server_process_digests=expected_server_process_digests,
                )
                or runtime_readback.get("schema") != SANDBOX_RUNTIME_READBACK_SCHEMA
            ):
                raise RefreshCandidateError(
                    "scan runtime controls are missing or do not match the immutable image"
                )
            bound_runtime_readback = json.loads(json.dumps(runtime_readback))
        else:
            bound_runtime_readback = {
                "state": "NOT_APPLICABLE",
                "reason": "remote endpoint launched no local process",
            }
        immutable_image_id = expected_image if local_process else None
        sandbox_mode = "docker" if local_process else "remote-no-local-process"
        container_cleanup_evidence = cleanup_evidence if local_process else "NOT_APPLICABLE"
    return {
        "schema": SCAN_EXECUTION_BINDING_SCHEMA,
        "target_slug": server.slug,
        "source": source,
        "sandbox": {
            "mode": sandbox_mode,
            "requested_image": requested_image,
            "immutable_image_id": immutable_image_id,
            "configured_launch_controls": configured_profile,
            "runtime_readback": bound_runtime_readback,
            "container_cleanup_evidence": container_cleanup_evidence,
        },
        "timeout": {
            "configured_seconds": None if fixture_mode else SCAN_TIMEOUT_SECONDS,
            "repository_outer_deadline_seconds": (
                repository_outer_timeout_seconds(SCAN_TIMEOUT_SECONDS)
                if local_process and not fixture_mode
                else None
            ),
            "runtime_readback_deadline_seconds": (
                SANDBOX_RUNTIME_READBACK_TIMEOUT_SECONDS
                if local_process and not fixture_mode
                else None
            ),
            "outcome": "completed",
            "hard_termination_evidence": "NOT_APPLICABLE",
        },
    }


def _receipt_digest_valid(receipt: dict[str, Any]) -> bool:
    claimed = receipt.get("receipt_digest")
    unsigned = dict(receipt)
    unsigned.pop("receipt_digest", None)
    return claimed == "sha256:" + _sha256_bytes(_json_bytes(unsigned))


def _write_masked_scan_proof(
    server: Server,
    scan: ScanRecord,
    proofs_dir: Path,
    *,
    execution_binding: dict[str, Any],
) -> str:
    """Retain scan-success provenance without retaining masked grade evidence."""
    receipt = _scan_receipt_payload(server, scan, execution_binding=execution_binding)
    name = f"{scan.server_slug}-{scan.id}.json"
    proof = {
        "format_version": 2,
        "proof_type": "masked_scan_success",
        "outcome": "scan_succeeded",
        "server_slug": scan.server_slug,
        "scan_id": scan.id,
        "server": receipt["server"],
        "scanned_at": scan.scanned_at.isoformat(),
        "scanner": receipt["scanner"],
        "sandbox": receipt["sandbox"],
        "evidence_present": scan.evidence is not None,
        "execution_binding": execution_binding,
    }
    proof["proof_digest"] = "sha256:" + _sha256_bytes(_json_bytes(proof))
    _write_private(proofs_dir / name, proof)
    return name


def _masked_proof_digest_valid(proof: dict[str, Any]) -> bool:
    claimed = proof.get("proof_digest")
    unsigned = dict(proof)
    unsigned.pop("proof_digest", None)
    return claimed == "sha256:" + _sha256_bytes(_json_bytes(unsigned))


def _validate_receipt(
    path: Path,
    *,
    server: Server,
    scan: ScanRecord,
    expected_image: str | None,
    expected_execution_binding: dict[str, Any],
) -> bool:
    try:
        receipt = _load_json(path)
    except RefreshCandidateError:
        return False
    if not isinstance(receipt, dict):
        return False
    scanner = receipt.get("scanner")
    sandbox = receipt.get("sandbox")
    base_valid = bool(
        set(receipt) == _RECEIPT_KEYS
        and receipt.get("format_version") == 2
        and _receipt_digest_valid(receipt)
        and receipt.get("execution_binding") == expected_execution_binding
        and receipt.get("server_slug") == server.slug
        and receipt.get("scan_id") == scan.id
        and isinstance(scanner, dict)
        and scanner.get("engine_name") == scan.engine_name
        and scanner.get("engine_version") == scan.engine_version
        and isinstance(sandbox, dict)
    )
    if not base_valid:
        return False
    if not _requires_local_sandbox(server):
        return bool(
            sandbox.get("mode") == "not_applicable"
            and sandbox.get("reason") == "remote_endpoint_no_local_process"
            and "MCP_TRUST_SANDBOX_IMAGE" not in sandbox
        )
    return bool(
        sandbox.get("MCP_TRUST_SANDBOX") == "docker"
        and sandbox.get("MCP_TRUST_SANDBOX_NETWORK") == "none"
        and sandbox.get("MCP_TRUST_SANDBOX_IMAGE") == expected_image
    )


def _fresh_result_matches_persisted_scan(
    conn: sqlite3.Connection,
    *,
    result: dict[str, object],
    receipt: dict[str, Any],
) -> bool:
    slug = result.get("server_slug")
    if not isinstance(slug, str):
        return False
    try:
        server = ServerRepository(conn).get(slug)
        scan = ScanRepository(conn).latest(slug)
    except (MemoryError, RecursionError, sqlite3.Error, TypeError, ValueError):
        return False
    if server is None or scan is None:
        return False
    expected_evidence = scan.evidence.model_dump(mode="json") if scan.evidence is not None else None
    sandbox = receipt.get("sandbox")
    expected_caveats = list(_BASE_RECEIPT_CAVEATS)
    if not _requires_local_sandbox(server):
        expected_caveats = [
            caveat for caveat in expected_caveats if not caveat.startswith("Network-off sandboxing")
        ] + [_REMOTE_TRANSPORT_CAVEAT]
    elif (
        isinstance(sandbox, dict)
        and sandbox.get("MCP_TRUST_SCAN_CREDENTIALS") == "dummy"
        and bool(server.source.env_keys)
        and scan.engine_name == "mcpaudit"
    ):
        expected_caveats.append(_DUMMY_CREDENTIAL_CAVEAT)
    return bool(
        result.get("scan_id") == scan.id
        and result.get("fresh_grade") == str(scan.grade)
        and result.get("transparency") == str(scan.transparency)
        and result.get("scanned_at") == scan.scanned_at.isoformat()
        and result.get("engine_name") == scan.engine_name
        and result.get("engine_version") == scan.engine_version
        and result.get("receipt") == scan.report_ref
        and receipt.get("server") == server.model_dump(mode="json")
        and receipt.get("scan") == scan.model_dump(mode="json")
        and receipt.get("evidence") == expected_evidence
        and receipt.get("danger_score") == grading.danger_score(scan.risk)
        and receipt.get("caveats") == expected_caveats
    )


def _snapshot_database(snapshot: _CandidateSnapshot) -> sqlite3.Connection:
    content = snapshot.files.get("registry.db")
    if content is None:
        raise RefreshCandidateError("candidate database is unavailable")
    try:
        conn = sqlite3.connect(":memory:")
        conn.deserialize(content)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA query_only = ON")
        integrity = conn.execute("PRAGMA integrity_check").fetchone()
        if integrity is None or integrity[0] != "ok":
            raise sqlite3.DatabaseError("candidate database integrity check failed")
        return conn
    except (AttributeError, MemoryError, sqlite3.Error) as exc:
        if "conn" in locals():
            conn.close()
        raise RefreshCandidateError("candidate database is unreadable") from exc


def _drift_payload(drift: ScanDrift | None) -> dict[str, object] | None:
    if drift is None:
        return None
    return {
        "cause": str(drift.cause),
        "surface_comparison": str(drift.surface_comparison),
        "summary": drift.summary,
        "previous_grade": str(drift.previous_grade),
        "current_grade": str(drift.current_grade),
    }


def _persisted_drift_payload(
    conn: sqlite3.Connection,
    *,
    slug: str,
) -> dict[str, object] | None:
    try:
        return _drift_payload(diff_latest(ScanRepository(conn).history(slug, limit=2)))
    except (
        MemoryError,
        RecursionError,
        sqlite3.Error,
        TypeError,
        ValueError,
    ) as exc:
        raise RefreshCandidateError("persisted drift is unreadable") from exc


def _scan_age_days(scanned_at: datetime, now: datetime) -> float:
    if scanned_at.tzinfo is None:
        scanned_at = scanned_at.replace(tzinfo=UTC)
    return round(
        max(
            0.0,
            (now.astimezone(UTC) - scanned_at.astimezone(UTC)).total_seconds() / 86400,
        ),
        6,
    )


def _parse_utc_datetime(value: object) -> datetime:
    parsed = datetime.fromisoformat(str(value).replace("Z", "+00:00"))
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=UTC)
    return parsed.astimezone(UTC)


def _artifact_inventory(root: Path) -> list[dict[str, object]]:
    artifacts: list[dict[str, object]] = []
    for path in sorted(candidate for candidate in root.rglob("*") if candidate.is_file()):
        relative = path.relative_to(root).as_posix()
        if relative in {MANIFEST_NAME, MANIFEST_DIGEST_NAME}:
            continue
        artifacts.append(
            {
                "path": relative,
                "bytes": path.stat().st_size,
                "sha256": _sha256(path),
            }
        )
    return artifacts


def _make_read_only(root: Path) -> None:
    for path in sorted(root.rglob("*"), reverse=True):
        if path.is_file():
            os.chmod(path, 0o400)
        elif path.is_dir():
            os.chmod(path, 0o500)
    os.chmod(root, 0o500)


def _make_files_read_only(root: Path) -> None:
    for path in root.rglob("*"):
        if path.is_file():
            os.chmod(path, 0o400)


def _materialize_candidate_snapshot(
    snapshot: _CandidateSnapshot,
    destination: Path,
) -> None:
    """Materialize only the captured, verified bytes into a new private tree."""
    destination.mkdir(mode=0o700)
    for relative in ("masked-proofs", "receipts"):
        (destination / relative).mkdir(mode=0o700)
    for relative, content in sorted(snapshot.files.items()):
        if not _safe_artifact_path(relative):
            raise RefreshCandidateError("verified candidate contains an unsafe artifact path")
        target = destination / relative
        if target.parent not in {
            destination,
            destination / "masked-proofs",
            destination / "receipts",
        }:
            raise RefreshCandidateError("verified candidate contains an unexpected directory")
        _write_private_bytes(target, content)
    _make_read_only(destination)


def _validate_v2_freshness_manifest(
    *,
    manifest: dict[str, Any],
    captured: _CandidateSnapshot,
    results: list[Any],
    created_at: datetime | None,
    expires_at: datetime | None,
    errors: list[str],
) -> None:
    """Cross-bind the V2 freshness and semantic projections."""
    freshness = manifest.get("freshness")
    required_freshness_keys = {
        "mode",
        "horizon_days",
        "evaluated_at",
        "earliest_stale_after",
        "publication_not_after",
        "state_counts",
    }
    if (
        not isinstance(freshness, dict)
        or set(freshness) != required_freshness_keys
        or freshness.get("mode") != "STATIC_HISTORICAL_ONLY"
        or freshness.get("horizon_days") != STALE_AFTER_DAYS
        or freshness.get("evaluated_at") != manifest.get("created_at")
        or created_at is None
        or expires_at is None
    ):
        errors.append("freshness_manifest_invalid")
        return
    state_counts = freshness.get("state_counts")
    if (
        not isinstance(state_counts, dict)
        or set(state_counts) != {state.value for state in FreshnessState}
        or any(type(value) is not int or value < 0 for value in state_counts.values())
    ):
        errors.append("freshness_counts_invalid")
        return
    successful = [
        result
        for result in results
        if isinstance(result, dict) and result.get("state") in {"fresh", "masked"}
    ]
    stale_after_values: list[datetime] = []
    for result in successful:
        try:
            scanned_at = _parse_utc_datetime(result["scanned_at"])
            stale_after = _parse_utc_datetime(result["stale_after"])
        except (KeyError, OverflowError, TypeError, ValueError):
            errors.append(
                f"freshness_result_invalid:{_safe_error_label(result.get('server_slug'))}"
            )
            continue
        assessment = assess_scan_freshness(scanned_at, created_at)
        if (
            assessment.state is not FreshnessState.FRESH
            or result.get("freshness_state") != str(assessment.state)
            or result.get("freshness_reason") != assessment.reason
            or assessment.stale_after != stale_after
        ):
            errors.append(
                f"freshness_result_mismatch:{_safe_error_label(result.get('server_slug'))}"
            )
        stale_after_values.append(stale_after)
    expected_counts = {
        "FRESH": len(successful),
        "STALE": 0,
        "UNKNOWN": len(results) - len(successful),
        "NOT_APPLICABLE": 0,
    }
    if state_counts != expected_counts:
        errors.append("freshness_counts_mismatch")
    earliest = min(stale_after_values) if stale_after_values else None
    expected_earliest = earliest.isoformat() if earliest is not None else None
    if freshness.get("earliest_stale_after") != expected_earliest:
        errors.append("earliest_stale_after_mismatch")
    expected_not_after = min(expires_at, earliest or expires_at).isoformat()
    if freshness.get("publication_not_after") != expected_not_after:
        errors.append("publication_not_after_mismatch")

    semantic = manifest.get("semantic_digests")
    expected_semantic = {
        "scan_results": _sha256_bytes(captured.files.get("scan_results.json", b"")),
        "static_snapshot": _sha256_bytes(captured.files.get("static_snapshot.json", b"")),
        "masking": (
            manifest.get("masking", {}).get("sha256")
            if isinstance(manifest.get("masking"), dict)
            else None
        ),
    }
    if semantic != expected_semantic:
        errors.append("semantic_digest_mismatch")
    source_tree_digest = manifest.get("source_tree_digest")
    if manifest.get("candidate_state") == "fixture":
        if source_tree_digest is not None:
            errors.append("fixture_source_tree_claim_invalid")
    elif (
        not isinstance(source_tree_digest, str)
        or re.fullmatch(r"sha256:[0-9a-f]{64}", source_tree_digest) is None
    ):
        errors.append("source_tree_digest_invalid")
    tool_versions = manifest.get("tool_versions")
    if (
        not isinstance(tool_versions, dict)
        or set(tool_versions) != {"python", "mcp_trust_candidate_schema"}
        or not isinstance(tool_versions.get("python"), str)
        or re.fullmatch(r"[0-9]+\.[0-9]+\.[0-9]+", tool_versions["python"]) is None
        or tool_versions.get("mcp_trust_candidate_schema") != CANDIDATE_SCHEMA
    ):
        errors.append("tool_versions_invalid")


def create_refresh_candidate(
    *,
    source_db: Path,
    seed_path: Path,
    masked_path: Path,
    output_parent: Path,
    default_image: str,
    scanner: Callable[[Server], EngineResult] | None = None,
    receipt_writer: Callable[[Server, ScanRecord, Path], str | None] | None = None,
    now: datetime | None = None,
    candidate_name: str | None = None,
    qualification_receipt: dict[str, Any] | None = None,
    repo_root: Path | None = None,
    policy_path: Path | None = None,
    _source_binding_provider: Callable[[Path], dict[str, Any]] | None = None,
    _qualification_revalidator: Callable[..., None] | None = None,
) -> Path:
    """Create one immutable candidate; never mutate canonical/public outputs.

    ``scanner`` is a trusted in-process test-fixture hook, not an isolation
    boundary. Fixture candidates remain non-publishable and prove no process,
    network, MCP, Docker, or receipt provenance property of that callback.
    """
    fixed_now = now or datetime.now(tz=UTC)
    if fixed_now.tzinfo is None:
        fixed_now = fixed_now.replace(tzinfo=UTC)
    fixture_mode = scanner is not None
    if not fixture_mode:
        if repo_root is None:
            raise RefreshCandidateError("real refresh requires the qualified repository root")
        try:
            require_current_host_capacity(
                qualification_receipt.get("host_capacity")
                if isinstance(qualification_receipt, dict)
                else None,
                anchor=repo_root,
                now=datetime.now(tz=UTC),
            )
        except HostCapacityError as exc:
            raise RefreshCandidateError("real refresh host capacity is not READY") from exc
    if not source_db.is_file():
        raise RefreshCandidateError(f"registry database is missing: {source_db}")
    reviewed = _reviewed_inputs(seed_path, masked_path)
    catalog_slugs = reviewed.catalog_slugs
    catalog_rows = reviewed.catalog_rows
    masked_slugs = reviewed.masked_slugs
    if not catalog_slugs:
        raise RefreshCandidateError("catalog identity must contain at least one server")
    unknown_masked_slugs = sorted(masked_slugs - catalog_slugs)
    if unknown_masked_slugs:
        raise RefreshCandidateError(
            "masked grade list contains unknown catalog slug(s): " + ",".join(unknown_masked_slugs)
        )
    catalog_by_slug = {row["slug"]: row for row in catalog_rows}

    if not fixture_mode:
        try:
            require_current_host_capacity(
                qualification_receipt.get("host_capacity"),
                anchor=repo_root,
                now=datetime.now(tz=UTC),
            )
        except HostCapacityError as exc:
            raise RefreshCandidateError(
                "real refresh host capacity changed before source database access"
            ) from exc
    source_conn = sqlite3.connect(f"{source_db.resolve().as_uri()}?mode=ro", uri=True)
    source_conn.row_factory = sqlite3.Row
    try:
        source_servers = ServerRepository(source_conn)
        servers: list[Server] = []
        for slug in sorted(catalog_slugs):
            server = source_servers.get(slug)
            if server is None:
                raise RefreshCandidateError(f"catalog server missing from registry DB: {slug}")
            reviewed_server = _reviewed_server_from_seed(
                catalog_by_slug[slug],
                added_at=server.added_at,
            )
            if _server_identity(server) != _server_identity(reviewed_server):
                raise RefreshCandidateError(
                    f"registry DB server metadata differs from reviewed catalog: {slug}"
                )
            servers.append(server)
    finally:
        source_conn.close()

    sandbox_evidence: dict[str, object]
    docker_host: str | None = None
    execution_image_bindings: dict[str, str] = {}
    qualification_manifest: dict[str, object]
    qualified_source_binding: dict[str, Any] | None = None
    execution_servers = servers
    blocked_slugs: frozenset[str] = frozenset()
    if fixture_mode:
        sandbox_evidence = {
            "mode": "deterministic-fixture",
            "default_image": default_image,
            "profiles": [_sandbox_profile(default_image)],
        }
        qualification_manifest = {
            "mode": "deterministic-fixture",
            "receipt": None,
        }
    else:
        if repo_root is None:
            raise RefreshCandidateError("real refresh requires the qualified repository root")
        effective_policy_path = policy_path or seed_path.with_name("refresh_policy.json")
        try:
            from mcp_trust.grade_refresh import (  # noqa: PLC0415
                GradeRefreshError,
                catalog_inventory,
                digest_file,
                load_policy,
                revalidate_ready_preflight_qualifications,
                validate_ready_preflight_contract,
            )

            execution_policy = load_policy(
                effective_policy_path,
                seed_path,
                masked_path,
            )
            expected_catalog_inventory = catalog_inventory(
                seed_path=seed_path,
                masked_path=masked_path,
                policy_path=effective_policy_path,
            )
            expected_catalog_counts = expected_catalog_inventory["counts"]
            expected_catalog_inventory_digest = "sha256:" + _sha256_bytes(
                _json_bytes(expected_catalog_inventory)
            )
            policy_digest = digest_file(effective_policy_path)
        except (GradeRefreshError, OSError) as exc:
            raise RefreshCandidateError("refresh execution policy is invalid") from exc
        receipt_catalog = (
            qualification_receipt.get("catalog")
            if isinstance(qualification_receipt, dict)
            else None
        )
        policy_counts = receipt_catalog.get("counts") if isinstance(receipt_catalog, dict) else None
        receipt_boundary = (
            receipt_catalog.get("execution_boundary") if isinstance(receipt_catalog, dict) else None
        )
        if (
            not isinstance(receipt_catalog, dict)
            or receipt_catalog.get("policy_digest") != policy_digest
            or receipt_catalog.get("denominator") != len(servers)
            or not isinstance(policy_counts, dict)
            or policy_counts.get("scannable") != len(execution_policy.scannable)
            or policy_counts.get("blocked") != len(execution_policy.blocked)
            or receipt_boundary
            != {
                "schema": "McpTrustRefreshExecutionBoundaryV1",
                "scannable": sorted(execution_policy.scannable),
                "blocked": sorted(execution_policy.blocked),
            }
        ):
            raise RefreshCandidateError("qualification receipt does not bind the execution policy")
        blocked_slugs = execution_policy.blocked
        execution_servers = [
            server for server in servers if server.slug in execution_policy.scannable
        ]
        if not isinstance(qualification_receipt, dict):
            raise RefreshCandidateError("real refresh requires a qualification receipt")
        try:
            expected_image_references = _required_local_sandbox_images(
                execution_servers,
                default_image=default_image,
            )
            validate_ready_preflight_contract(
                qualification_receipt,
                expected_image_references=expected_image_references,
                expected_catalog_counts=expected_catalog_counts,
                expected_catalog_inventory_digest=expected_catalog_inventory_digest,
            )
            (_qualification_revalidator or revalidate_ready_preflight_qualifications)(
                qualification_receipt,
                repo_root=repo_root,
                expected_image_references=expected_image_references,
                expected_catalog_counts=expected_catalog_counts,
                expected_catalog_inventory_digest=expected_catalog_inventory_digest,
                now=fixed_now,
            )
        except GradeRefreshError as exc:
            raise RefreshCandidateError(f"qualification receipt {exc}") from exc
        sandbox_evidence = preflight_real_refresh(
            execution_servers,
            default_image=default_image,
            host_capacity_receipt=qualification_receipt.get("host_capacity"),
            capacity_anchor=repo_root,
        )
        execution_host = sandbox_evidence.pop("_execution_docker_host", None)
        raw_bindings = sandbox_evidence.pop("_execution_image_bindings", {})
        if not isinstance(raw_bindings, dict) or not all(
            isinstance(key, str) and isinstance(value, str) for key, value in raw_bindings.items()
        ):
            raise RefreshCandidateError("preflight returned invalid image execution bindings")
        execution_image_bindings = dict(raw_bindings)
        if execution_host is not None:
            try:
                docker_host = normalize_local_docker_host(str(execution_host))
            except ValueError as exc:
                raise RefreshCandidateError(
                    "preflight returned an invalid Docker execution authority"
                ) from exc
        if _source_binding_provider is None:
            from mcp_trust.grade_refresh import source_binding  # noqa: PLC0415

            _source_binding_provider = source_binding
        qualified_source_binding = _source_binding_provider(repo_root)
        qualification_manifest = _qualification_metadata(
            qualification_receipt,
            seed_sha256=reviewed.seed_sha256,
            masked_sha256=reviewed.masked_sha256,
            expected_catalog_counts=expected_catalog_counts,
            expected_catalog_inventory_digest=expected_catalog_inventory_digest,
            sandbox_evidence=sandbox_evidence,
            now=fixed_now,
            current_source_binding=qualified_source_binding,
        )
        scanner_engine = MCPAuditEngine(timeout=SCAN_TIMEOUT_SECONDS)

        def scan_server(server: Server) -> EngineResult:
            if not _requires_local_sandbox(server):
                with _remote_transport_environment():
                    return scanner_engine.scan(server.source)
            requested_image = server.source.sandbox_image or default_image
            execution_image = execution_image_bindings.get(requested_image)
            if execution_image is None:
                raise RefreshCandidateError(
                    f"preflight image binding unavailable for {requested_image}"
                )
            execution_source = server.source.model_copy(update={"sandbox_image": execution_image})
            return scanner_engine.scan(execution_source)

        scanner = scan_server

    assert scanner is not None
    output_parent.mkdir(parents=True, exist_ok=True)
    name = candidate_name or f"refresh-candidate-{fixed_now.strftime('%Y%m%dT%H%M%SZ')}"
    if not _SAFE_CANDIDATE_NAME.fullmatch(name):
        raise RefreshCandidateError("candidate name must be a safe single path component")
    final = output_parent / name
    if final.exists():
        raise RefreshCandidateError(f"candidate already exists: {final}")
    temporary = Path(tempfile.mkdtemp(prefix=f".{name}.tmp-", dir=output_parent))
    published = False
    try:
        receipts_dir = temporary / "receipts"
        receipts_dir.mkdir(mode=0o700)
        masked_proofs_dir = temporary / "masked-proofs"
        masked_proofs_dir.mkdir(mode=0o700)
        if not fixture_mode:
            assert qualification_receipt is not None
            _write_private(temporary / "qualification_receipt.json", qualification_receipt)
        candidate_db = temporary / "registry.db"
        if not fixture_mode:
            try:
                require_current_host_capacity(
                    qualification_receipt.get("host_capacity"),
                    anchor=repo_root,
                    now=datetime.now(tz=UTC),
                )
            except HostCapacityError as exc:
                raise RefreshCandidateError(
                    "real refresh host capacity changed before candidate database access"
                ) from exc
        _sqlite_online_copy(source_db, candidate_db)
        conn = connect(str(candidate_db))
        init_schema(conn)
        scan_repo = ScanRepository(conn)
        conn.execute("PRAGMA secure_delete = ON")
        placeholders = ",".join("?" for _ in catalog_slugs)
        if placeholders:
            catalog_parameters = tuple(sorted(catalog_slugs))
            conn.execute(
                f"DELETE FROM scans WHERE server_slug NOT IN ({placeholders})",  # noqa: S608
                catalog_parameters,
            )
            conn.execute(
                f"DELETE FROM servers WHERE slug NOT IN ({placeholders})",  # noqa: S608
                catalog_parameters,
            )
        else:
            conn.execute("DELETE FROM scans")
            conn.execute("DELETE FROM servers")
        if masked_slugs:
            conn.executemany(
                "DELETE FROM scans WHERE server_slug = ?",
                ((slug,) for slug in sorted(masked_slugs)),
            )
        conn.commit()
        conn.execute("VACUUM")

        results: list[dict[str, object]] = []
        excluded: set[str] = set(blocked_slugs)
        verified_snapshot_scan_modes: dict[str, str] = {}
        writer = receipt_writer or _write_receipt
        execution_default_image = execution_image_bindings.get(default_image, default_image)
        with _scan_environment(execution_default_image, docker_host):
            for server in servers:
                previous = scan_repo.latest(server.slug)
                if server.slug in blocked_slugs:
                    results.append(
                        {
                            "server_slug": server.slug,
                            "state": "blocked-policy",
                            "fresh_grade": None,
                            "execution_disposition": "do-not-execute",
                            "reason": "sandbox_image_qualification_unknown",
                            "previous_grade": str(previous.grade) if previous else None,
                            "previous_scanned_at": (
                                previous.scanned_at.isoformat() if previous else None
                            ),
                            "previous_scan_age_days": (
                                _scan_age_days(previous.scanned_at, fixed_now) if previous else None
                            ),
                        }
                    )
                    continue
                try:
                    if not fixture_mode:
                        try:
                            require_current_host_capacity(
                                qualification_receipt.get("host_capacity"),
                                anchor=repo_root,
                                now=datetime.now(tz=UTC),
                            )
                        except HostCapacityError as exc:
                            raise RefreshCandidateError(
                                "real refresh host capacity changed before scan"
                            ) from exc
                    engine_result = scanner(server)
                    if not fixture_mode and engine_result.engine_name != "mcpaudit":
                        raise RefreshCandidateError("real refresh returned a non-mcpaudit result")
                    if engine_result.evidence is None:
                        results.append(
                            {
                                "server_slug": server.slug,
                                "state": "unknown-evidence",
                                "fresh_grade": None,
                                "previous_grade": str(previous.grade) if previous else None,
                                "previous_scanned_at": (
                                    previous.scanned_at.isoformat() if previous else None
                                ),
                            }
                        )
                        excluded.add(server.slug)
                        continue
                    requested_image = server.source.sandbox_image or default_image
                    expected_image = (
                        execution_image_bindings.get(requested_image, requested_image)
                        if _requires_local_sandbox(server)
                        else None
                    )
                    runtime_profile = next(
                        (
                            profile
                            for profile in sandbox_evidence.get("profiles", [])
                            if isinstance(profile, dict) and profile.get("image") == requested_image
                        ),
                        None,
                    )
                    try:
                        expected_server_process_digests = sandbox_server_process_digests(
                            *docker_launch_spec(server.source),
                            allow_python_console_script=(
                                server.source.kind == SourceKind.PYPI
                                and server.source.command is not None
                            ),
                        )
                    except Exception:  # invalid launch spec is classified as UNKNOWN
                        expected_server_process_digests = None
                    if (
                        not fixture_mode
                        and _requires_local_sandbox(server)
                        and (
                            engine_result.sandbox_image != expected_image
                            or engine_result.sandbox_cleanup_evidence
                            != "CONTAINER_ABSENCE_VERIFIED"
                            or not isinstance(expected_image, str)
                            or not isinstance(runtime_profile, dict)
                            or not isinstance(expected_server_process_digests, tuple)
                            or not valid_sandbox_runtime_readback(
                                engine_result.sandbox_runtime_readback,
                                expected_image_id=expected_image,
                                expected_profile=runtime_profile,
                                expected_dummy_env_names=list(server.source.env_keys),
                                expected_server_process_digests=expected_server_process_digests,
                            )
                        )
                    ):
                        results.append(
                            {
                                "server_slug": server.slug,
                                "state": "unknown-sandbox-evidence",
                                "fresh_grade": None,
                                "expected_sandbox_image": expected_image,
                                "sandbox_cleanup_evidence": (
                                    engine_result.sandbox_cleanup_evidence or "UNKNOWN"
                                ),
                                "sandbox_runtime_readback": (
                                    "VERIFIED"
                                    if isinstance(engine_result.sandbox_runtime_readback, dict)
                                    and engine_result.sandbox_runtime_readback.get("state")
                                    == "VERIFIED"
                                    else "UNKNOWN"
                                ),
                            }
                        )
                        excluded.add(server.slug)
                        continue
                    scan = ScanRecord(
                        id=uuid.uuid4().hex,
                        server_slug=server.slug,
                        engine_name=engine_result.engine_name,
                        engine_version=engine_result.engine_version,
                        grade=grading.grade(engine_result.risk),
                        transparency=grading.transparency(engine_result.risk),
                        risk=engine_result.risk,
                        findings=engine_result.findings,
                        evidence=engine_result.evidence,
                        scanned_at=fixed_now,
                        sandbox_image=engine_result.sandbox_image,
                    )
                    masked = server.slug in masked_slugs
                    execution_binding = _candidate_execution_binding(
                        server,
                        qualification=qualification_manifest,
                        sandbox_evidence=sandbox_evidence,
                        default_image=default_image,
                        expected_image=expected_image,
                        fixture_mode=fixture_mode,
                        cleanup_evidence=engine_result.sandbox_cleanup_evidence,
                        runtime_readback=engine_result.sandbox_runtime_readback,
                    )
                    if masked:
                        receipt_ref = None
                        masked_proof_ref = _write_masked_scan_proof(
                            server,
                            scan,
                            masked_proofs_dir,
                            execution_binding=execution_binding,
                        )
                    elif receipt_writer is None:
                        masked_proof_ref = None
                        receipt_ref = f"{scan.server_slug}-{scan.id}.json"
                        scan = scan.model_copy(update={"report_ref": receipt_ref})
                        _write_receipt(
                            server,
                            scan,
                            receipts_dir,
                            execution_binding=execution_binding,
                        )
                    else:
                        masked_proof_ref = None
                        receipt_ref = writer(server, scan, receipts_dir)
                    receipt_portable = bool(
                        receipt_ref
                        and "/" not in receipt_ref
                        and "\\" not in receipt_ref
                        and receipt_ref not in {".", ".."}
                    )
                    receipt_path = receipts_dir / receipt_ref if receipt_portable else None
                    receipt_valid = masked or bool(
                        receipt_path is not None
                        and receipt_path.is_file()
                        and (
                            fixture_mode
                            or _validate_receipt(
                                receipt_path,
                                server=server,
                                scan=scan,
                                expected_image=expected_image,
                                expected_execution_binding=execution_binding,
                            )
                        )
                    )
                    if not masked and (not receipt_ref or not receipt_valid):
                        results.append(
                            {
                                "server_slug": server.slug,
                                "state": "missing-receipt",
                                "fresh_grade": None,
                                "previous_grade": str(previous.grade) if previous else None,
                            }
                        )
                        excluded.add(server.slug)
                        continue
                    if not fixture_mode and not masked and _requires_local_sandbox(server):
                        verified_snapshot_scan_modes[scan.id] = "mcpaudit-local-network-off"
                    if masked:
                        drift = None
                    else:
                        if scan.report_ref != receipt_ref:
                            scan = scan.model_copy(update={"report_ref": receipt_ref})
                        scan_repo.record(scan)
                        drift = diff_latest(scan_repo.history(server.slug, limit=2))
                    results.append(
                        {
                            "server_slug": server.slug,
                            "state": "masked" if masked else "fresh",
                            "fresh_grade": None if masked else str(scan.grade),
                            "grade_visibility": "withheld" if masked else "reviewable",
                            "transparency": (None if masked else str(scan.transparency)),
                            "scanned_at": scan.scanned_at.isoformat(),
                            "scan_age_days": _scan_age_days(scan.scanned_at, fixed_now),
                            "freshness_state": str(FreshnessState.FRESH),
                            "freshness_reason": "fresh",
                            "stale_after": (
                                scan.scanned_at + timedelta(days=STALE_AFTER_DAYS)
                            ).isoformat(),
                            "scan_id": None if masked else scan.id,
                            "engine_name": scan.engine_name,
                            "engine_version": scan.engine_version,
                            "receipt": None if masked else receipt_ref,
                            "receipt_visibility": ("withheld" if masked else "reviewable"),
                            "scan_proof": masked_proof_ref,
                            "scan_proof_visibility": (
                                "reviewable-redacted" if masked else "not_applicable"
                            ),
                            "drift": _drift_payload(drift),
                        }
                    )
                except ScanTimeoutError as exc:
                    hard_termination_evidence = getattr(exc, "hard_termination_evidence", "UNKNOWN")
                    if hard_termination_evidence not in {
                        "UNKNOWN",
                        "CONTAINER_ABSENCE_VERIFIED_AFTER_TIMEOUT",
                    }:
                        hard_termination_evidence = "UNKNOWN"
                    results.append(
                        {
                            "server_slug": server.slug,
                            "state": "scan-timeout",
                            "fresh_grade": None,
                            "reason": "configured_scan_timeout_expired",
                            "configured_timeout_seconds": SCAN_TIMEOUT_SECONDS,
                            "timeout_outcome": "timeout",
                            "hard_termination_evidence": hard_termination_evidence,
                            "previous_grade": str(previous.grade) if previous else None,
                            "previous_scanned_at": (
                                previous.scanned_at.isoformat() if previous else None
                            ),
                            "previous_scan_age_days": (
                                _scan_age_days(previous.scanned_at, fixed_now) if previous else None
                            ),
                        }
                    )
                    excluded.add(server.slug)
                except Exception as exc:  # noqa: BLE001 - one row must become explicit partial
                    results.append(
                        {
                            "server_slug": server.slug,
                            "state": "scan-failed",
                            "fresh_grade": None,
                            "error_type": type(exc).__name__,
                            "previous_grade": str(previous.grade) if previous else None,
                            "previous_scanned_at": (
                                previous.scanned_at.isoformat() if previous else None
                            ),
                            "previous_scan_age_days": (
                                _scan_age_days(previous.scanned_at, fixed_now) if previous else None
                            ),
                        }
                    )
                    excluded.add(server.slug)
        conn.close()

        from mcp_trust.catalog.snapshot import build_snapshot

        snapshot = build_snapshot(
            str(candidate_db),
            excluded_slugs=frozenset(excluded),
            masked_slugs=masked_slugs,
            verified_scan_modes=verified_snapshot_scan_modes,
            now=fixed_now,
        )
        _write_private(
            temporary / "catalog_identity.json",
            {
                "schema": "RefreshCatalogIdentityV1",
                "seed_sha256": reviewed.seed_sha256,
                "server_count": len(catalog_rows),
                "servers": catalog_rows,
            },
        )
        _write_private(
            temporary / "scan_results.json",
            {
                "schema": "RefreshScanResultsV1",
                "generated_at": fixed_now.isoformat(),
                "results": results,
            },
        )
        _write_private(temporary / "static_snapshot.json", snapshot)

        if not fixture_mode:
            assert repo_root is not None
            assert _source_binding_provider is not None
            if _source_binding_provider(repo_root) != qualified_source_binding:
                raise RefreshCandidateError("execution source changed during refresh")
        complete = all(
            result["state"] in {"fresh", "masked", "blocked-policy"} for result in results
        )
        candidate_state = "fixture" if fixture_mode else "complete" if complete else "partial"
        successful_stale_after = sorted(
            str(result["stale_after"])
            for result in results
            if result.get("state") in {"fresh", "masked"}
            and isinstance(result.get("stale_after"), str)
        )
        candidate_expires_at = fixed_now + timedelta(hours=DEFAULT_MAX_AGE_HOURS)
        earliest_stale_after = (
            _parse_utc_datetime(successful_stale_after[0]) if successful_stale_after else None
        )
        publication_not_after = min(
            candidate_expires_at,
            earliest_stale_after or candidate_expires_at,
        )
        manifest = {
            "schema": CANDIDATE_SCHEMA,
            "created_at": fixed_now.isoformat(),
            "expires_at": candidate_expires_at.isoformat(),
            "candidate_state": candidate_state,
            "publication_allowed": candidate_state == "complete",
            "scan_mode": (
                "deterministic-fixture"
                if fixture_mode
                else _real_scan_mode(
                    local_count=sum(
                        _requires_local_sandbox(server) for server in execution_servers
                    ),
                    total_count=len(execution_servers),
                )
            ),
            "catalog": {
                "seed_sha256": reviewed.seed_sha256,
                "server_count": len(catalog_rows),
            },
            "masking": {
                "sha256": reviewed.masked_sha256,
                "slugs": sorted(masked_slugs),
            },
            "sandbox": sandbox_evidence,
            "qualification": qualification_manifest,
            "scan_counts": {
                "total": len(results),
                "fresh": sum(result["state"] == "fresh" for result in results),
                "masked": sum(result["state"] == "masked" for result in results),
                "blocked": sum(result["state"] == "blocked-policy" for result in results),
                "failed": sum(
                    result["state"] not in {"fresh", "masked", "blocked-policy"}
                    for result in results
                ),
            },
            "engine_versions": sorted(
                {
                    str(result["engine_version"])
                    for result in results
                    if result.get("engine_version")
                }
            ),
            "freshness": {
                "mode": "STATIC_HISTORICAL_ONLY",
                "horizon_days": STALE_AFTER_DAYS,
                "evaluated_at": fixed_now.isoformat(),
                "earliest_stale_after": (
                    earliest_stale_after.isoformat() if earliest_stale_after else None
                ),
                "publication_not_after": publication_not_after.isoformat(),
                "state_counts": {
                    "FRESH": sum(
                        result.get("freshness_state") == str(FreshnessState.FRESH)
                        for result in results
                    ),
                    "STALE": 0,
                    "UNKNOWN": sum(
                        result.get("state") not in {"fresh", "masked"} for result in results
                    ),
                    "NOT_APPLICABLE": 0,
                },
            },
            "semantic_digests": {
                "scan_results": _sha256(temporary / "scan_results.json"),
                "static_snapshot": _sha256(temporary / "static_snapshot.json"),
                "masking": reviewed.masked_sha256,
            },
            "source_tree_digest": (
                qualification_manifest.get("source_tree_digest")
                if isinstance(qualification_manifest, dict)
                else None
            ),
            "tool_versions": {
                "python": (
                    f"{sys.version_info.major}.{sys.version_info.minor}.{sys.version_info.micro}"
                ),
                "mcp_trust_candidate_schema": CANDIDATE_SCHEMA,
            },
            "artifacts": _artifact_inventory(temporary),
            "authority": {
                "candidate_creation": True,
                "publication": False,
                "deployment": False,
                "schedule_change": False,
            },
        }
        _write_private(temporary / MANIFEST_NAME, manifest)
        manifest_digest = _sha256(temporary / MANIFEST_NAME)
        _write_private_text(
            temporary / MANIFEST_DIGEST_NAME,
            manifest_digest + "\n",
        )
        _make_files_read_only(temporary)
        _fsync_directory(receipts_dir)
        _fsync_directory(masked_proofs_dir)
        _fsync_directory(temporary)
        os.replace(temporary, final)
        published = True
        _make_read_only(final)
        _fsync_directory(final / "receipts")
        _fsync_directory(final / "masked-proofs")
        _fsync_directory(final)
        _fsync_directory(output_parent)
    finally:
        if not published:
            shutil.rmtree(temporary, ignore_errors=True)

    verified = verify_refresh_candidate(
        final,
        now=fixed_now,
        expected_seed_path=seed_path,
        expected_masked_path=masked_path,
        repo_root=repo_root,
        _captured_reviewed_inputs=reviewed,
        _source_binding_provider=_source_binding_provider,
        _qualification_revalidator=_qualification_revalidator,
    )
    if not verified["structural_valid"]:
        raise RefreshCandidateError(
            "published candidate failed content verification: "
            + ",".join(str(error) for error in verified["errors"])
        )
    return final


def verify_refresh_candidate(
    candidate: Path,
    *,
    now: datetime | None = None,
    max_age_hours: int = DEFAULT_MAX_AGE_HOURS,
    expected_seed_path: Path | None = None,
    expected_masked_path: Path | None = None,
    repo_root: Path | None = None,
    _captured_reviewed_inputs: _ReviewedInputs | None = None,
    _source_binding_provider: Callable[[Path], dict[str, Any]] | None = None,
    _qualification_revalidator: Callable[..., None] | None = None,
    _include_candidate_snapshot: bool = False,
    _include_verified_masked_slugs: bool = False,
    _include_artifact_manifest: bool = False,
) -> dict[str, object]:
    """Verify manifest, every artifact, freshness, masking, and partial state."""
    fixed_now = now or datetime.now(tz=UTC)
    if fixed_now.tzinfo is None:
        fixed_now = fixed_now.replace(tzinfo=UTC)
    try:
        candidate_stat = candidate.lstat()
    except OSError:
        return {
            "structural_valid": False,
            "state": "missing",
            "publication_ready": False,
            "errors": ["candidate_missing_or_not_directory"],
        }
    if not stat.S_ISDIR(candidate_stat.st_mode) or stat.S_ISLNK(candidate_stat.st_mode):
        return {
            "structural_valid": False,
            "state": "invalid",
            "publication_ready": False,
            "errors": ["candidate_missing_or_not_directory"],
        }
    try:
        captured = _capture_candidate(candidate)
    except _CandidateSnapshotError as exc:
        return {
            "structural_valid": False,
            "state": "invalid",
            "publication_ready": False,
            "errors": [exc.code],
        }
    errors: list[str] = list(captured.errors)
    if _SAFE_CANDIDATE_NAME.fullmatch(candidate.name) is None:
        errors.append("candidate_name_invalid")

    actual_manifest_digest: str | None = None
    try:
        manifest = _captured_json(captured, MANIFEST_NAME)
        digest_content = captured.files[MANIFEST_DIGEST_NAME]
        expected_manifest_digest = digest_content.decode("ascii").strip()
        actual_manifest_digest = _sha256_bytes(captured.files[MANIFEST_NAME])
    except (KeyError, RefreshCandidateError, UnicodeError):
        manifest = {}
        expected_manifest_digest = ""
        errors.append("manifest_unreadable")
    if not expected_manifest_digest or expected_manifest_digest != actual_manifest_digest:
        errors.append("manifest_digest_mismatch")
    manifest_schema = manifest.get("schema") if isinstance(manifest, dict) else None
    legacy_schema = manifest_schema == CANDIDATE_SCHEMA_V1
    if not isinstance(manifest, dict) or manifest_schema not in {
        CANDIDATE_SCHEMA_V1,
        CANDIDATE_SCHEMA,
    }:
        errors.append("manifest_schema_invalid")
        manifest = {}
    elif set(manifest) != (_MANIFEST_KEYS_V1 if legacy_schema else _MANIFEST_KEYS):
        errors.append("manifest_fields_invalid")

    listed: set[str] = set()
    artifacts = manifest.get("artifacts")
    if not isinstance(artifacts, list) or len(artifacts) > _MAX_CANDIDATE_FILES:
        errors.append("artifact_manifest_invalid")
        artifacts = []
    for artifact in artifacts:
        if (
            not isinstance(artifact, dict)
            or set(artifact) != {"path", "bytes", "sha256"}
            or not isinstance(artifact.get("path"), str)
            or type(artifact.get("bytes")) is not int
            or int(artifact["bytes"]) < 0
            or not isinstance(artifact.get("sha256"), str)
            or _SHA256_TEXT.fullmatch(artifact["sha256"]) is None
        ):
            errors.append("artifact_manifest_invalid")
            continue
        relative = artifact["path"]
        if not _safe_artifact_path(relative) or relative in listed:
            errors.append("artifact_manifest_invalid")
            continue
        listed.add(relative)
        content = captured.files.get(relative)
        if (
            content is None
            or len(content) != artifact.get("bytes")
            or _sha256_bytes(content) != artifact.get("sha256")
        ):
            errors.append(f"artifact_mismatch:{relative}")
    actual = {
        relative
        for relative in captured.files
        if relative not in {MANIFEST_NAME, MANIFEST_DIGEST_NAME}
    }
    if actual != listed:
        errors.append("artifact_set_mismatch")
    actual_directories = {
        relative
        for relative in captured.tree_metadata
        if relative != "." and relative not in captured.file_metadata
    }
    if actual_directories != {"masked-proofs", "receipts"}:
        errors.append("candidate_directory_set_mismatch")

    created_at: datetime | None = None
    expires_at: datetime | None = None
    try:
        created_at = _parse_utc_datetime(manifest["created_at"])
        age_seconds = (fixed_now.astimezone(UTC) - created_at).total_seconds()
        age_hours = max(0.0, age_seconds / 3600)
        if age_seconds < 0:
            errors.append("candidate_timestamp_in_future")
    except (KeyError, OverflowError, ValueError, TypeError):
        age_hours = None
        errors.append("candidate_timestamp_invalid")
    try:
        expires_at = _parse_utc_datetime(manifest["expires_at"])
    except (KeyError, OverflowError, ValueError, TypeError):
        errors.append("candidate_expiry_invalid")
    if created_at is not None and expires_at is not None:
        try:
            expected_expiry = created_at + timedelta(hours=DEFAULT_MAX_AGE_HOURS)
        except OverflowError:
            errors.append("candidate_expiry_invalid")
        else:
            if expires_at != expected_expiry:
                errors.append("candidate_expiry_mismatch")
    candidate_time_stale = bool(
        (expires_at is not None and fixed_now.astimezone(UTC) >= expires_at)
        or (age_hours is not None and age_hours >= max_age_hours)
    )

    results_payload: Any = {}
    snapshot_payload: Any = {}
    catalog_payload: Any = {}
    try:
        results_payload = _captured_json(captured, "scan_results.json")
        snapshot_payload = _captured_json(captured, "static_snapshot.json")
        catalog_payload = _captured_json(captured, "catalog_identity.json")
    except RefreshCandidateError:
        errors.append("candidate_projection_unreadable")
    results = results_payload.get("results") if isinstance(results_payload, dict) else None
    if (
        not isinstance(results_payload, dict)
        or set(results_payload) != {"schema", "generated_at", "results"}
        or results_payload.get("schema") != "RefreshScanResultsV1"
        or not isinstance(results_payload.get("generated_at"), str)
        or not isinstance(results, list)
        or len(results) > _MAX_CATALOG_ROWS
    ):
        errors.append("scan_results_invalid")
        results = []
    elif results_payload.get("generated_at") != manifest.get("created_at"):
        errors.append("scan_results_timestamp_mismatch")
    if manifest.get("schema") == CANDIDATE_SCHEMA:
        _validate_v2_freshness_manifest(
            manifest=manifest,
            captured=captured,
            results=results,
            created_at=created_at,
            expires_at=expires_at,
            errors=errors,
        )
    catalog_rows = catalog_payload.get("servers") if isinstance(catalog_payload, dict) else None
    if (
        not isinstance(catalog_payload, dict)
        or set(catalog_payload) != {"schema", "seed_sha256", "server_count", "servers"}
        or catalog_payload.get("schema") != "RefreshCatalogIdentityV1"
        or not isinstance(catalog_rows, list)
        or len(catalog_rows) > _MAX_CATALOG_ROWS
        or not all(
            isinstance(row, dict) and _safe_artifact_component(row.get("slug"))
            for row in catalog_rows
        )
    ):
        errors.append("catalog_identity_invalid")
        catalog_payload = {}
        catalog_rows = []
    catalog_slugs = {
        row.get("slug")
        for row in catalog_rows
        if isinstance(row, dict) and isinstance(row.get("slug"), str)
    }
    catalog_by_slug = {
        row["slug"]: row
        for row in catalog_rows
        if isinstance(row, dict) and isinstance(row.get("slug"), str)
    }
    result_slugs = {
        result.get("server_slug")
        for result in results
        if isinstance(result, dict) and _safe_artifact_component(result.get("server_slug"))
    }
    if (
        len(catalog_slugs) != len(catalog_rows)
        or len(result_slugs) != len(results)
        or result_slugs != catalog_slugs
    ):
        errors.append("catalog_scan_coverage_mismatch")
    if not catalog_rows or not results:
        errors.append("empty_candidate")
    manifest_catalog = manifest.get("catalog")
    if (
        not isinstance(manifest_catalog, dict)
        or set(manifest_catalog) != {"seed_sha256", "server_count"}
        or not isinstance(manifest_catalog.get("seed_sha256"), str)
        or _SHA256_TEXT.fullmatch(manifest_catalog["seed_sha256"]) is None
        or type(manifest_catalog.get("server_count")) is not int
    ):
        errors.append("catalog_manifest_mismatch")
        manifest_catalog = {}
    elif (
        manifest_catalog.get("server_count") != len(catalog_rows)
        or type(catalog_payload.get("server_count")) is not int
        or not isinstance(catalog_payload.get("seed_sha256"), str)
        or _SHA256_TEXT.fullmatch(catalog_payload["seed_sha256"]) is None
        or catalog_payload.get("server_count") != len(catalog_rows)
        or manifest_catalog.get("seed_sha256") != catalog_payload.get("seed_sha256")
    ):
        errors.append("catalog_manifest_mismatch")
    manifest_masking = manifest.get("masking")
    declared_masked_slugs = (
        manifest_masking.get("slugs") if isinstance(manifest_masking, dict) else None
    )
    if (
        not isinstance(manifest_masking, dict)
        or set(manifest_masking) != {"sha256", "slugs"}
        or not isinstance(manifest_masking.get("sha256"), str)
        or _SHA256_TEXT.fullmatch(manifest_masking["sha256"]) is None
        or not isinstance(declared_masked_slugs, list)
        or len(declared_masked_slugs) > _MAX_CATALOG_ROWS
        or not all(_safe_artifact_component(slug) for slug in declared_masked_slugs)
        or len(set(declared_masked_slugs)) != len(declared_masked_slugs)
    ):
        errors.append("masking_manifest_invalid")
        manifest_masking = {}
        declared_masked_slugs = []
    reviewed_inputs_bound = False
    expected_policy_scannable: frozenset[str] | None = None
    expected_policy_blocked: frozenset[str] | None = None
    expected_catalog_counts: object = None
    expected_catalog_inventory_digest: object = None
    if (expected_seed_path is None) != (expected_masked_path is None):
        errors.append("reviewed_inputs_incomplete")
    elif expected_seed_path is not None and expected_masked_path is not None:
        try:
            reviewed = _captured_reviewed_inputs or _reviewed_inputs(
                expected_seed_path,
                expected_masked_path,
            )
            reviewed_inputs_bound = bool(
                catalog_rows == reviewed.catalog_rows
                and catalog_slugs == reviewed.catalog_slugs
                and manifest_catalog.get("seed_sha256") == reviewed.seed_sha256
                and manifest_masking.get("sha256") == reviewed.masked_sha256
                and set(declared_masked_slugs) == reviewed.masked_slugs
            )
            if not reviewed_inputs_bound:
                errors.append("reviewed_inputs_mismatch")
            try:
                from mcp_trust.grade_refresh import (  # noqa: PLC0415
                    GradeRefreshError,
                    catalog_inventory,
                    load_policy,
                )

                expected_policy_path = expected_seed_path.with_name("refresh_policy.json")
                expected_policy = load_policy(
                    expected_policy_path,
                    expected_seed_path,
                    expected_masked_path,
                )
                expected_catalog_inventory = catalog_inventory(
                    seed_path=expected_seed_path,
                    masked_path=expected_masked_path,
                    policy_path=expected_policy_path,
                )
                expected_catalog_counts = expected_catalog_inventory["counts"]
                expected_catalog_inventory_digest = "sha256:" + _sha256_bytes(
                    _json_bytes(expected_catalog_inventory)
                )
                expected_policy_scannable = expected_policy.scannable
                expected_policy_blocked = expected_policy.blocked
            except (GradeRefreshError, OSError):
                errors.append("reviewed_execution_policy_unavailable")
        except (OSError, RefreshCandidateError, TypeError, ValueError):
            errors.append("reviewed_inputs_unavailable")
    candidate_state = manifest.get("candidate_state")
    if not isinstance(candidate_state, str) or candidate_state not in _CANDIDATE_STATES:
        errors.append("candidate_state_invalid")
    scan_mode = manifest.get("scan_mode")
    execution_slugs = {
        result.get("server_slug")
        for result in results
        if isinstance(result, dict) and result.get("state") != "blocked-policy"
    }
    execution_rows = [
        row for row in catalog_rows if isinstance(row, dict) and row.get("slug") in execution_slugs
    ]
    catalog_remote_count = sum(
        isinstance(row, dict)
        and isinstance(row.get("source"), dict)
        and row["source"].get("kind") == "remote"
        and row["source"].get("command") is None
        for row in execution_rows
    )
    expected_real_scan_mode = _real_scan_mode(
        local_count=len(execution_rows) - catalog_remote_count,
        total_count=len(execution_rows),
    )
    sandbox_manifest = manifest.get("sandbox")
    sandbox_profiles = (
        sandbox_manifest.get("profiles") if isinstance(sandbox_manifest, dict) else None
    )
    sandbox_profile_rows = sandbox_profiles if isinstance(sandbox_profiles, list) else []
    reviewed_profile_bindings = {
        profile.get("image"): profile.get("image_digest")
        for profile in sandbox_profile_rows
        if isinstance(profile, dict)
        and isinstance(profile.get("image"), str)
        and isinstance(profile.get("image_digest"), str)
        and profile.get("kind") == "docker"
        and profile.get("network") == "none"
        and profile.get("read_only_root") is True
        and profile.get("capabilities") == "dropped-all"
        and profile.get("no_new_privileges") is True
        and isinstance(profile.get("memory"), str)
        and isinstance(profile.get("pids_limit"), int)
        and isinstance(profile.get("cpus"), str)
        and isinstance(profile.get("user"), str)
        and isinstance(profile.get("tmpfs"), str)
    }
    profiles_valid = bool(
        isinstance(sandbox_profiles, list)
        and len(sandbox_profile_rows) <= _MAX_CATALOG_ROWS
        and all(
            isinstance(profile, dict) and set(profile) == _SANDBOX_PROFILE_KEYS
            for profile in sandbox_profile_rows
        )
        and len(reviewed_profile_bindings) == len(sandbox_profile_rows)
    )
    if candidate_state == "fixture":
        sandbox_manifest_valid = bool(
            isinstance(sandbox_manifest, dict)
            and set(sandbox_manifest) == {"mode", "default_image", "profiles"}
            and sandbox_manifest.get("mode") == "deterministic-fixture"
            and isinstance(sandbox_manifest.get("default_image"), str)
            and len(sandbox_profile_rows) == 1
            and profiles_valid
        )
    else:
        sandbox_manifest_valid = bool(
            isinstance(sandbox_manifest, dict)
            and set(sandbox_manifest)
            == {"default_image", "docker_daemon", "profiles", "remote_transport_count"}
            and isinstance(sandbox_manifest.get("default_image"), str)
            and sandbox_manifest.get("docker_daemon") in ("available", "not_required")
            and type(sandbox_manifest.get("remote_transport_count")) is int
            and int(sandbox_manifest["remote_transport_count"]) >= 0
            and sandbox_manifest.get("remote_transport_count") == catalog_remote_count
            and sandbox_manifest.get("docker_daemon")
            == ("not_required" if catalog_remote_count == len(execution_rows) else "available")
            and profiles_valid
            and all(
                isinstance(digest, str) and re.fullmatch(r"sha256:[0-9a-f]{64}", digest) is not None
                for digest in reviewed_profile_bindings.values()
            )
        )
    if not sandbox_manifest_valid:
        errors.append("sandbox_manifest_invalid")
    qualification_manifest = manifest.get("qualification")
    if candidate_state == "fixture":
        qualification_valid = qualification_manifest == {
            "mode": "deterministic-fixture",
            "receipt": None,
        }
    else:
        qualification_valid = False
        if (
            isinstance(qualification_manifest, dict)
            and set(qualification_manifest)
            == {
                "mode",
                "receipt",
                "receipt_sha256",
                "preflight_receipt_digest",
                "policy_digest",
                "source_revision",
                "source_tree_digest",
            }
            and qualification_manifest.get("mode") == "grade-refresh-preflight"
            and qualification_manifest.get("receipt") == "qualification_receipt.json"
            and isinstance(sandbox_manifest, dict)
            and isinstance(manifest_catalog.get("seed_sha256"), str)
            and isinstance(manifest_masking.get("sha256"), str)
        ):
            try:
                from mcp_trust.grade_refresh import (  # noqa: PLC0415
                    GradeRefreshError,
                    revalidate_ready_preflight_qualifications,
                    source_binding,
                )

                if repo_root is None:
                    errors.append("qualification_current_source_unavailable")
                    raise RefreshCandidateError(
                        "current qualification source binding is unavailable"
                    )
                qualification_receipt = _captured_json(
                    captured,
                    "qualification_receipt.json",
                )
                receipt_catalog = (
                    qualification_receipt.get("catalog")
                    if isinstance(qualification_receipt, dict)
                    else None
                )
                current_source = (_source_binding_provider or source_binding)(repo_root)
                expected_image_references = sorted(reviewed_profile_bindings)
                (_qualification_revalidator or revalidate_ready_preflight_qualifications)(
                    qualification_receipt,
                    repo_root=repo_root,
                    expected_image_references=expected_image_references,
                    expected_catalog_counts=expected_catalog_counts,
                    expected_catalog_inventory_digest=expected_catalog_inventory_digest,
                    now=created_at or fixed_now,
                )
                if (_source_binding_provider or source_binding)(repo_root) != current_source:
                    raise RefreshCandidateError(
                        "current qualification source changed during verification"
                    )
                expected_qualification = _qualification_metadata(
                    qualification_receipt,
                    seed_sha256=manifest_catalog["seed_sha256"],
                    masked_sha256=manifest_masking["sha256"],
                    expected_catalog_counts=expected_catalog_counts,
                    expected_catalog_inventory_digest=expected_catalog_inventory_digest,
                    sandbox_evidence=sandbox_manifest,
                    now=created_at or fixed_now,
                    current_source_binding=current_source,
                )
                qualification_valid = qualification_manifest == expected_qualification
                receipt_boundary = (
                    receipt_catalog.get("execution_boundary")
                    if isinstance(receipt_catalog, dict)
                    else None
                )
                if (
                    expected_policy_scannable is not None
                    and expected_policy_blocked is not None
                    and receipt_boundary
                    != {
                        "schema": "McpTrustRefreshExecutionBoundaryV1",
                        "scannable": sorted(expected_policy_scannable),
                        "blocked": sorted(expected_policy_blocked),
                    }
                ):
                    qualification_valid = False
                    errors.append("qualification_execution_boundary_mismatch")
            except (
                GradeRefreshError,
                OSError,
                RefreshCandidateError,
                TypeError,
                ValueError,
            ):
                qualification_valid = False
    if not qualification_valid:
        errors.append("qualification_receipt_invalid")
    successful_results = [
        result
        for result in results
        if isinstance(result, dict) and result.get("state") in ("fresh", "masked")
    ]
    if candidate_state == "complete":
        for result in successful_results:
            slug = result.get("server_slug")
            slug_label = _safe_error_label(slug)
            try:
                scanned_at = _parse_utc_datetime(result["scanned_at"])
            except (KeyError, OverflowError, ValueError, TypeError):
                errors.append(f"scan_timestamp_invalid:{slug_label}")
                continue
            scan_age_seconds = (fixed_now.astimezone(UTC) - scanned_at).total_seconds()
            if scan_age_seconds < 0:
                errors.append(f"scan_timestamp_in_future:{slug_label}")
            elif scan_age_seconds / 3600 >= max_age_hours and not candidate_time_stale:
                errors.append(f"scan_timestamp_stale:{slug_label}")
            recorded_age = result.get("scan_age_days")
            if (
                created_at is None
                or type(recorded_age) not in {int, float}
                or not math.isfinite(float(recorded_age))
                or float(recorded_age) < 0
            ):
                errors.append(f"scan_age_invalid:{slug_label}")
            else:
                expected_age = _scan_age_days(scanned_at, created_at)
                if abs(float(recorded_age) - expected_age) > 0.000001:
                    errors.append(f"scan_age_mismatch:{slug_label}")
    expected_artifacts = {
        "registry.db",
        "catalog_identity.json",
        "scan_results.json",
        "static_snapshot.json",
    }
    if candidate_state != "fixture":
        expected_artifacts.add("qualification_receipt.json")
    expected_artifacts.update(
        f"receipts/{receipt_ref}"
        for result in results
        if isinstance(result, dict)
        and result.get("state") == "fresh"
        and isinstance((receipt_ref := result.get("receipt")), str)
    )
    expected_artifacts.update(
        f"masked-proofs/{proof_ref}"
        for result in results
        if isinstance(result, dict)
        and result.get("state") == "masked"
        and isinstance((proof_ref := result.get("scan_proof")), str)
    )
    if actual != expected_artifacts:
        errors.append("unreferenced_candidate_artifact")
    candidate_db: sqlite3.Connection | None = None
    verified_local_profile_images: set[str] = set()
    try:
        candidate_db = _snapshot_database(captured)
    except RefreshCandidateError:
        errors.append("candidate_database_unreadable")
    for result in results:
        if isinstance(result, dict) and result.get("state") == "blocked-policy":
            if (
                set(result) != _BLOCKED_RESULT_KEYS
                or result.get("fresh_grade") is not None
                or result.get("execution_disposition") != "do-not-execute"
                or result.get("reason") != "sandbox_image_qualification_unknown"
                or (
                    candidate_state != "fixture"
                    and expected_policy_blocked is not None
                    and result.get("server_slug") not in expected_policy_blocked
                )
            ):
                errors.append(
                    f"blocked_scan_schema_invalid:{_safe_error_label(result.get('server_slug'))}"
                )
            continue
        if isinstance(result, dict) and result.get("state") == "scan-timeout":
            if (
                set(result) != _TIMEOUT_RESULT_KEYS
                or result.get("fresh_grade") is not None
                or result.get("reason") != "configured_scan_timeout_expired"
                or result.get("configured_timeout_seconds") != SCAN_TIMEOUT_SECONDS
                or result.get("timeout_outcome") != "timeout"
                or not isinstance(result.get("hard_termination_evidence"), str)
                or result.get("hard_termination_evidence")
                not in {"UNKNOWN", "CONTAINER_ABSENCE_VERIFIED_AFTER_TIMEOUT"}
            ):
                errors.append(
                    f"timeout_scan_schema_invalid:{_safe_error_label(result.get('server_slug'))}"
                )
            continue
        if not isinstance(result, dict) or result.get("state") not in (
            "fresh",
            "masked",
        ):
            continue
        if not _safe_artifact_component(result.get("server_slug")):
            errors.append("successful_scan_schema_invalid:invalid")
            continue
        expected_result_keys = _SUCCESS_RESULT_KEYS_V1 if legacy_schema else _SUCCESS_RESULT_KEYS
        if set(result) != expected_result_keys:
            errors.append(
                f"successful_scan_schema_invalid:{_safe_error_label(result.get('server_slug'))}"
            )
        recorded_age = result.get("scan_age_days")
        if (
            type(recorded_age) not in {int, float}
            or not math.isfinite(float(recorded_age))
            or float(recorded_age) < 0
        ):
            errors.append(f"scan_age_invalid:{_safe_error_label(result.get('server_slug'))}")
        if result.get("state") == "masked":
            if (
                result.get("receipt") is not None
                or result.get("scan_id") is not None
                or result.get("grade_visibility") != "withheld"
                or result.get("receipt_visibility") != "withheld"
                or result.get("fresh_grade") is not None
                or result.get("transparency") is not None
                or result.get("drift") is not None
            ):
                errors.append("masked_scan_evidence_exposed")
            proof_ref = result.get("scan_proof")
            if (
                not _safe_artifact_component(proof_ref)
                or result.get("scan_proof_visibility") != "reviewable-redacted"
            ):
                errors.append("masked_scan_proof_ref_invalid")
                continue
            try:
                proof = _captured_json(captured, f"masked-proofs/{proof_ref}")
            except RefreshCandidateError:
                errors.append(f"masked_scan_proof_missing:{proof_ref}")
                continue
            proof_keys = {
                "format_version",
                "proof_type",
                "outcome",
                "server_slug",
                "scan_id",
                "server",
                "scanned_at",
                "scanner",
                "sandbox",
                "evidence_present",
                "execution_binding",
                "proof_digest",
            }
            scanner = proof.get("scanner") if isinstance(proof, dict) else None
            sandbox = proof.get("sandbox") if isinstance(proof, dict) else None
            proof_server = proof.get("server") if isinstance(proof, dict) else None
            proof_valid = bool(
                isinstance(proof, dict)
                and set(proof) == proof_keys
                and proof.get("format_version") == 2
                and _masked_proof_digest_valid(proof)
                and proof.get("proof_type") == "masked_scan_success"
                and proof.get("outcome") == "scan_succeeded"
                and proof.get("server_slug") == result.get("server_slug")
                and isinstance(proof.get("scan_id"), str)
                and proof.get("scanned_at") == result.get("scanned_at")
                and proof.get("evidence_present") is True
                and isinstance(scanner, dict)
                and set(scanner) == _SCANNER_KEYS
                and scanner.get("scanner_git_ref") is None
                and scanner.get("engine_name") == result.get("engine_name")
                and scanner.get("engine_version") == result.get("engine_version")
                and isinstance(sandbox, dict)
                and frozenset(sandbox)
                in {
                    _REMOTE_RECEIPT_SANDBOX_KEYS,
                    _LOCAL_RECEIPT_SANDBOX_KEYS,
                    _FIXTURE_RECEIPT_SANDBOX_KEYS,
                }
                and isinstance(proof_server, dict)
            )
            if not proof_valid:
                errors.append(f"masked_scan_proof_invalid:{proof_ref}")
                continue
            reviewed_server_for_binding: Server | None = None
            catalog_row_for_binding = catalog_by_slug.get(result.get("server_slug"))
            if isinstance(catalog_row_for_binding, dict) and isinstance(proof_server, dict):
                try:
                    reviewed_server_for_binding = _reviewed_server_from_seed(
                        catalog_row_for_binding,
                        added_at=datetime.fromisoformat(
                            str(proof_server.get("added_at")).replace("Z", "+00:00")
                        ),
                    )
                except (RefreshCandidateError, TypeError, ValueError):
                    reviewed_server_for_binding = None
            expected_masked_binding = None
            if (
                reviewed_server_for_binding is not None
                and isinstance(qualification_manifest, dict)
                and isinstance(sandbox_manifest, dict)
                and isinstance(sandbox_manifest.get("default_image"), str)
            ):
                requested_image_for_binding = (
                    reviewed_server_for_binding.source.sandbox_image
                    or sandbox_manifest["default_image"]
                )
                proof_binding = proof.get("execution_binding")
                proof_runtime = (
                    proof_binding.get("sandbox", {}).get("runtime_readback")
                    if isinstance(proof_binding, dict)
                    and isinstance(proof_binding.get("sandbox"), dict)
                    else None
                )
                try:
                    expected_masked_binding = _candidate_execution_binding(
                        reviewed_server_for_binding,
                        qualification=qualification_manifest,
                        sandbox_evidence=sandbox_manifest,
                        default_image=sandbox_manifest["default_image"],
                        expected_image=(
                            None
                            if candidate_state == "fixture"
                            else reviewed_profile_bindings.get(requested_image_for_binding)
                        ),
                        fixture_mode=candidate_state == "fixture",
                        cleanup_evidence=(
                            "NOT_APPLICABLE"
                            if candidate_state == "fixture"
                            else "CONTAINER_ABSENCE_VERIFIED"
                        ),
                        runtime_readback=proof_runtime,
                    )
                except RefreshCandidateError:
                    expected_masked_binding = None
            if proof.get("execution_binding") != expected_masked_binding:
                errors.append(f"masked_scan_execution_binding_invalid:{proof_ref}")
                continue
            if candidate_state == "complete":
                reviewed_server: Server | None = None
                catalog_row = catalog_by_slug.get(result.get("server_slug"))
                if isinstance(catalog_row, dict):
                    try:
                        reviewed_server = _reviewed_server_from_seed(
                            catalog_row,
                            added_at=datetime.fromisoformat(
                                str(proof_server.get("added_at")).replace("Z", "+00:00")
                            ),
                        )
                    except (RefreshCandidateError, TypeError, ValueError):
                        reviewed_server = None
                catalog_bound = bool(
                    reviewed_server is not None
                    and proof_server == reviewed_server.model_dump(mode="json")
                )
                remote_without_command = bool(
                    reviewed_server is not None and not _requires_local_sandbox(reviewed_server)
                )
                proof_image = sandbox.get("MCP_TRUST_SANDBOX_IMAGE")
                reviewed_image = (
                    reviewed_server.source.sandbox_image if reviewed_server is not None else None
                )
                requested_image = reviewed_image or (
                    sandbox_manifest.get("default_image")
                    if isinstance(sandbox_manifest, dict)
                    else None
                )
                expected_image_digest = reviewed_profile_bindings.get(requested_image)
                local_image_valid = bool(
                    isinstance(proof_image, str) and proof_image == expected_image_digest
                )
                sandbox_valid = bool(
                    catalog_bound
                    and (
                        (
                            sandbox.get("mode") == "not_applicable"
                            and sandbox.get("reason") == "remote_endpoint_no_local_process"
                        )
                        if remote_without_command
                        else (
                            sandbox.get("MCP_TRUST_SANDBOX") == "docker"
                            and sandbox.get("MCP_TRUST_SANDBOX_NETWORK") == "none"
                            and local_image_valid
                        )
                    )
                )
                if result.get("engine_name") != "mcpaudit" or not sandbox_valid:
                    errors.append(f"masked_scan_provenance_invalid:{proof_ref}")
                elif not remote_without_command and isinstance(requested_image, str):
                    verified_local_profile_images.add(requested_image)
            continue
        if (
            result.get("grade_visibility") != "reviewable"
            or result.get("receipt_visibility") != "reviewable"
            or result.get("scan_proof") is not None
            or result.get("scan_proof_visibility") != "not_applicable"
        ):
            errors.append(
                f"fresh_scan_semantics_invalid:{_safe_error_label(result.get('server_slug'))}"
            )
        receipt_ref = result.get("receipt")
        if not _safe_artifact_component(receipt_ref):
            errors.append("successful_scan_receipt_ref_invalid")
            continue
        try:
            receipt = _captured_json(captured, f"receipts/{receipt_ref}")
        except RefreshCandidateError:
            errors.append(f"successful_scan_receipt_missing:{receipt_ref}")
            continue
        if (
            not isinstance(receipt, dict)
            or receipt.get("server_slug") != result.get("server_slug")
            or receipt.get("scan_id") != result.get("scan_id")
        ):
            errors.append(f"successful_scan_receipt_mismatch:{receipt_ref}")
            continue
        receipt_schema_valid = (
            set(receipt) == _RECEIPT_KEYS_V1 and receipt.get("format_version") == 1
            if legacy_schema
            else set(receipt) == _RECEIPT_KEYS
            and receipt.get("format_version") == 2
            and _receipt_digest_valid(receipt)
        )
        if (
            not receipt_schema_valid
            or receipt.get("approval") != {"approval_ref": None}
            or not isinstance(receipt.get("caveats"), list)
            or not all(isinstance(item, str) for item in receipt["caveats"])
            or not _receipt_metadata_shape_valid(receipt)
        ):
            errors.append(f"successful_scan_receipt_schema_invalid:{receipt_ref}")
        if not legacy_schema:
            receipt_server = receipt.get("server")
            catalog_row = catalog_by_slug.get(result.get("server_slug"))
            reviewed_server_for_binding: Server | None = None
            if isinstance(catalog_row, dict) and isinstance(receipt_server, dict):
                try:
                    reviewed_server_for_binding = _reviewed_server_from_seed(
                        catalog_row,
                        added_at=datetime.fromisoformat(
                            str(receipt_server.get("added_at")).replace("Z", "+00:00")
                        ),
                    )
                except (RefreshCandidateError, TypeError, ValueError):
                    reviewed_server_for_binding = None
            expected_execution_binding = None
            if (
                reviewed_server_for_binding is not None
                and isinstance(qualification_manifest, dict)
                and isinstance(sandbox_manifest, dict)
                and isinstance(sandbox_manifest.get("default_image"), str)
            ):
                requested_image_for_binding = (
                    reviewed_server_for_binding.source.sandbox_image
                    or sandbox_manifest["default_image"]
                )
                try:
                    expected_execution_binding = _candidate_execution_binding(
                        reviewed_server_for_binding,
                        qualification=qualification_manifest,
                        sandbox_evidence=sandbox_manifest,
                        default_image=sandbox_manifest["default_image"],
                        expected_image=(
                            None
                            if candidate_state == "fixture"
                            else reviewed_profile_bindings.get(requested_image_for_binding)
                        ),
                        fixture_mode=candidate_state == "fixture",
                        cleanup_evidence=(
                            "NOT_APPLICABLE"
                            if candidate_state == "fixture"
                            else "CONTAINER_ABSENCE_VERIFIED"
                        ),
                        runtime_readback=(
                            receipt.get("execution_binding", {})
                            .get("sandbox", {})
                            .get("runtime_readback")
                            if isinstance(receipt.get("execution_binding"), dict)
                            else None
                        ),
                    )
                except RefreshCandidateError:
                    expected_execution_binding = None
            if receipt.get("execution_binding") != expected_execution_binding:
                errors.append(f"successful_scan_execution_binding_invalid:{receipt_ref}")
        if candidate_db is None or not _fresh_result_matches_persisted_scan(
            candidate_db,
            result=result,
            receipt=receipt,
        ):
            errors.append(f"fresh_scan_binding_mismatch:{receipt_ref}")
        slug = result.get("server_slug")
        if candidate_db is not None and isinstance(slug, str):
            try:
                if result.get("drift") != _persisted_drift_payload(
                    candidate_db,
                    slug=slug,
                ):
                    errors.append(f"fresh_scan_drift_mismatch:{receipt_ref}")
            except RefreshCandidateError:
                errors.append(f"fresh_scan_drift_unavailable:{receipt_ref}")
        if candidate_state == "complete":
            scanner = receipt.get("scanner")
            sandbox = receipt.get("sandbox")
            receipt_server = receipt.get("server")
            reviewed_server: Server | None = None
            catalog_row = catalog_by_slug.get(result.get("server_slug"))
            if isinstance(catalog_row, dict) and isinstance(receipt_server, dict):
                try:
                    reviewed_server = _reviewed_server_from_seed(
                        catalog_row,
                        added_at=datetime.fromisoformat(
                            str(receipt_server.get("added_at")).replace("Z", "+00:00")
                        ),
                    )
                except (RefreshCandidateError, TypeError, ValueError):
                    reviewed_server = None
            catalog_bound = bool(
                reviewed_server is not None
                and isinstance(receipt_server, dict)
                and receipt_server == reviewed_server.model_dump(mode="json")
            )
            remote_without_command = bool(
                reviewed_server is not None and not _requires_local_sandbox(reviewed_server)
            )
            receipt_image = (
                sandbox.get("MCP_TRUST_SANDBOX_IMAGE") if isinstance(sandbox, dict) else None
            )
            reviewed_image = (
                reviewed_server.source.sandbox_image if reviewed_server is not None else None
            )
            requested_image = reviewed_image or (
                sandbox_manifest.get("default_image")
                if isinstance(sandbox_manifest, dict)
                else None
            )
            expected_image_digest = reviewed_profile_bindings.get(requested_image)
            local_image_valid = bool(
                isinstance(receipt_image, str) and receipt_image == expected_image_digest
            )
            sandbox_valid = bool(
                catalog_bound
                and isinstance(sandbox, dict)
                and (
                    (
                        sandbox.get("mode") == "not_applicable"
                        and sandbox.get("reason") == "remote_endpoint_no_local_process"
                    )
                    if remote_without_command
                    else (
                        sandbox.get("MCP_TRUST_SANDBOX") == "docker"
                        and sandbox.get("MCP_TRUST_SANDBOX_NETWORK") == "none"
                        and local_image_valid
                    )
                )
            )
            if (
                result.get("engine_name") != "mcpaudit"
                or not isinstance(scanner, dict)
                or scanner.get("engine_name") != "mcpaudit"
                or not sandbox_valid
            ):
                errors.append(f"publishable_scan_provenance_invalid:{receipt_ref}")
            elif not remote_without_command and isinstance(requested_image, str):
                verified_local_profile_images.add(requested_image)
    if (
        candidate_state != "fixture"
        and expected_policy_blocked is not None
        and expected_policy_scannable is not None
    ):
        declared_blocked = {
            result.get("server_slug")
            for result in results
            if isinstance(result, dict) and result.get("state") == "blocked-policy"
        }
        nonblocked = {
            result.get("server_slug")
            for result in results
            if isinstance(result, dict) and result.get("state") != "blocked-policy"
        }
        if declared_blocked != expected_policy_blocked or nonblocked != expected_policy_scannable:
            errors.append("execution_policy_result_boundary_mismatch")
    excluded = {
        result.get("server_slug")
        for result in results
        if isinstance(result, dict) and result.get("state") != "fresh"
    }
    snapshot_servers = (
        snapshot_payload.get("servers") if isinstance(snapshot_payload, dict) else None
    )
    if (
        not isinstance(snapshot_payload, dict)
        or set(snapshot_payload)
        != {
            "schema_version",
            "generated_at",
            "generated_from_scan_at",
            "server_count",
            "servers",
        }
        or not isinstance(snapshot_servers, list)
        or len(snapshot_servers) > _MAX_CATALOG_ROWS
    ):
        errors.append("static_snapshot_invalid")
        snapshot_servers = []
    exposed = {server.get("slug") for server in snapshot_servers if isinstance(server, dict)}
    if excluded & exposed:
        errors.append("failed_or_masked_grade_exposed")
    fresh_slugs = {
        result.get("server_slug")
        for result in results
        if isinstance(result, dict) and result.get("state") == "fresh"
    }
    if candidate_state != "fixture" and exposed != fresh_slugs:
        errors.append("static_snapshot_coverage_mismatch")
    if age_hours is not None and created_at is not None and candidate_db is not None:
        try:
            from mcp_trust.catalog.snapshot import build_snapshot_from_connection

            expected_snapshot = build_snapshot_from_connection(
                candidate_db,
                excluded_slugs=frozenset(str(slug) for slug in excluded if isinstance(slug, str)),
                masked_slugs=frozenset(
                    str(result.get("server_slug"))
                    for result in results
                    if isinstance(result, dict) and result.get("state") == "masked"
                ),
                verified_scan_modes={
                    str(result["scan_id"]): "mcpaudit-local-network-off"
                    for result in results
                    if candidate_state != "fixture"
                    and isinstance(result, dict)
                    and result.get("state") == "fresh"
                    and isinstance(result.get("scan_id"), str)
                    and _catalog_row_requires_local_sandbox(
                        catalog_by_slug.get(result.get("server_slug"))
                    )
                },
                now=created_at,
            )
            if legacy_schema:
                for expected_server in expected_snapshot.get("servers", []):
                    if isinstance(expected_server, dict):
                        expected_server.pop("stale_after", None)
            if snapshot_payload != expected_snapshot:
                errors.append("static_snapshot_scan_binding_mismatch")
        except (
            MemoryError,
            RecursionError,
            sqlite3.Error,
            TypeError,
            ValueError,
        ):
            errors.append("static_snapshot_scan_binding_unavailable")
    elif candidate_db is None:
        errors.append("static_snapshot_scan_binding_unavailable")
    for server in snapshot_servers:
        if isinstance(server, dict) and not isinstance(server.get("scan_age_days"), (int, float)):
            errors.append("scan_age_missing")

    validated_scan_counts: dict[str, int] | None = None
    scan_counts = manifest.get("scan_counts")
    if (
        not isinstance(scan_counts, dict)
        or set(scan_counts)
        != (
            {"total", "fresh", "masked", "failed"}
            if legacy_schema
            else {"total", "fresh", "masked", "blocked", "failed"}
        )
        or not all(type(value) is int and value >= 0 for value in scan_counts.values())
    ):
        errors.append("scan_counts_invalid")
    else:
        expected_counts = {
            "total": len(results),
            "fresh": sum(
                isinstance(result, dict) and result.get("state") == "fresh" for result in results
            ),
            "masked": sum(
                isinstance(result, dict) and result.get("state") == "masked" for result in results
            ),
            **(
                {}
                if legacy_schema
                else {
                    "blocked": sum(
                        isinstance(result, dict) and result.get("state") == "blocked-policy"
                        for result in results
                    )
                }
            ),
            "failed": sum(
                isinstance(result, dict)
                and result.get("state")
                not in (
                    {"fresh", "masked"} if legacy_schema else {"fresh", "masked", "blocked-policy"}
                )
                for result in results
            ),
        }
        if scan_counts != expected_counts:
            errors.append("scan_counts_mismatch")
        else:
            validated_scan_counts = expected_counts
    expected_engine_versions = sorted(
        {
            str(result["engine_version"])
            for result in results
            if isinstance(result, dict) and isinstance(result.get("engine_version"), str)
        }
    )
    if manifest.get("engine_versions") != expected_engine_versions:
        errors.append("engine_versions_mismatch")
    if candidate_state == "complete":
        controlled_results = [
            result
            for result in results
            if isinstance(result, dict)
            and result.get("state") in {"fresh", "masked", "blocked-policy"}
        ]
        if (
            scan_mode != expected_real_scan_mode
            or len(controlled_results) != len(results)
            or manifest.get("publication_allowed") is not True
            or len(snapshot_servers)
            != sum(
                isinstance(result, dict) and result.get("state") == "fresh" for result in results
            )
        ):
            errors.append("complete_candidate_semantics_invalid")
        if verified_local_profile_images != set(reviewed_profile_bindings):
            errors.append("sandbox_profile_coverage_mismatch")
    else:
        if manifest.get("publication_allowed") is not False:
            errors.append("noncomplete_candidate_claims_publication")
        expected_noncomplete_mode = (
            "deterministic-fixture" if candidate_state == "fixture" else expected_real_scan_mode
        )
        if scan_mode != expected_noncomplete_mode:
            errors.append("candidate_scan_mode_invalid")
    authority = manifest.get("authority")
    expected_authority = {
        "candidate_creation": True,
        "publication": False,
        "deployment": False,
        "schedule_change": False,
    }
    if (
        not isinstance(authority, dict)
        or not all(type(value) is bool for value in authority.values())
        or authority != expected_authority
    ):
        errors.append("candidate_authority_invalid")

    masked_slugs = sorted(
        str(result.get("server_slug"))
        for result in results
        if isinstance(result, dict) and result.get("state") == "masked"
    )
    successful_masked_slugs = sorted(
        str(result.get("server_slug"))
        for result in successful_results
        if result.get("server_slug") in declared_masked_slugs
    )
    if masked_slugs != successful_masked_slugs:
        errors.append("masked_result_authorization_mismatch")
    if masked_slugs:
        try:
            if candidate_db is None:
                raise sqlite3.DatabaseError("candidate database is unavailable")
            placeholders = ",".join("?" for _ in masked_slugs)
            leaked_count = candidate_db.execute(
                f"SELECT COUNT(*) FROM scans WHERE server_slug IN ({placeholders})",
                masked_slugs,
            ).fetchone()[0]
            if leaked_count:
                errors.append("masked_scan_database_history_exposed")
        except (MemoryError, sqlite3.Error, TypeError):
            errors.append("candidate_database_unreadable")

    if candidate_db is not None:
        candidate_db.close()
    try:
        final_capture = _capture_candidate(candidate)
        if (
            final_capture.files != captured.files
            or final_capture.file_metadata != captured.file_metadata
            or final_capture.tree_metadata != captured.tree_metadata
            or final_capture.root_metadata != captured.root_metadata
            or final_capture.errors != captured.errors
        ):
            errors.append("candidate_changed_during_verification")
    except _CandidateSnapshotError:
        errors.append("candidate_changed_during_verification")

    structural_valid = not errors
    stale = candidate_time_stale
    publication_ready = bool(
        structural_valid
        and not stale
        and manifest.get("schema") == CANDIDATE_SCHEMA
        and candidate_state == "complete"
        and manifest.get("publication_allowed") is True
        and reviewed_inputs_bound
    )
    verification: dict[str, object] = {
        "structural_valid": structural_valid,
        "state": "invalid" if errors else "stale" if stale else str(candidate_state),
        "candidate_state": (
            candidate_state
            if isinstance(candidate_state, str) and candidate_state in _CANDIDATE_STATES
            else None
        ),
        "publication_ready": publication_ready,
        "manifest_sha256": actual_manifest_digest,
        "age_hours": round(age_hours, 6) if age_hours is not None else None,
        "scan_counts": validated_scan_counts,
        "reviewed_inputs_bound": reviewed_inputs_bound,
        "schema": manifest.get("schema"),
        "publication_eligible_schema": manifest.get("schema") == CANDIDATE_SCHEMA,
        "errors": sorted(set(errors)),
    }
    if _include_verified_masked_slugs:
        verification["_verified_masked_scan_slugs"] = masked_slugs
    if _include_candidate_snapshot:
        verification["_candidate_snapshot"] = captured
    if _include_artifact_manifest:
        verification["_artifact_manifest"] = artifacts
    return verification


def verified_masked_scan_slugs(
    candidate: Path,
    *,
    seed_path: Path,
    masked_path: Path,
    repo_root: Path,
    now: datetime | None = None,
    _source_binding_provider: Callable[[Path], dict[str, Any]] | None = None,
    _qualification_revalidator: Callable[..., None] | None = None,
) -> frozenset[str]:
    """Return proof-backed masked slugs from one publishable candidate.

    The site projection may consume only a complete, current candidate whose
    immutable artifact manifest and reviewed catalog/masking inputs have passed
    the full refresh verifier. The returned slugs carry one narrow claim:
    a scan succeeded. They intentionally carry no grade, score, or findings.
    """
    verification = verify_refresh_candidate(
        candidate,
        now=now,
        expected_seed_path=seed_path,
        expected_masked_path=masked_path,
        repo_root=repo_root,
        _source_binding_provider=_source_binding_provider,
        _qualification_revalidator=_qualification_revalidator,
        _include_verified_masked_slugs=True,
    )
    if not verification["publication_ready"]:
        errors = verification.get("errors")
        detail = ",".join(str(error) for error in errors) if isinstance(errors, list) else ""
        raise RefreshCandidateError(
            "site projection requires a complete, current, publishable candidate"
            + (f": {detail}" if detail else "")
        )

    verified_slugs = verification.get("_verified_masked_scan_slugs")
    if not isinstance(verified_slugs, list) or not all(
        isinstance(slug, str) for slug in verified_slugs
    ):
        raise RefreshCandidateError("verified candidate scan results are unavailable")
    slugs = frozenset(verified_slugs)
    scan_counts = verification.get("scan_counts")
    expected_count = scan_counts.get("masked") if isinstance(scan_counts, dict) else None
    if expected_count != len(slugs):
        raise RefreshCandidateError("verified candidate masked proof coverage changed")
    return slugs


def approve_refresh_candidate(
    *,
    candidate: Path,
    approval_path: Path,
    actor: str,
    reason: str,
    publication_target: Path,
    confirmation_digest: str,
    seed_path: Path,
    masked_path: Path,
    repo_root: Path,
    now: datetime | None = None,
    ttl_hours: int = 4,
    _source_binding_provider: Callable[[Path], dict[str, Any]] | None = None,
    _qualification_revalidator: Callable[..., None] | None = None,
) -> Path:
    """Create a short-lived approval bound to one verified candidate and target."""
    fixed_now = now or datetime.now(tz=UTC)
    if type(ttl_hours) is not int or not 0 < ttl_hours <= MAX_APPROVAL_TTL_HOURS:
        raise RefreshCandidateError("approval lifetime exceeds the bounded contract")
    reviewed = _reviewed_inputs(seed_path, masked_path)
    verification = verify_refresh_candidate(
        candidate,
        now=fixed_now,
        expected_seed_path=seed_path,
        expected_masked_path=masked_path,
        repo_root=repo_root,
        _captured_reviewed_inputs=reviewed,
        _source_binding_provider=_source_binding_provider,
        _qualification_revalidator=_qualification_revalidator,
    )
    if not verification["publication_ready"]:
        raise RefreshCandidateError("candidate is not complete, current, and publishable")
    digest = verification["manifest_sha256"]
    if confirmation_digest != digest:
        raise RefreshCandidateError("approval confirmation digest does not match candidate")
    if not actor.strip() or not reason.strip():
        raise RefreshCandidateError("approval actor and reason are required")
    if approval_path.exists():
        raise RefreshCandidateError(f"approval already exists: {approval_path}")
    approval_path.parent.mkdir(parents=True, exist_ok=True)
    _write_private(
        approval_path,
        {
            "schema": APPROVAL_SCHEMA,
            "candidate_manifest_sha256": digest,
            "approved_at": fixed_now.isoformat(),
            "expires_at": (fixed_now + timedelta(hours=ttl_hours)).isoformat(),
            "actor": actor,
            "reason": reason,
            "publication_target": str(publication_target.resolve()),
            "reviewed_seed_sha256": reviewed.seed_sha256,
            "reviewed_masked_sha256": reviewed.masked_sha256,
            "deployment_authority": False,
        },
    )
    os.chmod(approval_path, 0o400)
    return approval_path


def publish_refresh_candidate(
    *,
    candidate: Path,
    approval_path: Path | None,
    destination_parent: Path,
    seed_path: Path,
    masked_path: Path,
    repo_root: Path,
    now: datetime | None = None,
    _source_binding_provider: Callable[[Path], dict[str, Any]] | None = None,
    _qualification_revalidator: Callable[..., None] | None = None,
) -> Path:
    """Atomically stage an approved candidate locally; never deploy it."""
    if approval_path is None:
        raise RefreshCandidateError("publication approval is required")
    fixed_now = now or datetime.now(tz=UTC)
    reviewed = _reviewed_inputs(seed_path, masked_path)
    verification = verify_refresh_candidate(
        candidate,
        now=fixed_now,
        expected_seed_path=seed_path,
        expected_masked_path=masked_path,
        repo_root=repo_root,
        _captured_reviewed_inputs=reviewed,
        _source_binding_provider=_source_binding_provider,
        _qualification_revalidator=_qualification_revalidator,
        _include_candidate_snapshot=True,
    )
    if not verification["publication_ready"]:
        raise RefreshCandidateError("candidate failed immediate publication verification")
    candidate_snapshot = verification.get("_candidate_snapshot")
    if not isinstance(candidate_snapshot, _CandidateSnapshot):
        raise RefreshCandidateError("verified candidate snapshot is unavailable")
    approval, approval_digest = _load_read_only_json_with_digest(approval_path)
    if (
        not isinstance(approval, dict)
        or set(approval) != _APPROVAL_KEYS
        or approval.get("schema") != APPROVAL_SCHEMA
        or not isinstance(approval.get("candidate_manifest_sha256"), str)
        or _SHA256_TEXT.fullmatch(approval["candidate_manifest_sha256"]) is None
        or not isinstance(approval.get("reviewed_seed_sha256"), str)
        or _SHA256_TEXT.fullmatch(approval["reviewed_seed_sha256"]) is None
        or not isinstance(approval.get("reviewed_masked_sha256"), str)
        or _SHA256_TEXT.fullmatch(approval["reviewed_masked_sha256"]) is None
        or not isinstance(approval.get("actor"), str)
        or not approval["actor"].strip()
        or not isinstance(approval.get("reason"), str)
        or not approval["reason"].strip()
        or not isinstance(approval.get("publication_target"), str)
        or approval.get("deployment_authority") is not False
    ):
        raise RefreshCandidateError("publication approval is invalid")
    try:
        approved_at = _parse_utc_datetime(approval["approved_at"])
        expires = _parse_utc_datetime(approval["expires_at"])
    except (KeyError, OverflowError, ValueError, TypeError) as exc:
        raise RefreshCandidateError("publication approval expiry is invalid") from exc
    approval_lifetime = expires - approved_at
    if (
        approved_at > fixed_now.astimezone(UTC)
        or approval_lifetime <= timedelta(0)
        or approval_lifetime > timedelta(hours=MAX_APPROVAL_TTL_HOURS)
    ):
        raise RefreshCandidateError("publication approval lifetime is invalid")
    if expires <= fixed_now.astimezone(UTC):
        raise RefreshCandidateError("publication approval is expired")
    if approval.get("candidate_manifest_sha256") != verification["manifest_sha256"]:
        raise RefreshCandidateError("publication approval is bound to another candidate")
    if approval.get("publication_target") != str(destination_parent.resolve()):
        raise RefreshCandidateError("publication approval is bound to another target")
    if (
        approval.get("reviewed_seed_sha256") != reviewed.seed_sha256
        or approval.get("reviewed_masked_sha256") != reviewed.masked_sha256
    ):
        raise RefreshCandidateError("publication approval is bound to other reviewed inputs")
    destination_parent.mkdir(parents=True, exist_ok=True)
    final = destination_parent / candidate.name
    if final.exists():
        raise RefreshCandidateError(f"publication already exists: {final}")
    temporary = Path(tempfile.mkdtemp(prefix=f".{candidate.name}.publish-", dir=destination_parent))
    published = False
    try:
        _materialize_candidate_snapshot(
            candidate_snapshot,
            temporary / "candidate",
        )
        copied_verification = verify_refresh_candidate(
            temporary / "candidate",
            now=fixed_now,
            expected_seed_path=seed_path,
            expected_masked_path=masked_path,
            repo_root=repo_root,
            _captured_reviewed_inputs=reviewed,
            _source_binding_provider=_source_binding_provider,
            _qualification_revalidator=_qualification_revalidator,
        )
        if (
            not copied_verification["publication_ready"]
            or copied_verification["manifest_sha256"] != verification["manifest_sha256"]
        ):
            raise RefreshCandidateError("copied candidate failed immediate publication readback")
        _write_private(
            temporary / "PUBLICATION.json",
            {
                "schema": PUBLICATION_SCHEMA,
                "published_at": fixed_now.isoformat(),
                "candidate_manifest_sha256": verification["manifest_sha256"],
                "approval_sha256": approval_digest,
                "deployment_performed": False,
            },
        )
        _make_files_read_only(temporary)
        os.replace(temporary, final)
        published = True
        _make_read_only(final)
    finally:
        if not published:
            shutil.rmtree(temporary, ignore_errors=True)
    return final
