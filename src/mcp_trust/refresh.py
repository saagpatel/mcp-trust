"""Manual, approval-gated refresh candidates with no deployment authority."""

from __future__ import annotations

import hashlib
import importlib.util
import json
import math
import os
import re
import shutil
import sqlite3
import stat
import subprocess
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
from mcp_trust.core.models import ScanRecord, Server, SourceKind
from mcp_trust.engine.base import EngineResult
from mcp_trust.engine.mcpaudit import MCPAuditEngine
from mcp_trust.engine.sandbox import DockerSandbox, normalize_local_docker_host
from mcp_trust.receipts import build_scan_receipt
from mcp_trust.store.db import connect, init_schema
from mcp_trust.store.repository import ScanRepository, ServerRepository

CANDIDATE_SCHEMA = "RefreshCandidateV1"
APPROVAL_SCHEMA = "RefreshCandidateApprovalV1"
PUBLICATION_SCHEMA = "RefreshCandidatePublicationV1"
MANIFEST_NAME = "MANIFEST.json"
MANIFEST_DIGEST_NAME = "MANIFEST.sha256"
DEFAULT_MAX_AGE_HOURS = 24
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
_MANIFEST_KEYS = frozenset(
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
        "scan_counts",
        "engine_versions",
        "artifacts",
        "authority",
    }
)
_RECEIPT_KEYS = frozenset(
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
_FIXTURE_RECEIPT_SANDBOX_KEYS = _LOCAL_RECEIPT_SANDBOX_KEYS - {
    "MCP_TRUST_SANDBOX_IMAGE"
}
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
_SUCCESS_RESULT_KEYS = frozenset(
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
_SANDBOX_PROFILE_KEYS = frozenset(
    {
        "kind",
        "image",
        "network",
        "read_only_root",
        "capabilities",
        "no_new_privileges",
        "memory",
        "pids_limit",
        "cpus",
        "user",
        "tmpfs",
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
                unicodedata.category(character) in {"Cc", "Cf"}
                for character in value
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
        if len(
            {
                _stat_signature(before),
                _stat_signature(opened),
                _stat_signature(after_read),
                _stat_signature(after_path),
            }
        ) != 1:
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
                    if (
                        opened.st_dev != before.st_dev
                        or opened.st_ino != before.st_ino
                    ):
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
            if len(
                {
                    signature,
                    _stat_signature(opened),
                    _stat_signature(after_read),
                    _stat_signature(after_path),
                }
            ) != 1:
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
        if (
            before.st_uid != os.geteuid()
            or before.st_mode & 0o277
            or before.st_nlink != 1
        ):
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
        signatures = {
            _stat_signature(item) for item in (before, opened, after_read, after_path)
        }
        if len(signatures) != 1:
            raise RefreshCandidateError(
                f"immutable JSON artifact changed during read: {path.name}"
            )
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
    if (
        not isinstance(catalog_payload, list)
        or len(catalog_payload) > _MAX_CATALOG_ROWS
    ):
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
    docker_host: str | None = None,
) -> dict[str, object]:
    sandbox = DockerSandbox(image=image, network="none", host=docker_host)
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
        "network": "none",
        "read_only_root": True,
        "capabilities": "dropped-all",
        "no_new_privileges": True,
        "memory": sandbox.memory,
        "pids_limit": sandbox.pids_limit,
        "cpus": sandbox.cpus,
        "user": sandbox.user,
        "tmpfs": sandbox.workdir,
    }


def _requires_local_sandbox(server: Server) -> bool:
    return not (server.source.kind == SourceKind.REMOTE and server.source.command is None)


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
    runner: Callable[..., subprocess.CompletedProcess[str]] = subprocess.run,
) -> dict[str, object]:
    """Prove the network-off Docker controls and every pinned image locally."""
    local_servers = [server for server in servers if _requires_local_sandbox(server)]
    images = sorted(
        {server.source.sandbox_image or default_image for server in local_servers}
        | ({default_image} if local_servers else set())
    )
    profiles: list[dict[str, object]] = []
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
            profiles.append(_sandbox_profile(image, docker_host=docker_host))
    if importlib.util.find_spec("mcp_audit") is None:
        raise RefreshCandidateError("required MCPAudit engine package is unavailable")
    evidence: dict[str, object] = {
        "docker_daemon": "available" if local_servers else "not_required",
        "profiles": profiles,
        "remote_transport_count": len(servers) - len(local_servers),
    }
    if local_servers:
        # Private execution binding: removed before the candidate manifest is
        # written, then supplied to every DockerSandbox through a dedicated
        # mcp-trust variable. This is authority, not a public trust claim.
        evidence["_execution_docker_host"] = docker_host
    return evidence


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


def _scan_receipt_payload(server: Server, scan: ScanRecord) -> dict[str, Any]:
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
    return payload


def _write_receipt(server: Server, scan: ScanRecord, receipts_dir: Path) -> str:
    name = f"{scan.server_slug}-{scan.id}.json"
    payload = _scan_receipt_payload(server, scan)
    _write_private(receipts_dir / name, payload)
    return name


def _write_masked_scan_proof(
    server: Server,
    scan: ScanRecord,
    proofs_dir: Path,
) -> str:
    """Retain scan-success provenance without retaining masked grade evidence."""
    receipt = _scan_receipt_payload(server, scan)
    name = f"{scan.server_slug}-{scan.id}.json"
    proof = {
        "format_version": 1,
        "proof_type": "masked_scan_success",
        "outcome": "scan_succeeded",
        "server_slug": scan.server_slug,
        "scan_id": scan.id,
        "server": receipt["server"],
        "scanned_at": scan.scanned_at.isoformat(),
        "scanner": receipt["scanner"],
        "sandbox": receipt["sandbox"],
        "evidence_present": scan.evidence is not None,
    }
    _write_private(proofs_dir / name, proof)
    return name


def _validate_receipt(
    path: Path,
    *,
    server: Server,
    scan: ScanRecord,
    expected_image: str | None,
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
        receipt.get("server_slug") == server.slug
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
            caveat
            for caveat in expected_caveats
            if not caveat.startswith("Network-off sandboxing")
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
        max(0.0, (now.astimezone(UTC) - scanned_at.astimezone(UTC)).total_seconds() / 86400),
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
) -> Path:
    """Create one immutable candidate; never mutate canonical/public outputs."""
    fixed_now = now or datetime.now(tz=UTC)
    if fixed_now.tzinfo is None:
        fixed_now = fixed_now.replace(tzinfo=UTC)
    fixture_mode = scanner is not None
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
    if fixture_mode:
        sandbox_evidence = {
            "mode": "deterministic-fixture",
            "profiles": [_sandbox_profile(default_image)],
        }
    else:
        sandbox_evidence = preflight_real_refresh(servers, default_image=default_image)
        execution_host = sandbox_evidence.pop("_execution_docker_host", None)
        if execution_host is not None:
            try:
                docker_host = normalize_local_docker_host(str(execution_host))
            except ValueError as exc:
                raise RefreshCandidateError(
                    "preflight returned an invalid Docker execution authority"
                ) from exc
        scanner_engine = MCPAuditEngine(timeout=90.0)

        def scan_server(server: Server) -> EngineResult:
            if not _requires_local_sandbox(server):
                with _remote_transport_environment():
                    return scanner_engine.scan(server.source)
            return scanner_engine.scan(server.source)

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
        candidate_db = temporary / "registry.db"
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
        excluded: set[str] = set()
        verified_snapshot_scan_modes: dict[str, str] = {}
        writer = receipt_writer or _write_receipt
        with _scan_environment(default_image, docker_host):
            for server in servers:
                previous = scan_repo.latest(server.slug)
                try:
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
                    expected_image = (
                        server.source.sandbox_image or default_image
                        if _requires_local_sandbox(server)
                        else None
                    )
                    if (
                        not fixture_mode
                        and _requires_local_sandbox(server)
                        and engine_result.sandbox_image != expected_image
                    ):
                        results.append(
                            {
                                "server_slug": server.slug,
                                "state": "unknown-sandbox-evidence",
                                "fresh_grade": None,
                                "expected_sandbox_image": expected_image,
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
                    if masked:
                        receipt_ref = None
                        masked_proof_ref = _write_masked_scan_proof(
                            server,
                            scan,
                            masked_proofs_dir,
                        )
                    elif receipt_writer is None:
                        masked_proof_ref = None
                        receipt_ref = f"{scan.server_slug}-{scan.id}.json"
                        scan = scan.model_copy(update={"report_ref": receipt_ref})
                        _write_receipt(server, scan, receipts_dir)
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
                    if (
                        not fixture_mode
                        and not masked
                        and _requires_local_sandbox(server)
                    ):
                        verified_snapshot_scan_modes[scan.id] = (
                            "mcpaudit-local-network-off"
                        )
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

        complete = all(result["state"] in {"fresh", "masked"} for result in results)
        candidate_state = "fixture" if fixture_mode else "complete" if complete else "partial"
        manifest = {
            "schema": CANDIDATE_SCHEMA,
            "created_at": fixed_now.isoformat(),
            "expires_at": (fixed_now + timedelta(hours=DEFAULT_MAX_AGE_HOURS)).isoformat(),
            "candidate_state": candidate_state,
            "publication_allowed": candidate_state == "complete",
            "scan_mode": (
                "deterministic-fixture"
                if fixture_mode
                else _real_scan_mode(
                    local_count=sum(_requires_local_sandbox(server) for server in servers),
                    total_count=len(servers),
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
            "scan_counts": {
                "total": len(results),
                "fresh": sum(result["state"] == "fresh" for result in results),
                "masked": sum(result["state"] == "masked" for result in results),
                "failed": sum(result["state"] not in {"fresh", "masked"} for result in results),
            },
            "engine_versions": sorted(
                {
                    str(result["engine_version"])
                    for result in results
                    if result.get("engine_version")
                }
            ),
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
        os.replace(temporary, final)
        published = True
        _make_read_only(final)
    finally:
        if not published:
            shutil.rmtree(temporary, ignore_errors=True)

    verified = verify_refresh_candidate(
        final,
        now=fixed_now,
        expected_seed_path=seed_path,
        expected_masked_path=masked_path,
        _captured_reviewed_inputs=reviewed,
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
    _captured_reviewed_inputs: _ReviewedInputs | None = None,
    _include_candidate_snapshot: bool = False,
    _include_verified_masked_slugs: bool = False,
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
    if not isinstance(manifest, dict) or manifest.get("schema") != CANDIDATE_SCHEMA:
        errors.append("manifest_schema_invalid")
        manifest = {}
    elif set(manifest) != _MANIFEST_KEYS:
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
        if content is None or len(content) != artifact.get("bytes") or _sha256_bytes(
            content
        ) != artifact.get("sha256"):
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
    catalog_rows = catalog_payload.get("servers") if isinstance(catalog_payload, dict) else None
    if (
        not isinstance(catalog_payload, dict)
        or set(catalog_payload)
        != {"schema", "seed_sha256", "server_count", "servers"}
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
        if isinstance(result, dict)
        and _safe_artifact_component(result.get("server_slug"))
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
        except (OSError, RefreshCandidateError, TypeError, ValueError):
            errors.append("reviewed_inputs_unavailable")
    candidate_state = manifest.get("candidate_state")
    if (
        not isinstance(candidate_state, str)
        or candidate_state not in _CANDIDATE_STATES
    ):
        errors.append("candidate_state_invalid")
    scan_mode = manifest.get("scan_mode")
    catalog_remote_count = sum(
        isinstance(row, dict)
        and isinstance(row.get("source"), dict)
        and row["source"].get("kind") == "remote"
        and row["source"].get("command") is None
        for row in catalog_rows
    )
    expected_real_scan_mode = _real_scan_mode(
        local_count=len(catalog_rows) - catalog_remote_count,
        total_count=len(catalog_rows),
    )
    sandbox_manifest = manifest.get("sandbox")
    sandbox_profiles = (
        sandbox_manifest.get("profiles") if isinstance(sandbox_manifest, dict) else None
    )
    sandbox_profile_rows = sandbox_profiles if isinstance(sandbox_profiles, list) else []
    reviewed_profile_images = {
        profile.get("image")
        for profile in sandbox_profile_rows
        if isinstance(profile, dict)
        and isinstance(profile.get("image"), str)
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
        and len(reviewed_profile_images) == len(sandbox_profile_rows)
    )
    if candidate_state == "fixture":
        sandbox_manifest_valid = bool(
            isinstance(sandbox_manifest, dict)
            and set(sandbox_manifest) == {"mode", "profiles"}
            and sandbox_manifest.get("mode") == "deterministic-fixture"
            and len(sandbox_profile_rows) == 1
            and profiles_valid
        )
    else:
        sandbox_manifest_valid = bool(
            isinstance(sandbox_manifest, dict)
            and set(sandbox_manifest)
            == {"docker_daemon", "profiles", "remote_transport_count"}
            and sandbox_manifest.get("docker_daemon")
            in ("available", "not_required")
            and type(sandbox_manifest.get("remote_transport_count")) is int
            and int(sandbox_manifest["remote_transport_count"]) >= 0
            and sandbox_manifest.get("remote_transport_count")
            == catalog_remote_count
            and sandbox_manifest.get("docker_daemon")
            == (
                "not_required"
                if catalog_remote_count == len(catalog_rows)
                else "available"
            )
            and profiles_valid
        )
    if not sandbox_manifest_valid:
        errors.append("sandbox_manifest_invalid")
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
            elif (
                scan_age_seconds / 3600 >= max_age_hours
                and not candidate_time_stale
            ):
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
        if not isinstance(result, dict) or result.get("state") not in (
            "fresh",
            "masked",
        ):
            continue
        if not _safe_artifact_component(result.get("server_slug")):
            errors.append("successful_scan_schema_invalid:invalid")
            continue
        if set(result) != _SUCCESS_RESULT_KEYS:
            errors.append(
                f"successful_scan_schema_invalid:"
                f"{_safe_error_label(result.get('server_slug'))}"
            )
        recorded_age = result.get("scan_age_days")
        if (
            type(recorded_age) not in {int, float}
            or not math.isfinite(float(recorded_age))
            or float(recorded_age) < 0
        ):
            errors.append(
                f"scan_age_invalid:{_safe_error_label(result.get('server_slug'))}"
            )
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
            }
            scanner = proof.get("scanner") if isinstance(proof, dict) else None
            sandbox = proof.get("sandbox") if isinstance(proof, dict) else None
            proof_server = proof.get("server") if isinstance(proof, dict) else None
            proof_valid = bool(
                isinstance(proof, dict)
                and set(proof) == proof_keys
                and proof.get("format_version") == 1
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
                    reviewed_server is not None
                    and not _requires_local_sandbox(reviewed_server)
                )
                proof_image = sandbox.get("MCP_TRUST_SANDBOX_IMAGE")
                reviewed_image = (
                    reviewed_server.source.sandbox_image
                    if reviewed_server is not None
                    else None
                )
                local_image_valid = bool(
                    isinstance(proof_image, str)
                    and proof_image in reviewed_profile_images
                    and (reviewed_image is None or proof_image == reviewed_image)
                )
                sandbox_valid = bool(
                    catalog_bound
                    and (
                        (
                            sandbox.get("mode") == "not_applicable"
                            and sandbox.get("reason")
                            == "remote_endpoint_no_local_process"
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
                elif not remote_without_command and isinstance(proof_image, str):
                    verified_local_profile_images.add(proof_image)
            continue
        if (
            result.get("grade_visibility") != "reviewable"
            or result.get("receipt_visibility") != "reviewable"
            or result.get("scan_proof") is not None
            or result.get("scan_proof_visibility") != "not_applicable"
        ):
            errors.append(
                f"fresh_scan_semantics_invalid:"
                f"{_safe_error_label(result.get('server_slug'))}"
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
        if (
            set(receipt) != _RECEIPT_KEYS
            or receipt.get("format_version") != 1
            or receipt.get("approval") != {"approval_ref": None}
            or not isinstance(receipt.get("caveats"), list)
            or not all(isinstance(item, str) for item in receipt["caveats"])
            or not _receipt_metadata_shape_valid(receipt)
        ):
            errors.append(f"successful_scan_receipt_schema_invalid:{receipt_ref}")
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
            local_image_valid = bool(
                isinstance(receipt_image, str)
                and receipt_image in reviewed_profile_images
                and (reviewed_image is None or receipt_image == reviewed_image)
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
            elif not remote_without_command and isinstance(receipt_image, str):
                verified_local_profile_images.add(receipt_image)
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
        or set(scan_counts) != {"total", "fresh", "masked", "failed"}
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
            "failed": len(results) - len(successful_results),
        }
        if scan_counts != expected_counts:
            errors.append("scan_counts_mismatch")
        else:
            validated_scan_counts = expected_counts
    expected_engine_versions = sorted(
        {
            str(result["engine_version"])
            for result in results
            if isinstance(result, dict)
            and isinstance(result.get("engine_version"), str)
        }
    )
    if manifest.get("engine_versions") != expected_engine_versions:
        errors.append("engine_versions_mismatch")
    if candidate_state == "complete":
        if (
            scan_mode != expected_real_scan_mode
            or len(successful_results) != len(results)
            or manifest.get("publication_allowed") is not True
            or len(snapshot_servers)
            != sum(
                isinstance(result, dict) and result.get("state") == "fresh" for result in results
            )
        ):
            errors.append("complete_candidate_semantics_invalid")
        if verified_local_profile_images != reviewed_profile_images:
            errors.append("sandbox_profile_coverage_mismatch")
    else:
        if manifest.get("publication_allowed") is not False:
            errors.append("noncomplete_candidate_claims_publication")
        expected_noncomplete_mode = (
            "deterministic-fixture"
            if candidate_state == "fixture"
            else expected_real_scan_mode
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
        and candidate_state == "complete"
        and manifest.get("publication_allowed") is True
        and reviewed_inputs_bound
    )
    verification: dict[str, object] = {
        "structural_valid": structural_valid,
        "state": "invalid" if errors else "stale" if stale else str(candidate_state),
        "candidate_state": (
            candidate_state
            if isinstance(candidate_state, str)
            and candidate_state in _CANDIDATE_STATES
            else None
        ),
        "publication_ready": publication_ready,
        "manifest_sha256": actual_manifest_digest,
        "age_hours": round(age_hours, 6) if age_hours is not None else None,
        "scan_counts": validated_scan_counts,
        "reviewed_inputs_bound": reviewed_inputs_bound,
        "errors": sorted(set(errors)),
    }
    if _include_verified_masked_slugs:
        verification["_verified_masked_scan_slugs"] = masked_slugs
    if _include_candidate_snapshot:
        verification["_candidate_snapshot"] = captured
    return verification


def verified_masked_scan_slugs(
    candidate: Path,
    *,
    seed_path: Path,
    masked_path: Path,
    now: datetime | None = None,
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
    now: datetime | None = None,
    ttl_hours: int = 4,
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
        _captured_reviewed_inputs=reviewed,
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
    now: datetime | None = None,
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
        _captured_reviewed_inputs=reviewed,
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
    if approval.get("reviewed_seed_sha256") != reviewed.seed_sha256 or approval.get(
        "reviewed_masked_sha256"
    ) != reviewed.masked_sha256:
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
            _captured_reviewed_inputs=reviewed,
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
