"""One-target, receipt-only controlled scan artifacts.

This module is intentionally separate from the corpus-wide refresh candidate
builder.  A successful call writes one immutable review receipt; it never
updates the registry, builds a catalog candidate, or grants publication
authority.
"""

from __future__ import annotations

import errno
import hashlib
import ipaddress
import json
import os
import re
import sqlite3
import stat
import sys
import uuid
from collections.abc import Callable, Iterator
from contextlib import contextmanager
from ctypes import CDLL, c_char_p, c_int, c_uint, get_errno
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, Protocol
from urllib.parse import urlsplit

from mcp_trust.core import grading
from mcp_trust.core.models import ScanRecord, Server
from mcp_trust.engine.base import EngineResult, ScanTimeoutError
from mcp_trust.engine.mcpaudit import MCPAuditEngine, launch_spec
from mcp_trust.engine.sandbox import (
    SANDBOX_RUNTIME_READBACK_SCHEMA,
    normalize_local_docker_host,
    sandbox_server_process_digest,
    valid_sandbox_runtime_readback,
)
from mcp_trust.grade_refresh import (
    GradeRefreshError,
    RefreshPolicy,
    canonical_bytes,
    catalog_inventory,
    digest_bytes,
    digest_file,
    load_policy,
    revalidate_ready_preflight_qualifications,
    source_binding,
    validate_ready_preflight_contract,
)
from mcp_trust.refresh import (
    DEFAULT_MAX_AGE_HOURS,
    SCAN_TIMEOUT_SECONDS,
    RefreshCandidateError,
    _candidate_execution_binding,
    _load_json_with_digest,
    _load_read_only_json_with_digest,
    _parse_utc_datetime,
    _required_local_sandbox_images,
    _requires_local_sandbox,
    _reviewed_inputs,
    _reviewed_server_from_seed,
    _safe_artifact_component,
    _scan_environment,
    _scan_receipt_payload,
    _server_identity,
    preflight_real_refresh,
)
from mcp_trust.store.repository import ServerRepository

TARGET_SCAN_SCHEMA = "McpTrustTargetScanArtifactV1"
TARGET_SCAN_CLAIM_CEILING = (
    "One controlled local target scan with receipt-bound runtime evidence only; "
    "not an endorsement, production-safety claim, public-freshness claim, "
    "repeatability claim, publication, deployment, scheduler operation, egress "
    "success, or claim about any other target."
)
TARGET_SCAN_AUTHORITY = {
    "receipt_only": True,
    "registry_write": False,
    "candidate_build": False,
    "publication": False,
    "deployment": False,
    "scheduler_change": False,
}
_EXPECTED_CATALOG_COUNTS = {
    "scannable": 18,
    "blocked": 13,
    "intentionally_masked": 8,
    "unsupported_upstream": 8,
    "credential_dependent": 7,
    "backing_service_dependent": 10,
    "unsafe_to_execute_unsandboxed": 31,
    "missing_image_build_source": 0,
    "unqualified_image_build_source": 0,
}


def _current_catalog_binding(
    *,
    seed_path: Path,
    masked_path: Path,
    policy_path: Path,
) -> tuple[dict[str, int], str]:
    inventory = catalog_inventory(
        seed_path=seed_path,
        masked_path=masked_path,
        policy_path=policy_path,
    )
    counts = inventory.get("counts")
    if counts != _EXPECTED_CATALOG_COUNTS:
        raise RefreshCandidateError("target receipt requires the reviewed V20 catalog counts")
    return dict(counts), digest_bytes(canonical_bytes(inventory))

_ARTIFACT_KEYS = frozenset(
    {
        "schema",
        "observed_at",
        "target_slug",
        "reviewed_inputs",
        "source_binding",
        "registry_read_binding",
        "qualification_binding",
        "scan_receipt",
        "authority",
        "claim_ceiling",
        "artifact_digest",
    }
)
_REVIEWED_KEYS = frozenset(
    {
        "catalog_denominator",
        "scannable_count",
        "blocked_count",
        "seed_sha256",
        "masking_sha256",
        "policy_sha256",
    }
)
_SOURCE_KEYS = frozenset({"repository", "revision", "source_tree_digest"})
_REGISTRY_KEYS = frozenset(
    {
        "pre_sha256",
        "post_sha256",
        "stable_descriptor_identity",
        "sidecars_absent",
    }
)
_QUALIFICATION_KEYS = frozenset(
    {
        "preflight_file_sha256",
        "preflight_receipt_digest",
        "engine_receipt_digest",
        "target_requested_image",
        "target_immutable_image_id",
        "complete_qualified_image_set_digest",
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
        "execution_binding",
        "receipt_digest",
    }
)
_SLUG = re.compile(r"^[a-z0-9]+(?:-[a-z0-9]+)*$")
_SHA256 = re.compile(r"^sha256:[0-9a-f]{64}$")
_HEX_SHA256 = re.compile(r"^[0-9a-f]{64}$")
_REVISION = re.compile(r"^[0-9a-f]{40}$")
_MAX_ARTIFACT_BYTES = 16 * 1024 * 1024
_MAX_PRIVACY_NODES = 100_000
_AT_FDCWD = -100 if sys.platform.startswith("linux") else -2
_RENAME_EXCL = 0x00000004
_RENAME_NOREPLACE = 1
_SIDE_SUFFIXES = ("-wal", "-shm", "-journal")
_PRIVATE_PATH = re.compile(r"/(?:Users|home|tmp|private/tmp|Volumes)/", re.IGNORECASE)
_CREDENTIAL_VALUE = re.compile(r"(?i)(?:token|secret|password|credential|api[_-]?key)\s*[:=]\s*\S+")
_CREDENTIAL_OPTION = re.compile(
    r"(?i)^--?[a-z0-9_-]*(?:token|secret|password|credential|api[_-]?key)"
    r"[a-z0-9_-]*(?:=|$)"
)
_CREDENTIAL_ASSIGNMENT = re.compile(
    r"(?i)(?:^|[\s;,])[a-z0-9_-]*(?:token|secret|password|credential|api[_-]?key)"
    r"[a-z0-9_-]*\s*=\s*\S+"
)
_FORBIDDEN_NORMALIZED_KEYS = frozenset(
    {
        "credentialvalue",
        "environmentvalues",
        "envvalues",
        "password",
        "privatekey",
        "rawchat",
        "secret",
        "token",
    }
)


class _Engine(Protocol):
    def scan(self, source: object) -> EngineResult: ...


@dataclass(frozen=True)
class _RegistryRead:
    descriptor: int
    signature: tuple[int, int, int, int, int, int]
    sha256: str
    server: Server


def _sha256_bytes(content: bytes) -> str:
    return hashlib.sha256(content).hexdigest()


def _stat_signature(value: os.stat_result) -> tuple[int, int, int, int, int, int]:
    return (
        value.st_dev,
        value.st_ino,
        value.st_mode,
        value.st_nlink,
        value.st_size,
        value.st_mtime_ns,
    )


def _read_descriptor(descriptor: int, *, limit: int) -> bytes:
    os.lseek(descriptor, 0, os.SEEK_SET)
    chunks: list[bytes] = []
    total = 0
    while True:
        chunk = os.read(descriptor, min(1024 * 1024, limit + 1 - total))
        if not chunk:
            break
        chunks.append(chunk)
        total += len(chunk)
        if total > limit:
            raise RefreshCandidateError("target scan input exceeds the size limit")
    return b"".join(chunks)


def _require_sidecars_absent(path: Path) -> None:
    for suffix in _SIDE_SUFFIXES:
        sidecar = Path(f"{path}{suffix}")
        try:
            sidecar.lstat()
        except FileNotFoundError:
            continue
        except OSError as exc:
            raise RefreshCandidateError("registry database sidecar state is unreadable") from exc
        raise RefreshCandidateError("registry database has a SQLite sidecar")


@contextmanager
def _open_registry_target(path: Path, slug: str) -> Iterator[_RegistryRead]:
    """Hold a stable owner-private DB descriptor while reading one immutable row."""
    _require_sidecars_absent(path)
    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(path, flags)
    except OSError as exc:
        raise RefreshCandidateError("registry database cannot be opened safely") from exc
    connection: sqlite3.Connection | None = None
    try:
        opened = os.fstat(descriptor)
        try:
            current = os.stat(path, follow_symlinks=False)
        except OSError as exc:
            raise RefreshCandidateError("registry database identity is unavailable") from exc
        if (
            not stat.S_ISREG(opened.st_mode)
            or opened.st_uid != os.geteuid()
            or opened.st_nlink != 1
            or opened.st_mode & 0o077
            or _stat_signature(opened) != _stat_signature(current)
        ):
            raise RefreshCandidateError("registry database ownership or identity is unsafe")
        content = _read_descriptor(descriptor, limit=64 * 1024 * 1024)
        signature = _stat_signature(os.fstat(descriptor))
        if signature != _stat_signature(opened):
            raise RefreshCandidateError("registry database changed during binding")
        database_sha256 = _sha256_bytes(content)
        try:
            connection = sqlite3.connect(
                f"{path.resolve(strict=True).as_uri()}?mode=ro&immutable=1",
                uri=True,
            )
            connection.row_factory = sqlite3.Row
            connection.execute("PRAGMA query_only = ON")
            query_only = connection.execute("PRAGMA query_only").fetchone()
            if query_only is None or query_only[0] != 1:
                raise RefreshCandidateError("registry database query-only mode is unavailable")
            server = ServerRepository(connection).get(slug)
        except (OSError, sqlite3.Error) as exc:
            raise RefreshCandidateError("registry database immutable read failed") from exc
        if server is None:
            raise RefreshCandidateError("target is missing from the registry database")
        yield _RegistryRead(
            descriptor=descriptor,
            signature=signature,
            sha256=database_sha256,
            server=server,
        )
    finally:
        if connection is not None:
            connection.close()
        os.close(descriptor)


def _recheck_registry(path: Path, bound: _RegistryRead, expected_server: Server) -> str:
    _require_sidecars_absent(path)
    try:
        descriptor_stat = os.fstat(bound.descriptor)
        current = os.stat(path, follow_symlinks=False)
    except OSError as exc:
        raise RefreshCandidateError("registry database identity changed") from exc
    if (
        _stat_signature(descriptor_stat) != bound.signature
        or _stat_signature(current) != bound.signature
    ):
        raise RefreshCandidateError("registry database identity changed")
    digest = _sha256_bytes(_read_descriptor(bound.descriptor, limit=64 * 1024 * 1024))
    if digest != bound.sha256:
        raise RefreshCandidateError("registry database content changed")
    try:
        connection = sqlite3.connect(
            f"{path.resolve(strict=True).as_uri()}?mode=ro&immutable=1",
            uri=True,
        )
        connection.row_factory = sqlite3.Row
        connection.execute("PRAGMA query_only = ON")
        reread = ServerRepository(connection).get(expected_server.slug)
    except sqlite3.Error as exc:
        raise RefreshCandidateError("registry database immutable reread failed") from exc
    finally:
        if "connection" in locals():
            connection.close()
    if reread is None or _server_identity(reread) != _server_identity(expected_server):
        raise RefreshCandidateError("registry target changed after the scan")
    return digest


def _source_projection(value: object) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise RefreshCandidateError("source binding is unavailable")
    projection = {
        "repository": value.get("repository"),
        "revision": value.get("revision"),
        "source_tree_digest": value.get("source_tree_digest"),
    }
    if (
        set(projection) != _SOURCE_KEYS
        or not isinstance(projection["repository"], str)
        or not projection["repository"]
        or not isinstance(projection["revision"], str)
        or _REVISION.fullmatch(projection["revision"]) is None
        or not isinstance(projection["source_tree_digest"], str)
        or _SHA256.fullmatch(projection["source_tree_digest"]) is None
        or value.get("worktree_state") != "clean"
    ):
        raise RefreshCandidateError("source binding is not a clean immutable revision")
    return projection


def _target_category(policy: RefreshPolicy, slug: str) -> str:
    categories = (
        (policy.masked, "intentionally-masked"),
        (policy.unsupported, "unsupported"),
        (policy.credential_dependent, "credential-dependent"),
        (policy.backing_service_dependent, "backing-service-dependent"),
        (policy.blocked, "blocked"),
    )
    for values, label in categories:
        if slug in values:
            return label
    return "unknown"


def _select_target(
    slug: object,
    *,
    policy: RefreshPolicy,
    rows: list[dict[str, Any]],
    added_at: datetime,
) -> Server:
    if (
        not isinstance(slug, str)
        or _SLUG.fullmatch(slug) is None
        or not _safe_artifact_component(slug)
    ):
        raise RefreshCandidateError("target slug must be one exact safe kebab-case component")
    if slug not in policy.scannable:
        category = _target_category(policy, slug)
        raise RefreshCandidateError(f"target is not policy-scannable: {category}")
    matches = [row for row in rows if row.get("slug") == slug]
    if len(matches) != 1:
        raise RefreshCandidateError("target does not have one reviewed catalog identity")
    return _reviewed_server_from_seed(matches[0], added_at=added_at)


def _require_current_denominator(policy: RefreshPolicy, rows: list[dict[str, Any]]) -> None:
    if (
        len(rows) != 31
        or policy.raw.get("catalog_denominator") != 31
        or len(policy.scannable) != 18
        or len(policy.blocked) != 13
        or policy.scannable & policy.blocked
        or policy.scannable | policy.blocked != {str(row.get("slug")) for row in rows}
    ):
        raise RefreshCandidateError("target receipt requires the reviewed 31/18/13 boundary")


def _qualification_binding(
    receipt: dict[str, Any],
    *,
    preflight_file_sha256: str,
    seed_sha256: str,
    masked_sha256: str,
    policy_sha256: str,
    expected_images: list[str],
    expected_catalog_counts: dict[str, int],
    expected_catalog_inventory_digest: str,
    expected_boundary: dict[str, object],
    target_requested_image: str,
    live_sandbox: dict[str, object],
    current_source: dict[str, Any],
    now: datetime,
) -> dict[str, str]:
    try:
        validate_ready_preflight_contract(
            receipt,
            expected_image_references=expected_images,
            expected_catalog_counts=expected_catalog_counts,
            expected_catalog_inventory_digest=expected_catalog_inventory_digest,
        )
        observed_at = _parse_utc_datetime(receipt.get("observed_at"))
    except (GradeRefreshError, OverflowError, TypeError, ValueError) as exc:
        raise RefreshCandidateError("qualification receipt is not READY") from exc
    age = (now.astimezone(UTC) - observed_at).total_seconds()
    if age < 0 or age >= DEFAULT_MAX_AGE_HOURS * 3600:
        raise RefreshCandidateError("qualification receipt is stale or future-dated")
    catalog = receipt.get("catalog")
    source = receipt.get("source_binding")
    engine = receipt.get("engine_materialization")
    sandbox = receipt.get("sandbox")
    boundary = catalog.get("execution_boundary") if isinstance(catalog, dict) else None
    counts = catalog.get("counts") if isinstance(catalog, dict) else None
    if (
        source != current_source
        or not isinstance(catalog, dict)
        or catalog.get("seed_digest") != f"sha256:{seed_sha256}"
        or catalog.get("masking_digest") != f"sha256:{masked_sha256}"
        or catalog.get("policy_digest") != policy_sha256
        or catalog.get("denominator") != 31
        or not isinstance(counts, dict)
        or set(counts) != set(_EXPECTED_CATALOG_COUNTS)
        or any(type(value) is not int for value in counts.values())
        or counts != expected_catalog_counts
        or catalog.get("inventory_digest") != expected_catalog_inventory_digest
        or boundary != expected_boundary
        or not isinstance(engine, dict)
        or not isinstance(engine.get("receipt_digest"), str)
        or _SHA256.fullmatch(engine["receipt_digest"]) is None
        or not isinstance(sandbox, dict)
    ):
        raise RefreshCandidateError("qualification receipt input bindings differ")
    rows = sandbox.get("image_bindings")
    if not isinstance(rows, list):
        raise RefreshCandidateError("qualification image bindings are unavailable")
    complete: list[dict[str, str]] = []
    image_ids: dict[str, str] = {}
    sources = catalog.get("image_build_sources")
    if not isinstance(sources, dict):
        raise RefreshCandidateError("qualification image sources are unavailable")

    def reference_key(item: object) -> str:
        return str(item.get("reference")) if isinstance(item, dict) else ""

    for row in sorted(rows, key=reference_key):
        if not isinstance(row, dict):
            raise RefreshCandidateError("qualification image binding is invalid")
        reference = row.get("reference")
        image_id = row.get("image_id")
        source_row = sources.get(reference) if isinstance(reference, str) else None
        qualification = source_row.get("qualification") if isinstance(source_row, dict) else None
        qualification_digest = (
            qualification.get("receipt_digest") if isinstance(qualification, dict) else None
        )
        if (
            not isinstance(reference, str)
            or not isinstance(image_id, str)
            or _SHA256.fullmatch(image_id) is None
            or not isinstance(qualification_digest, str)
            or _SHA256.fullmatch(qualification_digest) is None
        ):
            raise RefreshCandidateError("qualification image lineage is invalid")
        image_ids[reference] = image_id
        complete.append(
            {
                "reference": reference,
                "image_id": image_id,
                "qualification_receipt_digest": qualification_digest,
            }
        )
    if set(image_ids) != set(expected_images) or target_requested_image not in image_ids:
        raise RefreshCandidateError("qualification image set is incomplete")
    profiles = live_sandbox.get("profiles")
    private_bindings = live_sandbox.get("_execution_image_bindings")
    private_host = live_sandbox.get("_execution_docker_host")
    if (
        not isinstance(profiles, list)
        or len(profiles) != 1
        or not isinstance(profiles[0], dict)
        or profiles[0].get("image") != target_requested_image
        or profiles[0].get("image_digest") != image_ids[target_requested_image]
        or private_bindings != {target_requested_image: image_ids[target_requested_image]}
        or not isinstance(private_host, str)
    ):
        raise RefreshCandidateError("live target image differs from the complete qualification")
    try:
        normalize_local_docker_host(private_host)
    except ValueError as exc:
        raise RefreshCandidateError("live target Docker authority is not local Unix") from exc
    claimed = receipt.get("receipt_digest")
    unsigned = dict(receipt)
    unsigned.pop("receipt_digest", None)
    if claimed != digest_bytes(canonical_bytes(unsigned)):
        raise RefreshCandidateError("qualification receipt digest changed")
    return {
        "preflight_file_sha256": f"sha256:{preflight_file_sha256}",
        "preflight_receipt_digest": claimed,
        "engine_receipt_digest": engine["receipt_digest"],
        "target_requested_image": target_requested_image,
        "target_immutable_image_id": image_ids[target_requested_image],
        "complete_qualified_image_set_digest": digest_bytes(canonical_bytes(complete)),
    }


def _private_ip_in_text(value: str) -> bool:
    for candidate in re.findall(r"(?<![0-9a-fA-F:.])(?:[0-9a-fA-F:.]{2,})(?![0-9a-fA-F:.])", value):
        try:
            address = ipaddress.ip_address(candidate.strip("[]"))
        except ValueError:
            continue
        if address.is_private or address.is_loopback or address.is_link_local:
            return True
    return False


def _privacy_validate(value: object) -> None:
    nodes = 0

    def walk(item: object, *, key: str = "") -> None:
        nonlocal nodes
        nodes += 1
        if nodes > _MAX_PRIVACY_NODES:
            raise RefreshCandidateError("target artifact privacy tree is too large")
        normalized = re.sub(r"[^a-z0-9]", "", key.lower())
        if normalized in _FORBIDDEN_NORMALIZED_KEYS or normalized.endswith(
            ("password", "privatekey", "secretvalue", "tokenvalue", "apikeyvalue")
        ):
            raise RefreshCandidateError("target artifact contains a privacy-forbidden field")
        if isinstance(item, dict):
            for child_key, child in item.items():
                if not isinstance(child_key, str):
                    raise RefreshCandidateError("target artifact contains a non-string key")
                walk(child, key=child_key)
        elif isinstance(item, list):
            for child in item:
                walk(child, key=key)
        elif isinstance(item, str):
            if (
                _PRIVATE_PATH.search(item)
                or item.lower().startswith("file:")
                or _CREDENTIAL_VALUE.search(item)
                or _CREDENTIAL_OPTION.search(item)
                or _CREDENTIAL_ASSIGNMENT.search(item)
                or _private_ip_in_text(item)
            ):
                raise RefreshCandidateError("target artifact contains a privacy-forbidden value")
            if "://" in item:
                parsed = urlsplit(item)
                if parsed.username is not None or parsed.password is not None:
                    raise RefreshCandidateError("target artifact URL contains user information")

    walk(value)


def _scan_receipt_valid(receipt: object, *, slug: str, image_id: str) -> bool:
    if not isinstance(receipt, dict) or set(receipt) != _RECEIPT_KEYS:
        return False
    unsigned = dict(receipt)
    claimed = unsigned.pop("receipt_digest", None)
    scanner = receipt.get("scanner")
    approval = receipt.get("approval")
    scan = receipt.get("scan")
    server_payload = receipt.get("server")
    execution = receipt.get("execution_binding")
    sandbox = execution.get("sandbox") if isinstance(execution, dict) else None
    try:
        parsed_scan = ScanRecord.model_validate(scan)
        parsed_server = Server.model_validate(server_payload)
    except Exception:
        return False
    return bool(
        receipt.get("format_version") == 2
        and claimed == digest_bytes(canonical_bytes(unsigned))
        and receipt.get("server_slug") == slug
        and isinstance(scanner, dict)
        and scanner.get("engine_name") == "mcpaudit"
        and scanner.get("scanner_git_ref") is None
        and approval == {"approval_ref": None}
        and isinstance(scan, dict)
        and parsed_server.slug == slug
        and parsed_scan.id == receipt.get("scan_id")
        and parsed_scan.server_slug == slug
        and parsed_scan.grade == grading.grade(parsed_scan.risk)
        and parsed_scan.transparency == grading.transparency(parsed_scan.risk)
        and receipt.get("danger_score") == grading.danger_score(parsed_scan.risk)
        and receipt.get("evidence") == scan.get("evidence")
        and scan.get("server_slug") == slug
        and scan.get("engine_name") == "mcpaudit"
        and scan.get("report_ref") is None
        and scan.get("sandbox_image") == image_id
        and isinstance(execution, dict)
        and execution.get("target_slug") == slug
        and isinstance(sandbox, dict)
        and sandbox.get("immutable_image_id") == image_id
        and sandbox.get("container_cleanup_evidence") == "CONTAINER_ABSENCE_VERIFIED"
    )


def _artifact_unsigned_digest(payload: dict[str, Any]) -> str:
    unsigned = dict(payload)
    unsigned.pop("artifact_digest", None)
    return digest_bytes(canonical_bytes(unsigned))


def _validate_artifact_shape(payload: object) -> dict[str, Any]:
    if not isinstance(payload, dict) or set(payload) != _ARTIFACT_KEYS:
        raise RefreshCandidateError("target scan artifact schema is invalid")
    reviewed = payload.get("reviewed_inputs")
    source = payload.get("source_binding")
    registry = payload.get("registry_read_binding")
    qualification = payload.get("qualification_binding")
    receipt = payload.get("scan_receipt")
    slug = payload.get("target_slug")
    if (
        payload.get("schema") != TARGET_SCAN_SCHEMA
        or not isinstance(slug, str)
        or _SLUG.fullmatch(slug) is None
        or not isinstance(reviewed, dict)
        or set(reviewed) != _REVIEWED_KEYS
        or reviewed.get("catalog_denominator") != 31
        or reviewed.get("scannable_count") != 18
        or reviewed.get("blocked_count") != 13
        or any(
            _SHA256.fullmatch(str(reviewed.get(key))) is None
            for key in ("seed_sha256", "masking_sha256", "policy_sha256")
        )
        or not isinstance(source, dict)
        or set(source) != _SOURCE_KEYS
        or not isinstance(registry, dict)
        or set(registry) != _REGISTRY_KEYS
        or registry.get("pre_sha256") != registry.get("post_sha256")
        or _SHA256.fullmatch(str(registry.get("pre_sha256"))) is None
        or registry.get("stable_descriptor_identity") is not True
        or registry.get("sidecars_absent") is not True
        or not isinstance(qualification, dict)
        or set(qualification) != _QUALIFICATION_KEYS
        or any(
            _SHA256.fullmatch(str(qualification.get(key))) is None
            for key in (
                "preflight_file_sha256",
                "preflight_receipt_digest",
                "engine_receipt_digest",
                "target_immutable_image_id",
                "complete_qualified_image_set_digest",
            )
        )
        or payload.get("authority") != TARGET_SCAN_AUTHORITY
        or payload.get("claim_ceiling") != TARGET_SCAN_CLAIM_CEILING
        or payload.get("artifact_digest") != _artifact_unsigned_digest(payload)
        or not _scan_receipt_valid(
            receipt,
            slug=slug,
            image_id=str(qualification.get("target_immutable_image_id")),
        )
    ):
        raise RefreshCandidateError("target scan artifact bindings are invalid")
    assert isinstance(receipt, dict)
    execution = receipt["execution_binding"]
    scan = receipt["scan"]
    expected_execution_source = {
        "revision": source["revision"],
        "source_tree_digest": source["source_tree_digest"],
        "policy_digest": reviewed["policy_sha256"],
        "preflight_receipt_digest": qualification["preflight_receipt_digest"],
    }
    execution_sandbox = execution.get("sandbox") if isinstance(execution, dict) else None
    if (
        payload.get("observed_at") != scan.get("scanned_at")
        or not isinstance(execution, dict)
        or execution.get("source") != expected_execution_source
        or not isinstance(execution_sandbox, dict)
        or execution_sandbox.get("requested_image") != qualification.get("target_requested_image")
    ):
        raise RefreshCandidateError("target scan artifact duplicated bindings differ")
    _source_projection({**source, "worktree_state": "clean"})
    _privacy_validate(payload)
    return payload


def _rename_no_replace_at(directory_fd: int, source: str, destination: str) -> None:
    try:
        libc = CDLL(None, use_errno=True)
    except OSError as exc:
        raise RefreshCandidateError("atomic no-replace runtime is unavailable") from exc
    source_bytes = os.fsencode(source)
    destination_bytes = os.fsencode(destination)
    if sys.platform == "darwin" and hasattr(libc, "renameatx_np"):
        rename = libc.renameatx_np
        rename.argtypes = [c_int, c_char_p, c_int, c_char_p, c_uint]
        rename.restype = c_int
        result = rename(directory_fd, source_bytes, directory_fd, destination_bytes, _RENAME_EXCL)
    elif sys.platform.startswith("linux") and hasattr(libc, "renameat2"):
        rename = libc.renameat2
        rename.argtypes = [c_int, c_char_p, c_int, c_char_p, c_uint]
        rename.restype = c_int
        result = rename(
            directory_fd,
            source_bytes,
            directory_fd,
            destination_bytes,
            _RENAME_NOREPLACE,
        )
    else:
        raise RefreshCandidateError("atomic no-replace rename is unavailable")
    if result != 0:
        error = get_errno()
        if error == errno.EEXIST:
            raise RefreshCandidateError("target scan artifact already exists")
        raise RefreshCandidateError(f"target scan atomic rename failed: errno {error}")


def _exclusive_finalize(
    output_path: Path,
    payload: dict[str, Any],
    *,
    rename_no_replace: Callable[[int, str, str], None] = _rename_no_replace_at,
) -> None:
    if output_path.name in {"", ".", ".."} or not _safe_artifact_component(output_path.name):
        raise RefreshCandidateError("target scan output name is unsafe")
    parent = output_path.parent
    flags = (
        os.O_RDONLY
        | getattr(os, "O_CLOEXEC", 0)
        | getattr(os, "O_DIRECTORY", 0)
        | getattr(os, "O_NOFOLLOW", 0)
    )
    try:
        parent_fd = os.open(parent, flags)
    except OSError as exc:
        raise RefreshCandidateError("target scan output parent cannot be opened safely") from exc
    temporary: str | None = None
    try:
        parent_stat = os.fstat(parent_fd)
        if (
            not stat.S_ISDIR(parent_stat.st_mode)
            or parent_stat.st_uid != os.geteuid()
            or parent_stat.st_mode & 0o077
        ):
            raise RefreshCandidateError("target scan output parent is not owner-private")
        try:
            os.stat(output_path.name, dir_fd=parent_fd, follow_symlinks=False)
        except FileNotFoundError:
            pass
        else:
            raise RefreshCandidateError("target scan artifact already exists")
        temporary = f".{output_path.name}.tmp-{uuid.uuid4().hex}"
        open_flags = (
            os.O_RDWR
            | os.O_CREAT
            | os.O_EXCL
            | getattr(os, "O_CLOEXEC", 0)
            | getattr(os, "O_NOFOLLOW", 0)
        )
        descriptor = os.open(temporary, open_flags, 0o600, dir_fd=parent_fd)
        try:
            content = canonical_bytes(payload)
            offset = 0
            while offset < len(content):
                written = os.write(descriptor, content[offset:])
                if written <= 0:
                    raise RefreshCandidateError("target scan artifact write was incomplete")
                offset += written
            os.fsync(descriptor)
            written_stat = os.fstat(descriptor)
            reread = _read_descriptor(descriptor, limit=_MAX_ARTIFACT_BYTES)
            _validate_artifact_shape(json.loads(reread))
            os.fchmod(descriptor, 0o400)
            os.fsync(descriptor)
            sealed_stat = os.fstat(descriptor)
        finally:
            os.close(descriptor)
        rename_no_replace(parent_fd, temporary, output_path.name)
        temporary = None
        os.fsync(parent_fd)
        final_fd = os.open(
            output_path.name,
            os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0),
            dir_fd=parent_fd,
        )
        try:
            final_stat = os.fstat(final_fd)
            final_content = _read_descriptor(final_fd, limit=_MAX_ARTIFACT_BYTES)
        finally:
            os.close(final_fd)
        if (
            (sealed_stat.st_dev, sealed_stat.st_ino, sealed_stat.st_size)
            != (final_stat.st_dev, final_stat.st_ino, final_stat.st_size)
            or (written_stat.st_dev, written_stat.st_ino, written_stat.st_size)
            != (final_stat.st_dev, final_stat.st_ino, final_stat.st_size)
            or stat.S_IMODE(final_stat.st_mode) != 0o400
            or final_content != canonical_bytes(payload)
        ):
            raise RefreshCandidateError("target scan artifact final readback failed")
        _validate_artifact_shape(json.loads(final_content))
    finally:
        if temporary is not None:
            try:
                os.unlink(temporary, dir_fd=parent_fd)
            except FileNotFoundError:
                pass
        os.close(parent_fd)


def _validate_output_destination(output_path: Path) -> None:
    """Fail before execution when the eventual exclusive output is already unsafe."""
    if output_path.name in {"", ".", ".."} or not _safe_artifact_component(output_path.name):
        raise RefreshCandidateError("target scan output name is unsafe")
    flags = (
        os.O_RDONLY
        | getattr(os, "O_CLOEXEC", 0)
        | getattr(os, "O_DIRECTORY", 0)
        | getattr(os, "O_NOFOLLOW", 0)
    )
    try:
        descriptor = os.open(output_path.parent, flags)
    except OSError as exc:
        raise RefreshCandidateError("target scan output parent cannot be opened safely") from exc
    try:
        current = os.fstat(descriptor)
        if (
            not stat.S_ISDIR(current.st_mode)
            or current.st_uid != os.geteuid()
            or current.st_mode & 0o077
        ):
            raise RefreshCandidateError("target scan output parent is not owner-private")
        try:
            os.stat(output_path.name, dir_fd=descriptor, follow_symlinks=False)
        except FileNotFoundError:
            return
        raise RefreshCandidateError("target scan artifact already exists")
    finally:
        os.close(descriptor)


@contextmanager
def _receipt_only_environment(default_image: str, docker_host: str) -> Iterator[None]:
    keys = ("MCP_TRUST_SCAN_APPROVAL_REF", "MCP_TRUST_SCANNER_GIT_REF", "MCP_TRUST_RECEIPTS_DIR")
    previous = {key: os.environ.get(key) for key in keys}
    try:
        for key in keys:
            os.environ.pop(key, None)
        with _scan_environment(default_image, docker_host):
            yield
    finally:
        for key, value in previous.items():
            if value is None:
                os.environ.pop(key, None)
            else:
                os.environ[key] = value


def create_target_scan_artifact(
    *,
    slug: str,
    source_db: Path,
    seed_path: Path,
    masked_path: Path,
    policy_path: Path,
    qualification_receipt_path: Path,
    repo_root: Path,
    output_path: Path,
    default_image: str | None = None,
    now: datetime | None = None,
    _source_binding_provider: Callable[[Path], dict[str, Any]] = source_binding,
    _qualification_revalidator: Callable[..., None] = revalidate_ready_preflight_qualifications,
    _preflight_provider: Callable[..., dict[str, object]] = preflight_real_refresh,
    _engine_factory: Callable[[], _Engine] | None = None,
    _finalizer: Callable[[Path, dict[str, Any]], None] = _exclusive_finalize,
) -> Path:
    """Run exactly one policy-scannable target and seal one receipt-only artifact."""
    fixed_now = now or datetime.now(tz=UTC)
    if fixed_now.tzinfo is None:
        fixed_now = fixed_now.replace(tzinfo=UTC)
    initial_source = _source_binding_provider(repo_root)
    source_projection = _source_projection(initial_source)
    reviewed = _reviewed_inputs(seed_path, masked_path)
    try:
        policy = load_policy(policy_path, seed_path, masked_path)
        policy_sha256 = digest_file(policy_path)
        expected_catalog_counts, expected_catalog_inventory_digest = _current_catalog_binding(
            seed_path=seed_path,
            masked_path=masked_path,
            policy_path=policy_path,
        )
    except (GradeRefreshError, OSError) as exc:
        raise RefreshCandidateError("refresh execution policy is invalid") from exc
    _require_current_denominator(policy, reviewed.catalog_rows)
    if default_image is None:
        raw_default = policy.raw.get("default_sandbox_image")
        if not isinstance(raw_default, str) or not raw_default:
            raise RefreshCandidateError("policy default sandbox image is invalid")
        default_image = raw_default
    elif default_image != policy.raw.get("default_sandbox_image"):
        raise RefreshCandidateError("target scan cannot override the reviewed default image")
    target = _select_target(
        slug,
        policy=policy,
        rows=reviewed.catalog_rows,
        added_at=fixed_now,
    )
    _validate_output_destination(output_path)
    preflight, preflight_file_sha256 = _load_json_with_digest(qualification_receipt_path)
    if not isinstance(preflight, dict):
        raise RefreshCandidateError("qualification receipt must be one JSON object")

    with _open_registry_target(source_db, slug) as registry:
        if _server_identity(registry.server) != _server_identity(target):
            raise RefreshCandidateError("registry target differs from the reviewed catalog")
        scannable_servers = [
            _reviewed_server_from_seed(row, added_at=fixed_now)
            for row in reviewed.catalog_rows
            if row.get("slug") in policy.scannable
        ]
        expected_images = _required_local_sandbox_images(
            scannable_servers,
            default_image=default_image,
        )
        if len(expected_images) != 5:
            raise RefreshCandidateError("target receipt requires five qualified images")
        expected_boundary: dict[str, object] = {
            "schema": "McpTrustRefreshExecutionBoundaryV1",
            "scannable": sorted(policy.scannable),
            "blocked": sorted(policy.blocked),
        }
        try:
            validate_ready_preflight_contract(
                preflight,
                expected_image_references=expected_images,
                expected_catalog_counts=expected_catalog_counts,
                expected_catalog_inventory_digest=expected_catalog_inventory_digest,
            )
            _qualification_revalidator(
                preflight,
                repo_root=repo_root,
                expected_image_references=expected_images,
                expected_catalog_counts=expected_catalog_counts,
                expected_catalog_inventory_digest=expected_catalog_inventory_digest,
                now=fixed_now,
            )
        except GradeRefreshError as exc:
            raise RefreshCandidateError(f"qualification receipt {exc}") from exc
        if not _requires_local_sandbox(target):
            raise RefreshCandidateError("target receipt requires a local sandboxed process")
        requested_image = target.source.sandbox_image or default_image
        live = _preflight_provider([target], default_image=requested_image)
        qualification = _qualification_binding(
            preflight,
            preflight_file_sha256=preflight_file_sha256,
            seed_sha256=reviewed.seed_sha256,
            masked_sha256=reviewed.masked_sha256,
            policy_sha256=policy_sha256,
            expected_images=expected_images,
            expected_catalog_counts=expected_catalog_counts,
            expected_catalog_inventory_digest=expected_catalog_inventory_digest,
            expected_boundary=expected_boundary,
            target_requested_image=requested_image,
            live_sandbox=live,
            current_source=initial_source,
            now=fixed_now,
        )
        docker_host = live.get("_execution_docker_host")
        immutable_image_id = qualification["target_immutable_image_id"]
        profiles = live.get("profiles")
        assert isinstance(docker_host, str)
        assert isinstance(profiles, list)
        public_live = {
            key: json.loads(json.dumps(value))
            for key, value in live.items()
            if not key.startswith("_execution_")
        }
        execution_source = target.source.model_copy(update={"sandbox_image": immutable_image_id})
        engine = (_engine_factory or (lambda: MCPAuditEngine(timeout=SCAN_TIMEOUT_SECONDS)))()
        tool_versions = preflight.get("tool_versions")
        expected_engine_version = (
            tool_versions.get("mcp_audits") if isinstance(tool_versions, dict) else None
        )
        if not isinstance(expected_engine_version, str):
            raise RefreshCandidateError("qualified MCPAudit version is unavailable")
        try:
            with _receipt_only_environment(immutable_image_id, docker_host):
                result = engine.scan(execution_source)
                if (
                    result.engine_name != "mcpaudit"
                    or result.engine_version != expected_engine_version
                    or result.evidence is None
                    or result.sandbox_image != immutable_image_id
                    or result.sandbox_cleanup_evidence != "CONTAINER_ABSENCE_VERIFIED"
                ):
                    raise RefreshCandidateError("target scan evidence is incomplete")
                expected_process = sandbox_server_process_digest(*launch_spec(target.source))
                profile = profiles[0]
                if (
                    not isinstance(profile, dict)
                    or not valid_sandbox_runtime_readback(
                        result.sandbox_runtime_readback,
                        expected_image_id=immutable_image_id,
                        expected_profile=profile,
                        expected_dummy_env_names=list(target.source.env_keys),
                        expected_server_process_digest=expected_process,
                    )
                    or result.sandbox_runtime_readback.get("schema")
                    != SANDBOX_RUNTIME_READBACK_SCHEMA
                ):
                    raise RefreshCandidateError("target scan runtime evidence is incomplete")
                scan = ScanRecord(
                    id=uuid.uuid4().hex,
                    server_slug=target.slug,
                    engine_name=result.engine_name,
                    engine_version=result.engine_version,
                    grade=grading.grade(result.risk),
                    transparency=grading.transparency(result.risk),
                    risk=result.risk,
                    findings=result.findings,
                    evidence=result.evidence,
                    scanned_at=fixed_now,
                    sandbox_image=result.sandbox_image,
                    report_ref=None,
                )
                execution_binding = _candidate_execution_binding(
                    target,
                    qualification={
                        "source_revision": source_projection["revision"],
                        "source_tree_digest": source_projection["source_tree_digest"],
                        "policy_digest": policy_sha256,
                        "preflight_receipt_digest": qualification["preflight_receipt_digest"],
                    },
                    sandbox_evidence=public_live,
                    default_image=default_image,
                    expected_image=immutable_image_id,
                    fixture_mode=False,
                    cleanup_evidence=result.sandbox_cleanup_evidence,
                    runtime_readback=result.sandbox_runtime_readback,
                )
                scan_receipt = _scan_receipt_payload(
                    target,
                    scan,
                    execution_binding=execution_binding,
                )
        except ScanTimeoutError as exc:
            raise RefreshCandidateError("target scan timed out; no artifact was written") from exc
        _privacy_validate(scan_receipt)
        if not _scan_receipt_valid(scan_receipt, slug=slug, image_id=immutable_image_id):
            raise RefreshCandidateError("target scan receipt integrity is invalid")

        if _source_binding_provider(repo_root) != initial_source:
            raise RefreshCandidateError("source binding changed after the scan")
        post_reviewed = _reviewed_inputs(seed_path, masked_path)
        try:
            post_policy = load_policy(policy_path, seed_path, masked_path)
            post_policy_sha256 = digest_file(policy_path)
            post_catalog_counts, post_catalog_inventory_digest = _current_catalog_binding(
                seed_path=seed_path,
                masked_path=masked_path,
                policy_path=policy_path,
            )
            post_preflight, post_preflight_sha256 = _load_json_with_digest(
                qualification_receipt_path
            )
            _qualification_revalidator(
                post_preflight,
                repo_root=repo_root,
                expected_image_references=expected_images,
                expected_catalog_counts=post_catalog_counts,
                expected_catalog_inventory_digest=post_catalog_inventory_digest,
                now=fixed_now,
            )
        except GradeRefreshError as exc:
            raise RefreshCandidateError("qualification inputs changed after the scan") from exc
        if (
            post_reviewed != reviewed
            or post_policy != policy
            or post_policy_sha256 != policy_sha256
            or post_catalog_counts != expected_catalog_counts
            or post_catalog_inventory_digest != expected_catalog_inventory_digest
            or post_preflight != preflight
            or post_preflight_sha256 != preflight_file_sha256
        ):
            raise RefreshCandidateError("reviewed inputs changed after the scan")
        post_live = _preflight_provider([target], default_image=requested_image)
        if post_live != live:
            raise RefreshCandidateError("target image binding changed after the scan")
        post_database_sha256 = _recheck_registry(source_db, registry, target)

        artifact: dict[str, Any] = {
            "schema": TARGET_SCAN_SCHEMA,
            "observed_at": scan_receipt["scan"]["scanned_at"],
            "target_slug": slug,
            "reviewed_inputs": {
                "catalog_denominator": 31,
                "scannable_count": 18,
                "blocked_count": 13,
                "seed_sha256": f"sha256:{reviewed.seed_sha256}",
                "masking_sha256": f"sha256:{reviewed.masked_sha256}",
                "policy_sha256": policy_sha256,
            },
            "source_binding": source_projection,
            "registry_read_binding": {
                "pre_sha256": f"sha256:{registry.sha256}",
                "post_sha256": f"sha256:{post_database_sha256}",
                "stable_descriptor_identity": True,
                "sidecars_absent": True,
            },
            "qualification_binding": qualification,
            "scan_receipt": scan_receipt,
            "authority": dict(TARGET_SCAN_AUTHORITY),
            "claim_ceiling": TARGET_SCAN_CLAIM_CEILING,
        }
        _privacy_validate(artifact)
        artifact["artifact_digest"] = _artifact_unsigned_digest(artifact)
        _validate_artifact_shape(artifact)
        if _source_binding_provider(repo_root) != initial_source:
            raise RefreshCandidateError("source binding changed before finalization")
        if _recheck_registry(source_db, registry, target) != post_database_sha256:
            raise RefreshCandidateError("registry database changed before finalization")
        _require_sidecars_absent(source_db)
        _finalizer(output_path, artifact)
    return output_path


def verify_target_scan_artifact(
    artifact_path: Path,
    *,
    source_db: Path,
    seed_path: Path,
    masked_path: Path,
    policy_path: Path,
    qualification_receipt_path: Path,
    repo_root: Path,
    now: datetime | None = None,
    _source_binding_provider: Callable[[Path], dict[str, Any]] = source_binding,
    _qualification_revalidator: Callable[..., None] = revalidate_ready_preflight_qualifications,
) -> dict[str, Any]:
    """Verify one finalized artifact against current read-only inputs; never execute."""
    fixed_now = now or datetime.now(tz=UTC)
    artifact, _file_digest = _load_read_only_json_with_digest(artifact_path)
    try:
        artifact_stat = artifact_path.lstat()
    except OSError as exc:
        raise RefreshCandidateError("target scan artifact readback is unavailable") from exc
    if stat.S_IMODE(artifact_stat.st_mode) != 0o400:
        raise RefreshCandidateError("target scan artifact mode is not 0400")
    payload = _validate_artifact_shape(artifact)
    current_source = _source_binding_provider(repo_root)
    if _source_projection(current_source) != payload["source_binding"]:
        raise RefreshCandidateError("target scan source binding is no longer current")
    reviewed = _reviewed_inputs(seed_path, masked_path)
    try:
        policy = load_policy(policy_path, seed_path, masked_path)
        policy_sha256 = digest_file(policy_path)
        expected_catalog_counts, expected_catalog_inventory_digest = _current_catalog_binding(
            seed_path=seed_path,
            masked_path=masked_path,
            policy_path=policy_path,
        )
    except GradeRefreshError as exc:
        raise RefreshCandidateError("target scan policy is no longer valid") from exc
    _require_current_denominator(policy, reviewed.catalog_rows)
    expected_reviewed = {
        "catalog_denominator": 31,
        "scannable_count": 18,
        "blocked_count": 13,
        "seed_sha256": f"sha256:{reviewed.seed_sha256}",
        "masking_sha256": f"sha256:{reviewed.masked_sha256}",
        "policy_sha256": policy_sha256,
    }
    if payload["reviewed_inputs"] != expected_reviewed:
        raise RefreshCandidateError("target scan reviewed inputs are no longer current")
    preflight, preflight_sha256 = _load_json_with_digest(qualification_receipt_path)
    if not isinstance(preflight, dict):
        raise RefreshCandidateError("target scan preflight is invalid")
    scannable = [
        _reviewed_server_from_seed(row, added_at=fixed_now)
        for row in reviewed.catalog_rows
        if row.get("slug") in policy.scannable
    ]
    default_image = policy.raw.get("default_sandbox_image")
    if not isinstance(default_image, str):
        raise RefreshCandidateError("target scan policy image is invalid")
    expected_images = _required_local_sandbox_images(scannable, default_image=default_image)
    if len(expected_images) != 5:
        raise RefreshCandidateError("target scan complete image set is no longer current")
    try:
        validate_ready_preflight_contract(
            preflight,
            expected_image_references=expected_images,
            expected_catalog_counts=expected_catalog_counts,
            expected_catalog_inventory_digest=expected_catalog_inventory_digest,
        )
        _qualification_revalidator(
            preflight,
            repo_root=repo_root,
            expected_image_references=expected_images,
            expected_catalog_counts=expected_catalog_counts,
            expected_catalog_inventory_digest=expected_catalog_inventory_digest,
            now=fixed_now,
        )
    except GradeRefreshError as exc:
        raise RefreshCandidateError("target scan preflight is no longer current") from exc
    qualification = payload["qualification_binding"]
    engine = preflight.get("engine_materialization")
    sandbox = preflight.get("sandbox")
    image_rows = sandbox.get("image_bindings") if isinstance(sandbox, dict) else None
    image_ids = {
        row.get("reference"): row.get("image_id")
        for row in image_rows or []
        if isinstance(row, dict)
    }
    catalog = preflight.get("catalog")
    boundary = catalog.get("execution_boundary") if isinstance(catalog, dict) else None
    expected_boundary = {
        "schema": "McpTrustRefreshExecutionBoundaryV1",
        "scannable": sorted(policy.scannable),
        "blocked": sorted(policy.blocked),
    }
    complete: list[dict[str, str]] = []
    sources = catalog.get("image_build_sources") if isinstance(catalog, dict) else None
    if not isinstance(sources, dict):
        raise RefreshCandidateError("target scan image lineage is no longer current")
    for reference in sorted(expected_images):
        source_row = sources.get(reference)
        receipt_row = source_row.get("qualification") if isinstance(source_row, dict) else None
        receipt_digest = (
            receipt_row.get("receipt_digest") if isinstance(receipt_row, dict) else None
        )
        image_id = image_ids.get(reference)
        if not isinstance(image_id, str) or not isinstance(receipt_digest, str):
            raise RefreshCandidateError("target scan image lineage is no longer current")
        complete.append(
            {
                "reference": reference,
                "image_id": image_id,
                "qualification_receipt_digest": receipt_digest,
            }
        )
    complete_digest = digest_bytes(canonical_bytes(complete))
    try:
        preflight_observed = _parse_utc_datetime(preflight.get("observed_at"))
    except (OverflowError, TypeError, ValueError) as exc:
        raise RefreshCandidateError("target scan preflight timestamp is invalid") from exc
    preflight_age = (fixed_now.astimezone(UTC) - preflight_observed).total_seconds()
    if (
        preflight.get("source_binding") != current_source
        or boundary != expected_boundary
        or preflight_age < 0
        or preflight_age >= DEFAULT_MAX_AGE_HOURS * 3600
        or qualification.get("preflight_file_sha256") != f"sha256:{preflight_sha256}"
        or qualification.get("preflight_receipt_digest") != preflight.get("receipt_digest")
        or not isinstance(engine, dict)
        or qualification.get("engine_receipt_digest") != engine.get("receipt_digest")
        or image_ids.get(qualification.get("target_requested_image"))
        != qualification.get("target_immutable_image_id")
        or qualification.get("complete_qualified_image_set_digest") != complete_digest
        or payload["scan_receipt"].get("scanner", {}).get("engine_version")
        != preflight.get("tool_versions", {}).get("mcp_audits")
    ):
        raise RefreshCandidateError("target scan qualification binding is no longer current")
    with _open_registry_target(source_db, str(payload["target_slug"])) as registry:
        expected = _select_target(
            payload["target_slug"],
            policy=policy,
            rows=reviewed.catalog_rows,
            added_at=registry.server.added_at,
        )
        expected_requested_image = expected.source.sandbox_image or default_image
        if _server_identity(registry.server) != _server_identity(expected):
            raise RefreshCandidateError("target scan registry identity is no longer current")
        current_db_sha256 = _recheck_registry(source_db, registry, expected)
    registry_binding = payload["registry_read_binding"]
    if (
        qualification.get("target_requested_image") != expected_requested_image
        or registry_binding.get("pre_sha256") != f"sha256:{current_db_sha256}"
        or registry_binding.get("post_sha256") != f"sha256:{current_db_sha256}"
    ):
        raise RefreshCandidateError("target scan registry binding is no longer current")
    _require_sidecars_absent(source_db)
    return {
        "schema": TARGET_SCAN_SCHEMA,
        "verified": True,
        "target_slug": payload["target_slug"],
        "artifact_digest": payload["artifact_digest"],
        "receipt_only": True,
        "claim_ceiling": TARGET_SCAN_CLAIM_CEILING,
    }
