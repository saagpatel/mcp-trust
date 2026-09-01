#!/usr/bin/env python3
"""Build each approved refresh image twice and emit fail-closed receipts.

The builds consume only prepared local artifacts, run with BuildKit network
mode ``none``, bypass caches, and never publish an image or catalog artifact.
"""

from __future__ import annotations

import argparse
import fcntl
import json
import os
import re
import shutil
import stat
import subprocess
from collections.abc import Callable
from contextlib import contextmanager
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from mcp_trust import dependency_boundary, grade_refresh
from mcp_trust.engine.sandbox import normalize_local_docker_host
from mcp_trust.host_capacity import (
    HostCapacityError,
    HostCapacitySample,
    read_host_capacity,
    require_current_host_capacity,
    validate_qualification_capacity_receipt,
)

ROOT = Path(__file__).resolve().parents[1]
INPUTS = ROOT / "docker/refresh/dependency-inputs.json"
RECEIPT_ROOT = ROOT / "docker/refresh/qualification"
DOCKER_CONTEXT = "colima-mcp-trust-sandbox"
EXPECTED_DOCKER_HOST = (
    "unix://" + (Path.home() / ".colima/mcp-trust-sandbox/docker.sock").as_posix()
)
_SAFE_RECEIPT_SET = re.compile(
    r"^v[0-9]+(?:[-._][A-Za-z0-9][A-Za-z0-9._-]{0,119})?$"
)
COHORTS = ("reference", "live-batch", "batch3", "batch4", "basic-memory")
QUALIFICATION_SET_SCHEMA = "McpTrustImageQualificationSetV1"
QUALIFICATION_ATTEMPT_SCHEMA = "McpTrustImageQualificationAttemptV1"
QUALIFICATION_COMPLETION_SCHEMA = "McpTrustImageQualificationCompletionV1"
QUALIFICATION_CLEANUP_SCHEMA = "McpTrustImageQualificationCleanupV1"
QUALIFICATION_OWNERSHIP_SCHEMA = "McpTrustImageQualificationOwnershipV1"
_HEX_DIGEST = re.compile(r"^[0-9a-f]{64}$")
_ATTEMPT_KEYS = frozenset(
    {
        "schema",
        "attempt_id",
        "set_receipt_digest",
        "cohort",
        "capacity_receipt_digest",
        "image_reference",
        "temporary_reference",
        "previous_final_image_id",
        "oci_outputs",
        "validation_receipt",
        "tool_snapshot",
        "capacity_receipt",
        "capacity_receipt_sha256",
        "exit_classification",
        "claim_ceiling",
        "receipt_digest",
    }
)
_COMPLETION_KEYS = frozenset(
    {
        "schema",
        "cohort",
        "attempt_id",
        "attempt_path",
        "attempt_sha256",
        "qualification_receipt",
        "qualification_receipt_sha256",
        "qualification_receipt_digest",
        "exit_classification",
        "receipt_digest",
    }
)
_CLEANUP_KEYS = frozenset(
    {
        "schema",
        "cohort",
        "attempt_id",
        "attempt_path",
        "attempt_sha256",
        "capacity_receipt",
        "capacity_receipt_sha256",
        "capacity_receipt_digest",
        "temporary_tag_absent",
        "final_tag_state",
        "oci_outputs_absent",
        "execution_boundary",
        "tool_versions",
        "tool_digests",
        "exit_classification",
        "claim_ceiling",
        "receipt_digest",
    }
)
_OWNERSHIP_KEYS = frozenset(
    {
        "schema",
        "cohort",
        "attempt_id",
        "attempt_path",
        "attempt_sha256",
        "owned_final_image_id",
        "exit_classification",
        "receipt_digest",
    }
)
BUILD_OPTIONS = {
    "builder": "buildx",
    "cache": "disabled",
    "load": False,
    "output": "oci",
    "pull": False,
    "provenance": False,
    "rewrite_timestamps": True,
    "sbom": False,
}
EXECUTION_BOUNDARY = {
    "docker_context": DOCKER_CONTEXT,
    "docker_transport": "local-unix",
    "builder_name": DOCKER_CONTEXT,
    "builder_driver": "docker",
    "builder_endpoint_matches_context": True,
    "redirect_environment_policy": "exact-context-no-proxy",
    "tool_execution_policy": "owner-private-digest-pinned-copies",
}
_STABLE_VERSION = re.compile(
    r"v?\d+\.\d+\.\d+(?:[-+][0-9A-Za-z][0-9A-Za-z.-]*)?"
)
_BUILDKIT_VERSION_LINE = re.compile(
    r"^\s*BuildKit version:\s*(v\d+\.\d+\.\d+(?:[-+][0-9A-Za-z][0-9A-Za-z.-]*)?)\s*$",
    flags=re.MULTILINE,
)
_BUILDX_VERSION_LINE = re.compile(
    r"github\.com/docker/buildx "
    r"(v\d+\.\d+\.\d+(?:[-+][0-9A-Za-z][0-9A-Za-z.-]*)?)"
    r"(?: [0-9a-f]{7,64}| Homebrew)?"
)
_BUILDER_HEADER = re.compile(
    r"\AName:\s*(\S+)\s*\nDriver:\s*(\S+)\s*$", flags=re.MULTILINE
)
_BUILDER_ENDPOINT_LINE = re.compile(r"^\s*Endpoint:\s*(\S+)\s*$", flags=re.MULTILINE)
_BUILDER_STATUS_LINE = re.compile(r"^\s*Status:\s*(\S+)\s*$", flags=re.MULTILINE)
_REDIRECT_ENVIRONMENT = {
    "ALL_PROXY",
    "BUILDKIT_HOST",
    "BUILDX_BUILDER",
    "DOCKER_CERT_PATH",
    "DOCKER_CONTEXT",
    "DOCKER_HOST",
    "DOCKER_TLS_VERIFY",
    "HTTPS_PROXY",
    "HTTP_PROXY",
    "NO_PROXY",
    "all_proxy",
    "https_proxy",
    "http_proxy",
    "no_proxy",
}


class QualificationError(RuntimeError):
    pass


class QualificationCapacityGate:
    """Revalidate one bound host-capacity receipt at each process boundary."""

    __slots__ = ("_anchor", "_clock", "_reader", "_receipt", "_scope_receipt")

    def __init__(
        self,
        *,
        receipt: object,
        anchor: Path,
        scope_receipt: dict[str, Any] | None = None,
        clock: Callable[[], datetime] = lambda: datetime.now(tz=UTC),
        reader: Callable[[Path], HostCapacitySample] = read_host_capacity,
    ) -> None:
        if scope_receipt is not None and scope_receipt.get("host_capacity") != receipt:
            raise QualificationError(
                "qualification scope and dynamic capacity receipts differ"
            )
        self._receipt = receipt
        self._scope_receipt = scope_receipt
        self._anchor = anchor
        self._clock = clock
        self._reader = reader

    @property
    def receipt(self) -> dict[str, Any]:
        value = self._scope_receipt or self._receipt
        return dict(value)

    def require_current(self) -> dict[str, Any]:
        try:
            return require_current_host_capacity(
                self._receipt,
                anchor=self._anchor,
                now=self._clock(),
                reader=self._reader,
            )
        except HostCapacityError as exc:
            raise QualificationError(
                "host capacity is not READY for Docker/Buildx execution"
            ) from exc

    def require_scope(self, *, operation: str, receipt_set: str, cohort: str) -> None:
        if self._scope_receipt is None:
            raise QualificationError("qualification capacity gate is not scope-bound")
        try:
            validate_qualification_capacity_receipt(
                self._scope_receipt,
                operation=operation,
                receipt_set=receipt_set,
                cohort=cohort,
            )
        except HostCapacityError as exc:
            raise QualificationError("qualification capacity gate scope differs") from exc


def _load_capacity_gate(
    path: Path, *, operation: str, receipt_set: str, cohort: str
) -> QualificationCapacityGate:
    try:
        receipt = grade_refresh.load_json(path)
        scoped = validate_qualification_capacity_receipt(
            receipt,
            operation=operation,
            receipt_set=receipt_set,
            cohort=cohort,
        )
    except (grade_refresh.GradeRefreshError, HostCapacityError) as exc:
        raise QualificationError("host-capacity receipt is unreadable or invalid") from exc
    return QualificationCapacityGate(
        receipt=scoped["host_capacity"], anchor=ROOT, scope_receipt=scoped
    )


def _completed(
    command: list[str],
    *,
    tools: dict[str, Path],
    capacity_gate: QualificationCapacityGate,
    capture: bool = False,
    timeout: int = 60,
) -> subprocess.CompletedProcess[str]:
    if type(capacity_gate) is not QualificationCapacityGate:
        raise QualificationError("qualification capacity gate is not bound")
    executable = tools.get(command[0])
    if executable is None:
        raise QualificationError(f"unbound qualification executable: {command[0]}")
    runtime_command = [executable.as_posix(), *command[1:]]
    environment = os.environ.copy()
    for key in _REDIRECT_ENVIRONMENT:
        environment.pop(key, None)
    environment["DOCKER_CONTEXT"] = DOCKER_CONTEXT
    environment["PATH"] = executable.parent.as_posix()
    capacity_gate.require_current()
    try:
        return subprocess.run(
            runtime_command,
            cwd=ROOT,
            text=True,
            capture_output=capture,
            check=False,
            timeout=timeout,
            env=environment,
        )
    except subprocess.TimeoutExpired as exc:
        raise QualificationError(
            f"command timed out after {timeout}s: {command[0]} {command[1]}"
        ) from exc


def _run(
    command: list[str],
    *,
    tools: dict[str, Path],
    capacity_gate: QualificationCapacityGate,
    capture: bool = False,
    timeout: int = 60,
) -> str:
    completed = _completed(
        command,
        tools=tools,
        capacity_gate=capacity_gate,
        capture=capture,
        timeout=timeout,
    )
    if completed.returncode != 0:
        detail = completed.stderr.strip() if capture else "see command output"
        raise QualificationError(
            f"command failed ({completed.returncode}): {command[0]} {command[1]}; {detail}"
        )
    return completed.stdout.strip() if capture else ""


def _write_new(path: Path, payload: dict[str, Any]) -> None:
    content = json.dumps(payload, indent=2, sort_keys=True).encode() + b"\n"
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    try:
        written = os.write(descriptor, content)
        if written != len(content):
            raise OSError("short write")
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def _lstat(path: Path) -> os.stat_result | None:
    try:
        return path.lstat()
    except FileNotFoundError:
        return None


def _require_safe_directory(path: Path, *, label: str) -> None:
    try:
        relative = path.relative_to(ROOT)
    except ValueError as exc:
        raise QualificationError(f"{label} escapes the repository") from exc
    current = ROOT
    for part in relative.parts:
        current /= part
        metadata = _lstat(current)
        if metadata is None:
            raise QualificationError(f"{label} parent is missing: {current.relative_to(ROOT)}")
        if current.is_symlink():
            raise QualificationError(f"{label} contains a symlink: {current.relative_to(ROOT)}")
        if not current.is_dir():
            raise QualificationError(f"{label} is not a directory: {current.relative_to(ROOT)}")


def _ensure_safe_directory(path: Path, *, label: str) -> None:
    try:
        relative = path.relative_to(ROOT)
    except ValueError as exc:
        raise QualificationError(f"{label} escapes the repository") from exc
    current = ROOT
    for part in relative.parts:
        current /= part
        metadata = _lstat(current)
        if metadata is None:
            current.mkdir(mode=0o700)
            metadata = _lstat(current)
        if current.is_symlink():
            raise QualificationError(f"{label} contains a symlink: {current.relative_to(ROOT)}")
        if metadata is None or not current.is_dir():
            raise QualificationError(f"{label} is not a directory: {current.relative_to(ROOT)}")


def _require_private_directory(path: Path, *, label: str) -> None:
    _require_safe_directory(path, label=label)
    metadata = path.stat()
    if metadata.st_uid != os.getuid() or stat.S_IMODE(metadata.st_mode) & 0o077:
        raise QualificationError(f"{label} must be owner-private")


def _require_empty_directory(path: Path, *, label: str) -> None:
    _require_private_directory(path, label=label)
    if any(path.iterdir()):
        raise QualificationError(f"{label} must be empty before qualification")


def _receipt_set_root(receipt_set: str) -> Path:
    if (
        _SAFE_RECEIPT_SET.fullmatch(receipt_set) is None
        or receipt_set in {".", ".."}
        or "\\" in receipt_set
    ):
        raise QualificationError("receipt set must be one safe versioned path component")
    _require_safe_directory(RECEIPT_ROOT, label="qualification receipt root")
    return RECEIPT_ROOT / receipt_set


def _unsigned_digest(payload: dict[str, Any]) -> str:
    unsigned = dict(payload)
    unsigned.pop("receipt_digest", None)
    return grade_refresh.digest_bytes(grade_refresh.canonical_bytes(unsigned))


def _read_bound_json(path: Path, *, schema: str) -> dict[str, Any]:
    metadata = _lstat(path)
    if (
        metadata is None
        or path.is_symlink()
        or not path.is_file()
        or metadata.st_uid != os.getuid()
        or stat.S_IMODE(metadata.st_mode) & 0o077
    ):
        raise QualificationError(f"qualification set file is unsafe: {path.name}")
    try:
        payload = grade_refresh.load_json(path)
    except grade_refresh.GradeRefreshError as exc:
        raise QualificationError(f"qualification set file is invalid: {path.name}") from exc
    if (
        not isinstance(payload, dict)
        or payload.get("schema") != schema
        or payload.get("receipt_digest") != _unsigned_digest(payload)
    ):
        raise QualificationError(f"qualification set file integrity is invalid: {path.name}")
    return payload


def _safe_set_child(root: Path, name: object, *, label: str) -> Path:
    if (
        not isinstance(name, str)
        or not name
        or name in {".", ".."}
        or Path(name).name != name
        or "/" in name
        or "\\" in name
    ):
        raise QualificationError(f"{label} is not one contained set file")
    path = root / name
    if path.parent != root:
        raise QualificationError(f"{label} escapes the qualification set")
    return path


@contextmanager
def _cohort_lock(receipt_set: str, cohort: str) -> Any:
    lock_root = ROOT / "tmp/qualification-locks"
    _ensure_safe_directory(lock_root, label="qualification lock root")
    _require_private_directory(lock_root, label="qualification lock root")
    lock_id = grade_refresh.digest_bytes(
        grade_refresh.canonical_bytes({"receipt_set": receipt_set})
    ).removeprefix("sha256:")
    path = lock_root / f"{lock_id}.lock"
    if path.is_symlink():
        raise QualificationError("qualification cohort lock is a symlink")
    descriptor = os.open(
        path, os.O_RDWR | os.O_CREAT | getattr(os, "O_NOFOLLOW", 0), 0o600
    )
    try:
        metadata = os.fstat(descriptor)
        if (
            not stat.S_ISREG(metadata.st_mode)
            or metadata.st_uid != os.getuid()
            or stat.S_IMODE(metadata.st_mode) & 0o077
        ):
            raise QualificationError("qualification cohort lock is unsafe")
        try:
            fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError as exc:
            raise QualificationError(
                f"qualification set is already active for cohort: {cohort}"
            ) from exc
        yield
    finally:
        try:
            fcntl.flock(descriptor, fcntl.LOCK_UN)
        finally:
            os.close(descriptor)


def _reference(path: str) -> dict[str, str]:
    try:
        normalized = dependency_boundary.repository_file(ROOT, path)
    except dependency_boundary.DependencyBoundaryError as exc:
        raise QualificationError(f"required qualification input is unsafe: {path}") from exc
    return {
        "path": normalized,
        "sha256": grade_refresh.digest_file(ROOT / normalized),
    }


def _exact_version(value: str, *, label: str, require_v: bool) -> str:
    version = value.strip()
    if (
        _STABLE_VERSION.fullmatch(version) is None
        or require_v != version.startswith("v")
    ):
        raise QualificationError(f"{label} did not return one exact version")
    return version


def _buildx_version(value: str) -> str:
    match = _BUILDX_VERSION_LINE.fullmatch(value.strip())
    if match is None:
        raise QualificationError("docker buildx did not return one exact version")
    return _exact_version(match.group(1), label="docker buildx", require_v=True)


def _buildkit_version(value: str) -> str:
    matches = _BUILDKIT_VERSION_LINE.findall(value)
    if len(matches) != 1:
        raise QualificationError("BuildKit inspect did not return one exact version")
    return _exact_version(matches[0], label="BuildKit inspect", require_v=True)


def _resolved_tool(executable: str) -> Path:
    resolved = shutil.which(executable)
    if resolved is None:
        raise QualificationError(f"{executable} executable is unavailable")
    path = Path(resolved).resolve(strict=True)
    metadata = path.stat()
    if not path.is_file() or metadata.st_uid not in {0, os.getuid()}:
        raise QualificationError(f"{executable} executable provenance is unsafe")
    if stat.S_IMODE(metadata.st_mode) & 0o022:
        raise QualificationError(f"{executable} executable is group/world writable")
    return path


def _snapshot_tools(output_root: Path, buildx: str) -> dict[str, Path]:
    snapshot_root = output_root / "tools"
    if _lstat(snapshot_root) is not None:
        raise QualificationError("qualification tool snapshot already exists")
    snapshot_root.mkdir(mode=0o700)
    tools: dict[str, Path] = {}
    try:
        for logical_name, source_name in (("docker", "docker"), (buildx, buildx)):
            source = _resolved_tool(source_name)
            destination = snapshot_root / logical_name
            shutil.copyfile(source, destination)
            destination.chmod(0o500)
            metadata = destination.stat()
            if (
                not destination.is_file()
                or metadata.st_uid != os.getuid()
                or stat.S_IMODE(metadata.st_mode) != 0o500
                or grade_refresh.digest_file(destination) != grade_refresh.digest_file(source)
            ):
                raise QualificationError(f"{logical_name} tool snapshot is invalid")
            tools[logical_name] = destination
    except BaseException:
        _cleanup_tool_snapshot(tools, snapshot_root=snapshot_root)
        raise
    return tools


def _cleanup_orphan_tool_snapshot(output_root: Path, buildx: str) -> None:
    """Remove only an exact pre-intent snapshot left by process interruption."""
    snapshot_root = output_root / "tools"
    if _lstat(snapshot_root) is None:
        return
    _require_private_directory(snapshot_root, label="orphan qualification tool snapshot")
    expected = {"docker": "docker", buildx: buildx}
    paths = {path.name: path for path in snapshot_root.iterdir()}
    if set(paths) != set(expected):
        raise QualificationError("orphan qualification tool snapshot is ambiguous")
    for logical_name, source_name in expected.items():
        path = paths[logical_name]
        metadata = _lstat(path)
        source = _resolved_tool(source_name)
        if (
            metadata is None
            or path.is_symlink()
            or not path.is_file()
            or metadata.st_uid != os.getuid()
            or stat.S_IMODE(metadata.st_mode) != 0o500
            or grade_refresh.digest_file(path) != grade_refresh.digest_file(source)
        ):
            raise QualificationError("orphan qualification tool snapshot is ambiguous")
    _cleanup_tool_snapshot(paths, snapshot_root=snapshot_root)


def _cleanup_tool_snapshot(
    tools: dict[str, Path], *, snapshot_root: Path | None = None
) -> None:
    root = snapshot_root or next(iter(tools.values())).parent
    for path in tools.values():
        metadata = _lstat(path)
        if metadata is None:
            continue
        if path.parent != root or path.is_symlink() or not path.is_file():
            raise QualificationError("qualification tool cleanup target is unsafe")
        path.unlink()
    if _lstat(root) is not None:
        if root.is_symlink() or not root.is_dir() or any(root.iterdir()):
            raise QualificationError("qualification tool directory cleanup is unsafe")
        root.rmdir()


def _tool_digests(tools: dict[str, Path], buildx: str) -> dict[str, str]:
    return {
        "docker": grade_refresh.digest_file(tools["docker"]),
        "docker_buildx": grade_refresh.digest_file(tools[buildx]),
    }


def _execution_boundary(
    buildx: str,
    *,
    tools: dict[str, Path],
    capacity_gate: QualificationCapacityGate,
) -> dict[str, object]:
    context_host_raw = _run(
        [
            "docker",
            "context",
            "inspect",
            DOCKER_CONTEXT,
            "--format",
            "{{json .Endpoints.docker.Host}}",
        ],
        tools=tools,
        capacity_gate=capacity_gate,
        capture=True,
    )
    try:
        context_host = normalize_local_docker_host(json.loads(context_host_raw))
    except (json.JSONDecodeError, TypeError, ValueError) as exc:
        raise QualificationError("Docker context is not one local Unix endpoint") from exc
    if context_host != EXPECTED_DOCKER_HOST:
        raise QualificationError("Docker context does not match mcp-trust-sandbox")
    socket_path = Path(context_host.removeprefix("unix://"))
    try:
        socket_metadata = socket_path.stat()
    except OSError as exc:
        raise QualificationError("approved Docker Unix socket is unavailable") from exc
    if (
        not stat.S_ISSOCK(socket_metadata.st_mode)
        or socket_metadata.st_uid != os.getuid()
        or stat.S_IMODE(socket_metadata.st_mode) & 0o022
    ):
        raise QualificationError("approved Docker endpoint is not an owner-bound Unix socket")

    inspected = _run(
        [buildx, "inspect", DOCKER_CONTEXT],
        tools=tools,
        capacity_gate=capacity_gate,
        capture=True,
    )
    header = _BUILDER_HEADER.search(inspected)
    endpoints = _BUILDER_ENDPOINT_LINE.findall(inspected)
    statuses = _BUILDER_STATUS_LINE.findall(inspected)
    if (
        header is None
        or header.groups() != (DOCKER_CONTEXT, "docker")
        or endpoints != [DOCKER_CONTEXT]
        or statuses != ["running"]
        or _buildkit_version(inspected) == ""
    ):
        raise QualificationError("Buildx builder is not the approved local context")
    return dict(EXECUTION_BOUNDARY)


def _tool_versions(
    buildx: str,
    *,
    tools: dict[str, Path],
    capacity_gate: QualificationCapacityGate,
) -> dict[str, str]:
    docker_client = _run(
        [
            "docker",
            "--context",
            DOCKER_CONTEXT,
            "version",
            "--format",
            "{{.Client.Version}}",
        ],
        tools=tools,
        capacity_gate=capacity_gate,
        capture=True,
    )
    docker_server = _run(
        [
            "docker",
            "--context",
            DOCKER_CONTEXT,
            "version",
            "--format",
            "{{.Server.Version}}",
        ],
        tools=tools,
        capacity_gate=capacity_gate,
        capture=True,
    )
    buildx_version = _run(
        [buildx, "version"],
        tools=tools,
        capacity_gate=capacity_gate,
        capture=True,
    )
    buildkit_inspect = _run(
        [buildx, "inspect", DOCKER_CONTEXT],
        tools=tools,
        capacity_gate=capacity_gate,
        capture=True,
    )
    return {
        "docker_client": _exact_version(
            docker_client, label="Docker client", require_v=False
        ),
        "docker_server": _exact_version(
            docker_server, label="Docker server", require_v=False
        ),
        "docker_buildx": _buildx_version(buildx_version),
        "buildkit_colima": _buildkit_version(buildkit_inspect),
    }


def _dependency_inputs(
    cohort: str, config: dict[str, Any]
) -> tuple[
    dict[str, dict[str, str]],
    dict[str, dict[str, str]],
    dict[str, dict[str, str]],
    dict[str, str],
    dict[str, dict[str, Any]],
]:
    manifests: dict[str, dict[str, str]] = {}
    locks: dict[str, dict[str, str]] = {}
    artifacts: dict[str, dict[str, str]] = {}
    normalized_locks: dict[str, str] = {}
    normalized_artifacts: dict[str, dict[str, Any]] = {}
    kinds = [kind for kind in ("npm", "python") if config.get(kind)]
    if not kinds:
        raise QualificationError(f"cohort has no dependencies: {cohort}")
    for kind in kinds:
        if kind == "npm":
            manifest_path = f"docker/refresh/locks/{cohort}/package.json"
            lock_path = f"docker/refresh/locks/{cohort}/package-lock.json"
        else:
            manifest_path = f"docker/refresh/locks/{cohort}/requirements.in"
            lock_path = f"docker/refresh/locks/{cohort}/requirements.lock"
        descriptor_path = f"docker/refresh/artifact-manifests/{cohort}/{kind}.json"
        manifest_ref = _reference(manifest_path)
        lock_ref = _reference(lock_path)
        try:
            if kind == "npm":
                dependency_boundary.validate_npm_lock(
                    ROOT / manifest_ref["path"], ROOT / lock_ref["path"]
                )
            else:
                dependency_boundary.validate_python_lock(
                    ROOT / manifest_ref["path"], ROOT / lock_ref["path"]
                )
        except dependency_boundary.DependencyBoundaryError as exc:
            raise QualificationError(
                f"dependency source policy failed: {cohort}/{kind}"
            ) from exc
        artifact_ref = _reference(descriptor_path)
        normalized = grade_refresh._dependency_artifact(
            repo_root=ROOT,
            kind=kind,
            lock_sha256=lock_ref["sha256"],
            value=artifact_ref,
        )
        if normalized is None:
            raise QualificationError(f"dependency artifact failed verification: {cohort}/{kind}")
        manifests[kind] = manifest_ref
        locks[kind] = lock_ref
        artifacts[kind] = artifact_ref
        normalized_locks[lock_path] = lock_ref["sha256"]
        normalized_artifacts[kind] = normalized
    return manifests, locks, artifacts, normalized_locks, normalized_artifacts


def _cohort_binding(cohort: str, config: dict[str, Any], *, platform: str) -> dict[str, str]:
    cohort_config = dict(config)
    cohort_config.pop("platform", None)
    try:
        validated = dependency_boundary.validate_cohort(
            cohort, cohort_config, repo_root=ROOT, platform=platform
        )
    except dependency_boundary.DependencyBoundaryError as exc:
        raise QualificationError(str(exc)) from exc
    dockerfile = dependency_boundary.repository_file(ROOT, validated["dockerfile"])
    build_source_sha256 = grade_refresh.digest_file(ROOT / dockerfile)
    manifests, _locks, _artifacts, normalized_locks, normalized_artifacts = (
        _dependency_inputs(cohort, validated)
    )
    build_input = {
        "build_source_sha256": build_source_sha256,
        "base_images": sorted(
            {str(validated["node_base"]), str(validated["python_base"])}
        ),
        "platform": platform,
        "dependency_manifests": manifests,
        "dependency_locks": dict(sorted(normalized_locks.items())),
        "dependency_artifacts": normalized_artifacts,
        "build_options": BUILD_OPTIONS,
        "execution_boundary": EXECUTION_BOUNDARY,
    }
    return {
        "image_reference": dependency_boundary.local_image_tag(
            validated["image_reference"]
        ),
        "build_source": dockerfile,
        "build_source_sha256": build_source_sha256,
        "build_input_digest": grade_refresh.digest_bytes(
            grade_refresh.canonical_bytes(build_input)
        ),
    }


def _tracked_source_binding() -> dict[str, str]:
    status = subprocess.run(
        ["git", "-C", ROOT.as_posix(), "status", "--porcelain=v1", "--untracked-files=no"],
        text=True,
        capture_output=True,
        check=False,
        timeout=30,
    )
    if status.returncode != 0 or status.stdout.strip():
        raise QualificationError("tracked source must be clean before qualification")
    try:
        source = grade_refresh.source_binding(ROOT)
    except grade_refresh.GradeRefreshError as exc:
        raise QualificationError("tracked source binding is unavailable") from exc
    revision = source.get("revision")
    tree = source.get("source_tree_digest")
    if not isinstance(revision, str) or not revision or not isinstance(tree, str):
        raise QualificationError("tracked source binding is incomplete")
    return {"revision": revision, "source_tree_digest": tree}


def _expected_set_manifest(
    *, receipt_set: str, cohorts: dict[str, Any], platform: str
) -> dict[str, Any]:
    bindings: dict[str, dict[str, str]] = {}
    for cohort in COHORTS:
        config = cohorts.get(cohort)
        if not isinstance(config, dict):
            raise QualificationError(f"dependency cohort is unavailable: {cohort}")
        bindings[cohort] = _cohort_binding(cohort, config, platform=platform)
    payload: dict[str, Any] = {
        "schema": QUALIFICATION_SET_SCHEMA,
        "receipt_set": receipt_set,
        "cohorts": list(COHORTS),
        "cohort_bindings": bindings,
        "source_binding": _tracked_source_binding(),
        "qualification_script": _reference("scripts/qualify_refresh_images.py"),
        "dependency_inputs": _reference("docker/refresh/dependency-inputs.json"),
        "authority": {
            "append_only": True,
            "publication_performed": False,
            "deployment_performed": False,
            "scheduler_change_performed": False,
            "mcp_execution": False,
        },
        "claim_ceiling": (
            "Local append-only image qualification set binding only; incomplete, "
            "interrupted, or unadopted sets remain UNKNOWN and do not prove publication, "
            "deployment, scheduler operation, production freshness, or endorsement."
        ),
    }
    payload["receipt_digest"] = _unsigned_digest(payload)
    return payload


def _set_file_names(root: Path) -> set[str]:
    _require_private_directory(root, label="qualification receipt set")
    names: set[str] = set()
    for path in root.iterdir():
        metadata = _lstat(path)
        if (
            metadata is None
            or path.is_symlink()
            or not path.is_file()
            or metadata.st_uid != os.getuid()
            or stat.S_IMODE(metadata.st_mode) & 0o077
        ):
            raise QualificationError(f"qualification set contains unsafe entry: {path.name}")
        names.add(path.name)
    return names


def _open_receipt_set(
    receipt_set: str, *, cohorts: dict[str, Any], platform: str
) -> tuple[Path, dict[str, Any]]:
    root = _receipt_set_root(receipt_set)
    expected = _expected_set_manifest(
        receipt_set=receipt_set, cohorts=cohorts, platform=platform
    )
    if _lstat(root) is None:
        root.mkdir(mode=0o700)
        try:
            _write_new(root / "qualification-set.json", expected)
        except BaseException:
            if not any(root.iterdir()):
                root.rmdir()
            raise
    else:
        _require_private_directory(root, label="qualification receipt set")
    actual = _read_bound_json(
        root / "qualification-set.json", schema=QUALIFICATION_SET_SCHEMA
    )
    if actual != expected:
        raise QualificationError("qualification set source or input binding differs")
    for cohort, binding in expected["cohort_bindings"].items():
        receipt = root / f"{cohort}.json"
        if _lstat(receipt) is None:
            continue
        validated = grade_refresh._image_build_qualification(
            repo_root=ROOT,
            reference=binding["image_reference"],
            build_source=binding["build_source"],
            build_source_sha256=binding["build_source_sha256"],
            receipt_path=receipt.relative_to(ROOT).as_posix(),
        )
        if validated is None:
            raise QualificationError(
                f"existing qualification receipt is invalid: {receipt.name}"
            )
    _validate_set_graph(root, set_manifest=actual)
    return root, actual


def _artifact_suffix(path: Path, prefix: str, cohort: str) -> str | None:
    pattern = rf"{re.escape(prefix)}-{re.escape(cohort)}-([0-9a-f]{{64}})\.json"
    match = re.fullmatch(pattern, path.name)
    return match.group(1) if match else None


def _valid_attempt_tool_snapshot(value: object) -> bool:
    if not isinstance(value, dict) or set(value) != {"docker", "docker-buildx"}:
        return False
    for name, descriptor in value.items():
        if (
            not isinstance(descriptor, dict)
            or set(descriptor) != {"path", "sha256"}
            or descriptor.get("path") != f"tmp/qualification/tools/{name}"
            or not isinstance(descriptor.get("sha256"), str)
            or _HEX_DIGEST.fullmatch(
                descriptor["sha256"].removeprefix("sha256:")
            )
            is None
        ):
            return False
    return True


def _validated_set_attempts(
    root: Path, *, cohort: str, set_manifest: dict[str, Any]
) -> tuple[list[tuple[Path, dict[str, Any]]], set[str], set[str], set[str]]:
    names = _set_file_names(root)
    allowed = {"qualification-set.json", *{f"{name}.json" for name in COHORTS}}
    attempts: list[tuple[Path, dict[str, Any]]] = []
    completions: set[str] = set()
    cleanups: set[str] = set()
    ownerships: set[str] = set()
    host_capacity_digests: set[str] = set()
    for name in names - allowed:
        path = root / name
        for prefix, schema, target in (
            ("capacity", "McpTrustQualificationCapacityReceiptV1", None),
            ("attempt", QUALIFICATION_ATTEMPT_SCHEMA, attempts),
            ("complete", QUALIFICATION_COMPLETION_SCHEMA, completions),
            ("cleanup", QUALIFICATION_CLEANUP_SCHEMA, cleanups),
            ("ownership", QUALIFICATION_OWNERSHIP_SCHEMA, ownerships),
        ):
            matched_cohort = next(
                (item for item in COHORTS if _artifact_suffix(path, prefix, item)), None
            )
            if matched_cohort is None:
                continue
            suffix = _artifact_suffix(path, prefix, matched_cohort)
            assert suffix is not None
            payload = _read_bound_json(path, schema=schema)
            if payload.get("cohort") != matched_cohort:
                raise QualificationError(f"qualification set artifact scope differs: {name}")
            if prefix == "capacity":
                if payload.get("receipt_digest", "").removeprefix("sha256:") != suffix:
                    raise QualificationError(f"capacity artifact filename differs: {name}")
                operation = payload.get("operation")
                if operation not in {"qualification", "cleanup"}:
                    raise QualificationError(f"capacity artifact operation is invalid: {name}")
                try:
                    validate_qualification_capacity_receipt(
                        payload,
                        operation=operation,
                        receipt_set=root.name,
                        cohort=matched_cohort,
                    )
                except HostCapacityError as exc:
                    raise QualificationError(
                        f"capacity artifact scope is invalid: {name}"
                    ) from exc
                host_digest = payload["host_capacity"]["receipt_digest"]
                if host_digest in host_capacity_digests:
                    raise QualificationError(
                        "one host-capacity observation was reused across set operations"
                    )
                host_capacity_digests.add(host_digest)
            elif target is attempts:
                capacity_name = payload.get("capacity_receipt")
                capacity_path = _safe_set_child(
                    root, capacity_name, label="attempt capacity receipt"
                )
                capacity = (
                    _read_bound_json(
                        capacity_path, schema="McpTrustQualificationCapacityReceiptV1"
                    )
                    if isinstance(capacity_name, str) else None
                )
                expected_attempt_id = grade_refresh.digest_bytes(
                    grade_refresh.canonical_bytes(
                        {
                            "set_receipt_digest": payload.get("set_receipt_digest"),
                            "cohort": payload.get("cohort"),
                            "capacity_receipt_digest": payload.get(
                                "capacity_receipt_digest"
                            ),
                        }
                    )
                ).removeprefix("sha256:")
                cohort_binding = set_manifest.get("cohort_bindings", {}).get(
                    matched_cohort, {}
                )
                if (
                    set(payload) != _ATTEMPT_KEYS
                    or payload.get("attempt_id") != suffix
                    or suffix != expected_attempt_id
                    or payload.get("set_receipt_digest")
                    != set_manifest.get("receipt_digest")
                    or payload.get("image_reference")
                    != cohort_binding.get("image_reference")
                    or payload.get("temporary_reference")
                    != f"mcp-trust-qualification:v0-{suffix}-first"
                    or payload.get("oci_outputs")
                    != [
                        f"tmp/qualification/{matched_cohort}-first.oci.tar",
                        f"tmp/qualification/{matched_cohort}-second.oci.tar",
                    ]
                    or payload.get("exit_classification")
                    != "PENDING_DOCKER_MUTATION_CLEANUP"
                    or payload.get("validation_receipt")
                    != f"tmp/qualification/{matched_cohort}-receipt.json"
                    or not _valid_attempt_tool_snapshot(payload.get("tool_snapshot"))
                    or (
                        payload.get("previous_final_image_id") is not None
                        and (
                            not isinstance(
                                payload.get("previous_final_image_id"), str
                            )
                            or _HEX_DIGEST.fullmatch(
                                payload["previous_final_image_id"].removeprefix(
                                    "sha256:"
                                )
                            )
                            is None
                        )
                    )
                    or not isinstance(capacity, dict)
                    or payload.get("capacity_receipt_digest")
                    != capacity.get("receipt_digest")
                    or payload.get("capacity_receipt_sha256")
                    != grade_refresh.digest_file(capacity_path)
                ):
                    raise QualificationError(f"attempt artifact filename differs: {name}")
                attempts.append((path, payload))
            else:
                expected_keys = {
                    "complete": _COMPLETION_KEYS,
                    "cleanup": _CLEANUP_KEYS,
                    "ownership": _OWNERSHIP_KEYS,
                }[prefix]
                if set(payload) != expected_keys or payload.get("attempt_id") != suffix:
                    raise QualificationError(f"resolution artifact filename differs: {name}")
                target.add(suffix)
            break
        else:
            raise QualificationError(f"qualification set contains unknown artifact: {name}")
    cohort_attempts = [item for item in attempts if item[1].get("cohort") == cohort]
    return cohort_attempts, completions, cleanups, ownerships


def _validate_set_graph(root: Path, *, set_manifest: dict[str, Any]) -> None:
    attempts_by_id: dict[str, tuple[Path, dict[str, Any]]] = {}
    completions: set[str] = set()
    cleanups: set[str] = set()
    ownerships: set[str] = set()
    for cohort in COHORTS:
        attempts, found_completions, found_cleanups, found_ownerships = (
            _validated_set_attempts(
                root, cohort=cohort, set_manifest=set_manifest
            )
        )
        completions = found_completions
        cleanups = found_cleanups
        ownerships = found_ownerships
        for path, attempt in attempts:
            attempt_id = str(attempt["attempt_id"])
            if attempt_id in attempts_by_id:
                raise QualificationError("qualification set has duplicate attempt identity")
            attempts_by_id[attempt_id] = (path, attempt)
    attempt_ids = set(attempts_by_id)
    if not completions <= attempt_ids:
        raise QualificationError("qualification set has orphan completion evidence")
    if not cleanups <= attempt_ids:
        raise QualificationError("qualification set has orphan cleanup evidence")
    if not ownerships <= attempt_ids:
        raise QualificationError("qualification set has orphan ownership evidence")
    if not completions <= ownerships:
        raise QualificationError(
            "qualification completion lacks final-tag ownership evidence"
        )
    for attempt_id in ownerships:
        attempt_path, attempt = attempts_by_id[attempt_id]
        _owned_final_image_id(
            root, attempt_path=attempt_path, attempt=attempt
        )

    for attempt_id in completions | cleanups:
        attempt_path, attempt = attempts_by_id[attempt_id]
        if not _attempt_resolved(
            root,
            attempt_path=attempt_path,
            attempt=attempt,
            completions=completions,
            cleanups=cleanups,
        ):
            raise QualificationError("qualification set resolution evidence is incomplete")

    for cohort in COHORTS:
        receipt = root / f"{cohort}.json"
        matching = {
            attempt_id
            for attempt_id, (_path, attempt) in attempts_by_id.items()
            if attempt.get("cohort") == cohort and attempt_id in completions
        }
        if receipt.is_file() and len(matching) != 1:
            raise QualificationError(
                f"qualification receipt lacks one completion graph: {receipt.name}"
            )
        if not receipt.is_file() and matching:
            raise QualificationError(
                f"qualification completion lacks its receipt: {cohort}.json"
            )

    referenced_capacity = {
        str(attempt.get("capacity_receipt"))
        for _path, attempt in attempts_by_id.values()
    }
    for attempt_id in cleanups:
        _attempt_path, attempt = attempts_by_id[attempt_id]
        cleanup = _read_bound_json(
            root / f"cleanup-{attempt['cohort']}-{attempt_id}.json",
            schema=QUALIFICATION_CLEANUP_SCHEMA,
        )
        referenced_capacity.add(str(cleanup.get("capacity_receipt")))
    actual_capacity = {
        path.name for path in root.iterdir() if path.name.startswith("capacity-")
    }
    if actual_capacity != referenced_capacity:
        raise QualificationError("qualification set has orphan capacity evidence")


def _image_id(
    reference: str,
    *,
    tools: dict[str, Path],
    capacity_gate: QualificationCapacityGate,
    required: bool = True,
) -> str | None:
    completed = _completed(
        [
            "docker",
            "--context",
            DOCKER_CONTEXT,
            "image",
            "inspect",
            "--format",
            "{{.Id}}",
            reference,
        ],
        tools=tools,
        capacity_gate=capacity_gate,
        capture=True,
    )
    if completed.returncode != 0:
        detail = completed.stderr.strip()
        missing = completed.returncode == 1 and re.fullmatch(
            r"(?:Error response from daemon: )?No such image: .+", detail
        )
        if not required and missing:
            return None
        raise QualificationError(
            f"local image inspection failed ({completed.returncode}): {reference}; {detail}"
        )
    image_id = completed.stdout.strip()
    if re.fullmatch(r"sha256:[0-9a-f]{64}", image_id) is None:
        raise QualificationError(f"invalid local image id for {reference}")
    return image_id


def _remove_tag(
    reference: str,
    *,
    tools: dict[str, Path],
    capacity_gate: QualificationCapacityGate,
) -> None:
    if _image_id(reference, tools=tools, capacity_gate=capacity_gate, required=False) is None:
        return
    _run(
        ["docker", "--context", DOCKER_CONTEXT, "image", "rm", reference],
        tools=tools,
        capacity_gate=capacity_gate,
        capture=True,
    )


def _final_tag_state(
    reference: str,
    previous_image_id: str | None,
    *,
    tools: dict[str, Path],
    capacity_gate: QualificationCapacityGate,
    owned_final_image_id: str | None = None,
) -> str:
    current = _image_id(reference, tools=tools, capacity_gate=capacity_gate, required=False)
    if current == previous_image_id:
        return "BASELINE_UNCHANGED"
    if owned_final_image_id is not None and current == owned_final_image_id:
        return "TASK_OWNED_RETAINED"
    raise QualificationError("final image tag ownership is ambiguous")


def _capacity_snapshot(
    *, root: Path, cohort: str, capacity_gate: QualificationCapacityGate
) -> tuple[Path, dict[str, Any]]:
    payload = capacity_gate.receipt
    digest = str(payload.get("receipt_digest", "")).removeprefix("sha256:")
    if _HEX_DIGEST.fullmatch(digest) is None:
        raise QualificationError("scoped capacity receipt digest is invalid")
    if any(
        path.name.endswith(f"-{digest}.json") and path.name.startswith("capacity-")
        for path in root.iterdir()
    ):
        raise QualificationError("scoped capacity receipt was already used in this set")
    path = root / f"capacity-{cohort}-{digest}.json"
    _write_new(path, payload)
    return path, payload


def _attempt_id(
    *, set_manifest: dict[str, Any], cohort: str, capacity_gate: QualificationCapacityGate
) -> str:
    return grade_refresh.digest_bytes(
        grade_refresh.canonical_bytes(
            {
                "set_receipt_digest": set_manifest["receipt_digest"],
                "cohort": cohort,
                "capacity_receipt_digest": capacity_gate.receipt["receipt_digest"],
            }
        )
    ).removeprefix("sha256:")


def _attempt_resolved(
    root: Path,
    *,
    attempt_path: Path,
    attempt: dict[str, Any],
    completions: set[str],
    cleanups: set[str],
) -> bool:
    attempt_id = str(attempt["attempt_id"])
    if attempt_id in completions and attempt_id in cleanups:
        raise QualificationError("qualification attempt has conflicting resolutions")
    attempt_sha256 = grade_refresh.digest_file(attempt_path)
    cohort = str(attempt["cohort"])
    if attempt_id in cleanups:
        cleanup = _read_bound_json(
            root / f"cleanup-{cohort}-{attempt_id}.json",
            schema=QUALIFICATION_CLEANUP_SCHEMA,
        )
        capacity_name = cleanup.get("capacity_receipt")
        if not isinstance(capacity_name, str):
            return False
        capacity_path = _safe_set_child(
            root, capacity_name, label="cleanup capacity receipt"
        )
        try:
            capacity = _read_bound_json(
                capacity_path, schema="McpTrustQualificationCapacityReceiptV1"
            )
            validate_qualification_capacity_receipt(
                capacity,
                operation="cleanup",
                receipt_set=root.name,
                cohort=cohort,
            )
        except (QualificationError, HostCapacityError):
            return False
        owned_final_id = _owned_final_image_id(
            root, attempt_path=attempt_path, attempt=attempt
        )
        final_state = cleanup.get("final_tag_state")
        return (
            cleanup.get("attempt_path") == attempt_path.name
            and cleanup.get("attempt_sha256") == attempt_sha256
            and cleanup.get("capacity_receipt_sha256")
            == grade_refresh.digest_file(capacity_path)
            and cleanup.get("capacity_receipt_digest")
            == capacity.get("receipt_digest")
            and cleanup.get("exit_classification") == "CLEANUP_CONFIRMED"
            and cleanup.get("temporary_tag_absent") is True
            and final_state in {"BASELINE_UNCHANGED", "TASK_OWNED_RETAINED"}
            and (final_state != "TASK_OWNED_RETAINED" or owned_final_id is not None)
            and cleanup.get("oci_outputs_absent") is True
            and cleanup.get("execution_boundary") == EXECUTION_BOUNDARY
            and grade_refresh._stable_image_build_tool_versions(
                cleanup.get("tool_versions")
            )
            and isinstance(cleanup.get("tool_digests"), dict)
            and set(cleanup["tool_digests"]) == {"docker", "docker_buildx"}
            and all(
                isinstance(value, str)
                and _HEX_DIGEST.fullmatch(value.removeprefix("sha256:")) is not None
                for value in cleanup["tool_digests"].values()
            )
        )
    if attempt_id in completions:
        receipt = root / f"{cohort}.json"
        if not receipt.is_file():
            return False
        completion = _read_bound_json(
            root / f"complete-{cohort}-{attempt_id}.json",
            schema=QUALIFICATION_COMPLETION_SCHEMA,
        )
        try:
            receipt_payload = grade_refresh.load_json(receipt)
        except grade_refresh.GradeRefreshError:
            return False
        return (
            completion.get("attempt_path") == attempt_path.name
            and completion.get("attempt_sha256") == attempt_sha256
            and completion.get("qualification_receipt") == receipt.name
            and completion.get("qualification_receipt_sha256")
            == grade_refresh.digest_file(receipt)
            and completion.get("qualification_receipt_digest")
            == receipt_payload.get("receipt_digest")
            and completion.get("exit_classification") == "QUALIFIED_REPEATABLE"
        )
    return False


def _unresolved_attempts(
    root: Path, *, cohort: str, set_manifest: dict[str, Any]
) -> list[tuple[Path, dict[str, Any]]]:
    attempts, completions, cleanups, _ownerships = _validated_set_attempts(
        root, cohort=cohort, set_manifest=set_manifest
    )
    return [
        (path, attempt)
        for path, attempt in attempts
        if not _attempt_resolved(
            root,
            attempt_path=path,
            attempt=attempt,
            completions=completions,
            cleanups=cleanups,
        )
    ]


def _begin_attempt(
    *,
    root: Path,
    set_manifest: dict[str, Any],
    cohort: str,
    attempt_id: str,
    capacity_gate: QualificationCapacityGate,
    image_reference: str,
    temporary_reference: str,
    previous_final_image_id: str | None,
    output_paths: list[str],
    tools: dict[str, Path],
) -> tuple[Path, dict[str, Any]]:
    if _lstat(root / f"{cohort}.json") is not None:
        raise QualificationError(f"qualification receipt already exists: {cohort}.json")
    if _unresolved_attempts(root, cohort=cohort, set_manifest=set_manifest):
        raise QualificationError(
            f"qualification cleanup is required before retrying cohort: {cohort}"
        )
    capacity_path, capacity = _capacity_snapshot(
        root=root, cohort=cohort, capacity_gate=capacity_gate
    )
    expected_attempt_id = _attempt_id(
        set_manifest=set_manifest, cohort=cohort, capacity_gate=capacity_gate
    )
    if attempt_id != expected_attempt_id:
        raise QualificationError("qualification attempt identity differs")
    tool_snapshot = {
        name: {
            "path": path.relative_to(ROOT).as_posix(),
            "sha256": grade_refresh.digest_file(path),
        }
        for name, path in sorted(tools.items())
    }
    attempt_binding = {
        "set_receipt_digest": set_manifest["receipt_digest"],
        "cohort": cohort,
        "capacity_receipt_digest": capacity["receipt_digest"],
        "image_reference": image_reference,
        "temporary_reference": temporary_reference,
        "previous_final_image_id": previous_final_image_id,
        "oci_outputs": output_paths,
        "validation_receipt": f"tmp/qualification/{cohort}-receipt.json",
        "tool_snapshot": tool_snapshot,
    }
    payload: dict[str, Any] = {
        "schema": QUALIFICATION_ATTEMPT_SCHEMA,
        "attempt_id": attempt_id,
        **attempt_binding,
        "capacity_receipt": capacity_path.name,
        "capacity_receipt_sha256": grade_refresh.digest_file(capacity_path),
        "exit_classification": "PENDING_DOCKER_MUTATION_CLEANUP",
        "claim_ceiling": (
            "Pessimistic pre-mutation intent only; absent completion or cleanup evidence "
            "means Docker tag state and qualification remain UNKNOWN."
        ),
    }
    payload["receipt_digest"] = _unsigned_digest(payload)
    path = root / f"attempt-{cohort}-{attempt_id}.json"
    _write_new(path, payload)
    return path, payload


def _write_ownership(
    *, root: Path, attempt_path: Path, attempt: dict[str, Any], image_id: str
) -> Path:
    if _HEX_DIGEST.fullmatch(image_id.removeprefix("sha256:")) is None:
        raise QualificationError("owned final image identity is invalid")
    payload: dict[str, Any] = {
        "schema": QUALIFICATION_OWNERSHIP_SCHEMA,
        "cohort": attempt["cohort"],
        "attempt_id": attempt["attempt_id"],
        "attempt_path": attempt_path.name,
        "attempt_sha256": grade_refresh.digest_file(attempt_path),
        "owned_final_image_id": image_id,
        "exit_classification": "FINAL_TAG_MUTATION_AUTHORIZED",
    }
    payload["receipt_digest"] = _unsigned_digest(payload)
    path = root / f"ownership-{attempt['cohort']}-{attempt['attempt_id']}.json"
    _write_new(path, payload)
    return path


def _owned_final_image_id(
    root: Path, *, attempt_path: Path, attempt: dict[str, Any]
) -> str | None:
    path = root / f"ownership-{attempt['cohort']}-{attempt['attempt_id']}.json"
    if _lstat(path) is None:
        return None
    payload = _read_bound_json(path, schema=QUALIFICATION_OWNERSHIP_SCHEMA)
    image_id = payload.get("owned_final_image_id")
    if (
        set(payload) != _OWNERSHIP_KEYS
        or payload.get("cohort") != attempt.get("cohort")
        or payload.get("attempt_id") != attempt.get("attempt_id")
        or payload.get("attempt_path") != attempt_path.name
        or payload.get("attempt_sha256") != grade_refresh.digest_file(attempt_path)
        or payload.get("exit_classification") != "FINAL_TAG_MUTATION_AUTHORIZED"
        or not isinstance(image_id, str)
        or _HEX_DIGEST.fullmatch(image_id.removeprefix("sha256:")) is None
    ):
        raise QualificationError("qualification ownership receipt is invalid")
    return image_id


def _write_completion(
    *,
    root: Path,
    attempt_path: Path,
    attempt: dict[str, Any],
    receipt: Path,
    payload: dict[str, Any],
) -> Path:
    completion: dict[str, Any] = {
        "schema": QUALIFICATION_COMPLETION_SCHEMA,
        "cohort": attempt["cohort"],
        "attempt_id": attempt["attempt_id"],
        "attempt_path": attempt_path.name,
        "attempt_sha256": grade_refresh.digest_file(attempt_path),
        "qualification_receipt": receipt.name,
        "qualification_receipt_sha256": grade_refresh.digest_bytes(
            json.dumps(payload, indent=2, sort_keys=True).encode() + b"\n"
        ),
        "qualification_receipt_digest": payload["receipt_digest"],
        "exit_classification": "QUALIFIED_REPEATABLE",
    }
    completion["receipt_digest"] = _unsigned_digest(completion)
    path = root / f"complete-{attempt['cohort']}-{attempt['attempt_id']}.json"
    _write_new(path, completion)
    return path


def qualify(
    cohort: str,
    config: dict[str, Any],
    *,
    buildx: str,
    receipt_root: Path,
    set_manifest: dict[str, Any],
    tools: dict[str, Path],
    capacity_gate: QualificationCapacityGate,
) -> Path:
    platform = config.get("platform")
    cohort_config = dict(config)
    cohort_config.pop("platform", None)
    try:
        config = dependency_boundary.validate_cohort(
            cohort,
            cohort_config,
            repo_root=ROOT,
            platform=platform,
        )
    except dependency_boundary.DependencyBoundaryError as exc:
        raise QualificationError(str(exc)) from exc
    _require_safe_directory(receipt_root, label="qualification receipt set")
    receipt = receipt_root / f"{cohort}.json"
    if _lstat(receipt) is not None:
        raise QualificationError(f"qualification receipt already exists: {receipt.name}")
    capacity_gate.require_scope(
        operation="qualification", receipt_set=receipt_root.name, cohort=cohort
    )
    image_reference = dependency_boundary.local_image_tag(config["image_reference"])
    dockerfile = dependency_boundary.repository_file(ROOT, config["dockerfile"])
    build_source_sha256 = grade_refresh.digest_file(ROOT / dockerfile)
    base_images = sorted({str(config["node_base"]), str(config["python_base"])})
    manifests, locks, artifacts, normalized_locks, normalized_artifacts = (
        _dependency_inputs(cohort, config)
    )
    platform_name = str(platform)
    build_input = {
        "build_source_sha256": build_source_sha256,
        "base_images": base_images,
        "platform": platform_name,
        "dependency_manifests": manifests,
        "dependency_locks": dict(sorted(normalized_locks.items())),
        "dependency_artifacts": normalized_artifacts,
        "build_options": BUILD_OPTIONS,
        "execution_boundary": EXECUTION_BOUNDARY,
    }
    common = [
        buildx,
        "build",
        "--builder",
        DOCKER_CONTEXT,
        "--network",
        "none",
        "--pull=false",
        "--no-cache",
        "--platform",
        platform_name,
        "--provenance=false",
        "--sbom=false",
        "--build-arg",
        "SOURCE_DATE_EPOCH=1710000000",
        "-f",
        dockerfile,
    ]
    output_root = ROOT / "tmp/qualification"
    _ensure_safe_directory(output_root, label="qualification OCI output root")
    _require_private_directory(output_root, label="qualification OCI output root")
    first_output = f"tmp/qualification/{cohort}-first.oci.tar"
    second_output = f"tmp/qualification/{cohort}-second.oci.tar"
    if _lstat(ROOT / first_output) is not None or _lstat(ROOT / second_output) is not None:
        raise QualificationError(f"qualification output already exists: {cohort}")
    attempt_id = _attempt_id(
        set_manifest=set_manifest, cohort=cohort, capacity_gate=capacity_gate
    )
    first_reference = f"mcp-trust-qualification:v0-{attempt_id}-first"
    if (
        _image_id(
            first_reference,
            tools=tools,
            capacity_gate=capacity_gate,
            required=False,
        )
        is not None
    ):
        raise QualificationError(f"qualification tag already exists: {first_reference}")
    previous_final_id = _image_id(
        image_reference,
        tools=tools,
        capacity_gate=capacity_gate,
        required=False,
    )
    first_command = [
        *common,
        f"--output=type=oci,dest={first_output},rewrite-timestamp=true",
        "-t",
        first_reference,
        ".",
    ]
    second_command = [
        *common,
        f"--output=type=oci,dest={second_output},rewrite-timestamp=true",
        "-t",
        image_reference,
        ".",
    ]
    first_load = ["docker", "--context", DOCKER_CONTEXT, "load", "-i", first_output]
    second_load = ["docker", "--context", DOCKER_CONTEXT, "load", "-i", second_output]
    boundary_before = _execution_boundary(buildx, tools=tools, capacity_gate=capacity_gate)
    tools_before = _tool_digests(tools, buildx)
    versions_before = _tool_versions(buildx, tools=tools, capacity_gate=capacity_gate)
    attempt_path, attempt = _begin_attempt(
        root=receipt_root,
        set_manifest=set_manifest,
        cohort=cohort,
        attempt_id=attempt_id,
        capacity_gate=capacity_gate,
        image_reference=image_reference,
        temporary_reference=first_reference,
        previous_final_image_id=previous_final_id,
        output_paths=[first_output, second_output],
        tools=tools,
    )
    first_id: str | None = None
    second_id: str | None = None
    owned_final_id: str | None = None
    succeeded = False
    try:
        try:
            _run(first_command, tools=tools, capacity_gate=capacity_gate, timeout=900)
            _run(first_load, tools=tools, capacity_gate=capacity_gate, timeout=300)
            first_id = _image_id(first_reference, tools=tools, capacity_gate=capacity_gate)
            _run(second_command, tools=tools, capacity_gate=capacity_gate, timeout=900)
            _write_ownership(
                root=receipt_root,
                attempt_path=attempt_path,
                attempt=attempt,
                image_id=first_id,
            )
            owned_final_id = first_id
            _run(second_load, tools=tools, capacity_gate=capacity_gate, timeout=300)
            second_id = _image_id(image_reference, tools=tools, capacity_gate=capacity_gate)
            if first_id != second_id:
                raise QualificationError(
                    f"repeat builds differed for {cohort}: {first_id} != {second_id}"
                )
        finally:
            for output in (ROOT / first_output, ROOT / second_output):
                if _lstat(output) is not None:
                    if output.is_symlink() or not output.is_file():
                        raise QualificationError("qualification output cleanup target is unsafe")
                    output.unlink()
            _remove_tag(first_reference, tools=tools, capacity_gate=capacity_gate)
        boundary_after = _execution_boundary(buildx, tools=tools, capacity_gate=capacity_gate)
        tools_after = _tool_digests(tools, buildx)
        versions_after = _tool_versions(buildx, tools=tools, capacity_gate=capacity_gate)
        if (
            boundary_before != boundary_after
            or tools_before != tools_after
            or versions_before != versions_after
        ):
            raise QualificationError("qualification execution boundary changed during build")
        if first_id is None or second_id is None:
            raise QualificationError("qualification image IDs are unavailable")
        payload: dict[str, Any] = {
            "schema": grade_refresh.IMAGE_BUILD_QUALIFICATION_SCHEMA,
            "observed_at": datetime.now(tz=UTC).isoformat(),
            "exit_classification": "QUALIFIED_REPEATABLE",
            "qualification_max_age_seconds": 86_400,
            "image_reference": image_reference,
            "platform": platform_name,
            "build_source_sha256": build_source_sha256,
            "build_input_digest": grade_refresh.digest_bytes(
                grade_refresh.canonical_bytes(build_input)
            ),
            "base_images": base_images,
            "dependency_manifests": manifests,
            "dependency_locks": locks,
            "dependency_artifacts": artifacts,
            "build_network_policy": ["none"],
            "build_options": BUILD_OPTIONS,
            "build_commands": [first_command, second_command],
            "load_commands": [first_load, second_load],
            "execution_boundary": boundary_after,
            "tool_versions": versions_after,
            "tool_digests": tools_after,
            "first_build_image_id": first_id,
            "second_build_image_id": second_id,
            "repeatable": True,
        }
        payload["receipt_digest"] = grade_refresh.digest_bytes(
            grade_refresh.canonical_bytes(payload)
        )
        validation_receipt = ROOT / f"tmp/qualification/{cohort}-receipt.json"
        _write_new(validation_receipt, payload)
        try:
            validated = grade_refresh._image_build_qualification(
                repo_root=ROOT,
                reference=image_reference,
                build_source=dockerfile,
                build_source_sha256=build_source_sha256,
                receipt_path=validation_receipt.relative_to(ROOT).as_posix(),
            )
            if validated is None:
                raise QualificationError(
                    f"generated receipt failed readback verification: {cohort}"
                )
        finally:
            validation_receipt.unlink(missing_ok=True)
        _write_completion(
            root=receipt_root,
            attempt_path=attempt_path,
            attempt=attempt,
            receipt=receipt,
            payload=payload,
        )
        _write_new(receipt, payload)
        succeeded = True
        return receipt
    finally:
        if not succeeded:
            _final_tag_state(
                image_reference,
                previous_final_id,
                tools=tools,
                capacity_gate=capacity_gate,
                owned_final_image_id=owned_final_id,
            )


def _remove_attempt_outputs(attempt: dict[str, Any]) -> None:
    outputs = attempt.get("oci_outputs")
    cohort = attempt.get("cohort")
    expected = [
        f"tmp/qualification/{cohort}-first.oci.tar",
        f"tmp/qualification/{cohort}-second.oci.tar",
    ]
    if outputs != expected:
        raise QualificationError("cleanup intent OCI output scope is invalid")
    for relative in expected:
        path = ROOT / relative
        metadata = _lstat(path)
        if metadata is None:
            continue
        if (
            path.is_symlink()
            or not path.is_file()
            or metadata.st_uid != os.getuid()
        ):
            raise QualificationError("cleanup OCI output target is unsafe")
        path.unlink()
    validation = attempt.get("validation_receipt")
    expected_validation = f"tmp/qualification/{cohort}-receipt.json"
    if validation != expected_validation:
        raise QualificationError("cleanup validation receipt scope is invalid")
    validation_path = ROOT / expected_validation
    validation_metadata = _lstat(validation_path)
    if validation_metadata is not None:
        if (
            validation_path.is_symlink()
            or not validation_path.is_file()
            or validation_metadata.st_uid != os.getuid()
            or stat.S_IMODE(validation_metadata.st_mode) & 0o077
        ):
            raise QualificationError("cleanup validation receipt target is unsafe")
        validation_path.unlink()
    snapshot = attempt.get("tool_snapshot")
    if not _valid_attempt_tool_snapshot(snapshot):
        raise QualificationError("cleanup tool snapshot scope is invalid")
    assert isinstance(snapshot, dict)
    for name, descriptor in snapshot.items():
        path = ROOT / descriptor["path"]
        metadata = _lstat(path)
        if metadata is None:
            continue
        if (
            path != ROOT / f"tmp/qualification/tools/{name}"
            or path.is_symlink()
            or not path.is_file()
            or metadata.st_uid != os.getuid()
            or grade_refresh.digest_file(path) != descriptor["sha256"]
        ):
            raise QualificationError("cleanup tool snapshot target is unsafe")
        path.unlink()
    snapshot_root = ROOT / "tmp/qualification/tools"
    if _lstat(snapshot_root) is not None:
        if snapshot_root.is_symlink() or not snapshot_root.is_dir() or any(
            snapshot_root.iterdir()
        ):
            raise QualificationError("cleanup tool snapshot directory is unsafe")
        snapshot_root.rmdir()


def _admit_cleanup_residue(
    *, capacity_gate: QualificationCapacityGate, attempt: dict[str, Any]
) -> None:
    capacity_gate.require_current()
    _remove_attempt_outputs(attempt)


def cleanup_interrupted(
    cohort: str,
    *,
    receipt_root: Path,
    set_manifest: dict[str, Any],
    tools: dict[str, Path],
    capacity_gate: QualificationCapacityGate,
    buildx: str,
) -> Path:
    capacity_gate.require_scope(
        operation="cleanup", receipt_set=receipt_root.name, cohort=cohort
    )
    unresolved = _unresolved_attempts(
        receipt_root, cohort=cohort, set_manifest=set_manifest
    )
    if len(unresolved) != 1:
        raise QualificationError(
            f"cleanup requires exactly one unresolved attempt for cohort: {cohort}"
        )
    attempt_path, attempt = unresolved[0]
    binding = set_manifest["cohort_bindings"][cohort]
    image_reference = str(attempt.get("image_reference"))
    temporary_reference = str(attempt.get("temporary_reference"))
    if (
        attempt.get("set_receipt_digest") != set_manifest["receipt_digest"]
        or image_reference != binding["image_reference"]
        or temporary_reference
        != f"mcp-trust-qualification:v0-{attempt['attempt_id']}-first"
        or attempt.get("exit_classification") != "PENDING_DOCKER_MUTATION_CLEANUP"
    ):
        raise QualificationError("cleanup intent binding is invalid")
    capacity_path, capacity = _capacity_snapshot(
        root=receipt_root, cohort=cohort, capacity_gate=capacity_gate
    )
    boundary_before = _execution_boundary(
        buildx, tools=tools, capacity_gate=capacity_gate
    )
    tools_before = _tool_digests(tools, buildx)
    versions_before = _tool_versions(
        buildx, tools=tools, capacity_gate=capacity_gate
    )
    _remove_tag(
        temporary_reference, tools=tools, capacity_gate=capacity_gate
    )
    previous = attempt.get("previous_final_image_id")
    if previous is not None and (
        not isinstance(previous, str)
        or _HEX_DIGEST.fullmatch(previous.removeprefix("sha256:")) is None
    ):
        raise QualificationError("cleanup prior final image binding is invalid")
    owned_final_id = _owned_final_image_id(
        receipt_root, attempt_path=attempt_path, attempt=attempt
    )
    final_tag_state = _final_tag_state(
        image_reference,
        previous,
        tools=tools,
        capacity_gate=capacity_gate,
        owned_final_image_id=owned_final_id,
    )
    temporary_absent = (
        _image_id(
            temporary_reference,
            tools=tools,
            capacity_gate=capacity_gate,
            required=False,
        )
        is None
    )
    boundary_after = _execution_boundary(
        buildx, tools=tools, capacity_gate=capacity_gate
    )
    tools_after = _tool_digests(tools, buildx)
    versions_after = _tool_versions(
        buildx, tools=tools, capacity_gate=capacity_gate
    )
    outputs_absent = all(_lstat(ROOT / path) is None for path in attempt["oci_outputs"])
    if (
        not temporary_absent
        or not outputs_absent
        or boundary_before != boundary_after
        or tools_before != tools_after
        or versions_before != versions_after
    ):
        raise QualificationError("interruption cleanup readback did not prove containment")
    payload: dict[str, Any] = {
        "schema": QUALIFICATION_CLEANUP_SCHEMA,
        "cohort": cohort,
        "attempt_id": attempt["attempt_id"],
        "attempt_path": attempt_path.name,
        "attempt_sha256": grade_refresh.digest_file(attempt_path),
        "capacity_receipt": capacity_path.name,
        "capacity_receipt_sha256": grade_refresh.digest_file(capacity_path),
        "capacity_receipt_digest": capacity["receipt_digest"],
        "temporary_tag_absent": True,
        "final_tag_state": final_tag_state,
        "oci_outputs_absent": True,
        "execution_boundary": boundary_after,
        "tool_versions": versions_after,
        "tool_digests": tools_after,
        "exit_classification": "CLEANUP_CONFIRMED",
        "claim_ceiling": (
            "Exact task-owned interruption cleanup readback only; no image "
            "qualification, MCP execution, publication, deployment, or freshness claim."
        ),
    }
    payload["receipt_digest"] = _unsigned_digest(payload)
    path = receipt_root / f"cleanup-{cohort}-{attempt['attempt_id']}.json"
    _write_new(path, payload)
    return path


def main() -> int:
    parser = argparse.ArgumentParser()
    operation = parser.add_mutually_exclusive_group(required=True)
    operation.add_argument(
        "--cohort",
        choices=COHORTS,
        help="qualify exactly one named cohort",
    )
    operation.add_argument(
        "--cleanup-cohort",
        choices=COHORTS,
        help="resolve exactly one interrupted cohort under fresh cleanup capacity",
    )
    parser.add_argument(
        "--receipt-set",
        required=True,
        help="new or valid append-only V122 receipt-set directory",
    )
    parser.add_argument(
        "--host-capacity",
        required=True,
        type=Path,
        help="fresh set/cohort/operation-scoped capacity receipt",
    )
    args = parser.parse_args()
    cohort = args.cohort or args.cleanup_cohort
    operation_name = "qualification" if args.cohort else "cleanup"
    capacity_gate = _load_capacity_gate(
        args.host_capacity,
        operation=operation_name,
        receipt_set=args.receipt_set,
        cohort=cohort,
    )
    with _cohort_lock(args.receipt_set, cohort):
        return _main_locked(args=args, cohort=cohort, capacity_gate=capacity_gate)


def _main_locked(
    *, args: argparse.Namespace, cohort: str, capacity_gate: QualificationCapacityGate
) -> int:
    try:
        payload = dependency_boundary.validate_preparation_inputs(
            grade_refresh.load_json(INPUTS), repo_root=ROOT
        )
    except dependency_boundary.DependencyBoundaryError as exc:
        raise QualificationError(str(exc)) from exc
    cohorts = payload["cohorts"]
    platform = payload.get("platform")
    if not isinstance(platform, str):
        raise QualificationError("qualification platform is unavailable")
    receipt_root, set_manifest = _open_receipt_set(
        args.receipt_set, cohorts=cohorts, platform=platform
    )
    if args.cohort:
        if _lstat(receipt_root / f"{cohort}.json") is not None:
            raise QualificationError(f"qualification receipt already exists: {cohort}.json")
        if _unresolved_attempts(
            receipt_root, cohort=cohort, set_manifest=set_manifest
        ):
            raise QualificationError(
                f"qualification cleanup is required before retrying cohort: {cohort}"
            )
    else:
        unresolved = _unresolved_attempts(
            receipt_root, cohort=cohort, set_manifest=set_manifest
        )
        if len(unresolved) != 1:
            raise QualificationError(
                f"cleanup requires exactly one unresolved attempt for cohort: {cohort}"
            )
        _admit_cleanup_residue(
            capacity_gate=capacity_gate, attempt=unresolved[0][1]
        )
    if shutil.which("docker-buildx") is None:
        raise QualificationError("docker-buildx executable is unavailable")
    output_root = ROOT / "tmp/qualification"
    _ensure_safe_directory(output_root, label="qualification OCI output root")
    if args.cohort:
        _cleanup_orphan_tool_snapshot(output_root, "docker-buildx")
    _require_empty_directory(output_root, label="qualification OCI output root")
    tools = _snapshot_tools(output_root, "docker-buildx")
    try:
        if args.cohort:
            config = cohorts.get(cohort)
            if not isinstance(config, dict):
                raise QualificationError(f"dependency cohort is unavailable: {cohort}")
            config = {**config, "platform": platform}
            receipt = qualify(
                cohort,
                config,
                buildx="docker-buildx",
                receipt_root=receipt_root,
                set_manifest=set_manifest,
                tools=tools,
                capacity_gate=capacity_gate,
            )
            print(f"QUALIFIED {cohort} {receipt.relative_to(ROOT)}")
        else:
            receipt = cleanup_interrupted(
                cohort,
                receipt_root=receipt_root,
                set_manifest=set_manifest,
                tools=tools,
                capacity_gate=capacity_gate,
                buildx="docker-buildx",
            )
            print(f"CLEANUP_CONFIRMED {cohort} {receipt.relative_to(ROOT)}")
    finally:
        _cleanup_tool_snapshot(tools)
    print("NO_PUBLICATION NO_DEPLOYMENT NO_SCHEDULER_MUTATION")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
