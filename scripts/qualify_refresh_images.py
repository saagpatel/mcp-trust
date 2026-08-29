#!/usr/bin/env python3
"""Build each approved refresh image twice and emit fail-closed receipts.

The builds consume only prepared local artifacts, run with BuildKit network
mode ``none``, bypass caches, and never publish an image or catalog artifact.
"""

from __future__ import annotations

import argparse
import json
import os
import re
import shutil
import stat
import subprocess
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from mcp_trust import dependency_boundary, grade_refresh
from mcp_trust.engine.sandbox import normalize_local_docker_host

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


def _completed(
    command: list[str],
    *,
    tools: dict[str, Path],
    capture: bool = False,
    timeout: int = 60,
) -> subprocess.CompletedProcess[str]:
    executable = tools.get(command[0])
    if executable is None:
        raise QualificationError(f"unbound qualification executable: {command[0]}")
    runtime_command = [executable.as_posix(), *command[1:]]
    environment = os.environ.copy()
    for key in _REDIRECT_ENVIRONMENT:
        environment.pop(key, None)
    environment["DOCKER_CONTEXT"] = DOCKER_CONTEXT
    environment["PATH"] = executable.parent.as_posix()
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
    capture: bool = False,
    timeout: int = 60,
) -> str:
    completed = _completed(command, tools=tools, capture=capture, timeout=timeout)
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


def _new_receipt_set_root(receipt_set: str) -> Path:
    if (
        _SAFE_RECEIPT_SET.fullmatch(receipt_set) is None
        or receipt_set in {".", ".."}
        or "\\" in receipt_set
    ):
        raise QualificationError("receipt set must be one safe versioned path component")
    _require_safe_directory(RECEIPT_ROOT, label="qualification receipt root")
    target = RECEIPT_ROOT / receipt_set
    if _lstat(target) is not None:
        raise QualificationError(f"qualification receipt set already exists: {receipt_set}")
    return target


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


def _execution_boundary(buildx: str, *, tools: dict[str, Path]) -> dict[str, object]:
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
        [buildx, "inspect", DOCKER_CONTEXT], tools=tools, capture=True
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


def _tool_versions(buildx: str, *, tools: dict[str, Path]) -> dict[str, str]:
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
        capture=True,
    )
    buildx_version = _run([buildx, "version"], tools=tools, capture=True)
    buildkit_inspect = _run(
        [buildx, "inspect", DOCKER_CONTEXT], tools=tools, capture=True
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


def _image_id(
    reference: str, *, tools: dict[str, Path], required: bool = True
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


def _remove_tag(reference: str, *, tools: dict[str, Path]) -> None:
    if _image_id(reference, tools=tools, required=False) is None:
        return
    _run(
        ["docker", "--context", DOCKER_CONTEXT, "image", "rm", reference],
        tools=tools,
        capture=True,
    )


def _restore_final_tag(
    reference: str, previous_image_id: str | None, *, tools: dict[str, Path]
) -> None:
    current = _image_id(reference, tools=tools, required=False)
    if previous_image_id is None:
        if current is not None:
            _remove_tag(reference, tools=tools)
        return
    if current != previous_image_id:
        _run(
            [
                "docker",
                "--context",
                DOCKER_CONTEXT,
                "tag",
                previous_image_id,
                reference,
            ],
            tools=tools,
            capture=True,
        )


def qualify(
    cohort: str,
    config: dict[str, Any],
    *,
    buildx: str,
    receipt_root: Path,
    tools: dict[str, Path],
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
    first_reference = f"mcp-trust-qualification:{receipt_root.name}-{cohort}-first"
    if _image_id(first_reference, tools=tools, required=False) is not None:
        raise QualificationError(f"qualification tag already exists: {first_reference}")
    previous_final_id = _image_id(image_reference, tools=tools, required=False)
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
    boundary_before = _execution_boundary(buildx, tools=tools)
    tools_before = _tool_digests(tools, buildx)
    versions_before = _tool_versions(buildx, tools=tools)
    first_id: str | None = None
    second_id: str | None = None
    succeeded = False
    try:
        try:
            _run(first_command, tools=tools, timeout=900)
            _run(first_load, tools=tools, timeout=300)
            first_id = _image_id(first_reference, tools=tools)
            _run(second_command, tools=tools, timeout=900)
            _run(second_load, tools=tools, timeout=300)
            second_id = _image_id(image_reference, tools=tools)
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
            _remove_tag(first_reference, tools=tools)
        boundary_after = _execution_boundary(buildx, tools=tools)
        tools_after = _tool_digests(tools, buildx)
        versions_after = _tool_versions(buildx, tools=tools)
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
        _write_new(receipt, payload)
        try:
            validated = grade_refresh._image_build_qualification(
                repo_root=ROOT,
                reference=image_reference,
                build_source=dockerfile,
                build_source_sha256=build_source_sha256,
                receipt_path=receipt.relative_to(ROOT).as_posix(),
            )
        except BaseException:
            receipt.unlink()
            raise
        if validated is None:
            receipt.unlink()
            raise QualificationError(
                f"generated receipt failed readback verification: {cohort}"
            )
        succeeded = True
        return receipt
    finally:
        if not succeeded:
            _restore_final_tag(image_reference, previous_final_id, tools=tools)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--cohort",
        action="append",
        choices=("reference", "live-batch", "batch3", "batch4", "basic-memory"),
        help="qualify only the named cohort; may be repeated",
    )
    parser.add_argument(
        "--receipt-set",
        required=True,
        help="new versioned receipt-set directory below docker/refresh/qualification",
    )
    args = parser.parse_args()
    receipt_root = _new_receipt_set_root(args.receipt_set)
    try:
        payload = dependency_boundary.validate_preparation_inputs(
            grade_refresh.load_json(INPUTS), repo_root=ROOT
        )
    except dependency_boundary.DependencyBoundaryError as exc:
        raise QualificationError(str(exc)) from exc
    cohorts = payload["cohorts"]
    if shutil.which("docker-buildx") is None:
        raise QualificationError("docker-buildx executable is unavailable")
    names = args.cohort or [
        "reference",
        "live-batch",
        "batch3",
        "batch4",
        "basic-memory",
    ]
    output_root = ROOT / "tmp/qualification"
    _ensure_safe_directory(output_root, label="qualification OCI output root")
    _require_empty_directory(output_root, label="qualification OCI output root")
    tools = _snapshot_tools(output_root, "docker-buildx")
    try:
        receipt_root.mkdir(mode=0o700)
        for name in names:
            config = cohorts.get(name)
            if not isinstance(config, dict):
                raise QualificationError(f"dependency cohort is unavailable: {name}")
            config = {**config, "platform": payload.get("platform")}
            receipt = qualify(
                name,
                config,
                buildx="docker-buildx",
                receipt_root=receipt_root,
                tools=tools,
            )
            print(f"QUALIFIED {name} {receipt.relative_to(ROOT)}")
    finally:
        _cleanup_tool_snapshot(tools)
    print("NO_PUBLICATION NO_DEPLOYMENT NO_SCHEDULER_MUTATION")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
