"""Fail-closed input validation for refresh dependency and image preparation.

These helpers are intentionally pure and must run before any Docker, BuildKit,
package-manager, network, or output-path operation.
"""

from __future__ import annotations

import json
import re
from pathlib import Path, PurePosixPath
from typing import Any
from urllib.parse import urlsplit

PREPARATION_SCHEMA = "McpTrustDependencyPreparationInputsV1"
SOURCE_BUILD_SCHEMA = "McpTrustPythonSourceBuildInputsV1"
REGISTRY_ENDPOINTS = {
    "npm": ["https://registry.npmjs.org"],
    "python": ["https://files.pythonhosted.org", "https://pypi.org/simple"],
}

_COMPONENT = re.compile(r"[a-z0-9][a-z0-9._-]{0,127}")
_FILENAME = re.compile(r"[A-Za-z0-9][A-Za-z0-9._+-]{0,255}")
_LOCAL_IMAGE = re.compile(r"mcp-trust-[a-z0-9][a-z0-9._-]*:[A-Za-z0-9_][A-Za-z0-9_.-]{0,127}")
_IMAGE_ID = re.compile(r"sha256:[0-9a-f]{64}")
_DIGEST_IMAGE = re.compile(r"([^@\s]+)@sha256:[0-9a-f]{64}")
_NPM_NAME = re.compile(
    r"(?:@[a-z0-9][a-z0-9._~-]*/)?[a-z0-9][a-z0-9._~-]*"
)
_SEMVER_PART = r"(?:0|[1-9][0-9]*)"
_EXACT_SEMVER = re.compile(
    rf"{_SEMVER_PART}\.{_SEMVER_PART}\.{_SEMVER_PART}"
    r"(?:-[0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*)?"
    r"(?:\+[0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*)?"
)
_PYTHON_NAME = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]*")
_PYTHON_VERSION = re.compile(r"[A-Za-z0-9][A-Za-z0-9.!+_-]*")
_SHA256_HEX = re.compile(r"[0-9a-f]{64}")


class DependencyBoundaryError(ValueError):
    """An input crossed the refresh dependency trust boundary."""


def cohort_component(value: object) -> str:
    if not isinstance(value, str) or _COMPONENT.fullmatch(value) is None:
        raise DependencyBoundaryError("dependency cohort name is unsafe")
    if value in {".", ".."}:
        raise DependencyBoundaryError("dependency cohort name is unsafe")
    return value


def repository_file(repo_root: Path, value: object) -> str:
    """Return a canonical repository-relative regular file with no symlink hop."""
    if not isinstance(value, str) or not value or "\\" in value:
        raise DependencyBoundaryError("repository file path is unsafe")
    relative = Path(value)
    if relative.is_absolute() or any(part in {"", ".", ".."} for part in relative.parts):
        raise DependencyBoundaryError("repository file path is unsafe")
    root = repo_root.resolve(strict=True)
    cursor = root
    try:
        for part in relative.parts:
            cursor /= part
            if cursor.is_symlink():
                raise DependencyBoundaryError("repository file path uses a symlink")
        resolved = cursor.resolve(strict=True)
    except OSError as exc:
        raise DependencyBoundaryError("repository file is unavailable") from exc
    if not resolved.is_relative_to(root) or not resolved.is_file():
        raise DependencyBoundaryError("repository file escapes its root")
    return resolved.relative_to(root).as_posix()


def repository_dockerfile(
    repo_root: Path,
    value: object,
    *,
    expected_external_images: frozenset[str] | None = None,
) -> str:
    relative = repository_file(repo_root, value)
    try:
        lines = (repo_root / relative).read_text(encoding="utf-8").splitlines()
    except (OSError, UnicodeError) as exc:
        raise DependencyBoundaryError("Dockerfile is unreadable") from exc
    stages: set[str] = set()
    external: set[str] = set()
    for raw in lines:
        tokens = raw.strip().split()
        if not tokens:
            continue
        if tokens[0].upper() == "COPY":
            for token in tokens[1:]:
                if token.startswith("--from=") and token.removeprefix("--from=") not in stages:
                    raise DependencyBoundaryError(
                        "Dockerfile COPY uses an external image source"
                    )
            continue
        if tokens[0].upper() != "FROM":
            continue
        if len(tokens) not in {2, 4} or (len(tokens) == 4 and tokens[2].upper() != "AS"):
            raise DependencyBoundaryError("Dockerfile FROM instruction is invalid")
        source = tokens[1]
        if source not in stages:
            if _DIGEST_IMAGE.fullmatch(source) is None:
                raise DependencyBoundaryError("Dockerfile uses a mutable external image")
            external.add(source)
        if len(tokens) == 4:
            if _COMPONENT.fullmatch(tokens[3]) is None or tokens[3] in stages:
                raise DependencyBoundaryError("Dockerfile stage name is invalid")
            stages.add(tokens[3])
    if not external:
        raise DependencyBoundaryError("Dockerfile has no immutable external image")
    if expected_external_images is not None and external != expected_external_images:
        raise DependencyBoundaryError("Dockerfile base images do not match the descriptor")
    return relative


def immutable_image(value: object, *, repositories: frozenset[str]) -> str:
    if not isinstance(value, str):
        raise DependencyBoundaryError("base image is not immutable")
    matched = _DIGEST_IMAGE.fullmatch(value)
    if matched is None or matched.group(1) not in repositories:
        raise DependencyBoundaryError("base image is not an approved immutable reference")
    return value


def local_image_tag(value: object, *, prefix: str = "mcp-trust-") -> str:
    if (
        not isinstance(value, str)
        or not value.startswith(prefix)
        or _LOCAL_IMAGE.fullmatch(value) is None
    ):
        raise DependencyBoundaryError("local image tag is unsafe")
    return value


def immutable_image_id(value: object) -> str:
    if not isinstance(value, str) or _IMAGE_ID.fullmatch(value) is None:
        raise DependencyBoundaryError("local image id is invalid")
    return value


def npm_dependencies(value: object) -> dict[str, str]:
    if not isinstance(value, dict):
        raise DependencyBoundaryError("npm dependency map is invalid")
    normalized: dict[str, str] = {}
    for name, version in value.items():
        if (
            not isinstance(name, str)
            or _NPM_NAME.fullmatch(name) is None
            or not isinstance(version, str)
            or _EXACT_SEMVER.fullmatch(version) is None
        ):
            raise DependencyBoundaryError("npm dependencies must use exact semver sources")
        normalized[name] = version
    return normalized


def python_requirements(value: object) -> list[str]:
    if not isinstance(value, list):
        raise DependencyBoundaryError("python dependency list is invalid")
    normalized: list[str] = []
    for requirement in value:
        if not isinstance(requirement, str) or requirement.count("==") != 1:
            raise DependencyBoundaryError("python dependencies must use exact pins")
        name, version = requirement.split("==", 1)
        if (
            _PYTHON_NAME.fullmatch(name) is None
            or _PYTHON_VERSION.fullmatch(version) is None
        ):
            raise DependencyBoundaryError("python dependencies must use exact pins")
        normalized.append(requirement)
    if len(normalized) != len(set(normalized)):
        raise DependencyBoundaryError("python dependencies contain duplicates")
    return normalized


def _requirement_groups(text: str) -> list[str]:
    groups: list[str] = []
    current = ""
    for raw in text.splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        current += (" " if current else "") + line.removesuffix("\\").strip()
        if not line.endswith("\\"):
            groups.append(current)
            current = ""
    if current:
        raise DependencyBoundaryError("python lock has an unterminated continuation")
    return groups


def validate_python_lock(manifest_path: Path, lock_path: Path) -> None:
    try:
        direct = python_requirements(_requirement_groups(manifest_path.read_text()))
        locked_groups = _requirement_groups(lock_path.read_text())
    except (OSError, UnicodeError) as exc:
        raise DependencyBoundaryError("python dependency inputs are unreadable") from exc
    direct_versions = {
        re.sub(r"[-_.]+", "-", item.split("==", 1)[0]).lower(): item.split("==", 1)[1]
        for item in direct
    }
    locked_versions: dict[str, str] = {}
    group_pattern = re.compile(
        r"([A-Za-z0-9][A-Za-z0-9._-]*)==([A-Za-z0-9][A-Za-z0-9.!+_-]*)"
        r"(?:\s+--hash=sha256:[0-9a-f]{64})+"
    )
    for group in locked_groups:
        matched = group_pattern.fullmatch(group)
        if matched is None:
            raise DependencyBoundaryError("python lock escapes the approved source policy")
        name, version = matched.groups()
        normalized = re.sub(r"[-_.]+", "-", name).lower()
        if normalized in locked_versions:
            raise DependencyBoundaryError("python lock contains duplicate projects")
        locked_versions[normalized] = version
    if not locked_versions or any(
        locked_versions.get(name) != version for name, version in direct_versions.items()
    ):
        raise DependencyBoundaryError("python lock does not bind its direct requirements")


def validate_npm_lock(manifest_path: Path, lock_path: Path) -> None:
    try:
        manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
        lock = json.loads(lock_path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise DependencyBoundaryError("npm dependency inputs are unreadable") from exc
    dependencies = manifest.get("dependencies") if isinstance(manifest, dict) else None
    npm_dependencies(dependencies)
    packages = lock.get("packages") if isinstance(lock, dict) else None
    if (
        lock.get("lockfileVersion") != 3
        or not isinstance(packages, dict)
        or not isinstance(packages.get(""), dict)
        or packages[""].get("dependencies") != dependencies
    ):
        raise DependencyBoundaryError("npm lock does not bind its direct dependencies")
    found: set[str] = set()
    for path, package in packages.items():
        if path == "":
            continue
        if (
            not isinstance(path, str)
            or "node_modules/" not in path
            or not isinstance(package, dict)
            or package.get("link") is True
            or not isinstance(package.get("version"), str)
            or not isinstance(package.get("resolved"), str)
            or not package["resolved"].startswith("https://registry.npmjs.org/")
            or not isinstance(package.get("integrity"), str)
            or re.fullmatch(r"sha512-[A-Za-z0-9+/]+={0,2}", package["integrity"])
            is None
        ):
            raise DependencyBoundaryError("npm lock escapes the approved registry source")
        found.add(path.rsplit("node_modules/", 1)[-1])
    if not dependencies or not set(dependencies) <= found:
        raise DependencyBoundaryError("npm lock is incomplete")


def validate_npm_console_script_bindings(
    manifest_path: Path,
    lock_path: Path,
    bindings: dict[str, tuple[str, str]],
) -> None:
    """Bind qualified npm source references to one exact JS console script."""
    validate_npm_lock(manifest_path, lock_path)
    try:
        manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
        lock = json.loads(lock_path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise DependencyBoundaryError("npm dependency inputs are unreadable") from exc
    dependencies = npm_dependencies(manifest.get("dependencies"))
    packages = lock["packages"]
    for reference, binding in bindings.items():
        if (
            _NPM_NAME.fullmatch(reference) is None
            or not isinstance(binding, tuple)
            or len(binding) != 2
        ):
            raise DependencyBoundaryError("npm console-script binding is invalid")
        command, target = binding
        target_path = PurePosixPath(target) if isinstance(target, str) else None
        if (
            not isinstance(command, str)
            or _COMPONENT.fullmatch(command) is None
            or target_path is None
            or target_path.is_absolute()
            or any(part in {"", ".", ".."} for part in target_path.parts)
            or target_path.suffix not in {".js", ".mjs", ".cjs"}
        ):
            raise DependencyBoundaryError("npm console-script binding is unsafe")
        package = packages.get(f"node_modules/{reference}")
        if (
            reference not in dependencies
            or not isinstance(package, dict)
            or package.get("version") != dependencies[reference]
            or not isinstance(package.get("bin"), dict)
            or package["bin"].get(command) != target
        ):
            raise DependencyBoundaryError(
                "npm console-script binding differs from the exact package lock"
            )
        providers = []
        for dependency in dependencies:
            candidate = packages.get(f"node_modules/{dependency}")
            if isinstance(candidate, dict) and isinstance(candidate.get("bin"), dict):
                if command in candidate["bin"]:
                    providers.append(dependency)
        if providers != [reference]:
            raise DependencyBoundaryError("npm console-script binding is ambiguous")


def validate_cohort(
    name: object, value: object, *, repo_root: Path, platform: object
) -> dict[str, Any]:
    cohort_component(name)
    expected = {
        "image_reference",
        "dockerfile",
        "node_base",
        "python_base",
        "python_version",
        "npm",
        "python",
    }
    if isinstance(value, dict) and "source_build_preparer" in value:
        expected.add("source_build_preparer")
    if not isinstance(value, dict) or set(value) != expected:
        raise DependencyBoundaryError("dependency cohort descriptor is invalid")
    if platform not in {"linux/arm64", "linux/amd64"}:
        raise DependencyBoundaryError("dependency cohort platform is unsupported")
    local_image_tag(value["image_reference"])
    node_base = immutable_image(
        value["node_base"], repositories=frozenset({"node", "python"})
    )
    python_base = immutable_image(
        value["python_base"], repositories=frozenset({"python"})
    )
    repository_dockerfile(
        repo_root,
        value["dockerfile"],
        expected_external_images=frozenset({node_base, python_base}),
    )
    if not isinstance(value["python_version"], str) or re.fullmatch(
        r"[0-9]+\.[0-9]+", value["python_version"]
    ) is None:
        raise DependencyBoundaryError("python version is invalid")
    npm = npm_dependencies(value["npm"])
    python = python_requirements(value["python"])
    if not npm and not python:
        raise DependencyBoundaryError("dependency cohort is empty")
    if "source_build_preparer" in value:
        if value["source_build_preparer"] != "scripts/prepare_basic_memory_dependencies.py":
            raise DependencyBoundaryError("source-build preparer is not approved")
        repository_file(repo_root, value["source_build_preparer"])
    return value


def validate_preparation_inputs(payload: object, *, repo_root: Path) -> dict[str, Any]:
    expected = {
        "schema",
        "platform",
        "source_date_epoch",
        "registry_endpoints",
        "preparation_images",
        "cohorts",
    }
    if (
        not isinstance(payload, dict)
        or set(payload) != expected
        or payload.get("schema") != PREPARATION_SCHEMA
        or payload.get("platform") not in {"linux/arm64", "linux/amd64"}
        or type(payload.get("source_date_epoch")) is not int
        or payload["source_date_epoch"] <= 0
        or payload.get("registry_endpoints") != REGISTRY_ENDPOINTS
    ):
        raise DependencyBoundaryError("dependency preparation descriptor is invalid")
    preparation = payload.get("preparation_images")
    if not isinstance(preparation, dict) or set(preparation) != {
        "uv_python_dockerfile",
        "uv_python_reference",
    }:
        raise DependencyBoundaryError("preparation image descriptor is invalid")
    repository_dockerfile(repo_root, preparation["uv_python_dockerfile"])
    if preparation["uv_python_dockerfile"] != (
        "docker/refresh/Dockerfile.dependency-prep"
    ):
        raise DependencyBoundaryError("preparation Dockerfile is not approved")
    local_image_tag(
        preparation["uv_python_reference"], prefix="mcp-trust-dependency-prep:"
    )
    cohorts = payload.get("cohorts")
    if not isinstance(cohorts, dict) or not cohorts:
        raise DependencyBoundaryError("dependency cohorts are missing")
    for name, cohort in cohorts.items():
        validate_cohort(name, cohort, repo_root=repo_root, platform=payload["platform"])
    return payload


def validate_source_build_inputs(payload: object) -> dict[str, Any]:
    expected = {
        "schema",
        "platform",
        "python_base",
        "source_date_epoch",
        "inputs",
        "expected_wheels",
    }
    if (
        not isinstance(payload, dict)
        or set(payload) != expected
        or payload.get("schema") != SOURCE_BUILD_SCHEMA
        or payload.get("platform") != "linux/arm64"
        or payload.get("source_date_epoch") != 1710000000
        or not isinstance(payload.get("inputs"), list)
        or len(payload["inputs"]) != 4
        or not isinstance(payload.get("expected_wheels"), dict)
        or len(payload["expected_wheels"]) != 2
    ):
        raise DependencyBoundaryError("source-build input descriptor is invalid")
    immutable_image(payload["python_base"], repositories=frozenset({"python"}))
    filenames: set[str] = set()
    roles: list[str] = []
    for item in payload["inputs"]:
        if not isinstance(item, dict) or set(item) != {"filename", "role", "sha256", "url"}:
            raise DependencyBoundaryError("source-build input row is invalid")
        filename = item["filename"]
        try:
            parsed = urlsplit(item["url"]) if isinstance(item["url"], str) else None
            parsed_port = parsed.port if parsed is not None else None
        except ValueError as exc:
            raise DependencyBoundaryError("source-build input URL is invalid") from exc
        if (
            not isinstance(filename, str)
            or _FILENAME.fullmatch(filename) is None
            or filename in filenames
            or item["role"] not in {"build-tool", "untrusted-source"}
            or not isinstance(item["sha256"], str)
            or _SHA256_HEX.fullmatch(item["sha256"]) is None
            or parsed is None
            or parsed.scheme != "https"
            or parsed.hostname != "files.pythonhosted.org"
            or parsed_port is not None
            or parsed.username is not None
            or parsed.password is not None
            or parsed.query
            or parsed.fragment
            or not parsed.path.startswith("/packages/")
        ):
            raise DependencyBoundaryError("source-build input row is invalid")
        filenames.add(filename)
        roles.append(item["role"])
    if roles.count("build-tool") != 2 or roles.count("untrusted-source") != 2:
        raise DependencyBoundaryError("source-build input roles are invalid")
    for filename, digest in payload["expected_wheels"].items():
        if (
            not isinstance(filename, str)
            or _FILENAME.fullmatch(filename) is None
            or not filename.endswith(".whl")
            or not isinstance(digest, str)
            or _SHA256_HEX.fullmatch(digest) is None
        ):
            raise DependencyBoundaryError("expected wheel binding is invalid")
    return payload
