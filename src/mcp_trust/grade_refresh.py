"""Review-only qualification controls for catalog grade refreshes.

This module never scans a real MCP server, publishes a grade, changes a
scheduler, or deploys.  It inventories the reviewed corpus, binds the local
source and toolchain, proves whether the exact catalog images are present, and
produces deterministic fixture and review receipts for an operator.
"""

from __future__ import annotations

import hashlib
import importlib.metadata
import json
import os
import platform
import re
import shlex
import shutil
import subprocess
import sys
import tarfile
from collections.abc import Callable
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

from mcp_trust.core import grading
from mcp_trust.core.models import ServerSource
from mcp_trust.engine.sandbox import DockerSandbox, normalize_local_docker_host
from mcp_trust.engine.stub import StubEngine

PREFLIGHT_SCHEMA = "McpTrustGradeRefreshPreflightV1"
REPEATABILITY_SCHEMA = "McpTrustFixtureRepeatabilityV1"
TRIAGE_SCHEMA = "McpTrustGradeDiffTriageV1"
STATE_CARD_SCHEMA = "McpTrustGradeRefreshStateCardV1"
POLICY_SCHEMA = "McpTrustRefreshPolicyV2"
IMAGE_BUILD_QUALIFICATION_SCHEMA = "McpTrustImageBuildQualificationV2"
_SHA256 = re.compile(r"^sha256:[0-9a-f]{64}$")
_GRADE_INDEX = {grade: index for index, grade in enumerate(("A", "B", "C", "D", "F"))}
_PREFLIGHT_KEYS = frozenset(
    {
        "schema",
        "observed_at",
        "status",
        "safe_to_execute_catalog",
        "exit_classification",
        "source_binding",
        "catalog",
        "sandbox",
        "tool_versions",
        "scheduler",
        "reasons",
        "authority",
        "receipt_digest",
    }
)
_REPEATABILITY_KEYS = frozenset(
    {
        "schema",
        "observed_at",
        "status",
        "fixture_kind",
        "catalog_denominator",
        "first_digest",
        "second_digest",
        "repeatable",
        "claim_ceiling",
        "receipt_digest",
    }
)
_TRIAGE_KEYS = frozenset(
    {
        "schema",
        "candidate_manifest_digest",
        "preflight_receipt_digest",
        "repeatability_receipt_digest",
        "review_required",
        "publication_allowed",
        "findings",
        "counts",
        "candidate_claimed_state",
        "candidate_verification",
        "receipt_digest",
    }
)
_IMAGE_BUILD_QUALIFICATION_KEYS = frozenset(
    {
        "schema",
        "observed_at",
        "exit_classification",
        "qualification_max_age_seconds",
        "image_reference",
        "platform",
        "build_source_sha256",
        "build_input_digest",
        "base_images",
        "dependency_manifests",
        "dependency_locks",
        "dependency_artifacts",
        "build_network_policy",
        "build_options",
        "build_commands",
        "load_commands",
        "tool_versions",
        "first_build_image_id",
        "second_build_image_id",
        "repeatable",
        "receipt_digest",
    }
)
class GradeRefreshError(RuntimeError):
    """The review-only qualification contract is invalid or incomplete."""


@dataclass(frozen=True)
class RefreshPolicy:
    raw: dict[str, Any]
    scannable: frozenset[str]
    blocked: frozenset[str]
    masked: frozenset[str]
    unsupported: frozenset[str]
    credential_dependent: frozenset[str]
    backing_service_dependent: frozenset[str]


def _reject_duplicate_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise GradeRefreshError("duplicate JSON key")
        result[key] = value
    return result


def load_json(path: Path) -> Any:
    try:
        return json.loads(
            path.read_text(encoding="utf-8"),
            object_pairs_hook=_reject_duplicate_keys,
        )
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise GradeRefreshError(f"unreadable JSON input: {path.name}") from exc


def canonical_bytes(payload: object) -> bytes:
    return (
        json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode()
        + b"\n"
    )


def digest_bytes(content: bytes) -> str:
    return "sha256:" + hashlib.sha256(content).hexdigest()


def digest_file(path: Path) -> str:
    try:
        return digest_bytes(path.read_bytes())
    except OSError as exc:
        raise GradeRefreshError(f"unreadable source binding: {path.name}") from exc


def _slug_set(payload: dict[str, Any], field: str) -> frozenset[str]:
    value = payload.get(field)
    if not isinstance(value, list) or not all(isinstance(item, str) and item for item in value):
        raise GradeRefreshError(f"refresh policy field {field} must be a string list")
    if len(value) != len(set(value)):
        raise GradeRefreshError(f"refresh policy field {field} contains duplicates")
    return frozenset(value)


def _safe_relative_path(value: object) -> bool:
    return (
        isinstance(value, str)
        and bool(value)
        and not Path(value).is_absolute()
        and ".." not in Path(value).parts
    )


def _valid_image_build_descriptor(value: object) -> bool:
    if not isinstance(value, dict) or set(value) != {
        "path",
        "provenance_status",
        "reproducibility_status",
        "qualification_receipt",
    }:
        return False
    if not _safe_relative_path(value.get("path")):
        return False
    if value.get("provenance_status") not in {
        "SOURCE_CONTROLLED",
        "RECOVERED_HISTORICAL_ARTIFACT",
    }:
        return False
    reproducibility = value.get("reproducibility_status")
    receipt = value.get("qualification_receipt")
    if reproducibility == "UNKNOWN":
        return receipt is None
    return reproducibility == "VERIFIED" and _safe_relative_path(receipt)


def load_policy(policy_path: Path, seed_path: Path, masked_path: Path) -> RefreshPolicy:
    policy = load_json(policy_path)
    seed = load_json(seed_path)
    masked = load_json(masked_path)
    expected_keys = {
        "schema",
        "catalog_denominator",
        "default_sandbox_image",
        "image_build_sources",
        "scannable",
        "blocked",
        "intentionally_masked",
        "unsupported_upstream",
        "credential_dependent",
        "backing_service_dependent",
        "unsafe_to_execute_unsandboxed",
        "credential_policy",
        "network_policy",
        "freshness_objective_hours",
        "publication_review_required",
    }
    if not isinstance(policy, dict) or set(policy) != expected_keys:
        raise GradeRefreshError("refresh policy schema or fields are invalid")
    if policy.get("schema") != POLICY_SCHEMA:
        raise GradeRefreshError("refresh policy schema is unsupported")
    if not isinstance(seed, list) or not all(isinstance(row, dict) for row in seed):
        raise GradeRefreshError("catalog seed must be a JSON object list")
    if not isinstance(masked, list) or not all(isinstance(item, str) for item in masked):
        raise GradeRefreshError("masked grade input must be a string list")
    if len(masked) != len(set(masked)):
        raise GradeRefreshError("masked grade input contains duplicates")
    slugs = [row.get("slug") for row in seed]
    if not all(isinstance(slug, str) and slug for slug in slugs) or len(slugs) != len(set(slugs)):
        raise GradeRefreshError("catalog slugs are invalid or duplicated")
    catalog = frozenset(str(slug) for slug in slugs)
    if policy.get("catalog_denominator") != len(catalog):
        raise GradeRefreshError("refresh policy catalog denominator mismatch")
    image_refs = {
        source.get("sandbox_image") or policy.get("default_sandbox_image")
        for row in seed
        if isinstance((source := row.get("source")), dict)
        and source.get("command") is not None
    }
    image_build_sources = policy.get("image_build_sources")
    if (
        not isinstance(image_build_sources, dict)
        or set(image_build_sources) != image_refs
        or not all(_valid_image_build_descriptor(source) for source in image_build_sources.values())
    ):
        raise GradeRefreshError("refresh policy image build sources are invalid")
    fields = {
        "scannable": _slug_set(policy, "scannable"),
        "blocked": _slug_set(policy, "blocked"),
        "masked": _slug_set(policy, "intentionally_masked"),
        "unsupported": _slug_set(policy, "unsupported_upstream"),
        "credential_dependent": _slug_set(policy, "credential_dependent"),
        "backing_service_dependent": _slug_set(policy, "backing_service_dependent"),
    }
    for field, values in fields.items():
        if not values <= catalog:
            raise GradeRefreshError(f"refresh policy {field} contains an unknown slug")
    overlapping = fields["scannable"] & fields["blocked"]
    covered = fields["scannable"] | fields["blocked"]
    if overlapping or covered != catalog:
        raise GradeRefreshError("every catalog entry must be exactly scannable or blocked")
    if fields["masked"] != frozenset(masked):
        raise GradeRefreshError("refresh policy masking does not match masked-grades.json")
    if policy.get("unsafe_to_execute_unsandboxed") != "all-local-process-entries":
        raise GradeRefreshError("unsafe execution policy must fail closed for local processes")
    if policy.get("network_policy") != "none":
        raise GradeRefreshError("catalog refresh network policy must be none")
    if policy.get("credential_policy") != "dummy-values-network-off-only":
        raise GradeRefreshError("catalog refresh credential policy is unsafe")
    if type(policy.get("freshness_objective_hours")) is not int or int(
        policy["freshness_objective_hours"]
    ) <= 0:
        raise GradeRefreshError("freshness objective must be a positive integer")
    if policy.get("publication_review_required") is not True:
        raise GradeRefreshError("publication review must be required")
    return RefreshPolicy(raw=policy, **fields)


def catalog_inventory(
    *, seed_path: Path, masked_path: Path, policy_path: Path
) -> dict[str, Any]:
    policy = load_policy(policy_path, seed_path, masked_path)
    seed = load_json(seed_path)
    rows: list[dict[str, Any]] = []
    for raw in sorted(seed, key=lambda item: item["slug"]):
        source = raw.get("source")
        if not isinstance(source, dict):
            raise GradeRefreshError("catalog source is invalid")
        slug = raw["slug"]
        local_process = source.get("command") is not None
        image = source.get("sandbox_image") or policy.raw["default_sandbox_image"]
        build_descriptor = policy.raw["image_build_sources"].get(image, {})
        rows.append(
            {
                "slug": slug,
                "source_kind": source.get("kind"),
                "source_reference": source.get("reference"),
                "sandbox_image": image if local_process else None,
                "image_build_source": (
                    build_descriptor.get("path") if local_process else None
                ),
                "image_build_provenance_status": (
                    build_descriptor.get("provenance_status") if local_process else None
                ),
                "image_reproducibility_status": (
                    build_descriptor.get("reproducibility_status") if local_process else None
                ),
                "image_qualification_receipt": (
                    build_descriptor.get("qualification_receipt") if local_process else None
                ),
                "scannable": slug in policy.scannable,
                "intentionally_masked": slug in policy.masked,
                "unsupported_upstream": slug in policy.unsupported,
                "credential_dependent": slug in policy.credential_dependent,
                "backing_service_dependent": slug in policy.backing_service_dependent,
                "unsafe_to_execute_unsandboxed": local_process,
                "live_credentials_allowed": False,
                "broad_egress_allowed": False,
                "execution_disposition": (
                    "pinned-network-off-sandbox-only"
                    if slug in policy.scannable
                    else "do-not-execute"
                ),
            }
        )
    return {
        "schema": "McpTrustCatalogRefreshInventoryV1",
        "catalog_denominator": len(rows),
        "counts": {
            "scannable": sum(row["scannable"] for row in rows),
            "blocked": sum(not row["scannable"] for row in rows),
            "intentionally_masked": sum(row["intentionally_masked"] for row in rows),
            "unsupported_upstream": sum(row["unsupported_upstream"] for row in rows),
            "credential_dependent": sum(row["credential_dependent"] for row in rows),
            "backing_service_dependent": sum(row["backing_service_dependent"] for row in rows),
            "unsafe_to_execute_unsandboxed": sum(
                row["unsafe_to_execute_unsandboxed"] for row in rows
            ),
            "missing_image_build_source": sum(
                row["unsafe_to_execute_unsandboxed"]
                and row["image_build_source"] is None
                for row in rows
            ),
            "unqualified_image_build_source": sum(
                row["unsafe_to_execute_unsandboxed"]
                and row["image_reproducibility_status"] != "VERIFIED"
                for row in rows
            ),
        },
        "entries": rows,
    }


def source_binding(repo_root: Path) -> dict[str, Any]:
    def git(*args: str) -> str | None:
        completed = subprocess.run(
            ["git", "-C", str(repo_root), *args],
            text=True,
            capture_output=True,
            check=False,
        )
        return completed.stdout.strip() if completed.returncode == 0 else None

    tracked = subprocess.run(
        ["git", "-C", str(repo_root), "ls-files", "-z"],
        capture_output=True,
        check=False,
    )
    if tracked.returncode != 0:
        raise GradeRefreshError("tracked source inventory is unavailable")
    relative_paths = [
        item.decode("utf-8") for item in tracked.stdout.split(b"\0") if item
    ]
    if not relative_paths:
        raise GradeRefreshError("tracked source inventory is empty")
    file_digests: dict[str, str] = {}
    for relative in relative_paths:
        relative_path = Path(relative)
        if relative_path.is_absolute() or ".." in relative_path.parts:
            raise GradeRefreshError("tracked source inventory contains an unsafe path")
        path = repo_root / relative_path
        if path.is_symlink():
            file_digests[relative] = digest_bytes(
                ("symlink:" + os.readlink(path)).encode("utf-8")
            )
        else:
            file_digests[relative] = digest_file(path)
    binding_digest = digest_bytes(canonical_bytes(file_digests))
    revision = git("rev-parse", "HEAD")
    status = git("status", "--porcelain=v1", "--untracked-files=all")
    return {
        "repository": "https://github.com/saagpatel/mcp-trust.git",
        "revision": revision or "UNKNOWN",
        "worktree_state": (
            "clean" if status == "" else "modified" if status is not None else "UNKNOWN"
        ),
        "source_tree_digest": binding_digest,
        "file_digests": file_digests,
    }


def _package_version(distribution: str) -> str:
    try:
        return importlib.metadata.version(distribution)
    except importlib.metadata.PackageNotFoundError:
        return "UNKNOWN"


def _run(
    runner: Callable[..., subprocess.CompletedProcess[str]], args: list[str]
) -> subprocess.CompletedProcess[str]:
    return runner(args, text=True, capture_output=True, check=False)


def _docker_host(
    runner: Callable[..., subprocess.CompletedProcess[str]],
) -> tuple[str | None, str | None]:
    inspected = _run(
        runner,
        ["docker", "context", "inspect", "--format", "{{json .Endpoints.docker.Host}}"],
    )
    if inspected.returncode != 0:
        return None, "docker_context_unavailable"
    try:
        value = json.loads(inspected.stdout.strip())
        return normalize_local_docker_host(value), None
    except (json.JSONDecodeError, TypeError, ValueError):
        return None, "docker_context_not_local_unix"


def _sandbox_controls(image: str, host: str) -> dict[str, Any]:
    sandbox = DockerSandbox(image=image, network="none", host=host)
    command, args = sandbox.wrap("fixture-command", ["--probe"])
    joined = [command, *args]
    required = {
        "network_none": "--network" in joined and "none" in joined,
        "read_only_root": "--read-only" in joined,
        "capabilities_dropped": "--cap-drop" in joined and "ALL" in joined,
        "no_new_privileges": "--security-opt" in joined
        and "no-new-privileges" in joined,
        "memory_limit": "--memory" in joined,
        "cpu_limit": "--cpus" in joined,
        "pids_limit": "--pids-limit" in joined,
        "non_root_user": "--user" in joined and sandbox.user not in {None, "0", "0:0"},
        "bounded_writable_tmpfs": "--tmpfs" in joined and sandbox.workdir in " ".join(joined),
        "no_host_mount": not any(token in joined for token in ("--volume", "-v", "--mount")),
    }
    return {"controls": required, "all_required_controls": all(required.values())}


def scheduler_readback(
    *,
    repo_root: Path,
    runner: Callable[..., subprocess.CompletedProcess[str]] = subprocess.run,
) -> dict[str, Any]:
    """Read the dormant LaunchAgent state without loading or changing it."""
    label = "com.d.mcp-trust-refresh"
    uid = os.getuid()
    repository_plist = repo_root / "deploy/launchd/com.d.mcp-trust-refresh.plist"
    installed_plist = Path.home() / "Library/LaunchAgents" / f"{label}.plist"
    source_digest = digest_file(repository_plist)
    installed_digest = digest_file(installed_plist) if installed_plist.is_file() else None
    disabled = _run(runner, ["launchctl", "print-disabled", f"gui/{uid}"])
    if disabled.returncode != 0:
        disabled_state: bool | str = "UNKNOWN"
    elif f'"{label}" => disabled' in disabled.stdout:
        disabled_state = True
    elif f'"{label}" => enabled' in disabled.stdout:
        disabled_state = False
    else:
        disabled_state = "UNKNOWN"
    domains = {
        "gui": f"gui/{uid}/{label}",
        "user": f"user/{uid}/{label}",
        "system": f"system/{label}",
    }
    loaded_domains = [
        name
        for name, target in domains.items()
        if _run(runner, ["launchctl", "print", target]).returncode == 0
    ]
    definitions_match: bool | str = (
        installed_digest == source_digest
        if installed_digest is not None
        else "NOT_APPLICABLE"
    )
    if disabled_state is True and not loaded_domains:
        state = "DISABLED_UNLOADED"
    elif disabled_state == "UNKNOWN":
        state = "UNKNOWN"
    else:
        state = "REVIEW_REQUIRED"
    return {
        "label": label,
        "state": state,
        "persistently_disabled": disabled_state,
        "loaded_domains": loaded_domains,
        "installed_definition_state": (
            "PRESENT" if installed_digest is not None else "ABSENT"
        ),
        "installed_plist": str(installed_plist) if installed_digest is not None else None,
        "installed_plist_sha256": installed_digest,
        "repository_plist_sha256": source_digest,
        "definitions_match": definitions_match,
        "mutation_performed": False,
    }


def dependency_bundle_metadata(path: Path) -> dict[str, Any]:
    """Return a path-safe content digest for one offline dependency tar bundle."""
    try:
        bundle_size = path.stat().st_size
        if bundle_size <= 0:
            raise GradeRefreshError("dependency artifact bundle is empty")
        rows: list[dict[str, Any]] = []
        seen: set[str] = set()
        with tarfile.open(path, mode="r:*") as archive:
            for member in archive.getmembers():
                relative = Path(member.name)
                if (
                    relative.is_absolute()
                    or not member.name
                    or ".." in relative.parts
                    or member.name in seen
                    or not (member.isfile() or member.isdir())
                ):
                    raise GradeRefreshError("dependency artifact bundle is unsafe")
                seen.add(member.name)
                if member.isdir():
                    continue
                stream = archive.extractfile(member)
                if stream is None:
                    raise GradeRefreshError("dependency artifact member is unreadable")
                content = stream.read()
                if len(content) != member.size:
                    raise GradeRefreshError("dependency artifact member size mismatch")
                rows.append(
                    {
                        "path": member.name,
                        "size": member.size,
                        "sha256": digest_bytes(content),
                    }
                )
    except (OSError, tarfile.TarError) as exc:
        raise GradeRefreshError("dependency artifact bundle is unreadable") from exc
    if not rows:
        raise GradeRefreshError("dependency artifact bundle has no files")
    rows.sort(key=lambda row: row["path"])
    return {
        "bundle_size": bundle_size,
        "file_count": len(rows),
        "content_digest": digest_bytes(canonical_bytes(rows)),
    }


def _exact_dependency_descriptor(
    *, repo_root: Path, value: object, expected_path_key: str = "path"
) -> tuple[str, str] | None:
    if not isinstance(value, dict) or set(value) != {expected_path_key, "sha256"}:
        return None
    relative = value.get(expected_path_key)
    expected = value.get("sha256")
    if (
        not _safe_relative_path(relative)
        or not isinstance(expected, str)
        or _SHA256.fullmatch(expected) is None
        or not (repo_root / str(relative)).is_file()
        or digest_file(repo_root / str(relative)) != expected
    ):
        return None
    return str(relative), expected


def _valid_npm_inputs(manifest_path: Path, lock_path: Path) -> bool:
    try:
        manifest = load_json(manifest_path)
        lock = load_json(lock_path)
    except GradeRefreshError:
        return False
    dependencies = manifest.get("dependencies") if isinstance(manifest, dict) else None
    packages = lock.get("packages") if isinstance(lock, dict) else None
    if (
        not isinstance(dependencies, dict)
        or not dependencies
        or not all(
            isinstance(name, str)
            and name
            and isinstance(version, str)
            and re.fullmatch(r"[0-9]+\.[0-9]+\.[0-9]+(?:-[0-9A-Za-z.-]+)?", version)
            for name, version in dependencies.items()
        )
        or lock.get("lockfileVersion") != 3
        or not isinstance(packages, dict)
        or len(packages) < 2
        or not isinstance(packages.get(""), dict)
        or packages[""].get("dependencies") != dependencies
    ):
        return False
    package_names: set[str] = set()
    for path, package in packages.items():
        if path == "":
            continue
        if (
            not isinstance(path, str)
            or "node_modules/" not in path
            or not isinstance(package, dict)
            or not isinstance(package.get("version"), str)
            or not package["version"]
            or not isinstance(package.get("resolved"), str)
            or not package["resolved"].startswith("https://registry.npmjs.org/")
            or not isinstance(package.get("integrity"), str)
            or re.fullmatch(r"sha512-[A-Za-z0-9+/]+={0,2}", package["integrity"])
            is None
            or package.get("link") is True
        ):
            return False
        package_names.add(path.rsplit("node_modules/", 1)[-1])
    return set(dependencies) <= package_names


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
        groups.append(current)
    return groups


def _normalized_project_name(value: str) -> str:
    return re.sub(r"[-_.]+", "-", value).lower()


def _valid_python_inputs(manifest_path: Path, lock_path: Path) -> bool:
    try:
        manifest_groups = _requirement_groups(manifest_path.read_text(encoding="utf-8"))
        lock_groups = _requirement_groups(lock_path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError):
        return False
    requirement = re.compile(r"^([A-Za-z0-9][A-Za-z0-9._-]*)==([^\s;]+)")
    direct: dict[str, str] = {}
    for group in manifest_groups:
        match = requirement.match(group)
        if match is None or "--hash=" in group:
            return False
        name, version = match.groups()
        direct[_normalized_project_name(name)] = version
    if not direct or len(direct) != len(manifest_groups):
        return False
    locked: dict[str, str] = {}
    for group in lock_groups:
        match = requirement.match(group)
        hashes = re.findall(r"--hash=sha256:[0-9a-f]{64}", group)
        if match is None or not hashes:
            return False
        name, version = match.groups()
        locked[_normalized_project_name(name)] = version
    return bool(locked) and all(locked.get(name) == version for name, version in direct.items())


def _dependency_artifact(
    *, repo_root: Path, kind: str, lock_sha256: str, value: object
) -> dict[str, Any] | None:
    descriptor_ref = _exact_dependency_descriptor(repo_root=repo_root, value=value)
    if descriptor_ref is None:
        return None
    descriptor_path, descriptor_sha256 = descriptor_ref
    try:
        descriptor = load_json(repo_root / descriptor_path)
    except GradeRefreshError:
        return None
    expected_keys = {
        "schema",
        "kind",
        "registry_endpoints",
        "lock_sha256",
        "bundle_path",
        "bundle_sha256",
        "bundle_size",
        "file_count",
        "content_digest",
        "prepared_at",
        "tool_versions",
        "preparation_network_policy",
        "package_code_executed",
    }
    endpoints = {
        "npm": ["https://registry.npmjs.org"],
        "python": ["https://files.pythonhosted.org", "https://pypi.org/simple"],
    }
    if (
        not isinstance(descriptor, dict)
        or set(descriptor) != expected_keys
        or descriptor.get("schema") != "McpTrustDependencyArtifactBundleV1"
        or descriptor.get("kind") != kind
        or descriptor.get("registry_endpoints") != endpoints.get(kind)
        or descriptor.get("lock_sha256") != lock_sha256
        or descriptor.get("preparation_network_policy")
        != "registry-client-allowlist-no-package-code"
        or descriptor.get("package_code_executed") is not False
        or not isinstance(descriptor.get("tool_versions"), dict)
        or not descriptor["tool_versions"]
        or not all(
            isinstance(key, str) and isinstance(value, str) and value
            for key, value in descriptor["tool_versions"].items()
        )
        or not _safe_relative_path(descriptor.get("bundle_path"))
        or not isinstance(descriptor.get("bundle_sha256"), str)
        or _SHA256.fullmatch(descriptor["bundle_sha256"]) is None
    ):
        return None
    try:
        prepared_at = datetime.fromisoformat(str(descriptor.get("prepared_at")))
    except ValueError:
        return None
    if prepared_at.tzinfo is None:
        return None
    bundle_path = repo_root / str(descriptor["bundle_path"])
    if (
        not bundle_path.is_file()
        or digest_file(bundle_path) != descriptor["bundle_sha256"]
    ):
        return None
    try:
        metadata = dependency_bundle_metadata(bundle_path)
    except GradeRefreshError:
        return None
    if any(descriptor.get(key) != value for key, value in metadata.items()):
        return None
    return {
        "descriptor_path": descriptor_path,
        "descriptor_sha256": descriptor_sha256,
        "bundle_path": str(descriptor["bundle_path"]),
        "bundle_sha256": str(descriptor["bundle_sha256"]),
        **metadata,
    }


def _image_build_qualification(
    *,
    repo_root: Path,
    reference: str,
    build_source: str,
    build_source_sha256: str,
    receipt_path: str,
    now: datetime | None = None,
) -> dict[str, Any] | None:
    """Validate a deterministic two-build receipt against tracked source bytes."""
    path = repo_root / receipt_path
    if not path.is_file():
        return None
    try:
        payload = load_json(path)
    except GradeRefreshError:
        return None
    if not isinstance(payload, dict) or set(payload) != _IMAGE_BUILD_QUALIFICATION_KEYS:
        return None
    claimed = payload.get("receipt_digest")
    unsigned = dict(payload)
    unsigned.pop("receipt_digest", None)
    try:
        observed_at = datetime.fromisoformat(str(payload.get("observed_at")))
    except ValueError:
        return None
    current = (now or datetime.now(tz=UTC)).astimezone(UTC)
    max_age = payload.get("qualification_max_age_seconds")
    if (
        payload.get("schema") != IMAGE_BUILD_QUALIFICATION_SCHEMA
        or not isinstance(claimed, str)
        or _SHA256.fullmatch(claimed) is None
        or claimed != digest_bytes(canonical_bytes(unsigned))
        or payload.get("image_reference") != reference
        or payload.get("build_source_sha256") != build_source_sha256
        or payload.get("repeatable") is not True
        or observed_at.tzinfo is None
        or type(max_age) is not int
        or max_age != 86_400
        or observed_at.astimezone(UTC) > current + timedelta(minutes=5)
        or current - observed_at.astimezone(UTC) > timedelta(seconds=max_age)
    ):
        return None
    first = payload.get("first_build_image_id")
    second = payload.get("second_build_image_id")
    if (
        not isinstance(first, str)
        or _SHA256.fullmatch(first) is None
        or first != second
    ):
        return None
    base_images = payload.get("base_images")
    network_policy = payload.get("build_network_policy")
    platform_name = payload.get("platform")
    tools = payload.get("tool_versions")
    manifests = payload.get("dependency_manifests")
    locks = payload.get("dependency_locks")
    artifacts = payload.get("dependency_artifacts")
    build_options = payload.get("build_options")
    build_commands = payload.get("build_commands")
    load_commands = payload.get("load_commands")
    if (
        not isinstance(base_images, list)
        or not base_images
        or not all(
            isinstance(item, str)
            and re.fullmatch(r"[^@\s]+@sha256:[0-9a-f]{64}", item) is not None
            for item in base_images
        )
        or network_policy != ["none"]
        or not isinstance(platform_name, str)
        or re.fullmatch(r"linux/(?:arm64|amd64)", platform_name) is None
        or not isinstance(tools, dict)
        or not tools
        or not all(
            isinstance(key, str) and isinstance(value, str) and value
            for key, value in tools.items()
        )
        or not isinstance(manifests, dict)
        or not isinstance(locks, dict)
        or not locks
        or not isinstance(artifacts, dict)
        or build_options
        != {
            "builder": "buildx",
            "cache": "disabled",
            "load": False,
            "output": "oci",
            "pull": False,
            "provenance": False,
            "rewrite_timestamps": True,
            "sbom": False,
        }
        or not isinstance(build_commands, list)
        or len(build_commands) != 2
        or not isinstance(load_commands, list)
        or len(load_commands) != 2
        or payload.get("exit_classification") != "QUALIFIED_REPEATABLE"
    ):
        return None
    build_text = (repo_root / build_source).read_text(encoding="utf-8")
    instructions: list[str] = []
    continuation = ""
    for raw_line in build_text.splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#"):
            continue
        if line.endswith("\\"):
            continuation += line[:-1].rstrip() + " "
            continue
        instructions.append((continuation + line).strip())
        continuation = ""
    if continuation:
        return None
    external_bases: list[str] = []
    stage_aliases: set[str] = set()
    for instruction in instructions:
        match = re.match(
            r"^FROM(?:\s+--platform=\S+)?\s+(\S+)(?:\s+AS\s+(\S+))?$",
            instruction,
            flags=re.IGNORECASE,
        )
        if match is None:
            continue
        base, alias = match.groups()
        if base not in stage_aliases:
            external_bases.append(base)
        if alias:
            stage_aliases.add(alias)
    if sorted(external_bases) != sorted(base_images):
        return None
    if any(instruction.upper().startswith("ADD ") for instruction in instructions):
        return None
    normalized = re.sub(r"[\[\],\"']+", " ", "\n".join(instructions).lower())
    normalized = re.sub(r"\s+", " ", normalized)
    if any(
        pattern in normalized
        for pattern in (
            "apt-get ",
            "apk add",
            "dnf install",
            "yum install",
            "npm install",
            "uv tool install",
            "npx ",
            "uvx ",
            "curl ",
            "wget ",
            "npm exec",
            "corepack ",
            "pip3 ",
            " eval ",
            " sh -c ",
            " bash -c ",
            "python -c ",
            "node -e ",
            "$(",
            "`",
        )
    ):
        return None
    if "npm ci" in normalized and "npm" not in locks:
        return None
    if "npm ci" in normalized and "--offline" not in normalized:
        return None
    if ("pip install" in normalized or "uv pip install" in normalized) and (
        "--require-hashes" not in normalized
        or "--no-index" not in normalized
        or "python" not in locks
    ):
        return None
    required_lock_kinds = {
        kind
        for marker, kind in (
            ("npm ", "npm"),
            ("uv pip", "python"),
            ("pip ", "python"),
        )
        if marker in normalized
    }
    if set(locks) != required_lock_kinds or not required_lock_kinds:
        return None

    def copy_sources(instruction: str) -> tuple[bool, list[str]]:
        if not instruction.upper().startswith("COPY "):
            return False, []
        body = instruction[5:].strip()
        from_stage = False
        while body.startswith("--"):
            try:
                flag, body = body.split(maxsplit=1)
            except ValueError:
                return False, []
            from_stage = from_stage or flag.startswith("--from=")
        if body.startswith("["):
            try:
                values = json.loads(body)
            except json.JSONDecodeError:
                return False, []
            sources = values[:-1] if isinstance(values, list) and len(values) >= 2 else []
            return from_stage, sources
        try:
            values = shlex.split(body)
        except ValueError:
            return False, []
        return from_stage, values[:-1] if len(values) >= 2 else []

    copied_sources = {
        source.removeprefix("./")
        for instruction in instructions
        for from_stage, sources in [copy_sources(instruction)]
        if not from_stage
        for source in sources
        if isinstance(source, str)
    }
    required_kinds = required_lock_kinds
    if (
        set(manifests) != required_kinds
        or set(locks) != required_kinds
        or set(artifacts) != required_kinds
    ):
        return None
    normalized_manifests: dict[str, dict[str, str]] = {}
    normalized_locks: dict[str, str] = {}
    normalized_artifacts: dict[str, dict[str, Any]] = {}
    expected_copied_sources: set[str] = set()
    for kind in sorted(required_kinds):
        manifest_ref = _exact_dependency_descriptor(repo_root=repo_root, value=manifests[kind])
        lock_ref = _exact_dependency_descriptor(repo_root=repo_root, value=locks[kind])
        if manifest_ref is None or lock_ref is None:
            return None
        manifest_path, manifest_sha256 = manifest_ref
        lock_path, lock_sha256 = lock_ref
        if kind == "npm" and not _valid_npm_inputs(
            repo_root / manifest_path, repo_root / lock_path
        ):
            return None
        if kind == "python" and not _valid_python_inputs(
            repo_root / manifest_path, repo_root / lock_path
        ):
            return None
        artifact = _dependency_artifact(
            repo_root=repo_root,
            kind=kind,
            lock_sha256=lock_sha256,
            value=artifacts[kind],
        )
        if artifact is None:
            return None
        normalized_manifests[kind] = {
            "path": manifest_path,
            "sha256": manifest_sha256,
        }
        normalized_locks[lock_path] = lock_sha256
        normalized_artifacts[kind] = artifact
        expected_copied_sources.update(
            {manifest_path, lock_path, str(artifact["bundle_path"])}
        )
    if copied_sources != expected_copied_sources:
        return None
    build_input = {
        "build_source_sha256": build_source_sha256,
        "base_images": sorted(base_images),
        "platform": platform_name,
        "dependency_manifests": normalized_manifests,
        "dependency_locks": dict(sorted(normalized_locks.items())),
        "dependency_artifacts": normalized_artifacts,
        "build_options": build_options,
    }
    expected_input_digest = digest_bytes(canonical_bytes(build_input))
    if payload.get("build_input_digest") != expected_input_digest:
        return None

    def valid_build_command(value: object, *, final: bool) -> str | None:
        if (
            not isinstance(value, list)
            or not all(isinstance(token, str) and token for token in value)
            or value[-1] != "."
            or any(token.startswith(("--secret", "--ssh", "--allow")) for token in value)
        ):
            return None

        executable = Path(value[0]).name
        if not (
            (executable == "docker-buildx" and value[1:2] == ["build"])
            or value[:3] == ["docker", "buildx", "build"]
        ):
            return None

        def pair(flag: str, expected: str) -> bool:
            return any(
                value[index : index + 2] == [flag, expected]
                for index in range(len(value) - 1)
            )

        try:
            tag = value[value.index("-t") + 1]
        except (ValueError, IndexError):
            return None
        outputs = [
            token
            for token in value
            if token.startswith("--output=type=oci,dest=")
            and token.endswith(",rewrite-timestamp=true")
        ]
        output_path = (
            outputs[0]
            .removeprefix("--output=type=oci,dest=")
            .removesuffix(",rewrite-timestamp=true")
            if len(outputs) == 1
            else ""
        )
        valid = (
            pair("--network", "none")
            and pair("--platform", platform_name)
            and pair("-f", build_source)
            and "--pull=false" in value
            and "--no-cache" in value
            and "--provenance=false" in value
            and "--sbom=false" in value
            and "--load" not in value
            and _safe_relative_path(output_path)
            and Path(output_path).parts[:2] == ("tmp", "qualification")
            and (tag == reference if final else tag.startswith("mcp-trust-qualification:"))
        )
        return output_path if valid else None

    output_paths = [
        valid_build_command(build_commands[0], final=False),
        valid_build_command(build_commands[1], final=True),
    ]
    if None in output_paths or any(
        command != ["docker", "load", "-i", output_path]
        for command, output_path in zip(load_commands, output_paths, strict=True)
    ):
        return None
    tracked_inputs = {
        **{value["path"]: value["sha256"] for value in normalized_manifests.values()},
        **normalized_locks,
        **{
            value["descriptor_path"]: value["descriptor_sha256"]
            for value in normalized_artifacts.values()
        },
    }
    return {
        "path": receipt_path,
        "sha256": digest_file(path),
        "receipt_digest": claimed,
        "qualified_image_id": first,
        "build_input_digest": expected_input_digest,
        "dependency_locks": dict(sorted(normalized_locks.items())),
        "dependency_artifacts": normalized_artifacts,
        "tracked_inputs": dict(sorted(tracked_inputs.items())),
        "state": "VERIFIED",
    }


def build_preflight_receipt(
    *,
    repo_root: Path,
    seed_path: Path,
    masked_path: Path,
    policy_path: Path,
    now: datetime | None = None,
    runner: Callable[..., subprocess.CompletedProcess[str]] = subprocess.run,
    include_scheduler_readback: bool = False,
) -> dict[str, Any]:
    observed_at = (now or datetime.now(tz=UTC)).astimezone(UTC)
    inventory = catalog_inventory(
        seed_path=seed_path, masked_path=masked_path, policy_path=policy_path
    )
    source = source_binding(repo_root)
    reasons: list[str] = []
    if source.get("revision") == "UNKNOWN":
        reasons.append("source_revision_unknown")
    if source.get("worktree_state") != "clean":
        reasons.append("source_worktree_not_clean")
    docker = shutil.which("docker")
    host: str | None = None
    docker_versions: dict[str, Any] = {"client": "UNKNOWN", "server": "UNKNOWN"}
    image_bindings: list[dict[str, Any]] = []
    if docker is None:
        reasons.append("docker_executable_missing")
    else:
        host, host_error = _docker_host(runner)
        if host_error:
            reasons.append(host_error)
        elif host is not None:
            version = _run(
                runner,
                [
                    "docker",
                    "--host",
                    host,
                    "version",
                    "--format",
                    "{{json .}}",
                ],
            )
            if version.returncode != 0:
                reasons.append("docker_daemon_unavailable")
            else:
                try:
                    parsed = json.loads(version.stdout)
                    docker_versions = {
                        "client": parsed["Client"]["Version"],
                        "server": parsed["Server"]["Version"],
                    }
                except (KeyError, TypeError, json.JSONDecodeError):
                    reasons.append("docker_version_unreadable")
    image_refs = sorted(
        {
            row["sandbox_image"]
            for row in inventory["entries"]
            if row.get("scannable") is True
            and isinstance(row.get("sandbox_image"), str)
        }
    )
    image_build_sources: dict[str, dict[str, Any]] = {}
    inventory_by_image = {
        row["sandbox_image"]: {
            "path": row.get("image_build_source"),
            "provenance_status": row.get("image_build_provenance_status"),
            "reproducibility_status": row.get("image_reproducibility_status"),
            "qualification_receipt": row.get("image_qualification_receipt"),
        }
        for row in inventory["entries"]
        if isinstance(row.get("sandbox_image"), str)
    }
    for reference in image_refs:
        descriptor = inventory_by_image.get(reference, {})
        build_source = descriptor.get("path")
        if not isinstance(build_source, str):
            image_build_sources[reference] = {
                "path": None,
                "sha256": "UNKNOWN",
                "state": "UNKNOWN",
            }
            reasons.append(f"image_build_source_missing:{reference}")
            continue
        build_path = repo_root / build_source
        if not build_path.is_file():
            image_build_sources[reference] = {
                "path": build_source,
                "sha256": "UNKNOWN",
                "state": "UNKNOWN",
            }
            reasons.append(f"image_build_source_unavailable:{reference}")
            continue
        build_source_sha256 = digest_file(build_path)
        binding: dict[str, Any] = {
            "path": build_source,
            "sha256": build_source_sha256,
            "provenance_status": descriptor.get("provenance_status", "UNKNOWN"),
            "reproducibility_status": descriptor.get(
                "reproducibility_status", "UNKNOWN"
            ),
            "qualification": None,
            "state": "UNQUALIFIED",
        }
        receipt_path = descriptor.get("qualification_receipt")
        if descriptor.get("reproducibility_status") != "VERIFIED":
            reasons.append(f"image_build_reproducibility_unknown:{reference}")
        elif not isinstance(receipt_path, str):
            binding["state"] = "UNKNOWN"
            reasons.append(f"image_build_qualification_missing:{reference}")
        else:
            qualification = _image_build_qualification(
                repo_root=repo_root,
                reference=reference,
                build_source=build_source,
                build_source_sha256=build_source_sha256,
                receipt_path=receipt_path,
                now=observed_at,
            )
            if qualification is None:
                binding["state"] = "UNKNOWN"
                reasons.append(f"image_build_qualification_invalid:{reference}")
            elif (
                source.get("file_digests", {}).get(receipt_path)
                != qualification["sha256"]
                or any(
                    source.get("file_digests", {}).get(input_path) != input_digest
                    for input_path, input_digest in qualification["tracked_inputs"].items()
                )
            ):
                binding["state"] = "UNKNOWN"
                reasons.append(f"image_build_qualification_unbound:{reference}")
            else:
                binding["state"] = "BOUND"
                binding["qualification"] = qualification
        image_build_sources[reference] = binding
    for reference in image_refs:
        binding: dict[str, Any] = {
            "reference": reference,
            "state": "UNKNOWN",
            "image_id": None,
            "repo_digests": [],
            "platform": None,
            "sandbox_controls": None,
        }
        if host is not None and "docker_daemon_unavailable" not in reasons:
            inspected = _run(
                runner,
                ["docker", "--host", host, "image", "inspect", reference],
            )
            if inspected.returncode != 0:
                binding["state"] = "MISSING"
                reasons.append(f"catalog_image_missing:{reference}")
            else:
                try:
                    item = json.loads(inspected.stdout)[0]
                    image_id = item["Id"]
                    repo_digests = item.get("RepoDigests") or []
                    if not isinstance(image_id, str) or _SHA256.fullmatch(image_id) is None:
                        raise ValueError("invalid image id")
                    if not isinstance(repo_digests, list) or not all(
                        isinstance(value, str) for value in repo_digests
                    ):
                        raise ValueError("invalid repository digests")
                    controls = _sandbox_controls(image_id, host)
                    binding.update(
                        {
                            "state": "BOUND",
                            "image_id": image_id,
                            "repo_digests": sorted(repo_digests),
                            "platform": (
                                f"{item.get('Os', 'UNKNOWN')}/"
                                f"{item.get('Architecture', 'UNKNOWN')}"
                            ),
                            "sandbox_controls": controls,
                        }
                    )
                    if not controls["all_required_controls"]:
                        reasons.append(f"sandbox_controls_incomplete:{reference}")
                    build_binding = image_build_sources.get(reference, {})
                    qualification = build_binding.get("qualification")
                    if (
                        isinstance(qualification, dict)
                        and qualification.get("qualified_image_id") != image_id
                    ):
                        reasons.append(f"catalog_image_qualification_mismatch:{reference}")
                except (IndexError, KeyError, TypeError, ValueError, json.JSONDecodeError):
                    binding["state"] = "UNKNOWN"
                    reasons.append(f"catalog_image_provenance_unknown:{reference}")
        image_bindings.append(binding)
    tool_versions = {
        "python": platform.python_version(),
        "python_executable": str(Path(sys.executable).resolve()),
        "mcp_audits": _package_version("mcp-audits"),
        "mcp_trust": _package_version("mcp-trust"),
        "docker_client": docker_versions["client"],
        "docker_server": docker_versions["server"],
    }
    if tool_versions["mcp_audits"] == "UNKNOWN":
        reasons.append("mcp_audits_runtime_unavailable")
    if tool_versions["mcp_trust"] == "UNKNOWN":
        reasons.append("mcp_trust_runtime_unavailable")
    execution_ready = not reasons and all(
        binding["state"] == "BOUND" for binding in image_bindings
    )
    payload: dict[str, Any] = {
        "schema": PREFLIGHT_SCHEMA,
        "observed_at": observed_at.isoformat(),
        "status": "READY" if execution_ready else "BLOCKED",
        "safe_to_execute_catalog": execution_ready,
        "exit_classification": "ready" if execution_ready else "preflight-blocked",
        "source_binding": source,
        "catalog": {
            "seed_digest": digest_file(seed_path),
            "masking_digest": digest_file(masked_path),
            "policy_digest": digest_file(policy_path),
            "inventory_digest": digest_bytes(canonical_bytes(inventory)),
            "denominator": inventory["catalog_denominator"],
            "counts": inventory["counts"],
            "image_build_sources": image_build_sources,
        },
        "sandbox": {
            "docker_host_kind": "local-unix" if host is not None else "UNKNOWN",
            "image_bindings": image_bindings,
            "network_policy": "none",
            "filesystem_policy": "read-only-root-bounded-tmpfs-no-host-mounts",
            "resource_policy": "cpu-memory-pids-timeout-required",
            "secret_policy": "no-live-secrets-dummy-network-off-only",
        },
        "tool_versions": tool_versions,
        "scheduler": (
            scheduler_readback(repo_root=repo_root)
            if include_scheduler_readback
            else {"state": "NOT_READ", "mutation_performed": False}
        ),
        "reasons": sorted(set(reasons)),
        "authority": {
            "candidate_build": execution_ready,
            "publication": False,
            "deployment": False,
            "scheduler_change": False,
        },
    }
    payload["receipt_digest"] = digest_bytes(canonical_bytes(payload))
    return payload


def build_fixture_repeatability_receipt(
    *, seed_path: Path, masked_path: Path, policy_path: Path, now: datetime | None = None
) -> dict[str, Any]:
    observed_at = (now or datetime.now(tz=UTC)).astimezone(UTC)
    inventory = catalog_inventory(
        seed_path=seed_path, masked_path=masked_path, policy_path=policy_path
    )
    seed = load_json(seed_path)
    engine = StubEngine()

    def run_once() -> list[dict[str, Any]]:
        rows: list[dict[str, Any]] = []
        for item in sorted(seed, key=lambda value: value["slug"]):
            source = ServerSource.model_validate(item["source"])
            result = engine.scan(source)
            rows.append(
                {
                    "slug": item["slug"],
                    "engine_name": result.engine_name,
                    "engine_version": result.engine_version,
                    "danger_grade": str(grading.grade(result.risk)),
                    "danger_score": grading.danger_score(result.risk),
                    "transparency": str(grading.transparency(result.risk)),
                    "risk": result.risk.model_dump(mode="json"),
                    "finding_fingerprints": [
                        digest_bytes(canonical_bytes(finding.model_dump(mode="json")))
                        for finding in result.findings
                    ],
                    "evidence_quality": "fixture-only",
                    "endorsement": False,
                }
            )
        return rows

    first = run_once()
    second = run_once()
    first_digest = digest_bytes(canonical_bytes(first))
    second_digest = digest_bytes(canonical_bytes(second))
    passed = first == second and len(first) == inventory["catalog_denominator"]
    payload: dict[str, Any] = {
        "schema": REPEATABILITY_SCHEMA,
        "observed_at": observed_at.isoformat(),
        "status": "PASS" if passed else "FAIL",
        "fixture_kind": "deterministic-stub-no-process-no-network",
        "catalog_denominator": inventory["catalog_denominator"],
        "first_digest": first_digest,
        "second_digest": second_digest,
        "repeatable": passed,
        "claim_ceiling": "Fixture determinism only; no real server or sandbox runtime proof.",
    }
    payload["receipt_digest"] = digest_bytes(canonical_bytes(payload))
    return payload


def _receipt_integrity_valid(
    payload: dict[str, Any], *, schema: str, expected_keys: frozenset[str]
) -> bool:
    if set(payload) != expected_keys or payload.get("schema") != schema:
        return False
    claimed = payload.get("receipt_digest")
    if not isinstance(claimed, str) or _SHA256.fullmatch(claimed) is None:
        return False
    unsigned = dict(payload)
    unsigned.pop("receipt_digest", None)
    return claimed == digest_bytes(canonical_bytes(unsigned))


def triage_candidate(
    *,
    candidate: Path,
    preflight: dict[str, Any],
    repeatability: dict[str, Any],
    seed_path: Path,
    masked_path: Path,
    candidate_verifier: Callable[..., dict[str, Any]] | None = None,
) -> dict[str, Any]:
    results_payload = load_json(candidate / "scan_results.json")
    manifest = load_json(candidate / "MANIFEST.json")
    results = results_payload.get("results") if isinstance(results_payload, dict) else None
    if not isinstance(results, list):
        raise GradeRefreshError("candidate scan results are invalid")
    findings: list[dict[str, str]] = []

    def add(severity: str, code: str, slug: str = "catalog") -> None:
        findings.append({"severity": severity, "code": code, "slug": slug})

    if candidate_verifier is None:
        from mcp_trust.refresh import verify_refresh_candidate  # noqa: PLC0415

        candidate_verifier = verify_refresh_candidate
    verification = candidate_verifier(
        candidate,
        expected_seed_path=seed_path,
        expected_masked_path=masked_path,
    )
    if (
        verification.get("structural_valid") is not True
        or verification.get("publication_ready") is not True
    ):
        add("Critical", "candidate_verification_failed")
    preflight_valid = _receipt_integrity_valid(
        preflight,
        schema=PREFLIGHT_SCHEMA,
        expected_keys=_PREFLIGHT_KEYS,
    )
    repeatability_valid = _receipt_integrity_valid(
        repeatability,
        schema=REPEATABILITY_SCHEMA,
        expected_keys=_REPEATABILITY_KEYS,
    )
    if not preflight_valid:
        add("Critical", "preflight_receipt_integrity_invalid")
    if not repeatability_valid:
        add("Critical", "repeatability_receipt_integrity_invalid")
    if (
        preflight.get("status") != "READY"
        or preflight.get("safe_to_execute_catalog") is not True
        or preflight.get("exit_classification") != "ready"
        or preflight.get("reasons") != []
    ):
        add("Critical", "preflight_not_ready")
    if (
        repeatability.get("status") != "PASS"
        or repeatability.get("repeatable") is not True
        or repeatability.get("first_digest") != repeatability.get("second_digest")
    ):
        add("High", "repeatability_not_proven")
    source_binding = preflight.get("source_binding")
    if not isinstance(source_binding, dict):
        source_binding = {}
    if source_binding.get("worktree_state") != "clean":
        add("High", "source_revision_not_cleanly_bound")
    catalog_binding = preflight.get("catalog", {})
    if not isinstance(catalog_binding, dict):
        add("Critical", "reviewed_catalog_binding_mismatch")
        catalog_binding = {}
    elif (
        catalog_binding.get("seed_digest") != digest_file(seed_path)
        or catalog_binding.get("masking_digest") != digest_file(masked_path)
    ):
        add("Critical", "reviewed_catalog_binding_mismatch")
    if repeatability.get("catalog_denominator") != catalog_binding.get("denominator"):
        add("High", "repeatability_denominator_mismatch")
    qualification = manifest.get("qualification")
    if (
        not isinstance(qualification, dict)
        or qualification.get("preflight_receipt_digest")
        != preflight.get("receipt_digest")
        or not isinstance(source_binding, dict)
        or qualification.get("source_revision") != source_binding.get("revision")
        or qualification.get("source_tree_digest")
        != source_binding.get("source_tree_digest")
        or qualification.get("policy_digest") != catalog_binding.get("policy_digest")
    ):
        add("Critical", "candidate_qualification_binding_mismatch")
    for result in results:
        if not isinstance(result, dict):
            add("Critical", "invalid_result_shape")
            continue
        slug = str(result.get("server_slug", "unknown"))
        state = result.get("state")
        if state not in {"fresh", "masked"}:
            add("Critical", f"result_{state or 'unknown'}", slug)
            continue
        if state == "masked":
            add("High", "masked_result_requires_review", slug)
        drift = result.get("drift")
        if not isinstance(drift, dict):
            add("Medium", "baseline_or_drift_unknown", slug)
            continue
        if (
            set(drift)
            != {
                "cause",
                "surface_comparison",
                "summary",
                "previous_grade",
                "current_grade",
            }
            or drift.get("previous_grade") not in _GRADE_INDEX
            or drift.get("current_grade") not in _GRADE_INDEX
            or drift.get("surface_comparison") not in {"changed", "unchanged", "unknown"}
            or drift.get("cause")
            not in {"surface-changed", "engine-changed", "score-moved", "undetermined", "no-change"}
            or not isinstance(drift.get("summary"), str)
        ):
            add("High", "drift_provenance_invalid", slug)
            continue
        previous = drift.get("previous_grade")
        current = drift.get("current_grade")
        if previous in _GRADE_INDEX and current in _GRADE_INDEX:
            delta = _GRADE_INDEX[current] - _GRADE_INDEX[previous]
            if delta < 0:
                add("High", "suspicious_upgrade", slug)
            if abs(delta) >= 2:
                add("High", "large_grade_change", slug)
        if drift.get("surface_comparison") == "unknown" or drift.get("cause") == "undetermined":
            add("High", "missing_comparable_provenance", slug)
    policy_digest = preflight.get("catalog", {}).get("policy_digest")
    if not isinstance(policy_digest, str) or _SHA256.fullmatch(policy_digest) is None:
        add("High", "policy_digest_missing")
    # Existing scan rows predate policy receipts; upgrades cannot be silently
    # treated as same-policy until a prior policy digest exists.
    add("Medium", "baseline_policy_digest_unknown")
    order = {"Critical": 0, "High": 1, "Medium": 2, "Low": 3}
    findings.sort(key=lambda item: (order[item["severity"]], item["slug"], item["code"]))
    payload: dict[str, Any] = {
        "schema": TRIAGE_SCHEMA,
        "candidate_manifest_digest": digest_file(candidate / "MANIFEST.json"),
        "preflight_receipt_digest": preflight.get("receipt_digest", "UNKNOWN"),
        "repeatability_receipt_digest": repeatability.get("receipt_digest", "UNKNOWN"),
        "review_required": bool(findings),
        "publication_allowed": False,
        "findings": findings,
        "counts": {
            severity: sum(item["severity"] == severity for item in findings)
            for severity in ("Critical", "High", "Medium", "Low")
        },
        "candidate_claimed_state": manifest.get("candidate_state"),
        "candidate_verification": {
            "structural_valid": verification.get("structural_valid", False),
            "publication_ready": verification.get("publication_ready", False),
            "state": verification.get("state", "UNKNOWN"),
            "errors": verification.get("errors", ["UNKNOWN"]),
        },
    }
    payload["receipt_digest"] = digest_bytes(canonical_bytes(payload))
    return payload


def _triage_integrity_valid(
    triage: dict[str, Any],
    *,
    preflight_digest: object,
    repeatability_digest: object,
) -> bool:
    findings = triage.get("findings")
    counts = triage.get("counts")
    verification = triage.get("candidate_verification")
    return bool(
        _receipt_integrity_valid(
            triage,
            schema=TRIAGE_SCHEMA,
            expected_keys=_TRIAGE_KEYS,
        )
        and isinstance(triage.get("candidate_manifest_digest"), str)
        and _SHA256.fullmatch(triage["candidate_manifest_digest"]) is not None
        and triage.get("preflight_receipt_digest") == preflight_digest
        and triage.get("repeatability_receipt_digest") == repeatability_digest
        and type(triage.get("review_required")) is bool
        and triage.get("publication_allowed") is False
        and isinstance(findings, list)
        and all(
            isinstance(finding, dict)
            and finding.get("severity") in {"Critical", "High", "Medium", "Low"}
            and isinstance(finding.get("code"), str)
            and isinstance(finding.get("slug"), str)
            for finding in findings
        )
        and isinstance(counts, dict)
        and set(counts) == {"Critical", "High", "Medium", "Low"}
        and all(
            type(counts[severity]) is int
            and counts[severity]
            == sum(finding["severity"] == severity for finding in findings)
            for severity in counts
        )
        and triage.get("candidate_claimed_state") == "complete"
        and isinstance(verification, dict)
        and set(verification)
        == {"structural_valid", "publication_ready", "state", "errors"}
        and verification.get("structural_valid") is True
        and verification.get("publication_ready") is True
        and verification.get("state") == "complete"
        and verification.get("errors") == []
    )


def build_state_card(
    *, preflight: dict[str, Any], repeatability: dict[str, Any], triage: dict[str, Any] | None
) -> dict[str, Any]:
    blockers = list(preflight.get("reasons", []))
    if repeatability.get("status") != "PASS":
        blockers.append("fixture_repeatability_failed")
    triage_valid = bool(
        triage is not None
        and _triage_integrity_valid(
            triage,
            preflight_digest=preflight.get("receipt_digest"),
            repeatability_digest=repeatability.get("receipt_digest"),
        )
    )
    if triage is None:
        blockers.append("candidate_not_built_or_triaged")
    elif not triage_valid:
        blockers.append("triage_receipt_invalid_or_unbound")
    elif triage.get("review_required"):
        blockers.append("candidate_review_required")
    source = preflight.get("source_binding", {})
    catalog = preflight.get("catalog", {})
    scheduler = preflight.get("scheduler", {})
    if triage_valid:
        assert triage is not None
        findings = list(triage.get("findings", []))
    else:
        findings = []
        if triage is not None:
            findings.append(
                {
                    "severity": "Critical",
                    "code": "triage_receipt_invalid_or_unbound",
                    "scope": "candidate",
                }
            )
        if preflight.get("status") != "READY":
            findings.append(
                {
                    "severity": "Critical",
                    "code": "sandbox_preflight_not_ready",
                    "scope": "catalog",
                }
            )
        if any(
            str(reason).startswith(
                (
                    "image_build_source_",
                    "image_build_reproducibility_",
                    "image_build_qualification_",
                )
            )
            for reason in preflight.get("reasons", [])
        ):
            findings.append(
                {
                    "severity": "High",
                    "code": "deterministic_image_reproduction_unknown",
                    "scope": "catalog-images",
                }
            )
        if repeatability.get("status") != "PASS":
            findings.append(
                {
                    "severity": "High",
                    "code": "fixture_repeatability_not_proven",
                    "scope": "catalog",
                }
            )
        findings.append(
            {
                "severity": "High",
                "code": "real_candidate_not_built_or_triaged",
                "scope": "catalog",
            }
        )
        findings.append(
            {
                "severity": "Medium",
                "code": "baseline_policy_digest_unknown",
                "scope": "catalog",
            }
        )
    if scheduler.get("definitions_match") is False:
        blockers.append("dormant_scheduler_definition_drift")
        findings.append(
            {
                "severity": "Medium",
                "code": "dormant_scheduler_definition_drift",
                "scope": "host-launchagent",
            }
        )
    elif scheduler.get("state") not in {"DISABLED_UNLOADED", "NOT_READ"}:
        blockers.append("scheduler_state_unknown_or_review_required")
        findings.append(
            {
                "severity": "High",
                "code": "scheduler_state_unknown_or_review_required",
                "scope": "host-launchagent",
            }
        )
    order = {"Critical": 0, "High": 1, "Medium": 2, "Low": 3}
    findings.sort(
        key=lambda item: (
            order.get(str(item.get("severity")), 4),
            str(item.get("scope", item.get("slug", "catalog"))),
            str(item.get("code", "unknown")),
        )
    )
    severity_findings = {
        severity: sum(item.get("severity") == severity for item in findings)
        for severity in ("Critical", "High", "Medium", "Low")
    }
    completed_controls = [
        "catalog-inventory",
        "source-and-policy-digests",
        "image-provenance-preflight-run",
        "sandbox-policy-defined",
        "review-only-authority",
    ]
    if repeatability.get("status") == "PASS":
        completed_controls.append("deterministic-fixture-repeatability")
    if triage_valid:
        completed_controls.append("grade-diff-review-triage-run")
    if scheduler.get("state") != "NOT_READ":
        completed_controls.append("scheduler-readback-no-mutation")
    return {
        "schema": STATE_CARD_SCHEMA,
        "source_revision": source.get("revision", "UNKNOWN"),
        "source_tree_digest": source.get("source_tree_digest", "UNKNOWN"),
        "catalog_denominator": catalog.get("denominator", 0),
        "catalog_counts": catalog.get("counts", {}),
        "scheduler_state": scheduler,
        "safe_to_execute_catalog": preflight.get("safe_to_execute_catalog", False),
        "fixture_repeatability": repeatability.get("status", "UNKNOWN"),
        "severity_findings": severity_findings,
        "findings": findings,
        "completed_controls": completed_controls,
        "outstanding_gates": sorted(set(blockers)),
        "publication_state": "WAITING_FOR_EXPLICIT_APPROVAL",
        "production_freshness": "UNKNOWN",
        "next_action": (
            "Approve deterministic reconstruction of all four image cohorts from the "
            "tracked recipes, including immutable base digests, complete dependency locks, "
            "narrow dependency-preparation egress, network-none repeat builds, qualification "
            "receipts, and exact image IDs; then rerun preflight."
            if not preflight.get("safe_to_execute_catalog")
            else "Create one local review candidate, rerun deterministic verification, and triage."
        ),
    }


def build_resume_capsule(
    *, task_id: str, state_card: dict[str, Any], now: datetime | None = None
) -> dict[str, Any]:
    created = (now or datetime.now(tz=UTC)).astimezone(UTC)
    target_digest = digest_bytes(canonical_bytes(state_card))
    authority_boundary = (
        "Read this Codex task status only; no publication, deployment, scheduler change, "
        "third-party execution, credentials, or outreach."
    )
    authority_digest = digest_bytes(authority_boundary.encode())
    execution_blocked = state_card.get("safe_to_execute_catalog") is not True
    waiting_code = (
        "deterministic-image-build-approval-required"
        if execution_blocked
        else "publication-approval-required"
    )
    capsule_id = (
        "mcp-trust-grade-refresh-deterministic-build-gate"
        if execution_blocked
        else "mcp-trust-grade-refresh-publication-gate"
    )
    waiting_digest = digest_bytes(
        canonical_bytes({"code": waiting_code, "target_digest": target_digest})
    )
    target = {
        "kind": "codex-task",
        "identity": task_id,
        "revision": str(state_card.get("source_revision", "UNKNOWN")),
        "digest": target_digest,
    }
    requested = {"kind": "codex-task-status", "target": target}
    resume_claim_ceiling = (
        "Resume deterministic image reconstruction only after explicit approval. Use "
        "approved registry egress only to prepare locked inputs, then run two network-none "
        "builds and a fresh READY preflight. Publication, deployment, and scheduling remain "
        "separately gated."
        if execution_blocked
        else (
            "Resume local review-only qualification after explicit chat approval; "
            "publication and deployment remain separately gated."
        )
    )
    resume_states = (
        ["deterministic-image-build-authorized"]
        if execution_blocked
        else ["publication-authorized"]
    )
    terminal_states = (
        ["deterministic-image-build-declined", "program-withdrawn"]
        if execution_blocked
        else ["publication-declined", "program-withdrawn"]
    )
    return {
        "schema": "HumanGateResumeCapsuleV1",
        "as_of": created.isoformat(),
        "capsule": {
            "capsule_id": capsule_id,
            "created_at": created.isoformat(),
            "expires_at": (created + timedelta(days=30)).isoformat(),
            "waiting_condition": {"code": waiting_code, "digest": waiting_digest},
            "target": target,
            "authority": {"boundary": authority_boundary, "digest": authority_digest},
            "read_registry": "human-gate-read-kinds-v1",
            "authorized_next_read": requested,
            "freshness_seconds": 600,
            "claim_ceiling": resume_claim_ceiling,
            "resume_states": resume_states,
            "terminal_states": terminal_states,
            "invalidation_states": ["source-revision-changed", "authority-changed"],
        },
        "observation": {
            "read_at": created.isoformat(),
            "readback_status": "not_run",
            "target": target,
            "authority_digest": authority_digest,
            "waiting_condition_digest": waiting_digest,
            "requested_read": requested,
            "wait_state": waiting_code,
            "is_terminal": False,
            "superseded_by": None,
        },
    }
