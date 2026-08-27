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
import tomllib
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
DISPOSITION_POLICY_SCHEMA_V1 = "McpTrustGradeRefreshDispositionPolicyV1"
DISPOSITION_POLICY_SCHEMA = "McpTrustGradeRefreshDispositionPolicyV2"
PUBLICATION_REVIEW_SCHEMA = "McpTrustPublicationReviewDecisionV1"
PUBLICATION_REVIEW_STATE_CARD_SCHEMA = "McpTrustPublicationReviewStateCardV1"
POLICY_SCHEMA = "McpTrustRefreshPolicyV2"
IMAGE_BUILD_QUALIFICATION_SCHEMA = "McpTrustImageBuildQualificationV2"
_SHA256 = re.compile(r"^sha256:[0-9a-f]{64}$")
_STABLE_VERSION = re.compile(
    r"v?\d+\.\d+\.\d+(?:[-+][0-9A-Za-z][0-9A-Za-z.-]*)?"
)
_IMAGE_BUILD_TOOL_VERSION_KEYS = frozenset(
    {"docker_client", "docker_server", "docker_buildx", "buildkit_colima"}
)
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
        "repeat_candidate_manifest_digest",
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


def _stable_image_build_tool_versions(value: object) -> bool:
    if not isinstance(value, dict) or set(value) != _IMAGE_BUILD_TOOL_VERSION_KEYS:
        return False
    for key, version in value.items():
        if not isinstance(version, str) or _STABLE_VERSION.fullmatch(version) is None:
            return False
        if key in {"docker_buildx", "buildkit_colima"}:
            if not version.startswith("v"):
                return False
        elif version.startswith("v"):
            return False
    return True


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
    excluded = (
        fields["masked"]
        | fields["unsupported"]
        | fields["credential_dependent"]
        | fields["backing_service_dependent"]
    )
    eligible = catalog - excluded
    if fields["blocked"] != excluded or fields["scannable"] != eligible:
        raise GradeRefreshError(
            "scannable and blocked entries must exactly match the category-derived "
            "execution boundary"
        )
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


def _locked_package_version(repo_root: Path, distribution: str) -> str:
    """Return one exact package version from the repository's frozen uv lock."""
    try:
        lock = tomllib.loads((repo_root / "uv.lock").read_text(encoding="utf-8"))
    except (OSError, UnicodeError, tomllib.TOMLDecodeError):
        return "UNKNOWN"
    packages = lock.get("package") if isinstance(lock, dict) else None
    if not isinstance(packages, list):
        return "UNKNOWN"
    normalized = _normalized_project_name(distribution)
    versions = [
        package.get("version")
        for package in packages
        if isinstance(package, dict)
        and isinstance(package.get("name"), str)
        and _normalized_project_name(package["name"]) == normalized
    ]
    if (
        len(versions) != 1
        or not isinstance(versions[0], str)
        or _STABLE_VERSION.fullmatch(versions[0]) is None
    ):
        return "UNKNOWN"
    return versions[0]


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


def _python_source_build_receipt(
    *, repo_root: Path, value: object
) -> dict[str, str] | None:
    receipt_ref = _exact_dependency_descriptor(repo_root=repo_root, value=value)
    if receipt_ref is None:
        return None
    receipt_path, receipt_sha256 = receipt_ref
    try:
        payload = load_json(repo_root / receipt_path)
    except GradeRefreshError:
        return None
    expected_keys = {
        "schema",
        "observed_at",
        "input_descriptor",
        "builder",
        "python_base",
        "platform",
        "source_date_epoch",
        "network_policy",
        "sandbox_controls",
        "input_artifacts",
        "first_build_wheels",
        "second_build_wheels",
        "repeatable",
        "package_code_executed",
        "exit_classification",
        "tool_versions",
        "receipt_digest",
    }
    if not isinstance(payload, dict) or set(payload) != expected_keys:
        return None
    claimed = payload.get("receipt_digest")
    unsigned = dict(payload)
    unsigned.pop("receipt_digest", None)
    if (
        payload.get("schema") != "McpTrustPythonSourceBuildReceiptV1"
        or not isinstance(claimed, str)
        or _SHA256.fullmatch(claimed) is None
        or claimed != digest_bytes(canonical_bytes(unsigned))
        or re.fullmatch(r"[^@\s]+@sha256:[0-9a-f]{64}", str(payload.get("python_base")))
        is None
        or payload.get("platform") not in {"linux/arm64", "linux/amd64"}
        or type(payload.get("source_date_epoch")) is not int
        or payload.get("network_policy") != "none-during-all-package-code-execution"
        or payload.get("repeatable") is not True
        or payload.get("package_code_executed") is not True
        or payload.get("exit_classification")
        != "QUALIFIED_REPEATABLE_NETWORK_NONE"
    ):
        return None
    try:
        observed_at = datetime.fromisoformat(str(payload.get("observed_at")))
    except ValueError:
        return None
    if observed_at.tzinfo is None:
        return None
    input_ref = _exact_dependency_descriptor(
        repo_root=repo_root, value=payload.get("input_descriptor")
    )
    builder_ref = _exact_dependency_descriptor(
        repo_root=repo_root, value=payload.get("builder")
    )
    if input_ref is None or builder_ref is None:
        return None
    try:
        inputs = load_json(repo_root / input_ref[0])
    except GradeRefreshError:
        return None
    if (
        not isinstance(inputs, dict)
        or inputs.get("schema") != "McpTrustPythonSourceBuildInputsV1"
        or inputs.get("python_base") != payload.get("python_base")
        or inputs.get("platform") != payload.get("platform")
        or inputs.get("source_date_epoch") != payload.get("source_date_epoch")
        or inputs.get("inputs") != payload.get("input_artifacts")
        or inputs.get("expected_wheels") != payload.get("first_build_wheels")
        or payload.get("first_build_wheels") != payload.get("second_build_wheels")
    ):
        return None
    controls = payload.get("sandbox_controls")
    expected_controls = {
        "read_only_root": True,
        "cap_drop": ["ALL"],
        "no_new_privileges": True,
        "memory": "512m",
        "pids": 64,
        "cpus": 1,
        "writable_mounts": ["task-owned-/work", "ephemeral-/tmp"],
        "secrets": "none",
    }
    tools = payload.get("tool_versions")
    if (
        controls != expected_controls
        or not isinstance(tools, dict)
        or not tools
        or not all(
            isinstance(key, str) and isinstance(item, str) and item
            for key, item in tools.items()
        )
    ):
        return None
    return {
        "path": receipt_path,
        "sha256": receipt_sha256,
        "receipt_digest": claimed,
        "input_descriptor_path": input_ref[0],
        "input_descriptor_sha256": input_ref[1],
        "builder_path": builder_ref[0],
        "builder_sha256": builder_ref[1],
    }


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
    source_build_ref = (
        descriptor.get("source_build_receipt")
        if isinstance(descriptor, dict)
        else None
    )
    if source_build_ref is not None:
        expected_keys.add("source_build_receipt")
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
        not in {
            "registry-client-allowlist-no-package-code",
            "registry-client-allowlist-build-code-network-none",
        }
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
    source_build: dict[str, str] | None = None
    package_code_executed = descriptor.get("package_code_executed")
    if package_code_executed is False:
        if source_build_ref is not None or descriptor.get("preparation_network_policy") != (
            "registry-client-allowlist-no-package-code"
        ):
            return None
    elif package_code_executed is True:
        if kind != "python" or descriptor.get("preparation_network_policy") != (
            "registry-client-allowlist-build-code-network-none"
        ):
            return None
        source_build = _python_source_build_receipt(
            repo_root=repo_root, value=source_build_ref
        )
        if source_build is None:
            return None
    else:
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
    normalized = {
        "descriptor_path": descriptor_path,
        "descriptor_sha256": descriptor_sha256,
        "bundle_path": str(descriptor["bundle_path"]),
        "bundle_sha256": str(descriptor["bundle_sha256"]),
        **metadata,
    }
    if source_build is not None:
        normalized["source_build_receipt"] = source_build
    return normalized


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
        or not _stable_image_build_tool_versions(tools)
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

        if not (
            (value[:2] == ["docker-buildx", "build"])
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
        **{
            tracked_path: tracked_sha256
            for value in normalized_artifacts.values()
            for source_build in [value.get("source_build_receipt")]
            if isinstance(source_build, dict)
            for tracked_path, tracked_sha256 in (
                (source_build["path"], source_build["sha256"]),
                (
                    source_build["input_descriptor_path"],
                    source_build["input_descriptor_sha256"],
                ),
                (source_build["builder_path"], source_build["builder_sha256"]),
            )
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
    execution_policy = load_policy(policy_path, seed_path, masked_path)
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
    locked_mcp_audits = _locked_package_version(repo_root, "mcp-audits")
    tool_versions = {
        "python": platform.python_version(),
        "python_executable": str(Path(sys.executable).resolve()),
        "mcp_audits": _package_version("mcp-audits"),
        "mcp_audits_locked": locked_mcp_audits,
        "mcp_trust": _package_version("mcp-trust"),
        "docker_client": docker_versions["client"],
        "docker_server": docker_versions["server"],
    }
    if tool_versions["mcp_audits"] == "UNKNOWN":
        reasons.append("mcp_audits_runtime_unavailable")
    if locked_mcp_audits == "UNKNOWN":
        reasons.append("mcp_audits_lock_unavailable")
    elif tool_versions["mcp_audits"] != locked_mcp_audits:
        reasons.append("mcp_audits_runtime_lock_mismatch")
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
            "execution_boundary": {
                "schema": "McpTrustRefreshExecutionBoundaryV1",
                "scannable": sorted(execution_policy.scannable),
                "blocked": sorted(execution_policy.blocked),
            },
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


def _controlled_result_projection(candidate: Path) -> dict[str, dict[str, Any]]:
    payload = load_json(candidate / "scan_results.json")
    results = payload.get("results") if isinstance(payload, dict) else None
    if not isinstance(results, list):
        raise GradeRefreshError("controlled candidate scan results are invalid")
    projected: dict[str, dict[str, Any]] = {}
    for result in results:
        if not isinstance(result, dict) or not isinstance(result.get("server_slug"), str):
            raise GradeRefreshError("controlled candidate result shape is invalid")
        slug = result["server_slug"]
        if slug in projected:
            raise GradeRefreshError("controlled candidate contains duplicate results")
        state = result.get("state")
        row: dict[str, Any] = {"server_slug": slug, "state": state}
        if state == "fresh":
            receipt_ref = result.get("receipt")
            if (
                not isinstance(receipt_ref, str)
                or not receipt_ref
                or Path(receipt_ref).name != receipt_ref
            ):
                raise GradeRefreshError("controlled candidate receipt reference is invalid")
            receipt = load_json(candidate / "receipts" / receipt_ref)
            scan = receipt.get("scan") if isinstance(receipt, dict) else None
            if not isinstance(scan, dict):
                raise GradeRefreshError("controlled candidate receipt is invalid")
            row.update(
                {
                    "fresh_grade": result.get("fresh_grade"),
                    "transparency": result.get("transparency"),
                    "engine_name": result.get("engine_name"),
                    "engine_version": result.get("engine_version"),
                    "risk": scan.get("risk"),
                    "findings": scan.get("findings"),
                    "evidence": receipt.get("evidence"),
                    "danger_score": receipt.get("danger_score"),
                    "sandbox": receipt.get("sandbox"),
                    "caveats": receipt.get("caveats"),
                    "freshness_state": result.get("freshness_state"),
                    "freshness_reason": result.get("freshness_reason"),
                    "stale_after": result.get("stale_after"),
                    "operator_masked": False,
                    "grade_withheld": False,
                }
            )
        elif state == "masked":
            proof_ref = result.get("scan_proof")
            if (
                not isinstance(proof_ref, str)
                or not proof_ref
                or Path(proof_ref).name != proof_ref
            ):
                raise GradeRefreshError("controlled masked proof reference is invalid")
            proof = load_json(candidate / "masked-proofs" / proof_ref)
            row.update(
                {
                    "engine_name": result.get("engine_name"),
                    "engine_version": result.get("engine_version"),
                    "proof_outcome": (
                        proof.get("outcome") if isinstance(proof, dict) else None
                    ),
                    "evidence_present": (
                        proof.get("evidence_present") if isinstance(proof, dict) else None
                    ),
                    "sandbox": proof.get("sandbox") if isinstance(proof, dict) else None,
                    "freshness_state": result.get("freshness_state"),
                    "freshness_reason": result.get("freshness_reason"),
                    "stale_after": result.get("stale_after"),
                    "operator_masked": True,
                    "grade_withheld": True,
                }
            )
        else:
            row.update(
                {
                    "fresh_grade": result.get("fresh_grade"),
                    "execution_disposition": result.get("execution_disposition"),
                    "reason": result.get("reason"),
                    "error_type": result.get("error_type"),
                }
            )
        projected[slug] = row
    return projected


def triage_candidate(
    *,
    candidate: Path,
    preflight: dict[str, Any],
    repeatability: dict[str, Any],
    seed_path: Path,
    masked_path: Path,
    repeat_candidate: Path | None = None,
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
    if verification.get("structural_valid") is not True:
        add("Critical", "candidate_verification_failed")
    elif verification.get("publication_ready") is not True:
        add("Critical", "candidate_not_publication_ready")
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
    repeat_candidate_manifest_digest: str | None = None
    if repeat_candidate is not None:
        repeat_verification = candidate_verifier(
            repeat_candidate,
            expected_seed_path=seed_path,
            expected_masked_path=masked_path,
        )
        if repeat_verification.get("structural_valid") is not True:
            add("Critical", "repeat_candidate_verification_failed")
        try:
            repeat_manifest = load_json(repeat_candidate / "MANIFEST.json")
            repeat_candidate_manifest_digest = digest_file(
                repeat_candidate / "MANIFEST.json"
            )
            if not isinstance(repeat_manifest, dict) or any(
                repeat_manifest.get(key) != manifest.get(key)
                for key in ("catalog", "masking", "qualification", "sandbox")
            ):
                add("High", "controlled_repeat_binding_mismatch")
            first_projection = _controlled_result_projection(candidate)
            second_projection = _controlled_result_projection(repeat_candidate)
            inconsistent_slugs = sorted(
                slug
                for slug in set(first_projection) | set(second_projection)
                if first_projection.get(slug) != second_projection.get(slug)
            )
            for slug in inconsistent_slugs:
                add("High", "controlled_repeat_inconsistent", slug)
        except GradeRefreshError:
            add("Critical", "controlled_repeat_evidence_invalid")
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
        "repeat_candidate_manifest_digest": repeat_candidate_manifest_digest,
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
        and (
            triage.get("repeat_candidate_manifest_digest") is None
            or (
                isinstance(triage.get("repeat_candidate_manifest_digest"), str)
                and _SHA256.fullmatch(triage["repeat_candidate_manifest_digest"])
                is not None
            )
        )
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
        and triage.get("candidate_claimed_state") in {"complete", "partial"}
        and isinstance(verification, dict)
        and set(verification)
        == {"structural_valid", "publication_ready", "state", "errors"}
        and verification.get("structural_valid") is True
        and verification.get("publication_ready")
        is (triage.get("candidate_claimed_state") == "complete")
        and verification.get("state") == triage.get("candidate_claimed_state")
        and verification.get("errors") == []
    )


def _load_disposition_policy(
    *, path: Path, inventory: dict[str, Any]
) -> dict[str, Any]:
    payload = load_json(path)
    base_keys = {
        "schema",
        "review_state",
        "grade_semantics",
        "historical_baseline",
        "forward_baseline",
        "scheduler",
        "entries",
    }
    if not isinstance(payload, dict):
        raise GradeRefreshError("refresh disposition policy fields are invalid")
    if payload.get("schema") != DISPOSITION_POLICY_SCHEMA:
        raise GradeRefreshError("refresh disposition policy schema is unsupported")
    review_state = payload.get("review_state")
    if review_state not in {
        "PROPOSED",
        "ACCEPTED",
        "SANITIZED_REACCEPTANCE_REQUIRED",
        "ACCEPTED_CURRENT_SOURCE_REVIEW",
    }:
        raise GradeRefreshError("refresh disposition review state is invalid")
    expected_keys = base_keys | ({"acceptance"} if review_state != "PROPOSED" else set())
    if set(payload) != expected_keys:
        raise GradeRefreshError("refresh disposition policy fields are invalid")
    if payload.get("grade_semantics") != "technical-danger-not-endorsement":
        raise GradeRefreshError("refresh disposition grade semantics are invalid")
    if payload.get("historical_baseline") != {
        "state": "UNKNOWN",
        "disposition": "preserve-unknown-no-retroactive-comparison",
    }:
        raise GradeRefreshError("historical baseline must remain UNKNOWN")
    expected_forward = (
        {
            "state": "OPERATOR_ACCEPTED_EXACT_V38_LOCAL_REVIEW_ONLY",
            "disposition": (
                "adopt-exact-v37-candidate-bindings-as-current-forward-baseline"
            ),
        }
        if review_state == "ACCEPTED_CURRENT_SOURCE_REVIEW"
        else
        {
            "state": "ACCEPTED",
            "disposition": "adopt-exact-v20-candidate-bindings-as-forward-baseline",
        }
        if review_state == "ACCEPTED"
        else (
            {
                "state": "PENDING_SANITIZED_REACCEPTANCE",
                "disposition": (
                    "preserve-exact-v20-bindings-pending-sanitized-artifact-"
                    "reacceptance"
                ),
            }
            if review_state == "SANITIZED_REACCEPTANCE_REQUIRED"
            else {
                "state": "PROPOSED",
                "disposition": "adopt-exact-candidate-bindings-after-operator-acceptance",
            }
        )
    )
    if payload.get("forward_baseline") != expected_forward:
        raise GradeRefreshError("forward baseline disposition is invalid")
    if review_state == "ACCEPTED_CURRENT_SOURCE_REVIEW":
        acceptance = payload.get("acceptance")
        expected_fields = {
            "authority",
            "scope",
            "acceptance_state",
            "accepted_review_path",
            "accepted_review_receipt_digest",
            "accepted_review_artifact_sha256",
            "accepted_review_policy_sha256",
            "accepted_disposition_path",
            "accepted_disposition_receipt_digest",
            "accepted_disposition_artifact_sha256",
        }
        if (
            not isinstance(acceptance, dict)
            or set(acceptance) != expected_fields
            or acceptance.get("authority") != "operator"
            or acceptance.get("scope")
            != "all-eight-current-masked-dispositions-and-exact-v37-forward-baseline"
            or acceptance.get("acceptance_state") != "ACCEPTED_EXACT_V38"
            or acceptance.get("accepted_review_path")
            != "accepted_publication_review_v38.json"
            or not isinstance(acceptance.get("accepted_review_policy_sha256"), str)
            or _SHA256.fullmatch(acceptance["accepted_review_policy_sha256"])
            is None
            or acceptance.get("accepted_disposition_path")
            != "accepted_disposition_artifact_v38.json"
            or any(
                not isinstance(acceptance.get(field), str)
                or _SHA256.fullmatch(acceptance[field]) is None
                for field in {
                    "accepted_review_receipt_digest",
                    "accepted_review_artifact_sha256",
                    "accepted_disposition_receipt_digest",
                    "accepted_disposition_artifact_sha256",
                }
            )
        ):
            raise GradeRefreshError("current-source acceptance binding is invalid")
    elif review_state == "ACCEPTED":
        acceptance = payload.get("acceptance")
        if (
            not isinstance(acceptance, dict)
            or set(acceptance)
            != {
                "authority",
                "scope",
                "accepted_review_path",
                "accepted_review_receipt_digest",
                "accepted_review_artifact_sha256",
            }
            or acceptance.get("authority") != "operator"
            or acceptance.get("scope")
            != "all-eight-masked-dispositions-and-exact-v20-forward-baseline"
            or acceptance.get("accepted_review_path")
            != "accepted_publication_review_v20.json"
            or not isinstance(acceptance.get("accepted_review_receipt_digest"), str)
            or _SHA256.fullmatch(acceptance["accepted_review_receipt_digest"]) is None
            or not isinstance(acceptance.get("accepted_review_artifact_sha256"), str)
            or _SHA256.fullmatch(acceptance["accepted_review_artifact_sha256"]) is None
        ):
            raise GradeRefreshError("refresh disposition acceptance binding is invalid")
    elif review_state == "SANITIZED_REACCEPTANCE_REQUIRED":
        acceptance = payload.get("acceptance")
        expected_fields = {
            "authority",
            "scope",
            "historical_review_receipt_digest",
            "historical_review_artifact_sha256",
            "sanitized_review_path",
            "sanitized_review_receipt_digest",
            "sanitized_review_artifact_sha256",
            "sanitization_policy",
            "sanitized_field",
            "sanitized_replacement",
            "original_value_sha256",
            "sanitized_acceptance_state",
        }
        if (
            not isinstance(acceptance, dict)
            or set(acceptance) != expected_fields
            or acceptance.get("authority") != "operator"
            or acceptance.get("scope")
            != "all-eight-masked-dispositions-and-exact-v20-forward-baseline"
            or acceptance.get("historical_review_receipt_digest")
            != "sha256:15b1367db8f671c84884247f2fc698abef8436897d9a7e1c31634d0f2bcbbddc"
            or acceptance.get("historical_review_artifact_sha256")
            != "sha256:2a7a95f129b86a115c067bf1542757a8524318a8b2f2f44a6b84d891c46139a8"
            or not isinstance(acceptance.get("sanitized_review_path"), str)
            or Path(acceptance["sanitized_review_path"]).name
            != acceptance["sanitized_review_path"]
            or not isinstance(acceptance.get("sanitized_review_receipt_digest"), str)
            or _SHA256.fullmatch(acceptance["sanitized_review_receipt_digest"]) is None
            or not isinstance(acceptance.get("sanitized_review_artifact_sha256"), str)
            or _SHA256.fullmatch(acceptance["sanitized_review_artifact_sha256"]) is None
            or acceptance.get("sanitization_policy")
            != "normalize-python-executable-to-versioned-command-v1"
            or acceptance.get("sanitized_field")
            != "forward_baseline.tool_versions.python_executable"
            or acceptance.get("sanitized_replacement") != "python3.11"
            or acceptance.get("original_value_sha256")
            != "sha256:9061081ffe2519f9fad388ce242ef4303808a4a5a5433e31db73a4ad925f89b8"
            or acceptance.get("sanitized_acceptance_state")
            != "PENDING_OPERATOR_REACCEPTANCE"
        ):
            raise GradeRefreshError("sanitized review lineage binding is invalid")
    if payload.get("scheduler") != {
        "disposition": "quarantine-disabled-unloaded",
        "definition_drift": "open-medium-gate",
        "activation_authorized": False,
        "activation_gate": "reconcile-definition-and-obtain-separate-approval",
    }:
        raise GradeRefreshError("scheduler disposition is invalid")
    entries = payload.get("entries")
    if not isinstance(entries, list):
        raise GradeRefreshError("refresh disposition entries must be a list")
    inventory_entries = inventory.get("entries")
    if not isinstance(inventory_entries, list):
        raise GradeRefreshError("catalog inventory entries are invalid")
    masked_inventory = {
        row["slug"]: row
        for row in inventory_entries
        if isinstance(row, dict)
        and isinstance(row.get("slug"), str)
        and row.get("intentionally_masked") is True
    }
    normalized: list[dict[str, str]] = []
    for entry in entries:
        if not isinstance(entry, dict) or set(entry) != {
            "slug",
            "disposition",
            "rationale_code",
            "next_review_condition",
        }:
            raise GradeRefreshError("refresh disposition entry fields are invalid")
        if not all(isinstance(value, str) and value for value in entry.values()):
            raise GradeRefreshError("refresh disposition entry values are invalid")
        slug = entry["slug"]
        inventory_row = masked_inventory.get(slug)
        if inventory_row is None:
            raise GradeRefreshError("refresh disposition references an unmasked entry")
        if (
            inventory_row.get("unsupported_upstream") is True
            and inventory_row.get("credential_dependent") is True
            and inventory_row.get("backing_service_dependent") is True
        ):
            expected = {
                "disposition": "KEEP_MASKED_ARCHIVED_UNSUPPORTED",
                "rationale_code": "archived-unsupported-credential-and-backing-service",
                "next_review_condition": (
                    "supported-upstream-and-approved-controlled-service-evidence"
                ),
            }
        elif inventory_row.get("backing_service_dependent") is True:
            expected = {
                "disposition": "KEEP_MASKED_REVIEW_REQUIRED",
                "rationale_code": "backing-service-not-exercised",
                "next_review_condition": "approved-controlled-backing-service-evidence",
            }
        else:
            expected = {
                "disposition": "KEEP_MASKED_REVIEW_REQUIRED",
                "rationale_code": "operator-masking-continuity",
                "next_review_condition": "explicit-human-disposition",
            }
        if any(entry.get(key) != value for key, value in expected.items()):
            raise GradeRefreshError(
                f"refresh disposition is inconsistent with inventory: {slug}"
            )
        normalized.append(dict(entry))
    slugs = [entry["slug"] for entry in normalized]
    if len(slugs) != len(set(slugs)) or set(slugs) != set(masked_inventory):
        raise GradeRefreshError("every masked catalog entry needs one disposition")
    result = dict(payload)
    result["entries"] = sorted(normalized, key=lambda item: item["slug"])
    return result


def _load_accepted_review(
    *, path: Path, disposition_policy: dict[str, Any]
) -> dict[str, Any]:
    acceptance = disposition_policy.get("acceptance")
    if not isinstance(acceptance, dict):
        raise GradeRefreshError("accepted disposition policy lacks acceptance evidence")
    sanitized = (
        disposition_policy.get("review_state")
        == "SANITIZED_REACCEPTANCE_REQUIRED"
    )
    current_source = (
        disposition_policy.get("review_state") == "ACCEPTED_CURRENT_SOURCE_REVIEW"
    )
    artifact_key = (
        "sanitized_review_artifact_sha256"
        if sanitized
        else "accepted_review_artifact_sha256"
    )
    receipt_key = (
        "sanitized_review_receipt_digest"
        if sanitized
        else "accepted_review_receipt_digest"
    )
    if digest_file(path) != acceptance.get(artifact_key):
        raise GradeRefreshError("accepted review artifact digest does not match policy")
    review = load_json(path)
    if review.get("schema") != PUBLICATION_REVIEW_SCHEMA:
        raise GradeRefreshError("accepted review schema is invalid")
    unsigned = dict(review)
    claimed = unsigned.pop("receipt_digest", None)
    if (
        not isinstance(claimed, str)
        or claimed != digest_bytes(canonical_bytes(unsigned))
        or claimed != acceptance.get(receipt_key)
    ):
        raise GradeRefreshError("accepted review receipt integrity is invalid")
    review_policy = review.get("disposition_policy")
    review_forward = review.get("forward_baseline")
    if (
        not isinstance(review_policy, dict)
        or not isinstance(review_forward, dict)
        or review.get("decision") != "NO_GO"
        or review.get("review_state") != "READY_FOR_HUMAN_DISPOSITION"
        or review.get("publication_allowed") is not False
        or review.get("deployment_allowed") is not False
        or review.get("scheduler_change_allowed") is not False
        or review_policy.get("review_state") != "PROPOSED"
        or review_forward.get("state") != "PROPOSED"
    ):
        raise GradeRefreshError("accepted review is not an exact proposed decision")
    if current_source:
        if (
            acceptance.get("accepted_review_path") != path.name
            or review_policy.get("sha256")
            != acceptance.get("accepted_review_policy_sha256")
        ):
            raise GradeRefreshError("current-source review policy binding is invalid")
        artifact_path = path.parent / str(acceptance.get("accepted_disposition_path", ""))
        if digest_file(artifact_path) != acceptance.get(
            "accepted_disposition_artifact_sha256"
        ):
            raise GradeRefreshError("accepted disposition artifact digest does not match policy")
        artifact = load_json(artifact_path)
        if not isinstance(artifact, dict):
            raise GradeRefreshError("accepted disposition artifact must be an object")
        artifact_unsigned = dict(artifact)
        artifact_receipt = artifact_unsigned.pop("receipt_digest", None)
        artifact_acceptance = artifact.get("acceptance")
        artifact_forward = artifact.get("forward_baseline")
        artifact_masked = artifact.get("masked_dispositions")
        artifact_privacy = artifact.get("privacy")
        artifact_public = artifact.get("separate_public_state")
        if (
            artifact.get("schema") != "McpTrustAcceptedDispositionArtifactV1"
            or artifact.get("decision") != "OPERATOR_ACCEPTED_EXACT_V38"
            or artifact_receipt
            != acceptance.get("accepted_disposition_receipt_digest")
            or artifact_receipt != digest_bytes(canonical_bytes(artifact_unsigned))
            or not isinstance(artifact_acceptance, dict)
            or artifact_acceptance.get("state") != "ACCEPTED_EXACT_V38"
            or artifact_acceptance.get("scope") != acceptance.get("scope")
            or artifact_acceptance.get("proposal_policy_sha256")
            != acceptance.get("accepted_review_policy_sha256")
            or not isinstance(artifact_forward, dict)
            or artifact_forward.get("state")
            != "OPERATOR_ACCEPTED_EXACT_V38_LOCAL_REVIEW_ONLY"
            or artifact.get("historical_baseline")
            != disposition_policy.get("historical_baseline")
            or not isinstance(artifact_masked, dict)
            or artifact_masked.get("count") != 8
            or artifact_masked.get("acceptance_state")
            != "ACCEPTED_EXACT_V38_RETAIN_MASKED"
            or artifact_masked.get("projection_repeatability") != "PASS"
            or artifact_privacy
            != {
                "host_specific_path_matches": 0,
                "credential_values_present": False,
                "masked_grade_risk_finding_or_receipt_fields_present": False,
                "raw_candidate_transfer_allowed": False,
            }
            or not isinstance(artifact_public, dict)
            or artifact_public.get("production_freshness") != "UNKNOWN"
            or artifact_public.get("production_source_binding") != "UNKNOWN"
            or artifact_public.get("production_deployment_revision") != "UNKNOWN"
            or artifact_public.get("relationship_to_v38")
            != "NOT_PUBLISHED_AND_NOT_DEPLOYED"
        ):
            raise GradeRefreshError("accepted disposition artifact integrity is invalid")
        shared_forward_fields = {
            "source_revision",
            "source_tree_digest",
            "policy_digest",
            "seed_digest",
            "masking_digest",
            "catalog_denominator",
            "preflight_receipt_digest",
            "repeatability_receipt_digest",
            "triage_receipt_digest",
            "candidate_manifest_digest",
            "repeat_candidate_manifest_digest",
        }
        if any(
            artifact_forward.get(field) != review_forward.get(field)
            for field in shared_forward_fields
        ):
            raise GradeRefreshError("accepted current-source forward baseline changed")
        artifact_entries = artifact_masked.get("entries")
        review_entries = review.get("entry_dispositions")
        if not isinstance(artifact_entries, list) or not isinstance(review_entries, list):
            raise GradeRefreshError("accepted current-source dispositions are invalid")
        artifact_projection = {
            entry.get("slug"): {
                "disposition": entry.get("disposition"),
                "rationale_code": entry.get("rationale_code"),
                "next_review_condition": entry.get("next_review_condition"),
                "projection_digest": entry.get("projection_digest"),
            }
            for entry in artifact_entries
            if isinstance(entry, dict)
        }
        review_projection = {
            entry.get("slug"): {
                "disposition": entry.get("disposition"),
                "rationale_code": entry.get("rationale_code"),
                "next_review_condition": entry.get("next_review_condition"),
                "projection_digest": (
                    entry.get("controlled_evidence", {}).get("projection_digest")
                    if isinstance(entry.get("controlled_evidence"), dict)
                    else None
                ),
            }
            for entry in review_entries
            if isinstance(entry, dict)
        }
        if len(artifact_projection) != 8 or artifact_projection != review_projection:
            raise GradeRefreshError("accepted current-source dispositions changed")
    if sanitized:
        tool_versions = review_forward.get("tool_versions")
        if (
            acceptance.get("sanitized_review_path") != path.name
            or not isinstance(tool_versions, dict)
            or tool_versions.get("python_executable")
            != acceptance.get("sanitized_replacement")
            or "/" in str(tool_versions.get("python_executable", ""))
        ):
            raise GradeRefreshError("sanitized review privacy binding is invalid")
    return review


def _privacy_safe_tool_versions(payload: object) -> dict[str, Any]:
    """Remove host paths while retaining a stable versioned interpreter label."""
    if not isinstance(payload, dict):
        raise GradeRefreshError("publication review tool versions are invalid")
    normalized = dict(payload)
    executable = normalized.get("python_executable")
    if executable is None:
        return normalized
    version = normalized.get("python")
    if not isinstance(executable, str) or not isinstance(version, str):
        raise GradeRefreshError("publication review Python tool binding is invalid")
    parts = version.split(".")
    if len(parts) < 2 or not all(part.isdigit() for part in parts[:2]):
        raise GradeRefreshError("publication review Python version is invalid")
    normalized["python_executable"] = f"python{parts[0]}.{parts[1]}"
    return normalized


def _sanitized_acceptance_projection_valid(payload: object) -> bool:
    """Validate the receipt lineage needed for sanitized state-card claims."""
    if not isinstance(payload, dict):
        return False
    return bool(
        payload.get("authority") == "operator"
        and payload.get("scope")
        == "all-eight-masked-dispositions-and-exact-v20-forward-baseline"
        and payload.get("historical_review_receipt_digest")
        == "sha256:15b1367db8f671c84884247f2fc698abef8436897d9a7e1c31634d0f2bcbbddc"
        and payload.get("historical_review_artifact_sha256")
        == "sha256:2a7a95f129b86a115c067bf1542757a8524318a8b2f2f44a6b84d891c46139a8"
        and isinstance(payload.get("sanitized_review_path"), str)
        and Path(payload["sanitized_review_path"]).name
        == payload["sanitized_review_path"]
        and isinstance(payload.get("sanitized_review_receipt_digest"), str)
        and _SHA256.fullmatch(payload["sanitized_review_receipt_digest"]) is not None
        and isinstance(payload.get("sanitized_review_artifact_sha256"), str)
        and _SHA256.fullmatch(payload["sanitized_review_artifact_sha256"]) is not None
        and payload.get("sanitization_policy")
        == "normalize-python-executable-to-versioned-command-v1"
        and payload.get("sanitized_field")
        == "forward_baseline.tool_versions.python_executable"
        and payload.get("sanitized_replacement") == "python3.11"
        and payload.get("original_value_sha256")
        == "sha256:9061081ffe2519f9fad388ce242ef4303808a4a5a5433e31db73a4ad925f89b8"
        and payload.get("sanitized_acceptance_state")
        == "PENDING_OPERATOR_REACCEPTANCE"
    )


def _masked_projection_evidence(
    *, slug: str, projection: dict[str, Any]
) -> dict[str, str]:
    sandbox = projection.get("sandbox")
    if (
        projection.get("state") != "masked"
        or projection.get("proof_outcome") != "scan_succeeded"
        or projection.get("evidence_present") is not True
        or not isinstance(sandbox, dict)
        or sandbox.get("MCP_TRUST_SANDBOX") != "docker"
        or sandbox.get("MCP_TRUST_SANDBOX_NETWORK") != "none"
        or sandbox.get("MCP_TRUST_SCAN_CREDENTIALS") != "dummy"
        or not isinstance(sandbox.get("MCP_TRUST_SANDBOX_IMAGE"), str)
        or _SHA256.fullmatch(sandbox["MCP_TRUST_SANDBOX_IMAGE"]) is None
        or "fresh_grade" in projection
        or "risk" in projection
        or "findings" in projection
    ):
        raise GradeRefreshError(f"masked controlled evidence is invalid: {slug}")
    return {
        "outcome": "scan_succeeded",
        "evidence_state": "present",
        "sandbox_image_id": sandbox["MCP_TRUST_SANDBOX_IMAGE"],
        "projection_digest": digest_bytes(canonical_bytes(projection)),
    }


def build_publication_review_decision(
    *,
    candidate: Path,
    repeat_candidate: Path,
    preflight: dict[str, Any],
    repeatability: dict[str, Any],
    triage: dict[str, Any],
    seed_path: Path,
    masked_path: Path,
    policy_path: Path,
    disposition_path: Path,
    accepted_review_path: Path | None = None,
    candidate_verifier: Callable[..., dict[str, Any]] | None = None,
    projection_builder: Callable[[Path], dict[str, dict[str, Any]]] | None = None,
) -> dict[str, Any]:
    """Build a deterministic, non-publishing disposition and decision receipt."""
    inventory = catalog_inventory(
        seed_path=seed_path,
        masked_path=masked_path,
        policy_path=policy_path,
    )
    disposition_policy = _load_disposition_policy(
        path=disposition_path, inventory=inventory
    )
    review_state = disposition_policy["review_state"]
    dispositions_accepted = review_state in {
        "ACCEPTED",
        "SANITIZED_REACCEPTANCE_REQUIRED",
        "ACCEPTED_CURRENT_SOURCE_REVIEW",
    }
    current_source_accepted = review_state == "ACCEPTED_CURRENT_SOURCE_REVIEW"
    sanitized_reacceptance_required = (
        review_state == "SANITIZED_REACCEPTANCE_REQUIRED"
    )
    accepted_review: dict[str, Any] | None = None
    if dispositions_accepted:
        if accepted_review_path is None:
            raise GradeRefreshError("accepted disposition policy requires a review artifact")
        accepted_review = _load_accepted_review(
            path=accepted_review_path, disposition_policy=disposition_policy
        )
    elif accepted_review_path is not None:
        raise GradeRefreshError("proposed disposition policy cannot accept a review artifact")
    recomputed_triage = triage_candidate(
        candidate=candidate,
        repeat_candidate=repeat_candidate,
        preflight=preflight,
        repeatability=repeatability,
        seed_path=seed_path,
        masked_path=masked_path,
        candidate_verifier=candidate_verifier,
    )
    if triage != recomputed_triage:
        raise GradeRefreshError("publication review triage is not independently reproducible")
    if triage.get("counts") != {
        "Critical": 0,
        "High": 8,
        "Medium": 9,
        "Low": 0,
    }:
        raise GradeRefreshError("publication review requires the exact admitted finding set")
    masked_findings = {
        finding.get("slug")
        for finding in triage.get("findings", [])
        if isinstance(finding, dict)
        and finding.get("severity") == "High"
        and finding.get("code") == "masked_result_requires_review"
    }
    masked_slugs = {
        entry["slug"]
        for entry in disposition_policy["entries"]
    }
    if masked_findings != masked_slugs:
        raise GradeRefreshError("masked findings and dispositions do not match")
    if projection_builder is None:
        projection_builder = _controlled_result_projection
    first_projection = projection_builder(candidate)
    second_projection = projection_builder(repeat_candidate)
    candidate_counts = {
        "fresh": sum(row.get("state") == "fresh" for row in first_projection.values()),
        "masked": sum(row.get("state") == "masked" for row in first_projection.values()),
        "total": len(first_projection),
    }
    if candidate_counts != {"fresh": 23, "masked": 8, "total": 31}:
        raise GradeRefreshError("publication review candidate denominator is invalid")
    if candidate_counts["total"] != inventory["catalog_denominator"]:
        raise GradeRefreshError("publication review inventory denominator changed")
    inventory_by_slug = {
        row["slug"]: row
        for row in inventory["entries"]
        if isinstance(row, dict) and isinstance(row.get("slug"), str)
    }
    entry_dispositions: list[dict[str, Any]] = []
    for disposition in disposition_policy["entries"]:
        slug = disposition["slug"]
        first = _masked_projection_evidence(
            slug=slug, projection=first_projection.get(slug, {})
        )
        second = _masked_projection_evidence(
            slug=slug, projection=second_projection.get(slug, {})
        )
        if first != second:
            raise GradeRefreshError(f"masked controlled repeats differ: {slug}")
        inventory_row = inventory_by_slug[slug]
        entry_dispositions.append(
            {
                **disposition,
                "acceptance_state": (
                    (
                        "HUMAN_ACCEPTED_V20"
                        if sanitized_reacceptance_required
                        else "HUMAN_ACCEPTED_V38"
                        if current_source_accepted
                        else "HUMAN_ACCEPTED"
                    )
                    if dispositions_accepted
                    else "PENDING_HUMAN_ACCEPTANCE"
                ),
                "classification": {
                    "unsupported_upstream": inventory_row["unsupported_upstream"],
                    "credential_dependent": inventory_row["credential_dependent"],
                    "backing_service_dependent": inventory_row[
                        "backing_service_dependent"
                    ],
                    "unsafe_to_execute_unsandboxed": inventory_row[
                        "unsafe_to_execute_unsandboxed"
                    ],
                },
                "controlled_evidence": first,
                "claim_ceiling": (
                    "Controlled network-none invocation and masked evidence presence only; "
                    "no unmasked grade, safety, endorsement, or backing-service claim."
                ),
            }
        )
    source = preflight.get("source_binding")
    catalog = preflight.get("catalog")
    sandbox = preflight.get("sandbox")
    scheduler = preflight.get("scheduler")
    if not all(isinstance(value, dict) for value in (source, catalog, sandbox, scheduler)):
        raise GradeRefreshError("publication review preflight bindings are invalid")
    assert isinstance(source, dict)
    assert isinstance(catalog, dict)
    assert isinstance(sandbox, dict)
    assert isinstance(scheduler, dict)
    if (
        preflight.get("status") != "READY"
        or preflight.get("safe_to_execute_catalog") is not True
        or catalog.get("policy_digest") != digest_file(policy_path)
        or catalog.get("seed_digest") != digest_file(seed_path)
        or catalog.get("masking_digest") != digest_file(masked_path)
        or catalog.get("denominator") != inventory["catalog_denominator"]
    ):
        raise GradeRefreshError("publication review preflight is stale or unbound")
    image_bindings = sandbox.get("image_bindings")
    if (
        not isinstance(image_bindings, list)
        or len(image_bindings) != 5
        or not all(
            isinstance(binding, dict)
            and isinstance(binding.get("reference"), str)
            and binding.get("state") == "BOUND"
            and isinstance(binding.get("image_id"), str)
            and _SHA256.fullmatch(binding["image_id"]) is not None
            and isinstance(binding.get("sandbox_controls"), dict)
            and binding["sandbox_controls"].get("all_required_controls") is True
            for binding in image_bindings
        )
    ):
        raise GradeRefreshError("publication review image bindings are incomplete")
    qualified_image_ids = {binding["image_id"] for binding in image_bindings}
    if any(
        entry["controlled_evidence"]["sandbox_image_id"] not in qualified_image_ids
        for entry in entry_dispositions
    ):
        raise GradeRefreshError("masked evidence does not use a qualified image binding")
    scheduler_safe = bool(
        scheduler.get("state") == "DISABLED_UNLOADED"
        and scheduler.get("persistently_disabled") is True
        and scheduler.get("loaded_domains") == []
        and scheduler.get("mutation_performed") is False
    )
    scheduler_gates = ["dormant_scheduler_definition_drift_before_activation"]
    if not scheduler_safe:
        scheduler_gates.append("scheduler_state_changed_or_unknown")
    if sanitized_reacceptance_required:
        acceptance_gates = ["sanitized_review_acceptance_required"]
    elif review_state in {"ACCEPTED", "ACCEPTED_CURRENT_SOURCE_REVIEW"}:
        acceptance_gates = []
    else:
        acceptance_gates = [
            "masked_disposition_acceptance_required",
            "forward_baseline_acceptance_required",
        ]
    payload: dict[str, Any] = {
        "schema": PUBLICATION_REVIEW_SCHEMA,
        "decision": "NO_GO",
        "review_state": (
            "READY_FOR_SANITIZED_REACCEPTANCE"
            if sanitized_reacceptance_required
            else (
                "ACCEPTED_FOR_SOURCE_REVIEW"
                if review_state in {"ACCEPTED", "ACCEPTED_CURRENT_SOURCE_REVIEW"}
                else "READY_FOR_HUMAN_DISPOSITION"
            )
        ),
        "publication_allowed": False,
        "deployment_allowed": False,
        "scheduler_change_allowed": False,
        "grade_semantics": disposition_policy["grade_semantics"],
        "claim_ceiling": (
            "V20 disposition acceptance lineage with a privacy-normalized exact candidate "
            "successor pending operator reacceptance; not publication, deployment, production "
            "freshness, scheduler, safety, or endorsement."
            if sanitized_reacceptance_required
            else (
                "Exact V38 current-source disposition acceptance for the controlled V37 "
                "candidate only; not publication, deployment, production freshness, "
                "scheduler, safety, backing-service functionality, credentialed "
                "functionality, or endorsement."
                if current_source_accepted
                else "Local disposition acceptance record for the exact controlled candidate only; "
                "not publication, deployment, production freshness, scheduler, safety, "
                "or endorsement."
                if review_state == "ACCEPTED"
                else "Local disposition proposal for the exact controlled candidate only; "
                "not publication, deployment, production freshness, scheduler, safety, "
                "or endorsement."
            )
        ),
        "disposition_policy": {
            "path": str(disposition_path.name),
            "sha256": digest_file(disposition_path),
            "review_state": disposition_policy["review_state"],
        },
        "entry_dispositions": entry_dispositions,
        "disposition_counts": {
            "total": len(entry_dispositions),
            "pending_human_acceptance": (
                0 if dispositions_accepted else len(entry_dispositions)
            ),
            "accepted_human": (
                len(entry_dispositions) if dispositions_accepted else 0
            ),
            "retain_masked": len(entry_dispositions),
        },
        "candidate_counts": candidate_counts,
        "historical_baseline": disposition_policy["historical_baseline"],
        "forward_baseline": {
            **disposition_policy["forward_baseline"],
            "source_revision": source.get("revision", "UNKNOWN"),
            "source_tree_digest": source.get("source_tree_digest", "UNKNOWN"),
            "policy_digest": catalog.get("policy_digest", "UNKNOWN"),
            "seed_digest": catalog.get("seed_digest", "UNKNOWN"),
            "masking_digest": catalog.get("masking_digest", "UNKNOWN"),
            "catalog_denominator": catalog.get("denominator", 0),
            "preflight_receipt_digest": preflight.get("receipt_digest", "UNKNOWN"),
            "repeatability_receipt_digest": repeatability.get(
                "receipt_digest", "UNKNOWN"
            ),
            "triage_receipt_digest": triage.get("receipt_digest", "UNKNOWN"),
            "candidate_manifest_digest": triage.get(
                "candidate_manifest_digest", "UNKNOWN"
            ),
            "repeat_candidate_manifest_digest": triage.get(
                "repeat_candidate_manifest_digest", "UNKNOWN"
            ),
            "tool_versions": _privacy_safe_tool_versions(
                preflight.get("tool_versions", {})
            ),
            "qualified_images": {
                binding["reference"]: binding["image_id"]
                for binding in sorted(image_bindings, key=lambda item: item["reference"])
            },
        },
        "scheduler_disposition": {
            **disposition_policy["scheduler"],
            "observed_state": scheduler.get("state", "UNKNOWN"),
            "persistently_disabled": scheduler.get("persistently_disabled", "UNKNOWN"),
            "loaded_domains": scheduler.get("loaded_domains", "UNKNOWN"),
            "definitions_match": scheduler.get("definitions_match", "UNKNOWN"),
            "installed_plist_sha256": scheduler.get(
                "installed_plist_sha256", "UNKNOWN"
            ),
            "repository_plist_sha256": scheduler.get(
                "repository_plist_sha256", "UNKNOWN"
            ),
            "mutation_performed": scheduler.get("mutation_performed", "UNKNOWN"),
        },
        "blocking_gates": [
            *acceptance_gates,
            *(
                []
                if current_source_accepted
                else ["exact_source_review_and_landing_required"]
            ),
            "immutable_site_artifact_and_rollback_binding_required",
            "explicit_publication_authority_required",
            "production_source_and_deployment_binding_unknown",
        ],
        "quarantined_gates": scheduler_gates,
        "false_green_guards": [
            "candidate-readiness-is-not-publication-authority",
            "masked-scan-success-is-not-an-unmasked-grade-or-safety-claim",
            "qualified-images-do-not-prove-third-party-behavior",
            "local-candidate-freshness-does-not-prove-production-freshness",
            "disabled-scheduler-state-does-not-resolve-definition-drift",
            (
                "v20-acceptance-is-not-sanitized-artifact-acceptance"
                if sanitized_reacceptance_required
                else (
                    "source-acceptance-record-is-not-publication-authority"
                    if review_state in {"ACCEPTED", "ACCEPTED_CURRENT_SOURCE_REVIEW"}
                    else "masking-configuration-is-not-human-disposition-evidence"
                )
            ),
        ],
    }
    if accepted_review is not None:
        payload["acceptance"] = dict(disposition_policy["acceptance"])
        proposed_entries = accepted_review.get("entry_dispositions")
        if not isinstance(proposed_entries, list) or len(proposed_entries) != len(
            entry_dispositions
        ):
            raise GradeRefreshError("accepted review disposition denominator changed")
        for proposed, accepted in zip(proposed_entries, entry_dispositions, strict=True):
            if not isinstance(proposed, dict):
                raise GradeRefreshError("accepted review disposition is invalid")
            proposed_without_state = dict(proposed)
            proposed_without_state.pop("acceptance_state", None)
            accepted_without_state = dict(accepted)
            accepted_without_state.pop("acceptance_state", None)
            if (
                proposed.get("acceptance_state") != "PENDING_HUMAN_ACCEPTANCE"
                or proposed_without_state != accepted_without_state
            ):
                raise GradeRefreshError("accepted review dispositions changed")
        proposed_forward = dict(accepted_review.get("forward_baseline", {}))
        accepted_forward = dict(payload["forward_baseline"])
        for projection in (proposed_forward, accepted_forward):
            projection.pop("state", None)
            projection.pop("disposition", None)
        if proposed_forward != accepted_forward:
            raise GradeRefreshError("accepted review forward baseline bindings changed")
        if (
            accepted_review.get("historical_baseline")
            != payload["historical_baseline"]
            or accepted_review.get("candidate_counts") != payload["candidate_counts"]
        ):
            raise GradeRefreshError("accepted review candidate semantics changed")
    payload["receipt_digest"] = digest_bytes(canonical_bytes(payload))
    return payload


def build_publication_review_state_card(payload: dict[str, Any]) -> dict[str, Any]:
    """Project one integrity-checked review decision into the durable state card."""
    if payload.get("schema") != PUBLICATION_REVIEW_SCHEMA:
        raise GradeRefreshError("publication review decision schema is invalid")
    unsigned = dict(payload)
    claimed = unsigned.pop("receipt_digest", None)
    if not isinstance(claimed, str) or claimed != digest_bytes(canonical_bytes(unsigned)):
        raise GradeRefreshError("publication review decision receipt integrity is invalid")
    forward = payload.get("forward_baseline")
    dispositions = payload.get("disposition_counts")
    candidates = payload.get("candidate_counts")
    blockers = payload.get("blocking_gates")
    quarantines = payload.get("quarantined_gates")
    if not all(
        isinstance(value, dict) for value in (forward, dispositions, candidates)
    ) or not all(isinstance(value, list) for value in (blockers, quarantines)):
        raise GradeRefreshError("publication review decision state fields are invalid")
    assert isinstance(forward, dict)
    assert isinstance(dispositions, dict)
    assert isinstance(candidates, dict)
    assert isinstance(blockers, list)
    assert isinstance(quarantines, list)
    total = dispositions.get("total")
    if not isinstance(total, int) or isinstance(total, bool) or total <= 0:
        raise GradeRefreshError("publication review disposition count is invalid")
    proposed_counts = {
        "total": total,
        "pending_human_acceptance": total,
        "accepted_human": 0,
        "retain_masked": total,
    }
    accepted_counts = {
        "total": total,
        "pending_human_acceptance": 0,
        "accepted_human": total,
        "retain_masked": total,
    }
    if payload.get("review_state") == "ACCEPTED_FOR_SOURCE_REVIEW":
        accepted = True
        sanitized_pending = False
        disposition_projection = payload.get("disposition_policy")
        current_source_accepted = bool(
            isinstance(disposition_projection, dict)
            and disposition_projection.get("review_state")
            == "ACCEPTED_CURRENT_SOURCE_REVIEW"
        )
        if dispositions != accepted_counts:
            raise GradeRefreshError("accepted disposition counts are invalid")
        if current_source_accepted and (
            forward.get("state")
            != "OPERATOR_ACCEPTED_EXACT_V38_LOCAL_REVIEW_ONLY"
            or not isinstance(payload.get("acceptance"), dict)
            or payload["acceptance"].get("acceptance_state")
            != "ACCEPTED_EXACT_V38"
            or "exact_source_review_and_landing_required" in blockers
        ):
            raise GradeRefreshError("current-source acceptance binding is invalid")
    elif payload.get("review_state") == "READY_FOR_SANITIZED_REACCEPTANCE":
        accepted = True
        sanitized_pending = True
        current_source_accepted = False
        if dispositions != accepted_counts:
            raise GradeRefreshError("V20 accepted disposition counts are invalid")
        if "sanitized_review_acceptance_required" not in blockers:
            raise GradeRefreshError("sanitized review acceptance gate is missing")
        disposition_policy = payload.get("disposition_policy")
        if (
            not isinstance(disposition_policy, dict)
            or disposition_policy.get("review_state")
            != "SANITIZED_REACCEPTANCE_REQUIRED"
            or forward.get("state") != "PENDING_SANITIZED_REACCEPTANCE"
            or not _sanitized_acceptance_projection_valid(payload.get("acceptance"))
        ):
            raise GradeRefreshError("sanitized review acceptance binding is invalid")
    elif payload.get("review_state") == "READY_FOR_HUMAN_DISPOSITION":
        accepted = False
        sanitized_pending = False
        current_source_accepted = False
        if dispositions != proposed_counts:
            raise GradeRefreshError("proposed disposition counts are invalid")
    else:
        raise GradeRefreshError("publication review state is invalid")
    state: dict[str, Any] = {
        "schema": PUBLICATION_REVIEW_STATE_CARD_SCHEMA,
        "source_revision": forward.get("source_revision", "UNKNOWN"),
        "source_tree_digest": forward.get("source_tree_digest", "UNKNOWN"),
        "catalog_denominator": forward.get("catalog_denominator", 0),
        "candidate_counts": candidates,
        "disposition_counts": dispositions,
        "severity_findings": {
            "Critical": 0,
            "High": dispositions.get("retain_masked", 0),
            "Medium": 10,
            "Low": 0,
        },
        "completed_controls": [
            "catalog-inventory",
            "source-and-policy-digests",
            "image-provenance-preflight-run",
            "sandbox-policy-defined",
            "deterministic-fixture-repeatability",
            "grade-diff-review-triage-run",
            "controlled-sandbox-candidate-repeat",
            (
                "masked-disposition-accepted-v20"
                if sanitized_pending
                else "masked-disposition-accepted-v38-current-source"
                if current_source_accepted
                else "masked-disposition-accepted"
                if accepted
                else "masked-disposition-proposal"
            ),
            (
                "sanitized-review-receipt-generated"
                if sanitized_pending
                else "v37-forward-baseline-accepted-v38"
                if current_source_accepted
                else "forward-baseline-accepted"
                if accepted
                else "forward-baseline-proposal"
            ),
            "publication-decision-packet",
            "scheduler-readback-no-mutation",
        ],
        "outstanding_gates": [*blockers, *quarantines],
        "publication_state": payload.get("decision", "UNKNOWN"),
        "production_freshness": "UNKNOWN",
        "next_action": (
            "Accept the exact sanitized artifact digest and receipt before source review; "
            "publication, deployment, and scheduler activation remain separately gated."
            if sanitized_pending
            else "Build and verify the deterministic local site candidate; immutable "
            "rollback binding, explicit publication authority, and production binding "
            "remain separate gates."
            if current_source_accepted
            else "Review and land the accepted source record locally; immutable site and "
            "rollback binding, explicit publication authority, and production binding "
            "remain separate gates."
            if accepted
            else "Accept or revise the eight proposed masked-entry dispositions and the "
            "forward baseline; publication remains separately gated."
        ),
        "publication_review_receipt_digest": claimed,
    }
    state["receipt_digest"] = digest_bytes(canonical_bytes(state))
    return state


def publication_review_markdown(payload: dict[str, Any]) -> str:
    """Render a compact, grade-free human review view of a decision receipt."""
    entries = payload.get("entry_dispositions", [])
    accepted = payload.get("disposition_counts", {}).get("accepted_human") == len(
        entries
    )
    sanitized_pending = (
        payload.get("review_state") == "READY_FOR_SANITIZED_REACCEPTANCE"
    )
    if sanitized_pending:
        acceptance_label = (
            "accepted in V20 and remains masked; sanitized successor reacceptance pending"
        )
    elif accepted:
        acceptance_label = "accepted and remains masked"
    else:
        acceptance_label = "acceptance pending"
    entry_lines = "\n".join(
        f"- `{entry['slug']}` — `{entry['disposition']}`; "
        f"reason `{entry['rationale_code']}`; "
        f"{acceptance_label}."
        for entry in entries
        if isinstance(entry, dict)
    )
    blockers = "\n".join(
        f"- `{gate}`" for gate in payload.get("blocking_gates", [])
    )
    quarantines = "\n".join(
        f"- `{gate}`" for gate in payload.get("quarantined_gates", [])
    )
    baseline = payload.get("forward_baseline", {})
    status_label = (
        "V20-accepted; sanitized successor pending reacceptance"
        if sanitized_pending
        else "Accepted"
        if accepted
        else "Proposed"
    )
    source_revision = baseline.get("source_revision", "UNKNOWN")
    policy_digest = baseline.get("policy_digest", "UNKNOWN")
    masking_digest = baseline.get("masking_digest", "UNKNOWN")
    return f"""# MCP Trust publication decision packet

Decision: **{payload.get('decision', 'UNKNOWN')}**

This is a local review artifact. It grants no publication, deployment,
scheduler, credential, backing-service, or outreach authority. A danger grade
is a technical capability assessment, not an endorsement.

## {status_label} masked-entry dispositions

{entry_lines or '- none'}

No masked grade, risk detail, or finding detail is disclosed by this packet.
Controlled success proves invocation and evidence presence only.

## Baseline

- Historical baseline: `UNKNOWN`; no retroactive same-policy comparison.
- {status_label} forward source revision: `{source_revision}`
- {status_label} forward policy digest: `{policy_digest}`
- {status_label} forward masking digest: `{masking_digest}`
- Adoption state: `{baseline.get('state', 'UNKNOWN')}`

## Blocking publication gates

{blockers or '- none'}

## Quarantined scheduler gates

{quarantines or '- none'}

Production freshness remains `UNKNOWN`. Publication remains a separate human
and deployment decision after the exact source, artifact, rollback, and public
readback bindings exist.
"""


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
        completed_controls.append("controlled-sandbox-candidate-repeat")
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
            "Approve deterministic reconstruction of all five image cohorts from the "
            "tracked recipes, including immutable base digests, complete dependency locks, "
            "narrow dependency-preparation egress, network-none repeat builds, qualification "
            "receipts, and exact image IDs; then rerun preflight."
            if not preflight.get("safe_to_execute_catalog")
            else (
                (
                    "Resolve the severity-ordered candidate findings and qualify every "
                    "blocked row before requesting a separate publication decision."
                    if catalog.get("counts", {}).get("blocked", 0)
                    else "Resolve and record dispositions for the severity-ordered candidate "
                    "findings before requesting a separate publication decision."
                )
                if triage_valid
                else "Create one local review candidate, rerun deterministic verification, "
                "and triage."
            )
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
