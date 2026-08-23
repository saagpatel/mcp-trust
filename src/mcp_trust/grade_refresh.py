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
import shutil
import subprocess
import sys
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
POLICY_SCHEMA = "McpTrustRefreshPolicyV1"
_SHA256 = re.compile(r"^sha256:[0-9a-f]{64}$")
_GRADE_INDEX = {grade: index for index, grade in enumerate(("A", "B", "C", "D", "F"))}
_SOURCE_BINDING_FILES = (
    "DEPLOY-VM.md",
    "Dockerfile.scan",
    "README.md",
    "deploy/launchd/com.d.mcp-trust-refresh.plist",
    "deploy/mcp-trust.env.example",
    "deploy/mcp-trust.service",
    "docs/GRADE-REFRESH-OPERATOR-RUNBOOK.md",
    "docs/GRADE-REFRESH-PROGRAM.md",
    "masked-grades.json",
    "pyproject.toml",
    "scripts/build_deploy_bundle.py",
    "scripts/grade_refresh.py",
    "scripts/refresh_candidate.py",
    "scripts/refresh_and_publish.sh",
    "scripts/validate_launch_state.py",
    "uv.lock",
    "src/mcp_trust/api/app.py",
    "src/mcp_trust/catalog/refresh_policy.json",
    "src/mcp_trust/catalog/seed_servers.json",
    "src/mcp_trust/core/governance.py",
    "src/mcp_trust/core/grading.py",
    "src/mcp_trust/core/provenance.py",
    "src/mcp_trust/engine/mcpaudit.py",
    "src/mcp_trust/engine/sandbox.py",
    "src/mcp_trust/grade_refresh.py",
    "src/mcp_trust/receipts.py",
    "src/mcp_trust/refresh.py",
    "tests/test_api.py",
    "tests/test_deploy_bundle_builder.py",
    "tests/test_grade_refresh.py",
    "tests/test_launch_state_validator.py",
    "tests/test_receipt_provenance.py",
    "tests/test_refresh_candidate.py",
    "tests/test_sandbox.py",
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
        or not all(
            source is None
            or (
                isinstance(source, str)
                and source
                and not Path(source).is_absolute()
                and ".." not in Path(source).parts
            )
            for source in image_build_sources.values()
        )
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
        rows.append(
            {
                "slug": slug,
                "source_kind": source.get("kind"),
                "source_reference": source.get("reference"),
                "sandbox_image": image if local_process else None,
                "image_build_source": (
                    policy.raw["image_build_sources"].get(image) if local_process else None
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
        },
        "entries": rows,
    }


def source_binding(repo_root: Path) -> dict[str, Any]:
    file_digests = {
        relative: digest_file(repo_root / relative) for relative in _SOURCE_BINDING_FILES
    }
    binding_digest = digest_bytes(canonical_bytes(file_digests))

    def git(*args: str) -> str | None:
        completed = subprocess.run(
            ["git", "-C", str(repo_root), *args],
            text=True,
            capture_output=True,
            check=False,
        )
        return completed.stdout.strip() if completed.returncode == 0 else None

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
        installed_digest == source_digest if installed_digest is not None else "UNKNOWN"
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
        "installed_plist": str(installed_plist) if installed_digest is not None else None,
        "installed_plist_sha256": installed_digest,
        "repository_plist_sha256": source_digest,
        "definitions_match": definitions_match,
        "mutation_performed": False,
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
            if isinstance(row.get("sandbox_image"), str)
        }
    )
    image_build_sources: dict[str, dict[str, Any]] = {}
    inventory_by_image = {
        row["sandbox_image"]: row.get("image_build_source")
        for row in inventory["entries"]
        if isinstance(row.get("sandbox_image"), str)
    }
    for reference in image_refs:
        build_source = inventory_by_image.get(reference)
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
        image_build_sources[reference] = {
            "path": build_source,
            "sha256": digest_file(build_path),
            "state": "BOUND",
        }
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


def triage_candidate(
    *, candidate: Path, preflight: dict[str, Any], repeatability: dict[str, Any]
) -> dict[str, Any]:
    results_payload = load_json(candidate / "scan_results.json")
    manifest = load_json(candidate / "MANIFEST.json")
    results = results_payload.get("results") if isinstance(results_payload, dict) else None
    if not isinstance(results, list):
        raise GradeRefreshError("candidate scan results are invalid")
    findings: list[dict[str, str]] = []

    def add(severity: str, code: str, slug: str = "catalog") -> None:
        findings.append({"severity": severity, "code": code, "slug": slug})

    if preflight.get("status") != "READY":
        add("Critical", "preflight_not_ready")
    if repeatability.get("status") != "PASS":
        add("High", "repeatability_not_proven")
    if preflight.get("source_binding", {}).get("worktree_state") != "clean":
        add("High", "source_revision_not_cleanly_bound")
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
    }
    payload["receipt_digest"] = digest_bytes(canonical_bytes(payload))
    return payload


def build_state_card(
    *, preflight: dict[str, Any], repeatability: dict[str, Any], triage: dict[str, Any] | None
) -> dict[str, Any]:
    blockers = list(preflight.get("reasons", []))
    if repeatability.get("status") != "PASS":
        blockers.append("fixture_repeatability_failed")
    if triage is None:
        blockers.append("candidate_not_built_or_triaged")
    elif triage.get("review_required"):
        blockers.append("candidate_review_required")
    source = preflight.get("source_binding", {})
    catalog = preflight.get("catalog", {})
    scheduler = preflight.get("scheduler", {})
    if triage is not None:
        findings = list(triage.get("findings", []))
    else:
        findings = []
        if preflight.get("status") != "READY":
            findings.append(
                {
                    "severity": "Critical",
                    "code": "sandbox_preflight_not_ready",
                    "scope": "catalog",
                }
            )
        if any(
            str(reason).startswith("image_build_source_")
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
        "completed_controls": [
            "catalog-inventory",
            "source-and-policy-digests",
            "image-provenance-preflight",
            "network-filesystem-resource-secret-policy",
            "deterministic-fixture-repeatability",
            "grade-diff-review-triage",
            "review-only-authority",
            "scheduler-readback-no-mutation",
        ],
        "outstanding_gates": sorted(set(blockers)),
        "publication_state": "WAITING_FOR_EXPLICIT_APPROVAL",
        "production_freshness": "UNKNOWN",
        "next_action": (
            "Recover or approve deterministic build sources for all four image cohorts, "
            "restore their verified immutable images, then rerun preflight; do not run "
            "catalog servers before READY."
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
    waiting_code = "publication-approval-required"
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
    return {
        "schema": "HumanGateResumeCapsuleV1",
        "as_of": created.isoformat(),
        "capsule": {
            "capsule_id": "mcp-trust-grade-refresh-publication-gate",
            "created_at": created.isoformat(),
            "expires_at": (created + timedelta(days=30)).isoformat(),
            "waiting_condition": {"code": waiting_code, "digest": waiting_digest},
            "target": target,
            "authority": {"boundary": authority_boundary, "digest": authority_digest},
            "read_registry": "human-gate-read-kinds-v1",
            "authorized_next_read": requested,
            "freshness_seconds": 600,
            "claim_ceiling": (
                "Resume local review-only qualification after explicit chat approval; "
                "publication and deployment remain separately gated."
            ),
            "resume_states": ["publication-authorized"],
            "terminal_states": ["publication-declined", "program-withdrawn"],
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
