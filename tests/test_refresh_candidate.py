"""Approval-gated refresh-candidate workflow and honesty boundaries."""

from __future__ import annotations

import hashlib
import json
import os
import sqlite3
import subprocess
import sys
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest

import mcp_trust.grade_refresh as grade_refresh
from mcp_trust import refresh as refresh_module
from mcp_trust.core.models import (
    RiskSummary,
    ScanEvidence,
    ScanRecord,
    Server,
    ServerSource,
    SourceKind,
    ToolEvidence,
    TrustGrade,
)
from mcp_trust.engine.base import EngineResult, ScanTimeoutError
from mcp_trust.engine.sandbox import (
    SANDBOX_RUNTIME_READBACK_CLAIM_CEILING,
    sandbox_server_process_digest,
)
from mcp_trust.engine.stub import StubEngine
from mcp_trust.refresh import (
    RefreshCandidateError,
    _real_scan_mode,
    create_refresh_candidate,
    preflight_real_refresh,
)
from mcp_trust.refresh import (
    approve_refresh_candidate as _approve_refresh_candidate,
)
from mcp_trust.refresh import (
    publish_refresh_candidate as _publish_refresh_candidate,
)
from mcp_trust.refresh import (
    verified_masked_scan_slugs as _verified_masked_scan_slugs,
)
from mcp_trust.refresh import (
    verify_refresh_candidate as _verify_refresh_candidate,
)
from mcp_trust.store.db import connect, init_schema
from mcp_trust.store.repository import ScanRepository, ServerRepository
from scripts import refresh_candidate as refresh_cli
from tests.receipt_fixtures import engine_materialization_receipt

FIXED_NOW = datetime(2026, 7, 18, 8, 0, tzinfo=UTC)
ROOT = Path(__file__).resolve().parents[1]
IMAGE_DIGEST = "sha256:" + ("a" * 64)


def _runtime_readback(*, image_id: str = IMAGE_DIGEST) -> dict[str, object]:
    return {
        "schema": "McpTrustSandboxRuntimeReadbackV2",
        "state": "VERIFIED",
        "proof_boundary": "live-mcp-server-process-and-docker-daemon-config",
        "image_id": image_id,
        "container_identity_digest": "sha256:" + "b" * 64,
        "controls": {
            "network_none": True,
            "read_only_root": True,
            "capabilities_dropped": True,
            "no_new_privileges": True,
            "memory_limit": True,
            "memory_swap_disabled": True,
            "cpu_limit": True,
            "pids_limit": True,
            "non_root_user": True,
            "bounded_writable_tmpfs": True,
            "no_host_mount": True,
            "not_privileged": True,
            "environment_policy": True,
            "live_process_observed": True,
            "server_process_identity": True,
            "shared_namespaces_and_cgroup": True,
        },
        "observed": {
            "uid": 1000,
            "gid": 1000,
            "network_interfaces": ["lo"],
            "memory_max_bytes": 512 * 1024 * 1024,
            "pids_max": 256,
            "cpu_quota": 100000,
            "cpu_period": 100000,
            "environment_names": ["HOME", "HOSTNAME", "PATH", "TMPDIR"],
            "image_environment_names": ["PATH"],
            "runtime_managed_environment_names": ["HOSTNAME"],
            "injected_dummy_env_names": [],
            "secret_values_emitted_in_readback": False,
            "server_process_cmdline_digest": sandbox_server_process_digest("/opt/alpha", []),
            "workdir": "/scan",
            "root_write_denied": True,
            "workdir_write_verified": True,
        },
        "claim_ceiling": SANDBOX_RUNTIME_READBACK_CLAIM_CEILING,
    }


@pytest.fixture(autouse=True)
def _reproduce_fixture_engine_materialization(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def verify(receipt: object, **_kwargs: object) -> dict[str, object]:
        digest = receipt.get("receipt_digest") if isinstance(receipt, dict) else None
        return {
            "materialization_ready": isinstance(digest, str),
            "receipt_digest": digest,
        }

    monkeypatch.setattr(
        grade_refresh,
        "verify_engine_materialization_receipt",
        verify,
    )


def _server(slug: str) -> Server:
    return Server(
        slug=slug,
        name=slug,
        source=ServerSource(
            kind=SourceKind.NPM,
            reference=f"@example/{slug}",
            command=f"/opt/{slug}",
        ),
        added_at=FIXED_NOW,
    )


def _write_refresh_policy(
    seed_path: Path,
    masked_path: Path,
    *,
    blocked: tuple[str, ...] = (),
) -> Path:
    seed = json.loads(seed_path.read_text(encoding="utf-8"))
    slugs = [row["slug"] for row in seed]
    masked_set = set(json.loads(masked_path.read_text(encoding="utf-8")))
    blocked_set = set(blocked) | masked_set
    default_image = "required:image"
    image_refs = {
        source.get("sandbox_image") or default_image
        for row in seed
        if isinstance((source := row.get("source")), dict) and source.get("command") is not None
    }
    policy = {
        "schema": "McpTrustRefreshPolicyV2",
        "catalog_denominator": len(slugs),
        "default_sandbox_image": default_image,
        "image_build_sources": {
            image: {
                "path": "Dockerfile.scan",
                "provenance_status": "SOURCE_CONTROLLED",
                "reproducibility_status": "VERIFIED",
                "qualification_receipt": "qualification.json",
            }
            for image in image_refs
        },
        "scannable": [slug for slug in slugs if slug not in blocked_set],
        "blocked": [slug for slug in slugs if slug in blocked_set],
        "intentionally_masked": sorted(masked_set),
        "unsupported_upstream": sorted(blocked_set - masked_set),
        "credential_dependent": [],
        "backing_service_dependent": [],
        "unsafe_to_execute_unsandboxed": "all-local-process-entries",
        "credential_policy": "dummy-values-network-off-only",
        "network_policy": "none",
        "freshness_objective_hours": 24,
        "publication_review_required": True,
    }
    path = seed_path.with_name("refresh_policy.json")
    path.write_text(json.dumps(policy), encoding="utf-8")
    return path


def _inputs(
    tmp_path: Path,
    *,
    slugs: tuple[str, ...] = ("alpha",),
    masked: tuple[str, ...] = (),
) -> tuple[Path, Path, Path]:
    db_path = tmp_path / "registry.db"
    conn = connect(db_path)
    init_schema(conn)
    servers = ServerRepository(conn)
    for slug in slugs:
        servers.upsert(_server(slug))
    conn.close()
    seed_path = tmp_path / "seed.json"
    seed_path.write_text(
        json.dumps(
            [
                {
                    "slug": slug,
                    "name": slug,
                    "source": {
                        "kind": "npm",
                        "reference": f"@example/{slug}",
                        "command": f"/opt/{slug}",
                    },
                }
                for slug in slugs
            ]
        ),
        encoding="utf-8",
    )
    masked_path = tmp_path / "masked.json"
    masked_path.write_text(json.dumps(list(masked)), encoding="utf-8")
    _write_refresh_policy(seed_path, masked_path)
    return db_path, seed_path, masked_path


def _stub_scanner(server: Server) -> EngineResult:
    return (
        StubEngine()
        .scan(server.source)
        .model_copy(
            update={
                "evidence": ScanEvidence(tools=[ToolEvidence(name="fixture-tool")]),
            }
        )
    )


def _qualification_receipt(
    seed_path: Path,
    masked_path: Path,
    *,
    profiles: list[dict[str, object]],
) -> dict[str, object]:
    controls = {
        "network_none": True,
        "read_only_root": True,
        "capabilities_dropped": True,
        "no_new_privileges": True,
        "memory_limit": True,
        "cpu_limit": True,
        "pids_limit": True,
        "non_root_user": True,
        "bounded_writable_tmpfs": True,
        "no_host_mount": True,
    }
    image_bindings = [
        {
            "reference": profile["image"],
            "state": "BOUND",
            "image_id": profile["image_digest"],
            "repo_digests": [],
            "platform": "linux/arm64",
            "sandbox_controls": {
                "controls": dict(controls),
                "all_required_controls": True,
            },
        }
        for profile in profiles
    ]
    build_sources: dict[str, dict[str, object]] = {}
    qualification_files: dict[str, str] = {}
    for index, profile in enumerate(profiles):
        qualification_path = f"docker/refresh/qualification/test-{index}.json"
        qualification_sha256 = "sha256:" + f"{index + 3:x}"[-1] * 64
        tracked_path = f"docker/refresh/locks/test-{index}.lock"
        tracked_sha256 = "sha256:" + f"{index + 5:x}"[-1] * 64
        build_sources[str(profile["image"])] = {
            "path": "Dockerfile.scan",
            "sha256": "sha256:" + ("b" * 64),
            "provenance_status": "SOURCE_CONTROLLED",
            "reproducibility_status": "VERIFIED",
            "qualification": {
                "path": qualification_path,
                "sha256": qualification_sha256,
                "receipt_digest": "sha256:" + ("d" * 64),
                "qualified_image_id": profile["image_digest"],
                "build_input_digest": "sha256:" + ("e" * 64),
                "dependency_locks": {"fixture": tracked_sha256},
                "dependency_artifacts": {},
                "tracked_inputs": {tracked_path: tracked_sha256},
                "state": "VERIFIED",
            },
            "state": "BOUND",
        }
        qualification_files[qualification_path] = qualification_sha256
        qualification_files[tracked_path] = tracked_sha256
    policy_path = seed_path.with_name("refresh_policy.json")
    if not policy_path.exists():
        _write_refresh_policy(seed_path, masked_path)
    policy = json.loads(policy_path.read_text(encoding="utf-8"))
    policy_digest = "sha256:" + hashlib.sha256(policy_path.read_bytes()).hexdigest()
    inventory = grade_refresh.catalog_inventory(
        seed_path=seed_path,
        masked_path=masked_path,
        policy_path=policy_path,
    )
    source_files = {
        "src/mcp_trust/catalog/refresh_policy.json": policy_digest,
        **{str(binding["path"]): str(binding["sha256"]) for binding in build_sources.values()},
        **qualification_files,
    }
    source_binding: dict[str, object] = {
        "revision": "a" * 40,
        "worktree_state": "clean",
        "source_tree_digest": "sha256:" + ("c" * 64),
        "repository": "https://example.test/mcp-trust.git",
        "file_digests": source_files,
    }
    payload: dict[str, object] = {
        "schema": "McpTrustGradeRefreshPreflightV2",
        "observed_at": FIXED_NOW.isoformat(),
        "status": "READY",
        "safe_to_execute_catalog": True,
        "exit_classification": "ready",
        "source_binding": source_binding,
        "engine_materialization": engine_materialization_receipt(
            source_binding=source_binding,
            observed_at=FIXED_NOW,
            repo_root=ROOT,
        ),
        "catalog": {
            "denominator": policy["catalog_denominator"],
            "counts": inventory["counts"],
            "execution_boundary": {
                "schema": "McpTrustRefreshExecutionBoundaryV1",
                "scannable": sorted(policy["scannable"]),
                "blocked": sorted(policy["blocked"]),
            },
            "seed_digest": "sha256:" + hashlib.sha256(seed_path.read_bytes()).hexdigest(),
            "masking_digest": "sha256:" + hashlib.sha256(masked_path.read_bytes()).hexdigest(),
            "policy_digest": policy_digest,
            "inventory_digest": grade_refresh.digest_bytes(
                grade_refresh.canonical_bytes(inventory)
            ),
            "image_build_sources": build_sources,
        },
        "sandbox": {
            "docker_host_kind": "local-unix",
            "image_bindings": image_bindings,
            "network_policy": "none",
            "filesystem_policy": "read-only-root-bounded-tmpfs-no-host-mounts",
            "resource_policy": "cpu-memory-pids-timeout-required",
            "secret_policy": "no-live-secrets-dummy-network-off-only",
        },
        "tool_versions": {
            "python": "3.11.15",
            "python_executable": "/fixture/python",
            "mcp_audits": "2.7.0",
            "mcp_audits_locked": "2.7.0",
            "mcp_trust": "0.1.1",
            "docker_client": "29.7.2",
            "docker_server": "29.5.2",
        },
        "scheduler": {"state": "NOT_READ", "mutation_performed": False},
        "reasons": [],
        "authority": {
            "candidate_build": True,
            "publication": False,
            "deployment": False,
            "scheduler_change": False,
        },
    }
    payload["receipt_digest"] = (
        "sha256:" + hashlib.sha256(refresh_module._json_bytes(payload)).hexdigest()
    )
    return payload


def _qualification_source_provider(receipt: dict[str, object]):
    source = receipt["source_binding"]
    assert isinstance(source, dict)
    return lambda _repo_root: source


def _expected_catalog_counts(seed_path: Path, masked_path: Path) -> object:
    return grade_refresh.catalog_inventory(
        seed_path=seed_path,
        masked_path=masked_path,
        policy_path=seed_path.with_name("refresh_policy.json"),
    )["counts"]


def _expected_catalog_inventory_digest(seed_path: Path, masked_path: Path) -> str:
    inventory = grade_refresh.catalog_inventory(
        seed_path=seed_path,
        masked_path=masked_path,
        policy_path=seed_path.with_name("refresh_policy.json"),
    )
    return grade_refresh.digest_bytes(grade_refresh.canonical_bytes(inventory))


def _test_current_source_kwargs(candidate: Path) -> dict[str, object]:
    receipt_path = candidate / "qualification_receipt.json"
    if not receipt_path.is_file():
        return {"repo_root": ROOT}
    receipt = json.loads(receipt_path.read_text(encoding="utf-8"))
    return {
        "repo_root": ROOT,
        "_source_binding_provider": _qualification_source_provider(receipt),
        "_qualification_revalidator": lambda *_args, **_kwargs: None,
    }


def verify_refresh_candidate(candidate: Path, **kwargs):
    binding_kwargs = _test_current_source_kwargs(candidate)
    binding_kwargs.update(kwargs)
    return _verify_refresh_candidate(
        candidate,
        **binding_kwargs,
    )


def verified_masked_scan_slugs(candidate: Path, **kwargs):
    binding_kwargs = _test_current_source_kwargs(candidate)
    binding_kwargs.update(kwargs)
    return _verified_masked_scan_slugs(
        candidate,
        **binding_kwargs,
    )


def approve_refresh_candidate(*, candidate: Path, **kwargs):
    return _approve_refresh_candidate(
        candidate=candidate,
        **_test_current_source_kwargs(candidate),
        **kwargs,
    )


def publish_refresh_candidate(*, candidate: Path, **kwargs):
    return _publish_refresh_candidate(
        candidate=candidate,
        **_test_current_source_kwargs(candidate),
        **kwargs,
    )


def _redigest_qualification(receipt: dict[str, object]) -> None:
    unsigned = dict(receipt)
    unsigned.pop("receipt_digest", None)
    receipt["receipt_digest"] = (
        "sha256:" + hashlib.sha256(refresh_module._json_bytes(unsigned)).hexdigest()
    )


def _replace_candidate_qualification(
    candidate: Path,
    receipt: dict[str, object],
) -> None:
    receipt_path = candidate / "qualification_receipt.json"
    manifest_path = candidate / "MANIFEST.json"
    digest_path = candidate / "MANIFEST.sha256"
    candidate.chmod(0o700)
    for path in (receipt_path, manifest_path, digest_path):
        path.chmod(0o600)
    receipt_bytes = refresh_module._json_bytes(receipt)
    receipt_path.write_bytes(receipt_bytes)
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    manifest["qualification"]["receipt_sha256"] = hashlib.sha256(receipt_bytes).hexdigest()
    manifest["qualification"]["preflight_receipt_digest"] = receipt["receipt_digest"]
    manifest["qualification"]["source_revision"] = receipt["source_binding"]["revision"]
    manifest["qualification"]["source_tree_digest"] = receipt["source_binding"][
        "source_tree_digest"
    ]
    manifest["source_tree_digest"] = receipt["source_binding"]["source_tree_digest"]
    for artifact in manifest["artifacts"]:
        if artifact["path"] == "qualification_receipt.json":
            artifact["bytes"] = len(receipt_bytes)
            artifact["sha256"] = hashlib.sha256(receipt_bytes).hexdigest()
    manifest_bytes = refresh_module._json_bytes(manifest)
    manifest_path.write_bytes(manifest_bytes)
    digest_path.write_text(
        hashlib.sha256(manifest_bytes).hexdigest() + "\n",
        encoding="utf-8",
    )
    for path in (receipt_path, manifest_path, digest_path):
        path.chmod(0o400)
    candidate.chmod(0o500)


def test_qualification_rejects_build_digest_not_bound_to_source_tree(
    tmp_path: Path,
) -> None:
    _db, seed_path, masked_path = _inputs(tmp_path)
    profile = refresh_module._sandbox_profile(
        "required:image",
        image_digest=IMAGE_DIGEST,
    )
    receipt = _qualification_receipt(
        seed_path,
        masked_path,
        profiles=[profile],
    )
    source = receipt["source_binding"]
    assert isinstance(source, dict)
    source_files = source["file_digests"]
    assert isinstance(source_files, dict)
    source_files["Dockerfile.scan"] = "sha256:" + ("e" * 64)
    unsigned = dict(receipt)
    unsigned.pop("receipt_digest")
    receipt["receipt_digest"] = (
        "sha256:" + hashlib.sha256(refresh_module._json_bytes(unsigned)).hexdigest()
    )

    with pytest.raises(
        RefreshCandidateError,
        match="not source-bound|READY image bindings are invalid|READY engine materialization",
    ):
        refresh_module._qualification_metadata(
            receipt,
            seed_sha256=hashlib.sha256(seed_path.read_bytes()).hexdigest(),
            masked_sha256=hashlib.sha256(masked_path.read_bytes()).hexdigest(),
            expected_catalog_counts=_expected_catalog_counts(seed_path, masked_path),
            expected_catalog_inventory_digest=_expected_catalog_inventory_digest(
                seed_path, masked_path
            ),
            sandbox_evidence={"profiles": [profile]},
            now=FIXED_NOW,
        )


def test_qualification_requires_exact_build_source_image_coverage(
    tmp_path: Path,
) -> None:
    _db, seed_path, masked_path = _inputs(tmp_path)
    profile = refresh_module._sandbox_profile(
        "required:image",
        image_digest=IMAGE_DIGEST,
    )
    receipt = _qualification_receipt(
        seed_path,
        masked_path,
        profiles=[profile],
    )
    catalog = receipt["catalog"]
    assert isinstance(catalog, dict)
    catalog["image_build_sources"] = {}
    unsigned = dict(receipt)
    unsigned.pop("receipt_digest")
    receipt["receipt_digest"] = (
        "sha256:" + hashlib.sha256(refresh_module._json_bytes(unsigned)).hexdigest()
    )

    with pytest.raises(
        RefreshCandidateError,
        match="READY sandbox evidence is invalid|provenance is incomplete",
    ):
        refresh_module._qualification_metadata(
            receipt,
            seed_sha256=hashlib.sha256(seed_path.read_bytes()).hexdigest(),
            masked_sha256=hashlib.sha256(masked_path.read_bytes()).hexdigest(),
            expected_catalog_counts=_expected_catalog_counts(seed_path, masked_path),
            expected_catalog_inventory_digest=_expected_catalog_inventory_digest(
                seed_path, masked_path
            ),
            sandbox_evidence={"profiles": [profile]},
            now=FIXED_NOW,
        )


@pytest.mark.parametrize(
    "mutation",
    (
        "network_policy",
        "sandbox_control",
        "qualification_state",
        "qualification_image_id",
        "tool_lock",
        "binding_reference",
        "build_source_path",
        "qualification_path",
    ),
)
def test_qualification_rejects_self_redigested_ready_evidence_tampering(
    tmp_path: Path,
    mutation: str,
) -> None:
    _db, seed_path, masked_path = _inputs(tmp_path)
    profile = refresh_module._sandbox_profile(
        "required:image",
        image_digest=IMAGE_DIGEST,
    )
    receipt = _qualification_receipt(
        seed_path,
        masked_path,
        profiles=[profile],
    )
    if mutation == "network_policy":
        receipt["sandbox"]["network_policy"] = "bridge"
    elif mutation == "sandbox_control":
        receipt["sandbox"]["image_bindings"][0]["sandbox_controls"]["controls"]["network_none"] = (
            False
        )
    elif mutation == "qualification_state":
        receipt["catalog"]["image_build_sources"]["required:image"]["qualification"]["state"] = (
            "UNKNOWN"
        )
    elif mutation == "qualification_image_id":
        receipt["catalog"]["image_build_sources"]["required:image"]["qualification"][
            "qualified_image_id"
        ] = "sha256:" + "f" * 64
    elif mutation == "binding_reference":
        receipt["sandbox"]["image_bindings"][0]["reference"] = []
    elif mutation == "build_source_path":
        receipt["catalog"]["image_build_sources"]["required:image"]["path"] = (
            "/tmp/escaped-Dockerfile"
        )
    elif mutation == "qualification_path":
        receipt["catalog"]["image_build_sources"]["required:image"]["qualification"]["path"] = (
            "../../escaped-receipt.json"
        )
    else:
        receipt["tool_versions"]["mcp_audits_locked"] = "2.6.0"
    _redigest_qualification(receipt)

    with pytest.raises(RefreshCandidateError, match="qualification receipt READY"):
        refresh_module._qualification_metadata(
            receipt,
            seed_sha256=hashlib.sha256(seed_path.read_bytes()).hexdigest(),
            masked_sha256=hashlib.sha256(masked_path.read_bytes()).hexdigest(),
            expected_catalog_counts=_expected_catalog_counts(seed_path, masked_path),
            expected_catalog_inventory_digest=_expected_catalog_inventory_digest(
                seed_path, masked_path
            ),
            sandbox_evidence={"profiles": [profile]},
            now=FIXED_NOW,
        )


def test_invalid_ready_receipt_is_rejected_before_docker_preflight(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    db_path, seed_path, masked_path = _inputs(tmp_path)
    profile = refresh_module._sandbox_profile(
        "required:image",
        image_digest=IMAGE_DIGEST,
    )
    receipt = _qualification_receipt(
        seed_path,
        masked_path,
        profiles=[profile],
    )
    receipt["sandbox"]["network_policy"] = "bridge"
    _redigest_qualification(receipt)
    preflight_called = False

    def forbidden_preflight(*_args: object, **_kwargs: object) -> dict[str, object]:
        nonlocal preflight_called
        preflight_called = True
        raise AssertionError("Docker preflight must not run")

    monkeypatch.setattr(refresh_module, "preflight_real_refresh", forbidden_preflight)
    with pytest.raises(RefreshCandidateError, match="READY sandbox evidence"):
        create_refresh_candidate(
            source_db=db_path,
            seed_path=seed_path,
            masked_path=masked_path,
            output_parent=tmp_path / "candidates",
            default_image="required:image",
            qualification_receipt=receipt,
            repo_root=ROOT,
            _source_binding_provider=_qualification_source_provider(receipt),
            now=FIXED_NOW,
            candidate_name="candidate",
        )

    assert preflight_called is False
    assert not (tmp_path / "candidates").exists()


def _candidate(
    tmp_path: Path,
    *,
    slugs: tuple[str, ...] = ("alpha",),
    masked: tuple[str, ...] = (),
    scanner=_stub_scanner,
    receipt_writer=None,
    now: datetime = FIXED_NOW,
) -> Path:
    db_path, seed_path, masked_path = _inputs(
        tmp_path,
        slugs=slugs,
        masked=masked,
    )
    return create_refresh_candidate(
        source_db=db_path,
        seed_path=seed_path,
        masked_path=masked_path,
        output_parent=tmp_path / "candidates",
        default_image="fixture:image",
        scanner=scanner,
        receipt_writer=receipt_writer,
        now=now,
        candidate_name="candidate",
    )


def _complete_remote_candidate(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    *,
    masked: tuple[str, ...] = (),
    slug: str = "alpha",
    source_mutates: bool = False,
) -> tuple[Path, Path, Path]:
    db_path = tmp_path / "registry.db"
    remote = _server(slug).model_copy(
        update={
            "source": ServerSource(
                kind=SourceKind.REMOTE,
                reference="https://example.test/mcp",
            )
        }
    )
    conn = connect(db_path)
    init_schema(conn)
    ServerRepository(conn).upsert(remote)
    conn.close()
    seed_path = tmp_path / "seed.json"
    seed_path.write_text(
        json.dumps([remote.model_dump(mode="json", exclude={"added_at"})]),
        encoding="utf-8",
    )
    masked_path = tmp_path / "masked.json"
    masked_path.write_text(json.dumps(list(masked)), encoding="utf-8")
    _write_refresh_policy(seed_path, masked_path)

    class RemoteMCPAuditEngine:
        def __init__(self, timeout: float) -> None:
            assert timeout == 90.0

        def scan(self, source: ServerSource) -> EngineResult:
            assert source == remote.source
            return _stub_scanner(remote).model_copy(
                update={
                    "engine_name": "mcpaudit",
                    "engine_version": "2.4.0",
                    "sandbox_image": None,
                }
            )

    monkeypatch.setattr(
        "mcp_trust.refresh.preflight_real_refresh",
        lambda servers, *, default_image: {
            "docker_daemon": "not_required",
            "default_image": default_image,
            "profiles": [],
            "remote_transport_count": len(servers),
        },
    )
    monkeypatch.setattr("mcp_trust.refresh.MCPAuditEngine", RemoteMCPAuditEngine)
    qualification = _qualification_receipt(
        seed_path,
        masked_path,
        profiles=[],
    )
    source_provider = _qualification_source_provider(qualification)
    if source_mutates:
        source = qualification["source_binding"]
        assert isinstance(source, dict)
        calls = 0

        def source_provider(_repo_root):
            nonlocal calls
            calls += 1
            return source if calls == 1 else {**source, "revision": "b" * 40}

    candidate = create_refresh_candidate(
        source_db=db_path,
        seed_path=seed_path,
        masked_path=masked_path,
        output_parent=tmp_path / "candidates",
        default_image="not-needed:image",
        qualification_receipt=qualification,
        repo_root=ROOT,
        _source_binding_provider=source_provider,
        now=FIXED_NOW,
        candidate_name="candidate",
    )
    return candidate, seed_path, masked_path


def test_real_candidate_rejects_source_change_after_preflight(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    with pytest.raises(RefreshCandidateError, match="source changed during refresh"):
        _complete_remote_candidate(
            tmp_path,
            monkeypatch,
            source_mutates=True,
        )


def test_candidate_verifier_rejects_self_redigested_tool_lock_tampering(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    candidate, seed_path, masked_path = _complete_remote_candidate(
        tmp_path,
        monkeypatch,
    )
    assert (
        verify_refresh_candidate(
            candidate,
            now=FIXED_NOW,
            expected_seed_path=seed_path,
            expected_masked_path=masked_path,
        )["publication_ready"]
        is True
    )

    receipt_path = candidate / "qualification_receipt.json"
    manifest_path = candidate / "MANIFEST.json"
    digest_path = candidate / "MANIFEST.sha256"
    candidate.chmod(0o700)
    for path in (receipt_path, manifest_path, digest_path):
        path.chmod(0o600)
    receipt = json.loads(receipt_path.read_text(encoding="utf-8"))
    receipt["tool_versions"]["mcp_audits_locked"] = "2.6.0"
    _redigest_qualification(receipt)
    receipt_bytes = refresh_module._json_bytes(receipt)
    receipt_path.write_bytes(receipt_bytes)

    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    manifest["qualification"]["receipt_sha256"] = hashlib.sha256(receipt_bytes).hexdigest()
    manifest["qualification"]["preflight_receipt_digest"] = receipt["receipt_digest"]
    for artifact in manifest["artifacts"]:
        if artifact["path"] == "qualification_receipt.json":
            artifact["bytes"] = len(receipt_bytes)
            artifact["sha256"] = hashlib.sha256(receipt_bytes).hexdigest()
    manifest_bytes = refresh_module._json_bytes(manifest)
    manifest_path.write_bytes(manifest_bytes)
    digest_path.write_text(
        hashlib.sha256(manifest_bytes).hexdigest() + "\n",
        encoding="utf-8",
    )
    for path in (receipt_path, manifest_path, digest_path):
        path.chmod(0o400)
    candidate.chmod(0o500)

    verification = verify_refresh_candidate(
        candidate,
        now=FIXED_NOW,
        expected_seed_path=seed_path,
        expected_masked_path=masked_path,
    )

    assert verification["structural_valid"] is False
    assert verification["publication_ready"] is False
    assert "qualification_receipt_invalid" in verification["errors"]


def test_candidate_verifier_rejects_current_source_change_during_verification(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    candidate, seed_path, masked_path = _complete_remote_candidate(
        tmp_path,
        monkeypatch,
    )
    receipt = json.loads((candidate / "qualification_receipt.json").read_text(encoding="utf-8"))
    source = receipt["source_binding"]
    calls = 0

    def changing_source(_repo_root: Path) -> dict[str, object]:
        nonlocal calls
        calls += 1
        if calls == 1:
            return source
        return {**source, "source_tree_digest": "sha256:" + "f" * 64}

    verification = _verify_refresh_candidate(
        candidate,
        now=FIXED_NOW,
        expected_seed_path=seed_path,
        expected_masked_path=masked_path,
        repo_root=ROOT,
        _source_binding_provider=changing_source,
        _qualification_revalidator=lambda *_args, **_kwargs: None,
    )

    assert verification["structural_valid"] is False
    assert verification["publication_ready"] is False
    assert "qualification_receipt_invalid" in verification["errors"]


def test_real_candidate_without_current_source_binding_is_not_verifiable(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    candidate, seed_path, masked_path = _complete_remote_candidate(
        tmp_path,
        monkeypatch,
    )

    verification = _verify_refresh_candidate(
        candidate,
        now=FIXED_NOW,
        expected_seed_path=seed_path,
        expected_masked_path=masked_path,
    )

    assert verification["structural_valid"] is False
    assert verification["publication_ready"] is False
    assert "qualification_current_source_unavailable" in verification["errors"]
    assert "qualification_receipt_invalid" in verification["errors"]


def test_candidate_verifier_rejects_self_redigested_source_forgery(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    candidate, seed_path, masked_path = _complete_remote_candidate(
        tmp_path,
        monkeypatch,
    )
    receipt_path = candidate / "qualification_receipt.json"
    receipt = json.loads(receipt_path.read_text(encoding="utf-8"))
    original_source = json.loads(json.dumps(receipt["source_binding"]))
    receipt["tool_versions"]["mcp_audits"] = "2.6.0"
    receipt["tool_versions"]["mcp_audits_locked"] = "2.6.0"
    receipt["source_binding"]["file_digests"]["src/mcp_trust/catalog/refresh_policy.json"] = (
        "sha256:" + "f" * 64
    )
    receipt["source_binding"]["source_tree_digest"] = "sha256:" + "e" * 64
    _redigest_qualification(receipt)
    _replace_candidate_qualification(candidate, receipt)

    verification = _verify_refresh_candidate(
        candidate,
        now=FIXED_NOW,
        expected_seed_path=seed_path,
        expected_masked_path=masked_path,
        repo_root=ROOT,
        _source_binding_provider=lambda _repo_root: original_source,
        _qualification_revalidator=lambda *_args, **_kwargs: None,
    )

    assert verification["structural_valid"] is False
    assert verification["publication_ready"] is False
    assert "qualification_receipt_invalid" in verification["errors"]


def test_static_image_qualification_is_recomputed_from_current_bytes(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from mcp_trust import grade_refresh

    _db, seed_path, masked_path = _inputs(tmp_path)
    profile = refresh_module._sandbox_profile(
        "required:image",
        image_digest=IMAGE_DIGEST,
    )
    receipt = _qualification_receipt(seed_path, masked_path, profiles=[profile])
    qualification = json.loads(
        json.dumps(receipt["catalog"]["image_build_sources"]["required:image"]["qualification"])
    )
    monkeypatch.setattr(
        grade_refresh,
        "_image_build_qualification",
        lambda **_kwargs: json.loads(json.dumps(qualification)),
    )
    monkeypatch.setattr(
        grade_refresh,
        "verify_engine_materialization_receipt",
        lambda receipt, **_kwargs: {
            "materialization_ready": True,
            "receipt_digest": receipt["receipt_digest"],
        },
    )
    grade_refresh.revalidate_ready_preflight_qualifications(
        receipt,
        repo_root=ROOT,
        expected_image_references=["required:image"],
        expected_catalog_counts=_expected_catalog_counts(seed_path, masked_path),
        expected_catalog_inventory_digest=_expected_catalog_inventory_digest(
            seed_path, masked_path
        ),
        now=FIXED_NOW,
    )
    receipt["catalog"]["image_build_sources"]["required:image"]["qualification"][
        "build_input_digest"
    ] = "sha256:" + "f" * 64
    _redigest_qualification(receipt)

    with pytest.raises(grade_refresh.GradeRefreshError, match="qualification changed"):
        grade_refresh.revalidate_ready_preflight_qualifications(
            receipt,
            repo_root=ROOT,
            expected_image_references=["required:image"],
            expected_catalog_counts=_expected_catalog_counts(seed_path, masked_path),
            expected_catalog_inventory_digest=_expected_catalog_inventory_digest(
                seed_path, masked_path
            ),
            now=FIXED_NOW,
        )


def test_ready_preflight_revalidation_rejects_engine_materialization_change(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _db, seed_path, masked_path = _inputs(tmp_path)
    receipt = _qualification_receipt(seed_path, masked_path, profiles=[])
    monkeypatch.setattr(
        grade_refresh,
        "verify_engine_materialization_receipt",
        lambda *_args, **_kwargs: {
            "materialization_ready": False,
            "receipt_digest": None,
        },
    )

    with pytest.raises(
        grade_refresh.GradeRefreshError,
        match="engine materialization changed",
    ):
        grade_refresh.revalidate_ready_preflight_qualifications(
            receipt,
            repo_root=ROOT,
            expected_image_references=[],
            expected_catalog_counts=_expected_catalog_counts(seed_path, masked_path),
            expected_catalog_inventory_digest=_expected_catalog_inventory_digest(
                seed_path, masked_path
            ),
            now=FIXED_NOW,
        )


def test_ready_preflight_rejects_legacy_schema_before_execution(
    tmp_path: Path,
) -> None:
    _db, seed_path, masked_path = _inputs(tmp_path)
    receipt = _qualification_receipt(seed_path, masked_path, profiles=[])
    receipt["schema"] = "McpTrustGradeRefreshPreflightV1"
    _redigest_qualification(receipt)

    with pytest.raises(
        grade_refresh.GradeRefreshError,
        match="preflight receipt is invalid",
    ):
        grade_refresh.validate_ready_preflight_contract(
            receipt,
            expected_image_references=[],
            expected_catalog_counts=_expected_catalog_counts(seed_path, masked_path),
            expected_catalog_inventory_digest=_expected_catalog_inventory_digest(
                seed_path, masked_path
            ),
        )


def test_ready_preflight_accepts_complete_dynamic_catalog_contract(tmp_path: Path) -> None:
    _db, seed_path, masked_path = _inputs(
        tmp_path,
        slugs=("alpha", "beta", "gamma"),
        masked=("gamma",),
    )
    receipt = _qualification_receipt(seed_path, masked_path, profiles=[])

    grade_refresh.validate_ready_preflight_contract(
        receipt,
        expected_image_references=[],
        expected_catalog_counts=_expected_catalog_counts(seed_path, masked_path),
        expected_catalog_inventory_digest=_expected_catalog_inventory_digest(
            seed_path, masked_path
        ),
    )

    assert receipt["catalog"]["denominator"] == 3
    assert receipt["catalog"]["counts"]["scannable"] == 2
    assert receipt["catalog"]["counts"]["blocked"] == 1


@pytest.mark.parametrize(
    "mutation",
    [
        "missing-key",
        "extra-key",
        "boolean",
        "float",
        "negative",
        "denominator-mismatch",
        "category-exceeds-blocked",
        "image-source-exceeds-unsafe",
        "boundary-extra-key",
        "boundary-duplicate",
        "boundary-non-string",
        "boundary-length-mismatch",
        "boundary-overlap",
        "boundary-unsafe-slug",
        "catalog-missing-provenance",
        "catalog-extra-key",
        "inventory-digest-mismatch",
    ],
)
def test_ready_preflight_rejects_false_green_catalog_contracts(
    tmp_path: Path,
    mutation: str,
) -> None:
    _db, seed_path, masked_path = _inputs(tmp_path)
    receipt = _qualification_receipt(seed_path, masked_path, profiles=[])
    catalog = receipt["catalog"]
    assert isinstance(catalog, dict)
    counts = catalog["counts"]
    boundary = catalog["execution_boundary"]
    assert isinstance(counts, dict)
    assert isinstance(boundary, dict)
    if mutation == "missing-key":
        counts.pop("intentionally_masked")
    elif mutation == "extra-key":
        counts["unexpected"] = 0
    elif mutation == "boolean":
        counts["missing_image_build_source"] = False
    elif mutation == "float":
        counts["scannable"] = 1.0
    elif mutation == "negative":
        counts["unsupported_upstream"] = -1
    elif mutation == "denominator-mismatch":
        catalog["denominator"] = 2
    elif mutation == "category-exceeds-blocked":
        counts["credential_dependent"] = 1
    elif mutation == "image-source-exceeds-unsafe":
        counts["unqualified_image_build_source"] = 2
    elif mutation == "boundary-extra-key":
        boundary["unexpected"] = []
    elif mutation == "boundary-duplicate":
        boundary["scannable"] = ["alpha", "alpha"]
    elif mutation == "boundary-non-string":
        boundary["scannable"] = [1]
    elif mutation == "boundary-length-mismatch":
        boundary["scannable"] = []
    elif mutation == "boundary-overlap":
        catalog["denominator"] = 2
        counts["blocked"] = 1
        boundary["blocked"] = ["alpha"]
    elif mutation == "boundary-unsafe-slug":
        boundary["scannable"] = ["../alpha"]
    elif mutation == "catalog-missing-provenance":
        catalog.pop("inventory_digest")
    elif mutation == "catalog-extra-key":
        catalog["unexpected"] = None
    else:
        catalog["inventory_digest"] = "sha256:" + "f" * 64
    _redigest_qualification(receipt)

    with pytest.raises(grade_refresh.GradeRefreshError, match="catalog evidence"):
        grade_refresh.validate_ready_preflight_contract(
            receipt,
            expected_image_references=[],
            expected_catalog_counts=_expected_catalog_counts(seed_path, masked_path),
            expected_catalog_inventory_digest=_expected_catalog_inventory_digest(
                seed_path, masked_path
            ),
        )


def test_ready_preflight_revalidation_rejects_count_drift_before_engine_check(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _db, seed_path, masked_path = _inputs(
        tmp_path,
        slugs=("alpha", "beta", "gamma"),
        masked=("gamma",),
    )
    receipt = _qualification_receipt(seed_path, masked_path, profiles=[])
    receipt["catalog"]["counts"]["intentionally_masked"] = 0
    receipt["catalog"]["counts"]["unsupported_upstream"] = 1
    _redigest_qualification(receipt)

    def forbidden_engine_check(*_args: object, **_kwargs: object) -> dict[str, object]:
        raise AssertionError("engine materialization must not run")

    monkeypatch.setattr(
        grade_refresh,
        "verify_engine_materialization_receipt",
        forbidden_engine_check,
    )

    with pytest.raises(grade_refresh.GradeRefreshError, match="catalog evidence"):
        grade_refresh.revalidate_ready_preflight_qualifications(
            receipt,
            repo_root=ROOT,
            expected_image_references=[],
            expected_catalog_counts=_expected_catalog_counts(seed_path, masked_path),
            expected_catalog_inventory_digest=_expected_catalog_inventory_digest(
                seed_path, masked_path
            ),
            now=FIXED_NOW,
        )


def _results(candidate: Path) -> list[dict[str, object]]:
    return json.loads((candidate / "scan_results.json").read_text())["results"]


def test_verified_masked_scan_slugs_exposes_only_success_claim(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    candidate, seed_path, masked_path = _complete_remote_candidate(
        tmp_path,
        monkeypatch,
        masked=("alpha",),
    )

    assert (
        verified_masked_scan_slugs(
            candidate,
            seed_path=seed_path,
            masked_path=masked_path,
            now=FIXED_NOW,
        )
        == frozenset()
    )


def test_verified_masked_scan_slugs_rejects_stale_candidate(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    candidate, seed_path, masked_path = _complete_remote_candidate(
        tmp_path,
        monkeypatch,
        masked=("alpha",),
    )

    with pytest.raises(RefreshCandidateError, match="complete, current, publishable"):
        verified_masked_scan_slugs(
            candidate,
            seed_path=seed_path,
            masked_path=masked_path,
            now=FIXED_NOW + timedelta(hours=25),
        )


def test_verified_masked_scan_slugs_uses_the_verified_candidate_snapshot(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    first_root = tmp_path / "first"
    second_root = tmp_path / "second"
    first_root.mkdir()
    second_root.mkdir()
    candidate, seed_path, masked_path = _complete_remote_candidate(
        first_root,
        monkeypatch,
        masked=("alpha",),
        slug="alpha",
    )
    replacement, _replacement_seed, _replacement_mask = _complete_remote_candidate(
        second_root,
        monkeypatch,
        masked=("beta",),
        slug="beta",
    )
    real_verify = verify_refresh_candidate

    def verify_then_swap(*args, **kwargs):
        verification = real_verify(*args, **kwargs)
        parked = tmp_path / "parked-candidate"
        candidate.parent.chmod(0o700)
        replacement.parent.chmod(0o700)
        candidate.chmod(0o700)
        replacement.chmod(0o700)
        candidate.rename(parked)
        replacement.rename(candidate)
        parked.rename(replacement)
        return verification

    monkeypatch.setattr(
        "mcp_trust.refresh.verify_refresh_candidate",
        verify_then_swap,
    )

    assert (
        verified_masked_scan_slugs(
            candidate,
            seed_path=seed_path,
            masked_path=masked_path,
            now=FIXED_NOW,
        )
        == frozenset()
    )


def test_candidate_replacement_during_verification_fails_closed(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    first_root = tmp_path / "first"
    second_root = tmp_path / "second"
    first_root.mkdir()
    second_root.mkdir()
    candidate = _candidate(first_root)
    replacement = _candidate(second_root)
    real_captured_json = refresh_module._captured_json
    swapped = False

    def capture_then_swap(snapshot, relative):
        nonlocal swapped
        payload = real_captured_json(snapshot, relative)
        if not swapped:
            swapped = True
            parked = tmp_path / "parked-candidate"
            candidate.parent.chmod(0o700)
            replacement.parent.chmod(0o700)
            candidate.chmod(0o700)
            replacement.chmod(0o700)
            candidate.rename(parked)
            replacement.rename(candidate)
            parked.rename(replacement)
        return payload

    monkeypatch.setattr(refresh_module, "_captured_json", capture_then_swap)

    verification = verify_refresh_candidate(candidate, now=FIXED_NOW)

    assert verification["structural_valid"] is False
    assert verification["publication_ready"] is False
    assert "candidate_changed_during_verification" in verification["errors"]


def _rebind_manifest_time(candidate: Path, created_at: datetime) -> None:
    manifest_path = candidate / "MANIFEST.json"
    digest_path = candidate / "MANIFEST.sha256"
    candidate.chmod(0o700)
    manifest_path.chmod(0o600)
    digest_path.chmod(0o600)
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    manifest["created_at"] = created_at.isoformat()
    manifest["expires_at"] = (created_at + timedelta(hours=24)).isoformat()
    manifest_path.write_text(json.dumps(manifest), encoding="utf-8")
    digest_path.write_text(
        hashlib.sha256(manifest_path.read_bytes()).hexdigest() + "\n",
        encoding="utf-8",
    )
    manifest_path.chmod(0o400)
    digest_path.chmod(0o400)
    candidate.chmod(0o500)


def _rebind_candidate_artifacts(candidate: Path, *artifact_names: str) -> None:
    manifest_path = candidate / "MANIFEST.json"
    digest_path = candidate / "MANIFEST.sha256"
    candidate.chmod(0o700)
    manifest_path.chmod(0o600)
    digest_path.chmod(0o600)
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    selected = set(artifact_names)
    for artifact in manifest["artifacts"]:
        if artifact["path"] not in selected:
            continue
        artifact_path = candidate / artifact["path"]
        artifact["bytes"] = artifact_path.stat().st_size
        artifact["sha256"] = hashlib.sha256(artifact_path.read_bytes()).hexdigest()
        artifact_path.chmod(0o400)
    manifest_path.write_text(json.dumps(manifest), encoding="utf-8")
    digest_path.write_text(
        hashlib.sha256(manifest_path.read_bytes()).hexdigest() + "\n",
        encoding="utf-8",
    )
    manifest_path.chmod(0o400)
    digest_path.chmod(0o400)
    candidate.chmod(0o500)


def _rebind_manifest(candidate: Path, **updates: object) -> None:
    manifest_path = candidate / "MANIFEST.json"
    digest_path = candidate / "MANIFEST.sha256"
    candidate.chmod(0o700)
    manifest_path.chmod(0o600)
    digest_path.chmod(0o600)
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    manifest.update(updates)
    manifest_path.write_text(json.dumps(manifest), encoding="utf-8")
    digest_path.write_text(
        hashlib.sha256(manifest_path.read_bytes()).hexdigest() + "\n",
        encoding="utf-8",
    )
    manifest_path.chmod(0o400)
    digest_path.chmod(0o400)
    candidate.chmod(0o500)


def test_deterministic_fixture_candidate_is_immutable_and_reviewable(
    tmp_path: Path,
) -> None:
    candidate = _candidate(tmp_path)

    verification = verify_refresh_candidate(candidate, now=FIXED_NOW)
    manifest = json.loads((candidate / "MANIFEST.json").read_text())

    assert verification["structural_valid"] is True
    assert verification["schema"] == "RefreshCandidateV2"
    assert verification["publication_eligible_schema"] is True
    assert verification["state"] == "fixture"
    assert verification["publication_ready"] is False
    assert manifest["scan_mode"] == "deterministic-fixture"
    assert manifest["freshness"] == {
        "mode": "STATIC_HISTORICAL_ONLY",
        "horizon_days": 90,
        "evaluated_at": FIXED_NOW.isoformat(),
        "earliest_stale_after": (FIXED_NOW + timedelta(days=90)).isoformat(),
        "publication_not_after": (FIXED_NOW + timedelta(hours=24)).isoformat(),
        "state_counts": {
            "FRESH": 1,
            "STALE": 0,
            "UNKNOWN": 0,
            "NOT_APPLICABLE": 0,
        },
    }
    assert set(manifest["semantic_digests"]) == {
        "scan_results",
        "static_snapshot",
        "masking",
    }
    assert manifest["tool_versions"]["mcp_trust_candidate_schema"] == "RefreshCandidateV2"
    assert manifest["authority"] == {
        "candidate_creation": True,
        "publication": False,
        "deployment": False,
        "schedule_change": False,
    }
    assert _results(candidate)[0]["state"] == "fresh"
    assert (candidate / "MANIFEST.json").stat().st_mode & 0o222 == 0
    assert candidate.stat().st_mode & 0o222 == 0


def test_candidate_receipt_self_binds_execution_contract(tmp_path: Path) -> None:
    candidate = _candidate(tmp_path)
    result = _results(candidate)[0]
    receipt_path = candidate / "receipts" / str(result["receipt"])
    receipt = json.loads(receipt_path.read_text(encoding="utf-8"))
    binding = receipt["execution_binding"]

    assert receipt["format_version"] == 2
    assert refresh_module._receipt_digest_valid(receipt) is True
    assert binding["schema"] == "McpTrustScanExecutionBindingV2"
    assert binding["target_slug"] == "alpha"
    assert binding["source"] == {
        "revision": None,
        "source_tree_digest": None,
        "policy_digest": None,
        "preflight_receipt_digest": None,
    }
    assert binding["sandbox"]["runtime_readback"]["state"] == "NOT_APPLICABLE"
    assert binding["sandbox"]["container_cleanup_evidence"] == "NOT_APPLICABLE"
    assert binding["timeout"] == {
        "configured_seconds": None,
        "repository_outer_deadline_seconds": None,
        "runtime_readback_deadline_seconds": None,
        "outcome": "completed",
        "hard_termination_evidence": "NOT_APPLICABLE",
    }


def test_local_execution_binding_refuses_missing_or_false_green_runtime_readback() -> None:
    server = _server("alpha")
    sandbox_evidence = {
        "profiles": [
            refresh_module._sandbox_profile(
                "required:image",
                image_digest=IMAGE_DIGEST,
            )
        ]
    }
    arguments = {
        "qualification": {},
        "sandbox_evidence": sandbox_evidence,
        "default_image": "required:image",
        "expected_image": IMAGE_DIGEST,
        "fixture_mode": False,
        "cleanup_evidence": "CONTAINER_ABSENCE_VERIFIED",
    }

    with pytest.raises(RefreshCandidateError, match="runtime controls"):
        refresh_module._candidate_execution_binding(
            server,
            runtime_readback=None,
            **arguments,
        )

    tampered = _runtime_readback()
    tampered["controls"]["network_none"] = False
    with pytest.raises(RefreshCandidateError, match="runtime controls"):
        refresh_module._candidate_execution_binding(
            server,
            runtime_readback=tampered,
            **arguments,
        )


def test_refresh_gate_accepts_exact_python_console_script_identity() -> None:
    server = _server("alpha")
    server = server.model_copy(
        update={
            "source": server.source.model_copy(
                update={
                    "kind": SourceKind.PYPI,
                    "reference": "mcp-server-time",
                    "command": "mcp-server-time",
                }
            )
        }
    )
    readback = _runtime_readback()
    readback["observed"]["server_process_cmdline_digest"] = sandbox_server_process_digest(
        "/opt/venv/bin/python", ["/opt/venv/bin/mcp-server-time"]
    )

    binding = refresh_module._candidate_execution_binding(
        server,
        qualification={},
        sandbox_evidence={
            "profiles": [
                refresh_module._sandbox_profile(
                    "required:image",
                    image_digest=IMAGE_DIGEST,
                )
            ]
        },
        default_image="required:image",
        expected_image=IMAGE_DIGEST,
        fixture_mode=False,
        cleanup_evidence="CONTAINER_ABSENCE_VERIFIED",
        runtime_readback=readback,
    )

    assert binding["sandbox"]["runtime_readback"]["state"] == "VERIFIED"


def test_refresh_gate_rejects_python_console_script_argument_drift() -> None:
    server = _server("alpha")
    server = server.model_copy(
        update={
            "source": server.source.model_copy(
                update={
                    "kind": SourceKind.PYPI,
                    "reference": "mcp-server-time",
                    "command": "mcp-server-time",
                }
            )
        }
    )
    readback = _runtime_readback()
    readback["observed"]["server_process_cmdline_digest"] = sandbox_server_process_digest(
        "/opt/venv/bin/python",
        ["/opt/venv/bin/mcp-server-time", "--drift"],
    )

    with pytest.raises(RefreshCandidateError, match="runtime controls"):
        refresh_module._candidate_execution_binding(
            server,
            qualification={},
            sandbox_evidence={
                "profiles": [
                    refresh_module._sandbox_profile(
                        "required:image",
                        image_digest=IMAGE_DIGEST,
                    )
                ]
            },
            default_image="required:image",
            expected_image=IMAGE_DIGEST,
            fixture_mode=False,
            cleanup_evidence="CONTAINER_ABSENCE_VERIFIED",
            runtime_readback=readback,
        )


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("memory_max_bytes", 1),
        ("pids_max", 1),
        ("cpu_quota", 50_000),
        ("uid", 65534),
        ("workdir", "/other"),
        ("environment_names", ["HOME", "TMPDIR"]),
        ("server_process_cmdline_digest", "sha256:" + "c" * 64),
    ],
)
def test_local_execution_binding_rejects_profile_mismatched_observations(
    field: str,
    value: object,
) -> None:
    server = _server("alpha")
    readback = _runtime_readback()
    readback["observed"][field] = value

    with pytest.raises(RefreshCandidateError, match="runtime controls"):
        refresh_module._candidate_execution_binding(
            server,
            qualification={},
            sandbox_evidence={
                "profiles": [
                    refresh_module._sandbox_profile(
                        "required:image",
                        image_digest=IMAGE_DIGEST,
                    )
                ]
            },
            default_image="required:image",
            expected_image=IMAGE_DIGEST,
            fixture_mode=False,
            cleanup_evidence="CONTAINER_ABSENCE_VERIFIED",
            runtime_readback=readback,
        )


def test_local_execution_binding_rejects_claim_ceiling_rewrite() -> None:
    readback = _runtime_readback()
    readback["claim_ceiling"] = "Everything is safe."

    with pytest.raises(RefreshCandidateError, match="runtime controls"):
        refresh_module._candidate_execution_binding(
            _server("alpha"),
            qualification={},
            sandbox_evidence={
                "profiles": [
                    refresh_module._sandbox_profile(
                        "required:image",
                        image_digest=IMAGE_DIGEST,
                    )
                ]
            },
            default_image="required:image",
            expected_image=IMAGE_DIGEST,
            fixture_mode=False,
            cleanup_evidence="CONTAINER_ABSENCE_VERIFIED",
            runtime_readback=readback,
        )


def test_legacy_v1_candidate_is_structurally_inspectable_but_ineligible(
    tmp_path: Path,
) -> None:
    candidate = _candidate(tmp_path)
    candidate.chmod(0o700)
    results_path = candidate / "scan_results.json"
    snapshot_path = candidate / "static_snapshot.json"
    for path in (results_path, snapshot_path):
        path.chmod(0o600)

    results = json.loads(results_path.read_text(encoding="utf-8"))
    for result in results["results"]:
        result.pop("freshness_state")
        result.pop("freshness_reason")
        result.pop("stale_after")
    results_path.write_text(json.dumps(results), encoding="utf-8")

    snapshot = json.loads(snapshot_path.read_text(encoding="utf-8"))
    for server in snapshot["servers"]:
        server.pop("stale_after", None)
    snapshot_path.write_text(json.dumps(snapshot), encoding="utf-8")
    _rebind_candidate_artifacts(candidate, "scan_results.json", "static_snapshot.json")

    manifest_path = candidate / "MANIFEST.json"
    manifest_path.chmod(0o600)
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    manifest["schema"] = "RefreshCandidateV1"
    manifest["scan_counts"].pop("blocked")
    for field in (
        "freshness",
        "semantic_digests",
        "source_tree_digest",
        "tool_versions",
    ):
        manifest.pop(field)
    receipt_paths = list((candidate / "receipts").glob("*.json"))
    for receipt_path in receipt_paths:
        receipt_path.chmod(0o600)
        receipt = json.loads(receipt_path.read_text(encoding="utf-8"))
        receipt["format_version"] = 1
        receipt.pop("execution_binding")
        receipt.pop("receipt_digest")
        receipt_path.write_text(json.dumps(receipt), encoding="utf-8")
    _rebind_candidate_artifacts(
        candidate,
        *(path.relative_to(candidate).as_posix() for path in receipt_paths),
    )
    candidate.chmod(0o700)
    manifest_path.chmod(0o600)
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    manifest["schema"] = "RefreshCandidateV1"
    manifest["scan_counts"].pop("blocked")
    for field in (
        "freshness",
        "semantic_digests",
        "source_tree_digest",
        "tool_versions",
    ):
        manifest.pop(field)
    manifest_path.write_text(json.dumps(manifest), encoding="utf-8")
    digest_path = candidate / "MANIFEST.sha256"
    digest_path.chmod(0o600)
    digest_path.write_text(
        hashlib.sha256(manifest_path.read_bytes()).hexdigest() + "\n",
        encoding="utf-8",
    )
    manifest_path.chmod(0o400)
    digest_path.chmod(0o400)
    candidate.chmod(0o500)

    verification = verify_refresh_candidate(candidate, now=FIXED_NOW)

    assert verification["structural_valid"] is True
    assert verification["schema"] == "RefreshCandidateV1"
    assert verification["publication_eligible_schema"] is False
    assert verification["publication_ready"] is False


def test_empty_reviewed_catalog_is_refused_before_candidate_creation(
    tmp_path: Path,
) -> None:
    db_path, seed_path, masked_path = _inputs(tmp_path, slugs=())

    with pytest.raises(RefreshCandidateError, match="at least one server"):
        create_refresh_candidate(
            source_db=db_path,
            seed_path=seed_path,
            masked_path=masked_path,
            output_parent=tmp_path / "candidates",
            default_image="fixture:image",
            scanner=_stub_scanner,
            now=FIXED_NOW,
            candidate_name="candidate",
        )


def test_legacy_empty_candidate_is_rejected_by_verifier(tmp_path: Path) -> None:
    candidate = _candidate(tmp_path)
    results_path = candidate / "scan_results.json"
    catalog_path = candidate / "catalog_identity.json"
    snapshot_path = candidate / "static_snapshot.json"
    candidate.chmod(0o700)
    for path in (results_path, catalog_path, snapshot_path):
        path.chmod(0o600)
    results = json.loads(results_path.read_text(encoding="utf-8"))
    results["results"] = []
    results_path.write_text(json.dumps(results), encoding="utf-8")
    catalog = json.loads(catalog_path.read_text(encoding="utf-8"))
    catalog["server_count"] = 0
    catalog["servers"] = []
    catalog_path.write_text(json.dumps(catalog), encoding="utf-8")
    snapshot = json.loads(snapshot_path.read_text(encoding="utf-8"))
    snapshot["server_count"] = 0
    snapshot["servers"] = []
    snapshot["generated_from_scan_at"] = ""
    snapshot_path.write_text(json.dumps(snapshot), encoding="utf-8")
    _rebind_candidate_artifacts(
        candidate,
        "scan_results.json",
        "catalog_identity.json",
        "static_snapshot.json",
    )
    _rebind_manifest(
        candidate,
        catalog={
            "seed_sha256": catalog["seed_sha256"],
            "server_count": 0,
        },
        scan_counts={"total": 0, "fresh": 0, "masked": 0, "blocked": 0, "failed": 0},
    )

    verification = verify_refresh_candidate(candidate, now=FIXED_NOW)

    assert verification["structural_valid"] is False
    assert verification["publication_ready"] is False
    assert "empty_candidate" in verification["errors"]


def test_real_scan_mode_describes_local_remote_and_mixed_transports() -> None:
    assert _real_scan_mode(local_count=2, total_count=2) == "mcpaudit-local-network-off"
    assert _real_scan_mode(local_count=0, total_count=2) == "mcpaudit-remote-live-network"
    assert _real_scan_mode(local_count=1, total_count=2) == "mcpaudit-mixed-transport"


def test_legacy_refresh_entrypoint_only_creates_a_candidate() -> None:
    script = (ROOT / "scripts/refresh_and_publish.sh").read_text(encoding="utf-8")

    assert "refresh_candidate.py create" in script
    assert "${REPO_ROOT}/.venv/bin/python" in script
    assert "uv run" not in script
    assert "mcp-trust scan" not in script
    assert "build_site.py" not in script
    assert "deploy_production" not in script
    assert "vercel deploy" not in script


def test_create_cli_returns_failure_for_partial_candidate(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    candidate = tmp_path / "partial"
    monkeypatch.setattr(
        refresh_cli,
        "create_refresh_candidate",
        lambda **_kwargs: candidate,
    )
    monkeypatch.setattr(
        refresh_cli,
        "verify_refresh_candidate",
        lambda *_args, **_kwargs: {
            "structural_valid": True,
            "candidate_state": "partial",
            "publication_ready": False,
            "errors": [],
        },
    )
    qualification = tmp_path / "qualification.json"
    qualification.write_text("{}", encoding="utf-8")

    result = refresh_cli.main(["create", "--qualification-receipt", str(qualification)])
    output = json.loads(capsys.readouterr().out)

    assert result == 1
    assert output["candidate_state"] == "partial"
    assert output["publication_ready"] is False
    assert output["deployment_performed"] is False


def test_verify_cli_returns_failure_when_candidate_is_not_publication_ready(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    monkeypatch.setattr(
        refresh_cli,
        "verify_refresh_candidate",
        lambda *_args, **_kwargs: {
            "structural_valid": True,
            "state": "stale",
            "candidate_state": "complete",
            "publication_ready": False,
            "manifest_sha256": "a" * 64,
            "age_hours": 24.0,
            "scan_counts": {"total": 1, "fresh": 1, "masked": 0, "failed": 0},
            "reviewed_inputs_bound": True,
            "errors": [],
        },
    )

    result = refresh_cli.main(["verify", str(tmp_path / "candidate")])
    output = json.loads(capsys.readouterr().out)

    assert result == 1
    assert output["structural_valid"] is True
    assert output["state"] == "stale"
    assert output["publication_ready"] is False


def test_unknown_masked_slug_refuses_before_scanning(tmp_path: Path) -> None:
    db_path, seed_path, masked_path = _inputs(
        tmp_path,
        masked=("alpah",),
    )
    scanned: list[str] = []

    def scanner(server: Server) -> EngineResult:
        scanned.append(server.slug)
        return _stub_scanner(server)

    with pytest.raises(
        RefreshCandidateError,
        match="masked grade list contains unknown catalog slug.*alpah",
    ):
        create_refresh_candidate(
            source_db=db_path,
            seed_path=seed_path,
            masked_path=masked_path,
            output_parent=tmp_path / "candidates",
            default_image="fixture:image",
            scanner=scanner,
            now=FIXED_NOW,
            candidate_name="candidate",
        )

    assert scanned == []


@pytest.mark.parametrize(
    ("field", "value"),
    (
        ("command", "/opt/reviewed-alpha"),
        ("reference", "@example/reviewed-alpha"),
        ("env_keys", ["REVIEWED_TOKEN"]),
        ("sandbox_image", "reviewed:image"),
    ),
)
def test_seed_source_metadata_mismatch_refuses_before_scanning(
    tmp_path: Path,
    field: str,
    value: object,
) -> None:
    db_path, seed_path, masked_path = _inputs(tmp_path)
    seed = json.loads(seed_path.read_text(encoding="utf-8"))
    seed[0]["source"][field] = value
    seed_path.write_text(json.dumps(seed), encoding="utf-8")
    scanned: list[str] = []

    def scanner(server: Server) -> EngineResult:
        scanned.append(server.slug)
        return _stub_scanner(server)

    with pytest.raises(
        RefreshCandidateError,
        match="registry DB server metadata differs from reviewed catalog: alpha",
    ):
        create_refresh_candidate(
            source_db=db_path,
            seed_path=seed_path,
            masked_path=masked_path,
            output_parent=tmp_path / "candidates",
            default_image="fixture:image",
            scanner=scanner,
            now=FIXED_NOW,
            candidate_name="candidate",
        )

    assert scanned == []


def test_candidate_supports_sqlite_uri_characters_in_source_path(
    tmp_path: Path,
) -> None:
    db_path, seed_path, masked_path = _inputs(tmp_path)
    special_db = tmp_path / "registry#operator?.db"
    db_path.rename(special_db)

    candidate = create_refresh_candidate(
        source_db=special_db,
        seed_path=seed_path,
        masked_path=masked_path,
        output_parent=tmp_path / "candidates",
        default_image="fixture:image",
        scanner=_stub_scanner,
        now=FIXED_NOW,
        candidate_name="candidate",
    )

    assert verify_refresh_candidate(candidate, now=FIXED_NOW)["structural_valid"] is True


def test_manifest_tampering_fails_content_verification(tmp_path: Path) -> None:
    candidate = _candidate(tmp_path)
    manifest = candidate / "MANIFEST.json"
    os.chmod(candidate, 0o700)
    os.chmod(manifest, 0o600)
    payload = json.loads(manifest.read_text())
    payload["publication_allowed"] = True
    manifest.write_text(json.dumps(payload), encoding="utf-8")
    os.chmod(manifest, 0o400)
    os.chmod(candidate, 0o500)

    verification = verify_refresh_candidate(
        candidate,
        now=FIXED_NOW,
        expected_seed_path=tmp_path / "seed.json",
        expected_masked_path=tmp_path / "masked.json",
    )

    assert verification["structural_valid"] is False
    assert "manifest_digest_mismatch" in verification["errors"]


def test_duplicate_json_keys_are_rejected_as_ambiguous(tmp_path: Path) -> None:
    candidate = _candidate(tmp_path)
    manifest_path = candidate / "MANIFEST.json"
    digest_path = candidate / "MANIFEST.sha256"
    candidate.chmod(0o700)
    manifest_path.chmod(0o600)
    digest_path.chmod(0o600)
    manifest_text = manifest_path.read_text(encoding="utf-8").strip()
    ambiguous = manifest_text[:-1] + ',"candidate_state":"complete"}'
    manifest_path.write_text(ambiguous, encoding="utf-8")
    digest_path.write_text(
        hashlib.sha256(manifest_path.read_bytes()).hexdigest() + "\n",
        encoding="utf-8",
    )
    manifest_path.chmod(0o400)
    digest_path.chmod(0o400)
    candidate.chmod(0o500)

    verification = verify_refresh_candidate(candidate, now=FIXED_NOW)

    assert verification["structural_valid"] is False
    assert verification["publication_ready"] is False
    assert "manifest_unreadable" in verification["errors"]


def test_unreadable_manifest_returns_structured_invalid_result(
    tmp_path: Path,
) -> None:
    candidate = _candidate(tmp_path)
    manifest_path = candidate / "MANIFEST.json"
    manifest_path.chmod(0o000)

    verification = verify_refresh_candidate(
        candidate,
        now=FIXED_NOW,
        expected_seed_path=tmp_path / "seed.json",
        expected_masked_path=tmp_path / "masked.json",
    )

    assert verification["structural_valid"] is False
    assert verification["publication_ready"] is False
    assert "manifest_unreadable" in verification["errors"]
    assert "manifest_digest_mismatch" in verification["errors"]


def test_invalid_masking_manifest_fails_closed_with_reviewed_inputs(
    tmp_path: Path,
) -> None:
    candidate = _candidate(tmp_path)
    manifest_path = candidate / "MANIFEST.json"
    digest_path = candidate / "MANIFEST.sha256"
    candidate.chmod(0o700)
    manifest_path.chmod(0o600)
    digest_path.chmod(0o600)
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    manifest["masking"] = []
    manifest_path.write_text(json.dumps(manifest), encoding="utf-8")
    digest_path.write_text(
        hashlib.sha256(manifest_path.read_bytes()).hexdigest() + "\n",
        encoding="utf-8",
    )
    manifest_path.chmod(0o400)
    digest_path.chmod(0o400)
    candidate.chmod(0o500)

    verification = verify_refresh_candidate(
        candidate,
        now=FIXED_NOW,
        expected_seed_path=tmp_path / "seed.json",
        expected_masked_path=tmp_path / "masked.json",
    )

    assert verification["structural_valid"] is False
    assert verification["publication_ready"] is False
    assert "masking_manifest_invalid" in verification["errors"]
    assert "reviewed_inputs_mismatch" in verification["errors"]


def test_rebound_manifest_cannot_relabel_fixture_as_publishable(
    tmp_path: Path,
) -> None:
    candidate = _candidate(tmp_path)
    manifest_path = candidate / "MANIFEST.json"
    digest_path = candidate / "MANIFEST.sha256"
    os.chmod(candidate, 0o700)
    os.chmod(manifest_path, 0o600)
    os.chmod(digest_path, 0o600)
    manifest = json.loads(manifest_path.read_text())
    manifest["candidate_state"] = "complete"
    manifest["scan_mode"] = "mcpaudit-local-network-off"
    manifest["publication_allowed"] = True
    manifest_path.write_text(json.dumps(manifest), encoding="utf-8")
    digest_path.write_text(
        hashlib.sha256(manifest_path.read_bytes()).hexdigest() + "\n",
        encoding="utf-8",
    )
    os.chmod(manifest_path, 0o400)
    os.chmod(digest_path, 0o400)
    os.chmod(candidate, 0o500)

    verification = verify_refresh_candidate(candidate, now=FIXED_NOW)

    assert verification["structural_valid"] is False
    assert verification["publication_ready"] is False
    assert any("publishable_scan_provenance_invalid" in error for error in verification["errors"])


def test_candidate_state_is_closed_to_known_values(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    candidate, seed_path, masked_path = _complete_remote_candidate(tmp_path, monkeypatch)
    _rebind_manifest(
        candidate,
        candidate_state="approved",
        publication_allowed=False,
    )

    verification = verify_refresh_candidate(
        candidate,
        now=FIXED_NOW,
        expected_seed_path=seed_path,
        expected_masked_path=masked_path,
    )

    assert verification["structural_valid"] is False
    assert verification["publication_ready"] is False
    assert verification["state"] == "invalid"
    assert "candidate_state_invalid" in verification["errors"]


def test_bidi_control_in_candidate_json_is_rejected_without_echo(
    tmp_path: Path,
) -> None:
    candidate = _candidate(tmp_path)
    _rebind_manifest(candidate, scan_mode="fixture\u202eapproved")

    verification = verify_refresh_candidate(candidate, now=FIXED_NOW)
    rendered = json.dumps(verification, ensure_ascii=False)

    assert verification["structural_valid"] is False
    assert verification["publication_ready"] is False
    assert "manifest_unreadable" in verification["errors"]
    assert "\u202e" not in rendered


def test_stale_candidate_is_not_publication_ready(tmp_path: Path) -> None:
    candidate = _candidate(tmp_path)

    verification = verify_refresh_candidate(
        candidate,
        now=FIXED_NOW + timedelta(hours=25),
    )

    assert verification["structural_valid"] is True
    assert verification["state"] == "stale"
    assert verification["publication_ready"] is False


def test_exact_expiry_boundary_is_stale(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    candidate, seed_path, masked_path = _complete_remote_candidate(tmp_path, monkeypatch)

    verification = verify_refresh_candidate(
        candidate,
        now=FIXED_NOW + timedelta(hours=24),
        expected_seed_path=seed_path,
        expected_masked_path=masked_path,
    )

    assert verification["structural_valid"] is True
    assert verification["state"] == "stale"
    assert verification["publication_ready"] is False


@pytest.mark.parametrize(
    ("expires_at", "expected_error"),
    [
        ("not-a-timestamp", "candidate_expiry_invalid"),
        (
            (FIXED_NOW + timedelta(hours=1)).isoformat(),
            "candidate_expiry_mismatch",
        ),
    ],
)
def test_invalid_or_mismatched_expiry_fails_closed(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    expires_at: str,
    expected_error: str,
) -> None:
    candidate, seed_path, masked_path = _complete_remote_candidate(tmp_path, monkeypatch)
    _rebind_manifest(candidate, expires_at=expires_at)

    verification = verify_refresh_candidate(
        candidate,
        now=FIXED_NOW,
        expected_seed_path=seed_path,
        expected_masked_path=masked_path,
    )

    assert verification["structural_valid"] is False
    assert verification["publication_ready"] is False
    assert expected_error in verification["errors"]


def test_timestamp_near_datetime_limit_returns_structured_expiry_failure(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    candidate, seed_path, masked_path = _complete_remote_candidate(tmp_path, monkeypatch)
    _rebind_manifest(
        candidate,
        created_at="9999-12-31T23:00:00+00:00",
        expires_at="9999-12-31T23:59:59+00:00",
    )

    verification = verify_refresh_candidate(
        candidate,
        now=FIXED_NOW,
        expected_seed_path=seed_path,
        expected_masked_path=masked_path,
    )

    assert verification["structural_valid"] is False
    assert verification["publication_ready"] is False
    assert "candidate_expiry_invalid" in verification["errors"]


@pytest.mark.parametrize(
    ("field", "expected_error"),
    [
        ("created_at", "candidate_timestamp_invalid"),
        ("expires_at", "candidate_expiry_invalid"),
    ],
)
def test_extreme_timezone_offset_returns_structured_timestamp_failure(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    field: str,
    expected_error: str,
) -> None:
    candidate, seed_path, masked_path = _complete_remote_candidate(tmp_path, monkeypatch)
    _rebind_manifest(candidate, **{field: "0001-01-01T00:00:00+23:59"})

    verification = verify_refresh_candidate(
        candidate,
        now=FIXED_NOW,
        expected_seed_path=seed_path,
        expected_masked_path=masked_path,
    )

    assert verification["structural_valid"] is False
    assert verification["publication_ready"] is False
    assert expected_error in verification["errors"]


def test_future_dated_complete_candidate_is_not_publication_ready(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    candidate, seed_path, masked_path = _complete_remote_candidate(
        tmp_path,
        monkeypatch,
    )
    _rebind_manifest_time(candidate, FIXED_NOW + timedelta(hours=1))

    verification = verify_refresh_candidate(
        candidate,
        now=FIXED_NOW,
        expected_seed_path=seed_path,
        expected_masked_path=masked_path,
    )

    assert verification["structural_valid"] is False
    assert verification["publication_ready"] is False
    assert "candidate_timestamp_in_future" in verification["errors"]


def test_fresh_manifest_cannot_replay_stale_complete_scans(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    candidate, seed_path, masked_path = _complete_remote_candidate(
        tmp_path,
        monkeypatch,
    )
    rebound_now = FIXED_NOW + timedelta(hours=48)
    _rebind_manifest_time(candidate, rebound_now)

    verification = verify_refresh_candidate(
        candidate,
        now=rebound_now,
        expected_seed_path=seed_path,
        expected_masked_path=masked_path,
    )

    assert verification["age_hours"] == 0.0
    assert verification["structural_valid"] is False
    assert verification["publication_ready"] is False
    assert "scan_timestamp_stale:alpha" in verification["errors"]
    assert "scan_age_mismatch:alpha" in verification["errors"]


def test_partial_scan_failure_never_retains_old_grade_as_fresh(tmp_path: Path) -> None:
    def scanner(server: Server) -> EngineResult:
        if server.slug == "beta":
            raise RuntimeError("fixture failure")
        return _stub_scanner(server)

    candidate = _candidate(tmp_path, slugs=("alpha", "beta"), scanner=scanner)
    by_slug = {row["server_slug"]: row for row in _results(candidate)}

    assert by_slug["alpha"]["state"] == "fresh"
    assert by_slug["beta"]["state"] == "scan-failed"
    assert by_slug["beta"]["fresh_grade"] is None
    assert by_slug["beta"]["error_type"] == "RuntimeError"
    assert "fixture failure" not in json.dumps(by_slug["beta"])


def test_scan_timeout_is_unknown_and_never_retains_a_fresh_grade(
    tmp_path: Path,
) -> None:
    def scanner(_server: Server) -> EngineResult:
        raise ScanTimeoutError("controlled timeout")

    candidate = _candidate(tmp_path, scanner=scanner)
    result = _results(candidate)[0]
    verification = verify_refresh_candidate(candidate, now=FIXED_NOW)

    assert result == {
        "server_slug": "alpha",
        "state": "scan-timeout",
        "fresh_grade": None,
        "reason": "configured_scan_timeout_expired",
        "configured_timeout_seconds": 90.0,
        "timeout_outcome": "timeout",
        "hard_termination_evidence": "UNKNOWN",
        "previous_grade": None,
        "previous_scanned_at": None,
        "previous_scan_age_days": None,
    }
    assert verification["structural_valid"] is True
    assert verification["publication_ready"] is False


def test_scan_timeout_preserves_verified_container_absence(tmp_path: Path) -> None:
    def scanner(_server: Server) -> EngineResult:
        raise ScanTimeoutError(
            "controlled timeout",
            hard_termination_evidence="CONTAINER_ABSENCE_VERIFIED_AFTER_TIMEOUT",
        )

    candidate = _candidate(tmp_path, scanner=scanner)
    result = _results(candidate)[0]
    verification = verify_refresh_candidate(candidate, now=FIXED_NOW)

    assert result["state"] == "scan-timeout"
    assert result["fresh_grade"] is None
    assert result["hard_termination_evidence"] == "CONTAINER_ABSENCE_VERIFIED_AFTER_TIMEOUT"
    assert verification["structural_valid"] is True
    assert verification["publication_ready"] is False


def test_verifier_rejects_non_string_timeout_evidence_without_crashing(
    tmp_path: Path,
) -> None:
    def scanner(_server: Server) -> EngineResult:
        raise ScanTimeoutError("controlled timeout")

    candidate = _candidate(tmp_path, scanner=scanner)
    candidate.chmod(0o700)
    results_path = candidate / "scan_results.json"
    results_path.chmod(0o600)
    results = json.loads(results_path.read_text(encoding="utf-8"))
    results["results"][0]["hard_termination_evidence"] = ["UNKNOWN"]
    results_path.write_text(json.dumps(results), encoding="utf-8")
    _rebind_candidate_artifacts(candidate, "scan_results.json")

    verification = verify_refresh_candidate(candidate, now=FIXED_NOW)

    assert verification["structural_valid"] is False
    assert any(error.startswith("timeout_scan_schema_invalid:") for error in verification["errors"])


def test_masked_real_entry_is_blocked_without_preflight_or_scanner_execution(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    db_path, seed_path, masked_path = _inputs(tmp_path, masked=("alpha",))

    engine_constructed = False

    class FailingMCPAuditEngine:
        def __init__(self, timeout: float) -> None:
            nonlocal engine_constructed
            engine_constructed = True

        def scan(self, source: ServerSource) -> EngineResult:
            raise RuntimeError(f"controlled failure for {source.reference}")

    monkeypatch.setattr(
        "mcp_trust.refresh.preflight_real_refresh",
        lambda servers, *, default_image: {
            "docker_daemon": "not_required",
            "default_image": default_image,
            "profiles": [],
            "remote_transport_count": 0,
        },
    )
    monkeypatch.setattr("mcp_trust.refresh.MCPAuditEngine", FailingMCPAuditEngine)

    qualification = _qualification_receipt(
        seed_path,
        masked_path,
        profiles=[],
    )
    candidate = create_refresh_candidate(
        source_db=db_path,
        seed_path=seed_path,
        masked_path=masked_path,
        output_parent=tmp_path / "candidates",
        default_image="required:image",
        qualification_receipt=qualification,
        repo_root=ROOT,
        _source_binding_provider=_qualification_source_provider(qualification),
        _qualification_revalidator=lambda *_args, **_kwargs: None,
        now=FIXED_NOW,
        candidate_name="candidate",
    )
    verification = verify_refresh_candidate(
        candidate,
        now=FIXED_NOW,
        expected_seed_path=seed_path,
        expected_masked_path=masked_path,
    )

    assert _results(candidate)[0]["state"] == "blocked-policy"
    assert engine_constructed is True
    assert verification["structural_valid"] is True
    assert verification["state"] == "complete"
    assert verification["publication_ready"] is True
    assert verification["errors"] == []


def test_policy_blocked_server_is_never_preflighted_or_scanned(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    db_path, seed_path, masked_path = _inputs(
        tmp_path,
        slugs=("alpha", "beta"),
    )
    policy_path = _write_refresh_policy(
        seed_path,
        masked_path,
        blocked=("beta",),
    )
    conn = connect(db_path)
    ScanRepository(conn).record(
        ScanRecord(
            id="old-beta",
            server_slug="beta",
            engine_name="mcpaudit",
            engine_version="2.3.0",
            grade=TrustGrade.D,
            risk=RiskSummary(composite=6.0),
            evidence=ScanEvidence(tools=[ToolEvidence(name="historical-tool")]),
            scanned_at=FIXED_NOW - timedelta(days=30),
        )
    )
    conn.close()
    preflighted: list[str] = []
    scanned: list[str] = []

    def preflight(servers: list[Server], *, default_image: str) -> dict[str, object]:
        preflighted.extend(server.slug for server in servers)
        return {
            "docker_daemon": "available",
            "default_image": default_image,
            "profiles": [
                refresh_module._sandbox_profile(
                    default_image,
                    image_digest=IMAGE_DIGEST,
                )
            ],
            "remote_transport_count": 0,
            "_execution_image_bindings": {default_image: IMAGE_DIGEST},
        }

    class LocalMCPAuditEngine:
        def __init__(self, timeout: float) -> None:
            assert timeout == 90.0

        def scan(self, source: ServerSource) -> EngineResult:
            scanned.append(source.reference)
            return _stub_scanner(_server("alpha")).model_copy(
                update={
                    "engine_name": "mcpaudit",
                    "engine_version": "2.7.0",
                    "sandbox_image": IMAGE_DIGEST,
                    "sandbox_cleanup_evidence": "CONTAINER_ABSENCE_VERIFIED",
                    "sandbox_runtime_readback": _runtime_readback(),
                }
            )

    monkeypatch.setattr("mcp_trust.refresh.preflight_real_refresh", preflight)
    monkeypatch.setattr("mcp_trust.refresh.MCPAuditEngine", LocalMCPAuditEngine)
    qualification = _qualification_receipt(
        seed_path,
        masked_path,
        profiles=[
            refresh_module._sandbox_profile(
                "required:image",
                image_digest=IMAGE_DIGEST,
            )
        ],
    )

    candidate = create_refresh_candidate(
        source_db=db_path,
        seed_path=seed_path,
        masked_path=masked_path,
        output_parent=tmp_path / "candidates",
        default_image="required:image",
        qualification_receipt=qualification,
        repo_root=ROOT,
        policy_path=policy_path,
        _source_binding_provider=_qualification_source_provider(qualification),
        _qualification_revalidator=lambda *_args, **_kwargs: None,
        now=FIXED_NOW,
        candidate_name="candidate",
    )
    verification = verify_refresh_candidate(
        candidate,
        now=FIXED_NOW,
        expected_seed_path=seed_path,
        expected_masked_path=masked_path,
    )
    by_slug = {row["server_slug"]: row for row in _results(candidate)}
    alpha_receipt = json.loads(
        (candidate / "receipts" / str(by_slug["alpha"]["receipt"])).read_text()
    )

    assert preflighted == ["alpha"]
    assert scanned == ["@example/alpha"]
    assert alpha_receipt["execution_binding"]["timeout"] == {
        "configured_seconds": 90.0,
        "repository_outer_deadline_seconds": 95.0,
        "runtime_readback_deadline_seconds": 5.0,
        "outcome": "completed",
        "hard_termination_evidence": "NOT_APPLICABLE",
    }
    assert by_slug["beta"] == {
        "server_slug": "beta",
        "state": "blocked-policy",
        "fresh_grade": None,
        "execution_disposition": "do-not-execute",
        "reason": "sandbox_image_qualification_unknown",
        "previous_grade": "D",
        "previous_scanned_at": (FIXED_NOW - timedelta(days=30)).isoformat(),
        "previous_scan_age_days": 30.0,
    }
    assert verification["structural_valid"] is True
    assert verification["state"] == "complete"
    assert verification["publication_ready"] is True


def test_verifier_rejects_eligible_result_relabelled_as_policy_blocked(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    candidate, seed_path, masked_path = _complete_remote_candidate(tmp_path, monkeypatch)
    results_path = candidate / "scan_results.json"
    candidate.chmod(0o700)
    results_path.chmod(0o600)
    payload = json.loads(results_path.read_text(encoding="utf-8"))
    payload["results"] = [
        {
            "server_slug": "alpha",
            "state": "blocked-policy",
            "fresh_grade": None,
            "execution_disposition": "do-not-execute",
            "reason": "sandbox_image_qualification_unknown",
            "previous_grade": None,
            "previous_scanned_at": None,
            "previous_scan_age_days": None,
        }
    ]
    results_path.write_text(json.dumps(payload), encoding="utf-8")
    _rebind_candidate_artifacts(candidate, "scan_results.json")

    verification = verify_refresh_candidate(
        candidate,
        now=FIXED_NOW,
        expected_seed_path=seed_path,
        expected_masked_path=masked_path,
    )

    assert verification["structural_valid"] is False
    assert verification["publication_ready"] is False
    assert "execution_policy_result_boundary_mismatch" in verification["errors"]
    assert "blocked_scan_schema_invalid:alpha" in verification["errors"]


def test_verifier_rejects_qualification_boundary_that_differs_from_live_policy(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    candidate, seed_path, masked_path = _complete_remote_candidate(tmp_path, monkeypatch)
    qualification_path = candidate / "qualification_receipt.json"
    candidate.chmod(0o700)
    qualification_path.chmod(0o600)
    qualification = json.loads(qualification_path.read_text(encoding="utf-8"))
    qualification["catalog"]["execution_boundary"] = {
        "schema": "McpTrustRefreshExecutionBoundaryV1",
        "scannable": [],
        "blocked": ["alpha"],
    }
    qualification["catalog"]["counts"] = {
        **qualification["catalog"]["counts"],
        "scannable": 0,
        "blocked": 1,
    }
    qualification.pop("receipt_digest")
    qualification["receipt_digest"] = (
        "sha256:" + hashlib.sha256(refresh_module._json_bytes(qualification)).hexdigest()
    )
    qualification_path.write_text(json.dumps(qualification), encoding="utf-8")
    _rebind_candidate_artifacts(candidate, "qualification_receipt.json")
    manifest = json.loads((candidate / "MANIFEST.json").read_text(encoding="utf-8"))
    qualification_manifest = dict(manifest["qualification"])
    qualification_manifest["receipt_sha256"] = hashlib.sha256(
        refresh_module._json_bytes(qualification)
    ).hexdigest()
    qualification_manifest["preflight_receipt_digest"] = qualification["receipt_digest"]
    _rebind_manifest(candidate, qualification=qualification_manifest)

    verification = verify_refresh_candidate(
        candidate,
        now=FIXED_NOW,
        expected_seed_path=seed_path,
        expected_masked_path=masked_path,
    )

    assert verification["structural_valid"] is False
    assert verification["publication_ready"] is False
    assert "qualification_receipt_invalid" in verification["errors"]


def test_failed_rescan_excludes_the_previous_grade_from_static_snapshot(
    tmp_path: Path,
) -> None:
    db_path, seed_path, masked_path = _inputs(tmp_path, slugs=("alpha", "beta"))
    conn = connect(db_path)
    ScanRepository(conn).record(
        ScanRecord(
            id="old-beta",
            server_slug="beta",
            engine_name="mcpaudit",
            engine_version="2.3.0",
            grade=TrustGrade.D,
            risk=RiskSummary(composite=6.0),
            evidence=ScanEvidence(tools=[ToolEvidence(name="fixture-tool")]),
            scanned_at=FIXED_NOW - timedelta(days=30),
        )
    )
    conn.close()

    def scanner(server: Server) -> EngineResult:
        if server.slug == "beta":
            raise RuntimeError("fixture failure")
        return _stub_scanner(server)

    candidate = create_refresh_candidate(
        source_db=db_path,
        seed_path=seed_path,
        masked_path=masked_path,
        output_parent=tmp_path / "candidates",
        default_image="fixture:image",
        scanner=scanner,
        now=FIXED_NOW,
        candidate_name="candidate",
    )
    snapshot = json.loads((candidate / "static_snapshot.json").read_text())

    assert "beta" not in {server["slug"] for server in snapshot["servers"]}
    beta = next(row for row in _results(candidate) if row["server_slug"] == "beta")
    assert beta["fresh_grade"] is None
    assert beta["previous_grade"] == "D"
    assert beta["previous_scan_age_days"] == 30.0


def test_candidate_reuses_grade_drift_attribution(tmp_path: Path) -> None:
    db_path, seed_path, masked_path = _inputs(tmp_path)
    conn = connect(db_path)
    ScanRepository(conn).record(
        ScanRecord(
            id="old-alpha",
            server_slug="alpha",
            engine_name="mcpaudit",
            engine_version="2.3.0",
            grade=TrustGrade.D,
            risk=RiskSummary(composite=6.0),
            evidence=ScanEvidence(tools=[ToolEvidence(name="fixture-tool")]),
            scanned_at=FIXED_NOW - timedelta(days=7),
        )
    )
    conn.close()

    candidate = create_refresh_candidate(
        source_db=db_path,
        seed_path=seed_path,
        masked_path=masked_path,
        output_parent=tmp_path / "candidates",
        default_image="fixture:image",
        scanner=_stub_scanner,
        now=FIXED_NOW,
        candidate_name="candidate",
    )
    result = _results(candidate)[0]

    assert result["drift"]["cause"] == "engine-changed"
    assert result["drift"]["surface_comparison"] == "unchanged"
    assert "engine change" in result["drift"]["summary"]


def test_rebound_manifest_cannot_invent_drift(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    candidate, seed_path, masked_path = _complete_remote_candidate(tmp_path, monkeypatch)
    results_path = candidate / "scan_results.json"
    candidate.chmod(0o700)
    results_path.chmod(0o600)
    payload = json.loads(results_path.read_text(encoding="utf-8"))
    payload["results"][0]["drift"] = {
        "cause": "surface-changed",
        "surface_comparison": "changed",
        "summary": "attacker-authored decision evidence",
        "previous_grade": "A",
        "current_grade": "F",
    }
    results_path.write_text(json.dumps(payload), encoding="utf-8")
    _rebind_candidate_artifacts(candidate, "scan_results.json")

    verification = verify_refresh_candidate(
        candidate,
        now=FIXED_NOW,
        expected_seed_path=seed_path,
        expected_masked_path=masked_path,
    )

    assert verification["structural_valid"] is False
    assert verification["publication_ready"] is False
    assert any(error.startswith("fresh_scan_drift_mismatch:") for error in verification["errors"])


def test_rebound_receipt_cannot_add_authoritative_claims(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    candidate, seed_path, masked_path = _complete_remote_candidate(tmp_path, monkeypatch)
    result = _results(candidate)[0]
    receipt_path = candidate / "receipts" / str(result["receipt"])
    candidate.chmod(0o700)
    receipt_path.chmod(0o600)
    receipt = json.loads(receipt_path.read_text(encoding="utf-8"))
    receipt["publication_ready"] = True
    receipt["approval"] = {"approval_ref": "attacker-authored"}
    receipt_path.write_text(json.dumps(receipt), encoding="utf-8")
    _rebind_candidate_artifacts(candidate, f"receipts/{receipt_path.name}")

    verification = verify_refresh_candidate(
        candidate,
        now=FIXED_NOW,
        expected_seed_path=seed_path,
        expected_masked_path=masked_path,
    )

    assert verification["structural_valid"] is False
    assert verification["publication_ready"] is False
    assert any(
        error.startswith("successful_scan_receipt_schema_invalid:")
        for error in verification["errors"]
    )


def test_receipt_cannot_assert_unverified_scanner_revision(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    candidate, seed_path, masked_path = _complete_remote_candidate(tmp_path, monkeypatch)
    result = _results(candidate)[0]
    receipt_path = candidate / "receipts" / str(result["receipt"])
    candidate.chmod(0o700)
    receipt_path.chmod(0o600)
    receipt = json.loads(receipt_path.read_text(encoding="utf-8"))
    receipt["scanner"]["scanner_git_ref"] = "attacker-claimed-revision"
    receipt_path.write_text(json.dumps(receipt), encoding="utf-8")
    _rebind_candidate_artifacts(candidate, f"receipts/{receipt_path.name}")

    verification = verify_refresh_candidate(
        candidate,
        now=FIXED_NOW,
        expected_seed_path=seed_path,
        expected_masked_path=masked_path,
    )

    assert verification["structural_valid"] is False
    assert verification["publication_ready"] is False
    assert any(
        error.startswith("successful_scan_receipt_schema_invalid:")
        for error in verification["errors"]
    )


def test_successful_result_cannot_add_authority_fields(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    candidate, seed_path, masked_path = _complete_remote_candidate(tmp_path, monkeypatch)
    results_path = candidate / "scan_results.json"
    candidate.chmod(0o700)
    results_path.chmod(0o600)
    payload = json.loads(results_path.read_text(encoding="utf-8"))
    payload["results"][0]["publication_ready"] = True
    results_path.write_text(json.dumps(payload), encoding="utf-8")
    _rebind_candidate_artifacts(candidate, "scan_results.json")

    verification = verify_refresh_candidate(
        candidate,
        now=FIXED_NOW,
        expected_seed_path=seed_path,
        expected_masked_path=masked_path,
    )

    assert verification["structural_valid"] is False
    assert verification["publication_ready"] is False
    assert "successful_scan_schema_invalid:alpha" in verification["errors"]


def test_fresh_result_cannot_relabel_evidence_visibility(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    candidate, seed_path, masked_path = _complete_remote_candidate(tmp_path, monkeypatch)
    results_path = candidate / "scan_results.json"
    candidate.chmod(0o700)
    results_path.chmod(0o600)
    payload = json.loads(results_path.read_text(encoding="utf-8"))
    payload["results"][0]["receipt_visibility"] = "approved"
    results_path.write_text(json.dumps(payload), encoding="utf-8")
    _rebind_candidate_artifacts(candidate, "scan_results.json")

    verification = verify_refresh_candidate(
        candidate,
        now=FIXED_NOW,
        expected_seed_path=seed_path,
        expected_masked_path=masked_path,
    )

    assert verification["structural_valid"] is False
    assert verification["publication_ready"] is False
    assert "fresh_scan_semantics_invalid:alpha" in verification["errors"]


def test_receipt_caveats_cannot_claim_publication_authority(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    candidate, seed_path, masked_path = _complete_remote_candidate(tmp_path, monkeypatch)
    result = _results(candidate)[0]
    receipt_path = candidate / "receipts" / str(result["receipt"])
    candidate.chmod(0o700)
    receipt_path.chmod(0o600)
    receipt = json.loads(receipt_path.read_text(encoding="utf-8"))
    receipt["caveats"].append("Publication approved.")
    receipt_path.write_text(json.dumps(receipt), encoding="utf-8")
    _rebind_candidate_artifacts(candidate, f"receipts/{receipt_path.name}")

    verification = verify_refresh_candidate(
        candidate,
        now=FIXED_NOW,
        expected_seed_path=seed_path,
        expected_masked_path=masked_path,
    )

    assert verification["structural_valid"] is False
    assert verification["publication_ready"] is False
    assert any(error.startswith("fresh_scan_binding_mismatch:") for error in verification["errors"])


def test_missing_receipt_is_explicit_and_not_fresh(tmp_path: Path) -> None:
    candidate = _candidate(
        tmp_path,
        receipt_writer=lambda _server, _scan, _directory: None,
    )

    result = _results(candidate)[0]
    assert result["state"] == "missing-receipt"
    assert result["fresh_grade"] is None


def test_unknown_evidence_is_explicit_and_not_fresh(tmp_path: Path) -> None:
    def scanner(_server: Server) -> EngineResult:
        return EngineResult(
            engine_name="stub",
            engine_version="fixture",
            risk=RiskSummary(composite=1.0),
            evidence=None,
        )

    candidate = _candidate(tmp_path, scanner=scanner)

    result = _results(candidate)[0]
    assert result["state"] == "unknown-evidence"
    assert result["fresh_grade"] is None


def test_masked_grade_is_withheld_from_results_and_snapshot(tmp_path: Path) -> None:
    db_path, seed_path, masked_path = _inputs(tmp_path, masked=("alpha",))
    masked_sentinel = "masked-secret-sentinel-8fd3c764"
    conn = connect(db_path)
    ScanRepository(conn).record(
        ScanRecord(
            id="old-alpha",
            server_slug="alpha",
            engine_name="mcpaudit",
            engine_version="2.3.0",
            grade=TrustGrade.D,
            risk=RiskSummary(composite=6.0),
            evidence=ScanEvidence(tools=[ToolEvidence(name=masked_sentinel)]),
            scanned_at=FIXED_NOW - timedelta(days=30),
        )
    )
    conn.close()
    candidate = create_refresh_candidate(
        source_db=db_path,
        seed_path=seed_path,
        masked_path=masked_path,
        output_parent=tmp_path / "candidates",
        default_image="fixture:image",
        scanner=_stub_scanner,
        now=FIXED_NOW,
        candidate_name="candidate",
    )

    result = _results(candidate)[0]
    snapshot = json.loads((candidate / "static_snapshot.json").read_text())
    candidate_conn = connect(candidate / "registry.db")
    masked_scan_count = candidate_conn.execute(
        "SELECT COUNT(*) FROM scans WHERE server_slug = 'alpha'"
    ).fetchone()[0]
    freelist_count = candidate_conn.execute("PRAGMA freelist_count").fetchone()[0]
    candidate_conn.close()
    assert result["state"] == "masked"
    assert result["fresh_grade"] is None
    assert result["grade_visibility"] == "withheld"
    assert result["receipt_visibility"] == "withheld"
    assert result["receipt"] is None
    assert result["scan_id"] is None
    assert result["drift"] is None
    assert list((candidate / "receipts").iterdir()) == []
    proof_ref = result["scan_proof"]
    assert isinstance(proof_ref, str)
    proof = json.loads((candidate / "masked-proofs" / proof_ref).read_text())
    assert proof["outcome"] == "scan_succeeded"
    assert proof["evidence_present"] is True
    assert proof["format_version"] == 2
    assert proof["execution_binding"]["schema"] == "McpTrustScanExecutionBindingV2"
    assert proof["execution_binding"]["sandbox"]["runtime_readback"]["state"] == ("NOT_APPLICABLE")
    assert refresh_module._masked_proof_digest_valid(proof) is True
    assert "scan" not in proof
    assert "evidence" not in proof
    assert "danger_score" not in proof
    assert masked_sentinel not in json.dumps(proof)
    assert masked_scan_count == 0
    assert freelist_count == 0
    assert masked_sentinel.encode() not in (candidate / "registry.db").read_bytes()
    assert snapshot["servers"] == []


def test_rebound_masked_proof_cannot_forge_runtime_binding(tmp_path: Path) -> None:
    candidate = _candidate(tmp_path, masked=("alpha",))
    result = _results(candidate)[0]
    proof_ref = str(result["scan_proof"])
    proof_path = candidate / "masked-proofs" / proof_ref
    candidate.chmod(0o700)
    proof_path.chmod(0o600)
    proof = json.loads(proof_path.read_text(encoding="utf-8"))
    proof["execution_binding"]["sandbox"]["runtime_readback"] = {"state": "VERIFIED"}
    proof.pop("proof_digest")
    proof["proof_digest"] = (
        "sha256:" + hashlib.sha256(refresh_module._json_bytes(proof)).hexdigest()
    )
    proof_path.write_bytes(refresh_module._json_bytes(proof))
    _rebind_candidate_artifacts(candidate, f"masked-proofs/{proof_ref}")

    verification = verify_refresh_candidate(candidate, now=FIXED_NOW)

    assert verification["structural_valid"] is False
    assert verification["publication_ready"] is False
    assert any(
        error.startswith("masked_scan_execution_binding_invalid:")
        for error in verification["errors"]
    )


def test_rebound_masked_result_without_scan_proof_is_rejected(tmp_path: Path) -> None:
    candidate = _candidate(tmp_path, masked=("alpha",))
    results_path = candidate / "scan_results.json"
    manifest_path = candidate / "MANIFEST.json"
    digest_path = candidate / "MANIFEST.sha256"
    candidate.chmod(0o700)
    results_path.chmod(0o600)
    manifest_path.chmod(0o600)
    digest_path.chmod(0o600)
    results_payload = json.loads(results_path.read_text())
    results_payload["results"][0]["scan_proof"] = None
    results_path.write_text(json.dumps(results_payload), encoding="utf-8")
    manifest = json.loads(manifest_path.read_text())
    for artifact in manifest["artifacts"]:
        if artifact["path"] == "scan_results.json":
            artifact["bytes"] = results_path.stat().st_size
            artifact["sha256"] = hashlib.sha256(results_path.read_bytes()).hexdigest()
    manifest_path.write_text(json.dumps(manifest), encoding="utf-8")
    digest_path.write_text(
        hashlib.sha256(manifest_path.read_bytes()).hexdigest() + "\n",
        encoding="utf-8",
    )
    for path in (results_path, manifest_path, digest_path):
        path.chmod(0o400)
    candidate.chmod(0o500)

    verification = verify_refresh_candidate(candidate, now=FIXED_NOW)

    assert verification["structural_valid"] is False
    assert verification["publication_ready"] is False
    assert "masked_scan_proof_ref_invalid" in verification["errors"]


def test_rebound_manifest_cannot_omit_catalog_result(tmp_path: Path) -> None:
    candidate = _candidate(tmp_path, slugs=("alpha", "beta"))
    results_path = candidate / "scan_results.json"
    manifest_path = candidate / "MANIFEST.json"
    digest_path = candidate / "MANIFEST.sha256"
    os.chmod(candidate, 0o700)
    os.chmod(results_path, 0o600)
    os.chmod(manifest_path, 0o600)
    os.chmod(digest_path, 0o600)
    results_payload = json.loads(results_path.read_text())
    results_payload["results"] = results_payload["results"][:1]
    results_path.write_text(json.dumps(results_payload), encoding="utf-8")
    manifest = json.loads(manifest_path.read_text())
    for artifact in manifest["artifacts"]:
        if artifact["path"] == "scan_results.json":
            artifact["bytes"] = results_path.stat().st_size
            artifact["sha256"] = hashlib.sha256(results_path.read_bytes()).hexdigest()
    manifest["scan_counts"] = {
        "total": 1,
        "fresh": 1,
        "masked": 0,
        "blocked": 0,
        "failed": 0,
    }
    manifest_path.write_text(json.dumps(manifest), encoding="utf-8")
    digest_path.write_text(
        hashlib.sha256(manifest_path.read_bytes()).hexdigest() + "\n",
        encoding="utf-8",
    )
    for path in (results_path, manifest_path, digest_path):
        os.chmod(path, 0o400)
    os.chmod(candidate, 0o500)

    verification = verify_refresh_candidate(candidate, now=FIXED_NOW)

    assert verification["structural_valid"] is False
    assert verification["publication_ready"] is False
    assert "catalog_scan_coverage_mismatch" in verification["errors"]


def test_rebound_manifest_cannot_change_snapshot_grade(tmp_path: Path) -> None:
    candidate = _candidate(tmp_path)
    snapshot_path = candidate / "static_snapshot.json"
    manifest_path = candidate / "MANIFEST.json"
    digest_path = candidate / "MANIFEST.sha256"
    os.chmod(candidate, 0o700)
    os.chmod(snapshot_path, 0o600)
    os.chmod(manifest_path, 0o600)
    os.chmod(digest_path, 0o600)
    snapshot = json.loads(snapshot_path.read_text())
    snapshot["servers"] = [
        {
            "slug": "alpha",
            "grade": "A",
            "scan_age_days": 0.0,
        }
    ]
    snapshot["server_count"] = 1
    snapshot_path.write_text(json.dumps(snapshot), encoding="utf-8")
    manifest = json.loads(manifest_path.read_text())
    for artifact in manifest["artifacts"]:
        if artifact["path"] == "static_snapshot.json":
            artifact["bytes"] = snapshot_path.stat().st_size
            artifact["sha256"] = hashlib.sha256(snapshot_path.read_bytes()).hexdigest()
    manifest_path.write_text(json.dumps(manifest), encoding="utf-8")
    digest_path.write_text(
        hashlib.sha256(manifest_path.read_bytes()).hexdigest() + "\n",
        encoding="utf-8",
    )
    for path in (snapshot_path, manifest_path, digest_path):
        os.chmod(path, 0o400)
    os.chmod(candidate, 0o500)

    verification = verify_refresh_candidate(candidate, now=FIXED_NOW)

    assert verification["structural_valid"] is False
    assert verification["publication_ready"] is False
    assert "static_snapshot_scan_binding_mismatch" in verification["errors"]


def test_rebound_manifest_cannot_change_fresh_result_grade(tmp_path: Path) -> None:
    candidate = _candidate(tmp_path)
    results_path = candidate / "scan_results.json"
    manifest_path = candidate / "MANIFEST.json"
    digest_path = candidate / "MANIFEST.sha256"
    os.chmod(candidate, 0o700)
    os.chmod(results_path, 0o600)
    os.chmod(manifest_path, 0o600)
    os.chmod(digest_path, 0o600)
    results_payload = json.loads(results_path.read_text())
    results_payload["results"][0]["fresh_grade"] = "A"
    results_path.write_text(json.dumps(results_payload), encoding="utf-8")
    manifest = json.loads(manifest_path.read_text())
    for artifact in manifest["artifacts"]:
        if artifact["path"] == "scan_results.json":
            artifact["bytes"] = results_path.stat().st_size
            artifact["sha256"] = hashlib.sha256(results_path.read_bytes()).hexdigest()
    manifest_path.write_text(json.dumps(manifest), encoding="utf-8")
    digest_path.write_text(
        hashlib.sha256(manifest_path.read_bytes()).hexdigest() + "\n",
        encoding="utf-8",
    )
    for path in (results_path, manifest_path, digest_path):
        os.chmod(path, 0o400)
    os.chmod(candidate, 0o500)

    verification = verify_refresh_candidate(candidate, now=FIXED_NOW)

    assert verification["structural_valid"] is False
    assert any(error.startswith("fresh_scan_binding_mismatch:") for error in verification["errors"])


def test_rebound_manifest_rejects_unreferenced_artifact(tmp_path: Path) -> None:
    candidate = _candidate(tmp_path)
    extra = candidate / "receipts" / "masked-leak.json"
    manifest_path = candidate / "MANIFEST.json"
    digest_path = candidate / "MANIFEST.sha256"
    os.chmod(candidate, 0o700)
    os.chmod(extra.parent, 0o700)
    os.chmod(manifest_path, 0o600)
    os.chmod(digest_path, 0o600)
    extra.write_text('{"grade":"A"}\n', encoding="utf-8")
    manifest = json.loads(manifest_path.read_text())
    manifest["artifacts"].append(
        {
            "path": "receipts/masked-leak.json",
            "bytes": extra.stat().st_size,
            "sha256": hashlib.sha256(extra.read_bytes()).hexdigest(),
        }
    )
    manifest_path.write_text(json.dumps(manifest), encoding="utf-8")
    digest_path.write_text(
        hashlib.sha256(manifest_path.read_bytes()).hexdigest() + "\n",
        encoding="utf-8",
    )
    for path in (extra, manifest_path, digest_path):
        os.chmod(path, 0o400)
    os.chmod(extra.parent, 0o500)
    os.chmod(candidate, 0o500)

    verification = verify_refresh_candidate(candidate, now=FIXED_NOW)

    assert verification["structural_valid"] is False
    assert "unreferenced_candidate_artifact" in verification["errors"]


def test_nested_manifest_named_file_is_not_excluded_from_artifact_set(
    tmp_path: Path,
) -> None:
    candidate = _candidate(tmp_path)
    nested = candidate / "receipts" / "MANIFEST.json"
    os.chmod(candidate, 0o700)
    os.chmod(nested.parent, 0o700)
    nested.write_text('{"masked":"receipt"}\n', encoding="utf-8")
    nested.chmod(0o400)
    nested.parent.chmod(0o500)
    candidate.chmod(0o500)

    verification = verify_refresh_candidate(candidate, now=FIXED_NOW)

    assert verification["structural_valid"] is False
    assert "artifact_set_mismatch" in verification["errors"]
    assert "unreferenced_candidate_artifact" in verification["errors"]


def test_duplicate_artifact_manifest_entry_is_rejected(tmp_path: Path) -> None:
    candidate = _candidate(tmp_path)
    manifest = json.loads((candidate / "MANIFEST.json").read_text(encoding="utf-8"))
    manifest["artifacts"].append(dict(manifest["artifacts"][0]))
    _rebind_manifest(candidate, artifacts=manifest["artifacts"])

    verification = verify_refresh_candidate(candidate, now=FIXED_NOW)

    assert verification["structural_valid"] is False
    assert "artifact_manifest_invalid" in verification["errors"]


def test_boolean_scan_count_cannot_alias_integer_count(tmp_path: Path) -> None:
    candidate = _candidate(tmp_path)
    _rebind_manifest(
        candidate,
        scan_counts={
            "total": True,
            "fresh": True,
            "masked": False,
            "blocked": False,
            "failed": False,
        },
    )

    verification = verify_refresh_candidate(candidate, now=FIXED_NOW)

    assert verification["structural_valid"] is False
    assert verification["scan_counts"] is None
    assert "scan_counts_invalid" in verification["errors"]


def test_hardlinked_candidate_artifact_is_rejected(tmp_path: Path) -> None:
    candidate = _candidate(tmp_path)
    results_path = candidate / "scan_results.json"
    external = tmp_path / "external-results.json"
    external.write_bytes(results_path.read_bytes())
    external.chmod(0o400)
    candidate.chmod(0o700)
    results_path.unlink()
    os.link(external, results_path)
    candidate.chmod(0o500)

    verification = verify_refresh_candidate(candidate, now=FIXED_NOW)

    assert verification["structural_valid"] is False
    assert verification["publication_ready"] is False
    assert "hardlinked_artifact:scan_results.json" in verification["errors"]


def test_oversized_candidate_json_returns_bounded_invalid_result(
    tmp_path: Path,
) -> None:
    candidate = _candidate(tmp_path)
    results_path = candidate / "scan_results.json"
    candidate.chmod(0o700)
    results_path.chmod(0o600)
    payload = json.loads(results_path.read_text(encoding="utf-8"))
    payload["padding"] = "x" * (17 * 1024 * 1024)
    results_path.write_text(json.dumps(payload), encoding="utf-8")
    _rebind_candidate_artifacts(candidate, "scan_results.json")

    verification = verify_refresh_candidate(candidate, now=FIXED_NOW)

    assert verification["structural_valid"] is False
    assert verification["publication_ready"] is False
    assert "artifact_too_large:scan_results.json" in verification["errors"]


def test_deeply_nested_json_returns_structured_invalid_result(tmp_path: Path) -> None:
    candidate = _candidate(tmp_path)
    results_path = candidate / "scan_results.json"
    candidate.chmod(0o700)
    results_path.chmod(0o600)
    results_path.write_text("[" * 10000 + "0" + "]" * 10000, encoding="utf-8")
    _rebind_candidate_artifacts(candidate, "scan_results.json")

    verification = verify_refresh_candidate(candidate, now=FIXED_NOW)

    assert verification["structural_valid"] is False
    assert verification["publication_ready"] is False
    assert "candidate_projection_unreadable" in verification["errors"]


def test_extreme_json_integer_returns_structured_invalid_result(tmp_path: Path) -> None:
    candidate = _candidate(tmp_path)
    results_path = candidate / "scan_results.json"
    candidate.chmod(0o700)
    results_path.chmod(0o600)
    results_path.write_text(
        '{"schema":"RefreshScanResultsV1","generated_at":"'
        + FIXED_NOW.isoformat()
        + '","results":[],"extreme":'
        + "9" * 5000
        + "}",
        encoding="utf-8",
    )
    _rebind_candidate_artifacts(candidate, "scan_results.json")

    previous_limit = sys.get_int_max_str_digits()
    sys.set_int_max_str_digits(0)
    try:
        verification = verify_refresh_candidate(candidate, now=FIXED_NOW)
    finally:
        sys.set_int_max_str_digits(previous_limit)

    assert verification["structural_valid"] is False
    assert verification["publication_ready"] is False
    assert "candidate_projection_unreadable" in verification["errors"]


def test_deeply_nested_database_json_returns_structured_invalid_result(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    candidate, seed_path, masked_path = _complete_remote_candidate(tmp_path, monkeypatch)
    database_path = candidate / "registry.db"
    candidate.chmod(0o700)
    database_path.chmod(0o600)
    conn = sqlite3.connect(database_path)
    conn.execute(
        "UPDATE scans SET risk_json = ?",
        ("[" * 10000 + "0" + "]" * 10000,),
    )
    conn.commit()
    conn.close()
    _rebind_candidate_artifacts(candidate, "registry.db")

    verification = verify_refresh_candidate(
        candidate,
        now=FIXED_NOW,
        expected_seed_path=seed_path,
        expected_masked_path=masked_path,
    )

    assert verification["structural_valid"] is False
    assert verification["publication_ready"] is False
    assert any(
        error.startswith("fresh_scan_") or error == "static_snapshot_scan_binding_unavailable"
        for error in verification["errors"]
    )


def test_unsafe_artifact_name_cannot_create_deceptive_output(tmp_path: Path) -> None:
    candidate = _candidate(tmp_path)
    unsafe_name = "evidence-\u202ejson"
    candidate.chmod(0o700)
    unsafe_path = candidate / unsafe_name
    unsafe_path.write_text("attacker-authored", encoding="utf-8")
    unsafe_path.chmod(0o400)
    candidate.chmod(0o500)

    verification = verify_refresh_candidate(candidate, now=FIXED_NOW)
    rendered = json.dumps(verification, ensure_ascii=False)

    assert verification["structural_valid"] is False
    assert verification["publication_ready"] is False
    assert "unsafe_artifact_name" in verification["errors"]
    assert "\u202e" not in rendered
    assert unsafe_name not in rendered


def test_real_preflight_refuses_when_required_sandbox_is_unavailable(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr("mcp_trust.refresh.shutil.which", lambda _name: None)

    with pytest.raises(RefreshCandidateError, match="Docker executable"):
        preflight_real_refresh([_server("alpha")], default_image="required:image")


def test_real_preflight_refuses_missing_pinned_image(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    host = "unix:///Users/operator/.colima/default/docker.sock"
    monkeypatch.setenv("DOCKER_HOST", host)
    monkeypatch.setattr("mcp_trust.refresh.shutil.which", lambda _name: "/usr/bin/docker")

    def runner(command: list[str], **_kwargs) -> subprocess.CompletedProcess[str]:
        return subprocess.CompletedProcess(
            command,
            0 if command == ["docker", "--host", host, "info"] else 1,
            "",
            "",
        )

    with pytest.raises(RefreshCandidateError, match="required local sandbox image"):
        preflight_real_refresh(
            [_server("alpha")],
            default_image="required:image",
            runner=runner,
        )


def test_real_preflight_refuses_missing_mcpaudit_engine(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv(
        "DOCKER_HOST",
        "unix:///Users/operator/.colima/default/docker.sock",
    )
    monkeypatch.setattr("mcp_trust.refresh.shutil.which", lambda _name: "/usr/bin/docker")
    monkeypatch.setattr("mcp_trust.refresh.modules_belong_to_distribution", lambda *_args: False)

    def runner(command: list[str], **_kwargs) -> subprocess.CompletedProcess[str]:
        stdout = (
            json.dumps([{"Id": IMAGE_DIGEST}]) if command[-3:-1] == ["image", "inspect"] else ""
        )
        return subprocess.CompletedProcess(command, 0, stdout, "")

    with pytest.raises(RefreshCandidateError, match="MCPAudit engine"):
        preflight_real_refresh(
            [_server("alpha")],
            default_image="required:image",
            runner=runner,
        )


def test_real_preflight_binds_one_explicit_local_docker_endpoint(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    host = "unix:///Users/operator/.colima/default/docker.sock"
    commands: list[list[str]] = []
    monkeypatch.setenv("DOCKER_HOST", host)
    monkeypatch.setattr("mcp_trust.refresh.shutil.which", lambda _name: "/usr/bin/docker")
    monkeypatch.setattr(
        "mcp_trust.refresh.modules_belong_to_distribution",
        lambda *_args: True,
    )

    def runner(command: list[str], **_kwargs) -> subprocess.CompletedProcess[str]:
        commands.append(command)
        stdout = (
            json.dumps([{"Id": IMAGE_DIGEST}]) if command[-3:-1] == ["image", "inspect"] else ""
        )
        return subprocess.CompletedProcess(command, 0, stdout, "")

    evidence = preflight_real_refresh(
        [_server("alpha")],
        default_image="required:image",
        runner=runner,
    )

    assert commands == [
        ["docker", "--host", host, "info"],
        ["docker", "--host", host, "image", "inspect", "required:image"],
    ]
    assert evidence["_execution_docker_host"] == host
    assert evidence["_execution_image_bindings"] == {
        "required:image": IMAGE_DIGEST,
    }


def test_real_preflight_resolves_and_binds_the_current_local_docker_context(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    host = "unix:///Users/operator/.colima/default/docker.sock"
    commands: list[list[str]] = []
    monkeypatch.delenv("DOCKER_HOST", raising=False)
    monkeypatch.setattr("mcp_trust.refresh.shutil.which", lambda _name: "/usr/bin/docker")
    monkeypatch.setattr(
        "mcp_trust.refresh.modules_belong_to_distribution",
        lambda *_args: True,
    )

    def runner(command: list[str], **_kwargs) -> subprocess.CompletedProcess[str]:
        commands.append(command)
        if command[1:3] == ["context", "inspect"]:
            stdout = json.dumps(host)
        elif command[-3:-1] == ["image", "inspect"]:
            stdout = json.dumps([{"Id": IMAGE_DIGEST}])
        else:
            stdout = ""
        return subprocess.CompletedProcess(command, 0, stdout, "")

    evidence = preflight_real_refresh(
        [_server("alpha")],
        default_image="required:image",
        runner=runner,
    )

    assert commands == [
        [
            "docker",
            "context",
            "inspect",
            "--format",
            "{{json .Endpoints.docker.Host}}",
        ],
        ["docker", "--host", host, "info"],
        ["docker", "--host", host, "image", "inspect", "required:image"],
    ]
    assert evidence["_execution_docker_host"] == host
    assert evidence["_execution_image_bindings"] == {
        "required:image": IMAGE_DIGEST,
    }


def test_real_preflight_rejects_remote_docker_daemon_authority(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("DOCKER_HOST", "tcp://example.test:2375")
    monkeypatch.setattr("mcp_trust.refresh.shutil.which", lambda _name: "/usr/bin/docker")
    monkeypatch.setattr(
        "mcp_trust.refresh.modules_belong_to_distribution",
        lambda *_args: True,
    )

    with pytest.raises(RefreshCandidateError, match="local Unix socket"):
        preflight_real_refresh(
            [_server("alpha")],
            default_image="required:image",
        )


def test_remote_only_preflight_does_not_require_docker(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    remote = _server("alpha").model_copy(
        update={
            "source": ServerSource(
                kind=SourceKind.REMOTE,
                reference="https://example.test/mcp",
            )
        }
    )
    monkeypatch.setattr("mcp_trust.refresh.shutil.which", lambda _name: None)
    monkeypatch.setattr(
        "mcp_trust.refresh.modules_belong_to_distribution",
        lambda *_args: True,
    )

    evidence = preflight_real_refresh(
        [remote],
        default_image="not-needed:image",
    )

    assert evidence == {
        "docker_daemon": "not_required",
        "default_image": "not-needed:image",
        "profiles": [],
        "remote_transport_count": 1,
    }


def test_remote_only_real_candidate_records_sandbox_not_applicable(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    db_path = tmp_path / "registry.db"
    remote = _server("alpha").model_copy(
        update={
            "source": ServerSource(
                kind=SourceKind.REMOTE,
                reference="https://example.test/mcp",
            )
        }
    )
    conn = connect(db_path)
    init_schema(conn)
    ServerRepository(conn).upsert(remote)
    conn.close()
    seed_path = tmp_path / "seed.json"
    seed_path.write_text(
        json.dumps([remote.model_dump(mode="json", exclude={"added_at"})]),
        encoding="utf-8",
    )
    masked_path = tmp_path / "masked.json"
    masked_path.write_text("[]", encoding="utf-8")

    class RemoteMCPAuditEngine:
        def __init__(self, timeout: float) -> None:
            assert timeout == 90.0

        def scan(self, source: ServerSource) -> EngineResult:
            assert source == remote.source
            assert "MCP_TRUST_SANDBOX" not in os.environ
            assert "MCP_TRUST_SANDBOX_NETWORK" not in os.environ
            assert "MCP_TRUST_SANDBOX_IMAGE" not in os.environ
            assert "MCP_TRUST_SCAN_CREDENTIALS" not in os.environ
            return _stub_scanner(remote).model_copy(
                update={
                    "engine_name": "mcpaudit",
                    "engine_version": "2.4.0",
                    "sandbox_image": None,
                }
            )

    monkeypatch.setattr(
        "mcp_trust.refresh.preflight_real_refresh",
        lambda servers, *, default_image: {
            "docker_daemon": "not_required",
            "default_image": default_image,
            "profiles": [],
            "remote_transport_count": len(servers),
        },
    )
    monkeypatch.setattr("mcp_trust.refresh.MCPAuditEngine", RemoteMCPAuditEngine)

    qualification = _qualification_receipt(
        seed_path,
        masked_path,
        profiles=[],
    )
    candidate = create_refresh_candidate(
        source_db=db_path,
        seed_path=seed_path,
        masked_path=masked_path,
        output_parent=tmp_path / "candidates",
        default_image="not-needed:image",
        qualification_receipt=qualification,
        repo_root=ROOT,
        _source_binding_provider=_qualification_source_provider(qualification),
        _qualification_revalidator=lambda *_args, **_kwargs: None,
        now=FIXED_NOW,
        candidate_name="candidate",
    )
    result = _results(candidate)[0]
    receipt = json.loads(
        (candidate / "receipts" / str(result["receipt"])).read_text(encoding="utf-8")
    )
    manifest = json.loads((candidate / "MANIFEST.json").read_text(encoding="utf-8"))
    snapshot = json.loads((candidate / "static_snapshot.json").read_text(encoding="utf-8"))
    verification = verify_refresh_candidate(
        candidate,
        now=FIXED_NOW,
        expected_seed_path=seed_path,
        expected_masked_path=masked_path,
    )

    assert manifest["scan_mode"] == "mcpaudit-remote-live-network"
    assert snapshot["servers"][0]["scan_mode"] == "mcpaudit-remote-live-network"
    assert snapshot["servers"][0]["sandbox"] == {
        "mode": "not_applicable",
        "reason": "remote_endpoint_no_local_process",
    }
    assert receipt["sandbox"] == {
        "mode": "not_applicable",
        "reason": "remote_endpoint_no_local_process",
    }
    assert not any(
        caveat.startswith("Network-off sandboxing") or "dummy credentials" in caveat
        for caveat in receipt["caveats"]
    )
    assert any("live network" in caveat for caveat in receipt["caveats"])
    assert verification["structural_valid"] is True
    assert verification["publication_ready"] is True


def test_complete_candidate_requires_reviewed_inputs_for_publication(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    candidate, seed_path, masked_path = _complete_remote_candidate(
        tmp_path,
        monkeypatch,
    )

    unbound = verify_refresh_candidate(candidate, now=FIXED_NOW)
    bound = verify_refresh_candidate(
        candidate,
        now=FIXED_NOW,
        expected_seed_path=seed_path,
        expected_masked_path=masked_path,
    )

    assert unbound["structural_valid"] is False
    assert unbound["reviewed_inputs_bound"] is False
    assert unbound["publication_ready"] is False
    assert "qualification_receipt_invalid" in unbound["errors"]
    assert bound["structural_valid"] is True
    assert bound["reviewed_inputs_bound"] is True
    assert bound["publication_ready"] is True


def test_reviewed_input_symlinks_are_not_source_binding(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    candidate, seed_path, masked_path = _complete_remote_candidate(tmp_path, monkeypatch)
    reviewed_seed = tmp_path / "reviewed-seed-link.json"
    reviewed_masked = tmp_path / "reviewed-masked-link.json"
    reviewed_seed.symlink_to(seed_path)
    reviewed_masked.symlink_to(masked_path)

    verification = verify_refresh_candidate(
        candidate,
        now=FIXED_NOW,
        expected_seed_path=reviewed_seed,
        expected_masked_path=reviewed_masked,
    )

    assert verification["structural_valid"] is False
    assert verification["reviewed_inputs_bound"] is False
    assert verification["publication_ready"] is False
    assert "reviewed_inputs_unavailable" in verification["errors"]


def test_reviewed_input_replacement_during_read_is_not_source_binding(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    candidate, seed_path, masked_path = _complete_remote_candidate(tmp_path, monkeypatch)
    replacement_seed = tmp_path / "replacement-seed.json"
    replacement_seed.write_bytes(seed_path.read_bytes())
    real_open = os.open
    replaced = False

    def replace_then_open(path, flags, mode=0o777, *, dir_fd=None):
        nonlocal replaced
        if not replaced and isinstance(path, (str, os.PathLike)) and Path(path) == seed_path:
            replaced = True
            os.replace(replacement_seed, seed_path)
        if dir_fd is None:
            return real_open(path, flags, mode)
        return real_open(path, flags, mode, dir_fd=dir_fd)

    monkeypatch.setattr(os, "open", replace_then_open)

    verification = verify_refresh_candidate(
        candidate,
        now=FIXED_NOW,
        expected_seed_path=seed_path,
        expected_masked_path=masked_path,
    )

    assert verification["structural_valid"] is False
    assert verification["reviewed_inputs_bound"] is False
    assert verification["publication_ready"] is False
    assert "reviewed_inputs_unavailable" in verification["errors"]


def test_extreme_reviewed_input_integer_returns_structured_unavailable(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    candidate, seed_path, masked_path = _complete_remote_candidate(tmp_path, monkeypatch)
    seed_path.write_text("[" + "9" * 5000 + "]", encoding="utf-8")

    verification = verify_refresh_candidate(
        candidate,
        now=FIXED_NOW,
        expected_seed_path=seed_path,
        expected_masked_path=masked_path,
    )

    assert verification["structural_valid"] is False
    assert verification["reviewed_inputs_bound"] is False
    assert verification["publication_ready"] is False
    assert "reviewed_inputs_unavailable" in verification["errors"]


def test_repeated_verification_output_is_deterministic(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    candidate, seed_path, masked_path = _complete_remote_candidate(tmp_path, monkeypatch)

    first = verify_refresh_candidate(
        candidate,
        now=FIXED_NOW,
        expected_seed_path=seed_path,
        expected_masked_path=masked_path,
    )
    second = verify_refresh_candidate(
        candidate,
        now=FIXED_NOW,
        expected_seed_path=seed_path,
        expected_masked_path=masked_path,
    )

    assert first == second
    assert json.dumps(first, sort_keys=True) == json.dumps(second, sort_keys=True)


def test_complete_candidate_rejects_external_seed_catalog_mismatch(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    candidate, seed_path, masked_path = _complete_remote_candidate(
        tmp_path,
        monkeypatch,
    )
    reviewed_seed = tmp_path / "reviewed-seed.json"
    reviewed_rows = json.loads(seed_path.read_text(encoding="utf-8"))
    reviewed_rows.append(
        {
            "slug": "beta",
            "name": "beta",
            "source": {
                "kind": "npm",
                "reference": "@example/beta",
                "command": "/opt/beta",
            },
        }
    )
    reviewed_seed.write_text(json.dumps(reviewed_rows), encoding="utf-8")

    verification = verify_refresh_candidate(
        candidate,
        now=FIXED_NOW,
        expected_seed_path=reviewed_seed,
        expected_masked_path=masked_path,
    )

    assert verification["structural_valid"] is False
    assert verification["reviewed_inputs_bound"] is False
    assert "reviewed_inputs_mismatch" in verification["errors"]


def test_complete_candidate_rejects_external_mask_authorization_mismatch(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    candidate, seed_path, _masked_path = _complete_remote_candidate(
        tmp_path,
        monkeypatch,
        masked=("alpha",),
    )
    reviewed_mask = tmp_path / "reviewed-mask.json"
    reviewed_mask.write_text("[]", encoding="utf-8")

    verification = verify_refresh_candidate(
        candidate,
        now=FIXED_NOW,
        expected_seed_path=seed_path,
        expected_masked_path=reviewed_mask,
    )

    assert verification["structural_valid"] is False
    assert verification["reviewed_inputs_bound"] is False
    assert "reviewed_inputs_mismatch" in verification["errors"]


def test_complete_candidate_rejects_rebound_transport_count(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    candidate, seed_path, masked_path = _complete_remote_candidate(tmp_path, monkeypatch)
    manifest = json.loads((candidate / "MANIFEST.json").read_text(encoding="utf-8"))
    sandbox = dict(manifest["sandbox"])
    sandbox["remote_transport_count"] = 0
    _rebind_manifest(candidate, sandbox=sandbox)

    verification = verify_refresh_candidate(
        candidate,
        now=FIXED_NOW,
        expected_seed_path=seed_path,
        expected_masked_path=masked_path,
    )

    assert verification["structural_valid"] is False
    assert verification["publication_ready"] is False
    assert "sandbox_manifest_invalid" in verification["errors"]


def test_complete_candidate_rejects_rebound_unreviewed_sandbox_image(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    db_path, seed_path, masked_path = _inputs(tmp_path)

    class LocalMCPAuditEngine:
        def __init__(self, timeout: float) -> None:
            assert timeout == 90.0

        def scan(self, source: ServerSource) -> EngineResult:
            return (
                StubEngine()
                .scan(source)
                .model_copy(
                    update={
                        "engine_name": "mcpaudit",
                        "engine_version": "2.4.0",
                        "evidence": ScanEvidence(tools=[ToolEvidence(name="fixture-tool")]),
                        "sandbox_image": IMAGE_DIGEST,
                        "sandbox_cleanup_evidence": "CONTAINER_ABSENCE_VERIFIED",
                        "sandbox_runtime_readback": _runtime_readback(),
                    }
                )
            )

    monkeypatch.setattr(
        "mcp_trust.refresh.preflight_real_refresh",
        lambda servers, *, default_image: {
            "docker_daemon": "available",
            "default_image": default_image,
            "profiles": [
                refresh_module._sandbox_profile(
                    default_image,
                    image_digest=IMAGE_DIGEST,
                )
            ],
            "remote_transport_count": 0,
            "_execution_image_bindings": {default_image: IMAGE_DIGEST},
        },
    )
    monkeypatch.setattr("mcp_trust.refresh.MCPAuditEngine", LocalMCPAuditEngine)
    qualification = _qualification_receipt(
        seed_path,
        masked_path,
        profiles=[
            refresh_module._sandbox_profile(
                "required:image",
                image_digest=IMAGE_DIGEST,
            )
        ],
    )
    candidate = create_refresh_candidate(
        source_db=db_path,
        seed_path=seed_path,
        masked_path=masked_path,
        output_parent=tmp_path / "candidates",
        default_image="required:image",
        qualification_receipt=qualification,
        repo_root=ROOT,
        _source_binding_provider=_qualification_source_provider(qualification),
        _qualification_revalidator=lambda *_args, **_kwargs: None,
        now=FIXED_NOW,
        candidate_name="candidate",
    )
    manifest = json.loads((candidate / "MANIFEST.json").read_text(encoding="utf-8"))
    assert manifest["scan_mode"] == "mcpaudit-local-network-off"
    assert (
        verify_refresh_candidate(
            candidate,
            now=FIXED_NOW,
            expected_seed_path=seed_path,
            expected_masked_path=masked_path,
        )["publication_ready"]
        is True
    )

    result = _results(candidate)[0]
    receipt_path = candidate / "receipts" / str(result["receipt"])
    registry_path = candidate / "registry.db"
    manifest_path = candidate / "MANIFEST.json"
    digest_path = candidate / "MANIFEST.sha256"
    candidate.chmod(0o700)
    for path in (receipt_path, registry_path, manifest_path, digest_path):
        path.chmod(0o600)
    conn = connect(registry_path)
    conn.execute(
        "UPDATE scans SET sandbox_image = ? WHERE id = ?",
        ("unreviewed:image", result["scan_id"]),
    )
    conn.commit()
    conn.close()
    receipt = json.loads(receipt_path.read_text(encoding="utf-8"))
    receipt["scan"]["sandbox_image"] = "unreviewed:image"
    receipt["sandbox"]["MCP_TRUST_SANDBOX_IMAGE"] = "unreviewed:image"
    receipt_path.write_text(json.dumps(receipt), encoding="utf-8")
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    for artifact in manifest["artifacts"]:
        artifact_path = candidate / artifact["path"]
        artifact["bytes"] = artifact_path.stat().st_size
        artifact["sha256"] = hashlib.sha256(artifact_path.read_bytes()).hexdigest()
    manifest_path.write_text(json.dumps(manifest), encoding="utf-8")
    digest_path.write_text(
        hashlib.sha256(manifest_path.read_bytes()).hexdigest() + "\n",
        encoding="utf-8",
    )
    for path in (receipt_path, registry_path, manifest_path, digest_path):
        path.chmod(0o400)
    candidate.chmod(0o500)

    verification = verify_refresh_candidate(candidate, now=FIXED_NOW)

    assert verification["structural_valid"] is False
    assert verification["publication_ready"] is False
    assert any(
        error.startswith("publishable_scan_provenance_invalid:") for error in verification["errors"]
    )


def test_candidate_registry_and_snapshot_exclude_non_catalog_server(
    tmp_path: Path,
) -> None:
    db_path, seed_path, masked_path = _inputs(tmp_path)
    conn = connect(db_path)
    extra = _server("extra")
    ServerRepository(conn).upsert(extra)
    ScanRepository(conn).record(
        ScanRecord(
            id="extra-real-scan",
            server_slug=extra.slug,
            engine_name="mcpaudit",
            engine_version="2.4.0",
            grade=TrustGrade.A,
            risk=RiskSummary(composite=0.0),
            evidence=ScanEvidence(tools=[ToolEvidence(name="extra-tool")]),
            scanned_at=FIXED_NOW,
        )
    )
    conn.close()

    candidate = create_refresh_candidate(
        source_db=db_path,
        seed_path=seed_path,
        masked_path=masked_path,
        output_parent=tmp_path / "candidates",
        default_image="fixture:image",
        scanner=_stub_scanner,
        now=FIXED_NOW,
        candidate_name="candidate",
    )
    snapshot = json.loads((candidate / "static_snapshot.json").read_text(encoding="utf-8"))
    candidate_conn = connect(candidate / "registry.db")
    candidate_servers = ServerRepository(candidate_conn).list()
    candidate_conn.close()

    assert [server.slug for server in candidate_servers] == ["alpha"]
    assert "extra" not in {server["slug"] for server in snapshot["servers"]}
    assert verify_refresh_candidate(candidate, now=FIXED_NOW)["structural_valid"] is True


def test_candidate_name_cannot_escape_output_directory(tmp_path: Path) -> None:
    db_path, seed_path, masked_path = _inputs(tmp_path)

    with pytest.raises(RefreshCandidateError, match="safe single path component"):
        create_refresh_candidate(
            source_db=db_path,
            seed_path=seed_path,
            masked_path=masked_path,
            output_parent=tmp_path / "candidates",
            default_image="fixture:image",
            scanner=_stub_scanner,
            now=FIXED_NOW,
            candidate_name="../escaped",
        )

    assert not (tmp_path / "escaped").exists()


def test_publication_without_distinct_approval_is_refused(tmp_path: Path) -> None:
    candidate = _candidate(tmp_path)

    with pytest.raises(RefreshCandidateError, match="approval is required"):
        publish_refresh_candidate(
            candidate=candidate,
            approval_path=None,
            destination_parent=tmp_path / "published",
            seed_path=tmp_path / "seed.json",
            masked_path=tmp_path / "masked.json",
            now=FIXED_NOW,
        )


def test_local_publication_binds_the_reviewed_seed_and_mask_inputs(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    candidate, seed_path, masked_path = _complete_remote_candidate(
        tmp_path,
        monkeypatch,
    )
    verification = verify_refresh_candidate(
        candidate,
        now=FIXED_NOW,
        expected_seed_path=seed_path,
        expected_masked_path=masked_path,
    )
    approval_path = tmp_path / "approval.json"
    destination = tmp_path / "published"

    approve_refresh_candidate(
        candidate=candidate,
        approval_path=approval_path,
        actor="operator",
        reason="reviewed inputs match the candidate",
        publication_target=destination,
        confirmation_digest=str(verification["manifest_sha256"]),
        seed_path=seed_path,
        masked_path=masked_path,
        now=FIXED_NOW,
    )
    published = publish_refresh_candidate(
        candidate=candidate,
        approval_path=approval_path,
        destination_parent=destination,
        seed_path=seed_path,
        masked_path=masked_path,
        now=FIXED_NOW,
    )
    approval = json.loads(approval_path.read_text(encoding="utf-8"))
    publication = json.loads((published / "PUBLICATION.json").read_text(encoding="utf-8"))

    assert approval["reviewed_seed_sha256"] == hashlib.sha256(seed_path.read_bytes()).hexdigest()
    assert approval_path.stat().st_mode & 0o777 == 0o400
    assert (
        approval["reviewed_masked_sha256"] == hashlib.sha256(masked_path.read_bytes()).hexdigest()
    )
    assert publication["deployment_performed"] is False
    assert (
        verify_refresh_candidate(
            published / "candidate",
            now=FIXED_NOW,
            expected_seed_path=seed_path,
            expected_masked_path=masked_path,
        )["publication_ready"]
        is True
    )


def test_publication_rejects_writable_approval_receipt(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    candidate, seed_path, masked_path = _complete_remote_candidate(
        tmp_path,
        monkeypatch,
    )
    verification = verify_refresh_candidate(
        candidate,
        now=FIXED_NOW,
        expected_seed_path=seed_path,
        expected_masked_path=masked_path,
    )
    approval_path = tmp_path / "approval.json"
    approve_refresh_candidate(
        candidate=candidate,
        approval_path=approval_path,
        actor="operator",
        reason="reviewed candidate",
        publication_target=tmp_path / "published",
        confirmation_digest=str(verification["manifest_sha256"]),
        seed_path=seed_path,
        masked_path=masked_path,
        now=FIXED_NOW,
    )
    approval_path.chmod(0o600)

    with pytest.raises(RefreshCandidateError, match="unsafe ownership or permissions"):
        publish_refresh_candidate(
            candidate=candidate,
            approval_path=approval_path,
            destination_parent=tmp_path / "published",
            seed_path=seed_path,
            masked_path=masked_path,
            now=FIXED_NOW,
        )


def test_publication_uses_verified_snapshot_if_source_candidate_is_replaced(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    first_root = tmp_path / "first"
    second_root = tmp_path / "second"
    first_root.mkdir()
    second_root.mkdir()
    candidate, seed_path, masked_path = _complete_remote_candidate(
        first_root,
        monkeypatch,
        slug="alpha",
    )
    replacement, _replacement_seed, _replacement_mask = _complete_remote_candidate(
        second_root,
        monkeypatch,
        slug="beta",
    )
    verification = verify_refresh_candidate(
        candidate,
        now=FIXED_NOW,
        expected_seed_path=seed_path,
        expected_masked_path=masked_path,
    )
    expected_digest = str(verification["manifest_sha256"])
    approval_path = tmp_path / "approval.json"
    destination = tmp_path / "published"
    approve_refresh_candidate(
        candidate=candidate,
        approval_path=approval_path,
        actor="operator",
        reason="reviewed candidate",
        publication_target=destination,
        confirmation_digest=expected_digest,
        seed_path=seed_path,
        masked_path=masked_path,
        now=FIXED_NOW,
    )
    real_load_approval = refresh_module._load_read_only_json_with_digest
    swapped = False

    def load_then_swap(path):
        nonlocal swapped
        loaded = real_load_approval(path)
        if not swapped:
            swapped = True
            parked = tmp_path / "parked-candidate"
            candidate.parent.chmod(0o700)
            replacement.parent.chmod(0o700)
            candidate.chmod(0o700)
            replacement.chmod(0o700)
            candidate.rename(parked)
            replacement.rename(candidate)
            parked.rename(replacement)
        return loaded

    monkeypatch.setattr(
        refresh_module,
        "_load_read_only_json_with_digest",
        load_then_swap,
    )

    published = publish_refresh_candidate(
        candidate=candidate,
        approval_path=approval_path,
        destination_parent=destination,
        seed_path=seed_path,
        masked_path=masked_path,
        now=FIXED_NOW,
    )
    published_verification = verify_refresh_candidate(
        published / "candidate",
        now=FIXED_NOW,
        expected_seed_path=seed_path,
        expected_masked_path=masked_path,
    )

    assert published_verification["publication_ready"] is True
    assert published_verification["manifest_sha256"] == expected_digest


def test_publication_rejects_extra_approval_authority_fields(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    candidate, seed_path, masked_path = _complete_remote_candidate(tmp_path, monkeypatch)
    verification = verify_refresh_candidate(
        candidate,
        now=FIXED_NOW,
        expected_seed_path=seed_path,
        expected_masked_path=masked_path,
    )
    approval_path = tmp_path / "approval.json"
    destination = tmp_path / "published"
    approve_refresh_candidate(
        candidate=candidate,
        approval_path=approval_path,
        actor="operator",
        reason="reviewed candidate",
        publication_target=destination,
        confirmation_digest=str(verification["manifest_sha256"]),
        seed_path=seed_path,
        masked_path=masked_path,
        now=FIXED_NOW,
    )
    approval_path.chmod(0o600)
    approval = json.loads(approval_path.read_text(encoding="utf-8"))
    approval["publication_ready"] = True
    approval_path.write_text(json.dumps(approval), encoding="utf-8")
    approval_path.chmod(0o400)

    with pytest.raises(RefreshCandidateError, match="approval is invalid"):
        publish_refresh_candidate(
            candidate=candidate,
            approval_path=approval_path,
            destination_parent=destination,
            seed_path=seed_path,
            masked_path=masked_path,
            now=FIXED_NOW,
        )


def test_publication_rejects_extreme_approval_integer(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    candidate, seed_path, masked_path = _complete_remote_candidate(tmp_path, monkeypatch)
    verification = verify_refresh_candidate(
        candidate,
        now=FIXED_NOW,
        expected_seed_path=seed_path,
        expected_masked_path=masked_path,
    )
    approval_path = tmp_path / "approval.json"
    destination = tmp_path / "published"
    approve_refresh_candidate(
        candidate=candidate,
        approval_path=approval_path,
        actor="operator",
        reason="reviewed candidate",
        publication_target=destination,
        confirmation_digest=str(verification["manifest_sha256"]),
        seed_path=seed_path,
        masked_path=masked_path,
        now=FIXED_NOW,
    )
    approval_path.chmod(0o600)
    approval_path.write_text(
        '{"schema":"RefreshPublicationApprovalV1","extreme":' + "9" * 5000 + "}",
        encoding="utf-8",
    )
    approval_path.chmod(0o400)

    with pytest.raises(
        RefreshCandidateError,
        match="unreadable immutable JSON artifact",
    ):
        publish_refresh_candidate(
            candidate=candidate,
            approval_path=approval_path,
            destination_parent=destination,
            seed_path=seed_path,
            masked_path=masked_path,
            now=FIXED_NOW,
        )

    assert not destination.exists()


def test_renamed_deceptive_candidate_is_not_verifiable_or_publishable(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    candidate, seed_path, masked_path = _complete_remote_candidate(tmp_path, monkeypatch)
    initial = verify_refresh_candidate(
        candidate,
        now=FIXED_NOW,
        expected_seed_path=seed_path,
        expected_masked_path=masked_path,
    )
    approval_path = tmp_path / "approval.json"
    destination = tmp_path / "published"
    approve_refresh_candidate(
        candidate=candidate,
        approval_path=approval_path,
        actor="operator",
        reason="reviewed candidate",
        publication_target=destination,
        confirmation_digest=str(initial["manifest_sha256"]),
        seed_path=seed_path,
        masked_path=masked_path,
        now=FIXED_NOW,
    )
    candidate.parent.chmod(0o700)
    renamed = candidate.rename(candidate.parent / "candidate-\u202ejson")

    verification = verify_refresh_candidate(
        renamed,
        now=FIXED_NOW,
        expected_seed_path=seed_path,
        expected_masked_path=masked_path,
    )

    assert verification["structural_valid"] is False
    assert verification["publication_ready"] is False
    assert "candidate_name_invalid" in verification["errors"]
    assert "\u202e" not in json.dumps(verification, ensure_ascii=False)
    with pytest.raises(RefreshCandidateError, match="failed immediate"):
        publish_refresh_candidate(
            candidate=renamed,
            approval_path=approval_path,
            destination_parent=destination,
            seed_path=seed_path,
            masked_path=masked_path,
            now=FIXED_NOW,
        )
    assert not destination.exists()


def test_fixture_candidate_cannot_receive_publication_approval(tmp_path: Path) -> None:
    candidate = _candidate(tmp_path)
    verification = verify_refresh_candidate(candidate, now=FIXED_NOW)

    with pytest.raises(RefreshCandidateError, match="not complete"):
        approve_refresh_candidate(
            candidate=candidate,
            approval_path=tmp_path / "approval.json",
            actor="operator",
            reason="fixture must remain fixture",
            publication_target=tmp_path / "published",
            confirmation_digest=str(verification["manifest_sha256"]),
            seed_path=tmp_path / "seed.json",
            masked_path=tmp_path / "masked.json",
            now=FIXED_NOW,
        )


def test_snapshot_projection_surfaces_scan_age_and_excludes_masked(
    tmp_path: Path,
) -> None:
    from mcp_trust.catalog.snapshot import build_snapshot

    db_path, _seed, _masked = _inputs(tmp_path, slugs=("alpha", "beta"))
    conn = connect(db_path)
    scans = ScanRepository(conn)
    for slug in ("alpha", "beta"):
        scans.record(
            ScanRecord(
                id=slug,
                server_slug=slug,
                engine_name="mcpaudit",
                engine_version="2.4.0",
                grade=TrustGrade.B,
                risk=RiskSummary(composite=2.0),
                evidence=ScanEvidence(tools=[ToolEvidence(name="ping")]),
                scanned_at=FIXED_NOW - timedelta(days=2),
            )
        )
    conn.close()

    snapshot = build_snapshot(
        str(db_path),
        masked_slugs=frozenset({"beta"}),
        now=FIXED_NOW,
    )

    assert snapshot["schema_version"] == 2
    assert snapshot["server_count"] == 1
    assert snapshot["servers"][0]["slug"] == "alpha"
    assert snapshot["servers"][0]["scan_age_days"] == 2.0
