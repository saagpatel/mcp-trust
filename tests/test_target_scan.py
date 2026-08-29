"""Target-scoped receipt-only scan boundary tests."""

from __future__ import annotations

import inspect
import json
import os
import sqlite3
from datetime import UTC, datetime
from pathlib import Path

import pytest

from mcp_trust import refresh as refresh_module
from mcp_trust import target_scan
from mcp_trust.core.models import (
    RiskSummary,
    ScanEvidence,
    Server,
    ToolEvidence,
)
from mcp_trust.engine.base import EngineResult, ScanTimeoutError
from mcp_trust.engine.mcpaudit import launch_spec
from mcp_trust.engine.sandbox import (
    SANDBOX_RUNTIME_READBACK_CLAIM_CEILING,
    sandbox_server_process_digest,
)
from mcp_trust.grade_refresh import canonical_bytes, digest_bytes, digest_file, load_policy
from mcp_trust.refresh import RefreshCandidateError
from mcp_trust.store.db import connect, init_schema
from mcp_trust.store.repository import ServerRepository
from scripts import refresh_candidate as refresh_cli

ROOT = Path(__file__).resolve().parents[1]
SEED = ROOT / "src/mcp_trust/catalog/seed_servers.json"
MASKED = ROOT / "masked-grades.json"
POLICY = ROOT / "src/mcp_trust/catalog/refresh_policy.json"
FIXED_NOW = datetime(2026, 8, 29, 2, 30, tzinfo=UTC)
TARGET = "mcp-reference-time"
IMAGE_ID = "sha256:" + "a" * 64
SOURCE_BINDING = {
    "revision": "b" * 40,
    "worktree_state": "clean",
    "source_tree_digest": "sha256:" + "c" * 64,
    "repository": "https://example.test/mcp-trust.git",
    "file_digests": {},
}


def _target_server(*, added_at: datetime = FIXED_NOW) -> Server:
    rows = json.loads(SEED.read_text(encoding="utf-8"))
    row = next(item for item in rows if item["slug"] == TARGET)
    return Server.model_validate({**row, "added_at": added_at})


def _database(path: Path) -> Path:
    connection = connect(path)
    init_schema(connection)
    ServerRepository(connection).upsert(_target_server())
    connection.close()
    path.chmod(0o600)
    return path


def _profile() -> dict[str, object]:
    policy = load_policy(POLICY, SEED, MASKED)
    image = str(policy.raw["default_sandbox_image"])
    return refresh_module._sandbox_profile(
        image,
        image_digest=IMAGE_ID,
        docker_host="unix:///controlled/docker.sock",
    )


def _runtime_readback(server: Server) -> dict[str, object]:
    command, args = launch_spec(server.source)
    return {
        "schema": "McpTrustSandboxRuntimeReadbackV1",
        "state": "VERIFIED",
        "proof_boundary": "live-mcp-server-process-and-docker-daemon-config",
        "image_id": IMAGE_ID,
        "container_identity_digest": "sha256:" + "d" * 64,
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
            "environment_names": ["HOME", "PATH", "TMPDIR"],
            "image_environment_names": ["PATH"],
            "injected_dummy_env_names": [],
            "secret_values_emitted_in_readback": False,
            "server_process_cmdline_digest": sandbox_server_process_digest(command, args),
            "workdir": "/scan",
            "root_write_denied": True,
            "workdir_write_verified": True,
        },
        "claim_ceiling": SANDBOX_RUNTIME_READBACK_CLAIM_CEILING,
    }


def _preflight() -> dict[str, object]:
    policy = load_policy(POLICY, SEED, MASKED)
    rows = json.loads(SEED.read_text(encoding="utf-8"))
    images = sorted(
        {
            source.get("sandbox_image") or policy.raw["default_sandbox_image"]
            for row in rows
            if row["slug"] in policy.scannable
            and isinstance((source := row.get("source")), dict)
            and source.get("command") is not None
        }
    )
    image_bindings = []
    image_sources = {}
    for index, image in enumerate(images):
        image_id = IMAGE_ID if image == policy.raw["default_sandbox_image"] else (
            "sha256:" + f"{index + 1:x}" * 64
        )[:71]
        image_bindings.append(
            {
                "reference": image,
                "state": "BOUND",
                "image_id": image_id,
            }
        )
        image_sources[image] = {
            "qualification": {"receipt_digest": "sha256:" + f"{index + 6:x}" * 64}
        }
    payload: dict[str, object] = {
        "schema": "McpTrustGradeRefreshPreflightV2",
        "observed_at": FIXED_NOW.isoformat(),
        "status": "READY",
        "safe_to_execute_catalog": True,
        "exit_classification": "ready",
        "source_binding": SOURCE_BINDING,
        "engine_materialization": {"receipt_digest": "sha256:" + "e" * 64},
        "catalog": {
            "denominator": 31,
            "counts": {"scannable": 18, "blocked": 13},
            "execution_boundary": {
                "schema": "McpTrustRefreshExecutionBoundaryV1",
                "scannable": sorted(policy.scannable),
                "blocked": sorted(policy.blocked),
            },
            "seed_digest": digest_file(SEED),
            "masking_digest": digest_file(MASKED),
            "policy_digest": digest_file(POLICY),
            "image_build_sources": image_sources,
        },
        "sandbox": {"image_bindings": image_bindings},
        "tool_versions": {"mcp_audits": "2.7.0"},
        "scheduler": {"mutation_performed": False},
        "authority": {
            "candidate_build": True,
            "publication": False,
            "deployment": False,
            "scheduler_change": False,
        },
    }
    payload["receipt_digest"] = digest_bytes(canonical_bytes(payload))
    return payload


def _write_preflight(path: Path, payload: dict[str, object] | None = None) -> Path:
    if path.exists():
        path.chmod(0o600)
    path.write_bytes(canonical_bytes(payload or _preflight()))
    path.chmod(0o400)
    return path


def _live() -> dict[str, object]:
    profile = _profile()
    image = str(profile["image"])
    return {
        "docker_daemon": "available",
        "profiles": [profile],
        "default_image": image,
        "remote_transport_count": 0,
        "_execution_docker_host": "unix:///controlled/docker.sock",
        "_execution_image_bindings": {image: IMAGE_ID},
    }


class _Engine:
    def __init__(self, result: EngineResult | BaseException) -> None:
        self.result = result
        self.calls = 0

    def scan(self, source: object) -> EngineResult:
        self.calls += 1
        if isinstance(self.result, BaseException):
            raise self.result
        return self.result


def _engine_result(**updates: object) -> EngineResult:
    server = _target_server()
    result = EngineResult(
        engine_name="mcpaudit",
        engine_version="2.7.0",
        risk=RiskSummary(composite=1.0),
        evidence=ScanEvidence(tools=[ToolEvidence(name="get-current-time")]),
        sandbox_image=IMAGE_ID,
        sandbox_cleanup_evidence="CONTAINER_ABSENCE_VERIFIED",
        sandbox_runtime_readback=_runtime_readback(server),
    )
    return result.model_copy(update=updates)


def _creation_kwargs(tmp_path: Path, engine: _Engine) -> dict[str, object]:
    output_parent = tmp_path / "receipts"
    output_parent.mkdir(mode=0o700)
    return {
        "slug": TARGET,
        "source_db": _database(tmp_path / "registry.db"),
        "seed_path": SEED,
        "masked_path": MASKED,
        "policy_path": POLICY,
        "qualification_receipt_path": _write_preflight(tmp_path / "preflight.json"),
        "repo_root": ROOT,
        "output_path": output_parent / "target.json",
        "now": FIXED_NOW,
        "_source_binding_provider": lambda _root: SOURCE_BINDING,
        "_qualification_revalidator": lambda *_args, **_kwargs: None,
        "_preflight_provider": lambda *_args, **_kwargs: _live(),
        "_engine_factory": lambda: engine,
    }


@pytest.fixture(autouse=True)
def _admit_fixture_preflight(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(
        target_scan,
        "validate_ready_preflight_contract",
        lambda *_args, **_kwargs: None,
    )


def test_target_selection_rejects_unsafe_and_blocked_before_execution() -> None:
    policy = load_policy(POLICY, SEED, MASKED)
    rows = json.loads(SEED.read_text(encoding="utf-8"))
    invalid = ["", "../time", "time,other", "*", "TIME", "time/other", "é"]
    for slug in invalid:
        with pytest.raises(RefreshCandidateError, match="safe kebab-case"):
            target_scan._select_target(slug, policy=policy, rows=rows, added_at=FIXED_NOW)
    for category in (
        policy.masked,
        policy.unsupported,
        policy.credential_dependent,
        policy.backing_service_dependent,
    ):
        if category:
            with pytest.raises(RefreshCandidateError, match="not policy-scannable"):
                target_scan._select_target(
                    sorted(category)[0], policy=policy, rows=rows, added_at=FIXED_NOW
                )


def test_corpus_candidate_contract_remains_31_18_13_and_has_no_selector() -> None:
    policy = load_policy(POLICY, SEED, MASKED)
    assert policy.raw["catalog_denominator"] == 31
    assert len(policy.scannable) == 18
    assert len(policy.blocked) == 13
    assert "slug" not in inspect.signature(refresh_module.create_refresh_candidate).parameters


def test_cli_rejects_repeated_target_selector() -> None:
    with pytest.raises(SystemExit):
        refresh_cli._parser().parse_args(
            [
                "target-receipt",
                "--slug",
                TARGET,
                "--slug",
                "mcp-reference-fetch",
                "--db",
                "registry.db",
                "--qualification-receipt",
                "preflight.json",
                "--out",
                "receipt.json",
            ]
        )


@pytest.mark.parametrize(
    "hostile",
    [
        "/Users/operator/private.json",
        "/home/operator/private.json",
        "/tmp/private.json",
        "file:///etc/passwd",
        "https://user:password@example.test/value",
        "connect 192.168.1.10",
        "token=live-value",
        "--token",
        "--aws-secret-access-key",
        "AWS_SECRET_ACCESS_KEY=live-secret",
    ],
)
def test_recursive_privacy_rejects_hostile_values(hostile: str) -> None:
    with pytest.raises(RefreshCandidateError, match="privacy-forbidden|user information"):
        target_scan._privacy_validate({"nested": [{"value": hostile}]})


@pytest.mark.parametrize(
    "key",
    ["token", "password", "private_key", "credential_value", "environment_values"],
)
def test_recursive_privacy_rejects_hostile_keys(key: str) -> None:
    with pytest.raises(RefreshCandidateError, match="privacy-forbidden"):
        target_scan._privacy_validate({"nested": {key: "opaque"}})


@pytest.mark.parametrize(
    "payload",
    [
        {"args": ["--token", "live-secret"]},
        {"args": ["--aws-secret-access-key", "live-secret"]},
        {"value": "AWS_SECRET_ACCESS_KEY=live-secret"},
    ],
)
def test_recursive_privacy_rejects_split_credential_arguments(
    payload: dict[str, object],
) -> None:
    with pytest.raises(RefreshCandidateError, match="privacy-forbidden"):
        target_scan._privacy_validate(payload)


def test_ordinary_scan_receipt_cannot_verify_as_target_artifact() -> None:
    with pytest.raises(RefreshCandidateError, match="schema"):
        target_scan._validate_artifact_shape(
            {"format_version": 1, "server_slug": TARGET, "scan_id": "ordinary"}
        )


def test_registry_read_is_immutable_exact_and_rejects_sidecars(tmp_path: Path) -> None:
    database = _database(tmp_path / "registry.db")
    with target_scan._open_registry_target(database, TARGET) as bound:
        assert bound.server.slug == TARGET
        assert len(bound.sha256) == 64
        assert target_scan._recheck_registry(database, bound, bound.server) == bound.sha256
    Path(f"{database}-wal").write_bytes(b"foreign")
    with pytest.raises(RefreshCandidateError, match="sidecar"):
        with target_scan._open_registry_target(database, TARGET):
            pass


def test_registry_rejects_group_or_world_permissions(tmp_path: Path) -> None:
    database = _database(tmp_path / "registry.db")
    database.chmod(0o640)
    with pytest.raises(RefreshCandidateError, match="ownership"):
        with target_scan._open_registry_target(database, TARGET):
            pass


def test_create_scans_one_target_and_seals_receipt(tmp_path: Path) -> None:
    engine = _Engine(_engine_result())
    kwargs = _creation_kwargs(tmp_path, engine)
    database = kwargs["source_db"]
    assert isinstance(database, Path)
    before = database.read_bytes()
    output = target_scan.create_target_scan_artifact(**kwargs)
    assert engine.calls == 1
    assert output.is_file()
    assert output.stat().st_mode & 0o777 == 0o400
    assert database.read_bytes() == before
    connection = sqlite3.connect(database)
    assert connection.execute("SELECT COUNT(*) FROM scans").fetchone()[0] == 0
    connection.close()
    artifact = json.loads(output.read_text(encoding="utf-8"))
    assert artifact["schema"] == target_scan.TARGET_SCAN_SCHEMA
    assert artifact["target_slug"] == TARGET
    assert artifact["authority"] == target_scan.TARGET_SCAN_AUTHORITY
    assert artifact["registry_read_binding"]["pre_sha256"] == artifact[
        "registry_read_binding"
    ]["post_sha256"]


def test_writable_owner_private_preflight_is_accepted(tmp_path: Path) -> None:
    engine = _Engine(_engine_result())
    kwargs = _creation_kwargs(tmp_path, engine)
    preflight = kwargs["qualification_receipt_path"]
    assert isinstance(preflight, Path)
    preflight.chmod(0o600)
    target_scan.create_target_scan_artifact(**kwargs)
    assert engine.calls == 1


def test_complete_image_set_is_validated_but_live_preflight_is_target_only(
    tmp_path: Path,
) -> None:
    engine = _Engine(_engine_result())
    kwargs = _creation_kwargs(tmp_path, engine)
    expected_sets: list[list[str]] = []
    live_counts: list[int] = []

    def revalidate(_receipt: object, **call: object) -> None:
        expected_sets.append(list(call["expected_image_references"]))

    def preflight(servers: list[Server], **_kwargs: object) -> dict[str, object]:
        live_counts.append(len(servers))
        return _live()

    kwargs["_qualification_revalidator"] = revalidate
    kwargs["_preflight_provider"] = preflight
    target_scan.create_target_scan_artifact(**kwargs)
    assert len(expected_sets) == 2
    assert all(len(images) == 5 for images in expected_sets)
    assert live_counts == [1, 1]


@pytest.mark.parametrize(
    "updates",
    [
        {"engine_name": "stub"},
        {"engine_version": "2.6.0"},
        {"evidence": None},
        {"sandbox_image": "sha256:" + "f" * 64},
        {"sandbox_cleanup_evidence": "UNKNOWN"},
        {"sandbox_runtime_readback": None},
    ],
)
def test_false_green_engine_results_write_no_artifact(
    tmp_path: Path, updates: dict[str, object]
) -> None:
    engine = _Engine(_engine_result(**updates))
    kwargs = _creation_kwargs(tmp_path, engine)
    output = kwargs["output_path"]
    assert isinstance(output, Path)
    with pytest.raises(RefreshCandidateError, match="evidence is incomplete"):
        target_scan.create_target_scan_artifact(**kwargs)
    assert engine.calls == 1
    assert not output.exists()


def test_timeout_writes_no_artifact(tmp_path: Path) -> None:
    engine = _Engine(
        ScanTimeoutError(
            "timeout",
            hard_termination_evidence="CONTAINER_ABSENCE_VERIFIED_AFTER_TIMEOUT",
        )
    )
    kwargs = _creation_kwargs(tmp_path, engine)
    output = kwargs["output_path"]
    assert isinstance(output, Path)
    with pytest.raises(RefreshCandidateError, match="timed out"):
        target_scan.create_target_scan_artifact(**kwargs)
    assert not output.exists()


def test_unsafe_output_is_rejected_before_scanner(tmp_path: Path) -> None:
    engine = _Engine(_engine_result())
    kwargs = _creation_kwargs(tmp_path, engine)
    output = kwargs["output_path"]
    assert isinstance(output, Path)
    output.parent.chmod(0o755)
    with pytest.raises(RefreshCandidateError, match="owner-private"):
        target_scan.create_target_scan_artifact(**kwargs)
    assert engine.calls == 0


def test_privacy_hostile_engine_evidence_writes_no_artifact(tmp_path: Path) -> None:
    result = _engine_result(
        evidence=ScanEvidence(tools=[ToolEvidence(name="/Users/operator/private")])
    )
    engine = _Engine(result)
    kwargs = _creation_kwargs(tmp_path, engine)
    output = kwargs["output_path"]
    assert isinstance(output, Path)
    with pytest.raises(RefreshCandidateError, match="privacy-forbidden"):
        target_scan.create_target_scan_artifact(**kwargs)
    assert engine.calls == 1
    assert not output.exists()


def test_source_drift_after_scan_writes_no_artifact(tmp_path: Path) -> None:
    engine = _Engine(_engine_result())
    kwargs = _creation_kwargs(tmp_path, engine)
    calls = 0

    def binding(_root: Path) -> dict[str, object]:
        nonlocal calls
        calls += 1
        if calls == 1:
            return SOURCE_BINDING
        return {**SOURCE_BINDING, "revision": "f" * 40}

    kwargs["_source_binding_provider"] = binding
    output = kwargs["output_path"]
    assert isinstance(output, Path)
    with pytest.raises(RefreshCandidateError, match="source binding changed"):
        target_scan.create_target_scan_artifact(**kwargs)
    assert not output.exists()


def test_database_drift_after_scan_writes_no_artifact(tmp_path: Path) -> None:
    kwargs: dict[str, object]

    class MutatingEngine(_Engine):
        def scan(self, source: object) -> EngineResult:
            database = kwargs["source_db"]
            assert isinstance(database, Path)
            with database.open("ab") as handle:
                handle.write(b"drift")
            return super().scan(source)

    engine = MutatingEngine(_engine_result())
    kwargs = _creation_kwargs(tmp_path, engine)
    output = kwargs["output_path"]
    assert isinstance(output, Path)
    with pytest.raises(RefreshCandidateError, match="database"):
        target_scan.create_target_scan_artifact(**kwargs)
    assert not output.exists()


def test_target_only_forged_qualification_is_rejected(tmp_path: Path) -> None:
    engine = _Engine(_engine_result())
    kwargs = _creation_kwargs(tmp_path, engine)
    forged = _preflight()
    sandbox = forged["sandbox"]
    catalog = forged["catalog"]
    assert isinstance(sandbox, dict)
    assert isinstance(catalog, dict)
    sandbox["image_bindings"] = [sandbox["image_bindings"][0]]
    sources = catalog["image_build_sources"]
    assert isinstance(sources, dict)
    reference = sandbox["image_bindings"][0]["reference"]
    catalog["image_build_sources"] = {reference: sources[reference]}
    forged.pop("receipt_digest")
    forged["receipt_digest"] = digest_bytes(canonical_bytes(forged))
    qualification = kwargs["qualification_receipt_path"]
    assert isinstance(qualification, Path)
    _write_preflight(qualification, forged)
    with pytest.raises(RefreshCandidateError, match="image set is incomplete"):
        target_scan.create_target_scan_artifact(**kwargs)


def test_exclusive_finalization_refuses_collision_and_preserves_foreign_file(
    tmp_path: Path,
) -> None:
    parent = tmp_path / "private"
    parent.mkdir(mode=0o700)
    output = parent / "receipt.json"
    output.write_text("foreign", encoding="utf-8")
    output.chmod(0o400)
    with pytest.raises(RefreshCandidateError, match="already exists"):
        target_scan._exclusive_finalize(output, {})
    assert output.read_text(encoding="utf-8") == "foreign"
    assert not list(parent.glob(".*.tmp-*"))


def test_exclusive_finalization_rejects_nonprivate_parent(tmp_path: Path) -> None:
    parent = tmp_path / "shared"
    parent.mkdir(mode=0o755)
    with pytest.raises(RefreshCandidateError, match="owner-private"):
        target_scan._exclusive_finalize(parent / "receipt.json", {})


def test_exclusive_finalization_collision_race_preserves_foreign_output(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    parent = tmp_path / "private"
    parent.mkdir(mode=0o700)
    output = parent / "receipt.json"
    monkeypatch.setattr(target_scan, "_validate_artifact_shape", lambda payload: payload)

    def collide(directory_fd: int, _source: str, destination: str) -> None:
        descriptor = os.open(
            destination,
            os.O_WRONLY | os.O_CREAT | os.O_EXCL,
            0o400,
            dir_fd=directory_fd,
        )
        try:
            os.write(descriptor, b"foreign")
            os.fsync(descriptor)
        finally:
            os.close(descriptor)
        raise RefreshCandidateError("target scan artifact already exists")

    with pytest.raises(RefreshCandidateError, match="already exists"):
        target_scan._exclusive_finalize(output, {}, rename_no_replace=collide)
    assert output.read_bytes() == b"foreign"
    assert not list(parent.glob(".*.tmp-*"))


def test_output_symlink_parent_is_rejected_before_execution(tmp_path: Path) -> None:
    real_parent = tmp_path / "real"
    real_parent.mkdir(mode=0o700)
    alias = tmp_path / "alias"
    alias.symlink_to(real_parent, target_is_directory=True)
    with pytest.raises(RefreshCandidateError, match="cannot be opened safely"):
        target_scan._validate_output_destination(alias / "receipt.json")


def test_verifier_rebinds_source_preflight_and_registry(tmp_path: Path) -> None:
    engine = _Engine(_engine_result())
    kwargs = _creation_kwargs(tmp_path, engine)
    artifact = target_scan.create_target_scan_artifact(**kwargs)
    verification = target_scan.verify_target_scan_artifact(
        artifact,
        source_db=kwargs["source_db"],
        seed_path=SEED,
        masked_path=MASKED,
        policy_path=POLICY,
        qualification_receipt_path=kwargs["qualification_receipt_path"],
        repo_root=ROOT,
        now=FIXED_NOW,
        _source_binding_provider=lambda _root: SOURCE_BINDING,
        _qualification_revalidator=lambda *_args, **_kwargs: None,
    )
    assert verification["verified"] is True
    assert verification["receipt_only"] is True
