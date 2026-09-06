from __future__ import annotations

import io
import json
import subprocess
import tarfile
from datetime import UTC, datetime
from pathlib import Path

import pytest

import mcp_trust.engine.runtime as engine_runtime
import mcp_trust.grade_refresh as grade_refresh
from mcp_trust.core.models import ServerSource, SourceKind
from mcp_trust.engine.mcpaudit import docker_launch_spec
from mcp_trust.grade_refresh import (
    GradeRefreshError,
    build_fixture_repeatability_receipt,
    build_preflight_receipt,
    build_resume_capsule,
    build_state_card,
    catalog_inventory,
    scheduler_readback,
    triage_candidate,
)
from scripts import grade_refresh as grade_refresh_cli
from scripts import qualify_refresh_images
from tests.receipt_fixtures import engine_materialization_receipt, host_capacity_receipt

ROOT = Path(__file__).resolve().parents[1]
SEED = ROOT / "src/mcp_trust/catalog/seed_servers.json"
MASKED = ROOT / "masked-grades.json"
POLICY = ROOT / "src/mcp_trust/catalog/refresh_policy.json"
NOW = datetime(2026, 8, 23, 13, 0, tzinfo=UTC)


@pytest.fixture(autouse=True)
def _admit_fixture_host_capacity(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(
        grade_refresh,
        "require_current_host_capacity",
        lambda receipt, **_kwargs: grade_refresh.validate_host_capacity_receipt(receipt),
    )


def test_repeat_projection_ignores_only_per_run_container_identity() -> None:
    binding = {
        "schema": "McpTrustScanExecutionBindingV2",
        "sandbox": {
            "runtime_readback": {
                "container_identity_digest": "sha256:" + "a" * 64,
                "controls": {"network_none": True},
            }
        },
    }

    projected = grade_refresh._repeatable_execution_binding_projection(binding)

    assert "container_identity_digest" not in projected["sandbox"]["runtime_readback"]
    assert projected["sandbox"]["runtime_readback"]["controls"] == {
        "network_none": True
    }
    assert binding["sandbox"]["runtime_readback"]["container_identity_digest"] == (
        "sha256:" + "a" * 64
    )


def test_scannable_npm_console_scripts_are_bound_to_exact_image_paths() -> None:
    policy = json.loads(POLICY.read_text(encoding="utf-8"))
    scannable = set(policy["scannable"])
    rows = json.loads(SEED.read_text(encoding="utf-8"))

    checked = 0
    for row in rows:
        source_payload = row["source"]
        if row["slug"] not in scannable or source_payload["kind"] != "npm":
            continue
        source = ServerSource.model_validate(source_payload)
        assert source.kind == SourceKind.NPM
        assert source.command is not None
        image = source.sandbox_image or policy["default_sandbox_image"]
        descriptor = policy["image_build_sources"][image]
        qualification = json.loads(
            (ROOT / descriptor["qualification_receipt"]).read_text(encoding="utf-8")
        )
        lock_path = qualification["dependency_locks"]["npm"]["path"]
        package_lock = json.loads((ROOT / lock_path).read_text(encoding="utf-8"))
        package = package_lock["packages"][f"node_modules/{source.reference}"]
        bin_mapping = package["bin"]
        script = bin_mapping[source.command] if isinstance(bin_mapping, dict) else bin_mapping

        command, args = docker_launch_spec(source)
        assert command == "/usr/local/bin/node"
        assert args[0] == f"/opt/npm/node_modules/.bin/{source.command}"
        expected_link = f"../{source.reference}/{script}"
        dockerfile = (ROOT / descriptor["path"]).read_text(encoding="utf-8")
        assert (
            f'readlink {args[0]} | grep -Fqx -- "{expected_link}"' in dockerfile
        )
        checked += 1

    assert checked == 13


def test_qualification_enforces_all_npm_console_script_bindings() -> None:
    inputs = json.loads(
        (ROOT / "docker/refresh/dependency-inputs.json").read_text(encoding="utf-8")
    )
    qualify_refresh_images._validate_console_script_contract(inputs["cohorts"])


def test_every_scannable_image_provides_the_fixed_runtime_attestor() -> None:
    policy = json.loads(POLICY.read_text(encoding="utf-8"))
    rows = json.loads(SEED.read_text(encoding="utf-8"))
    scannable = set(policy["scannable"])
    images = {
        row["source"].get("sandbox_image") or policy["default_sandbox_image"]
        for row in rows
        if row["slug"] in scannable
    }

    assert len(images) == 5
    for image in images:
        dockerfile = (
            ROOT / policy["image_build_sources"][image]["path"]
        ).read_text(encoding="utf-8")
        assert (
            "COPY --from=python-dependencies /opt/venv /opt/venv" in dockerfile
            or "ln -s /usr/local/bin/python /opt/venv/bin/python" in dockerfile
        )


def test_triage_cli_requires_repeat_candidate() -> None:
    with pytest.raises(SystemExit):
        grade_refresh_cli._parser().parse_args(  # noqa: SLF001
            [
                "triage",
                "--candidate",
                "first",
                "--preflight",
                "preflight.json",
                "--repeatability",
                "repeatability.json",
            ]
        )


def test_triage_rejects_same_or_symlinked_repeat_path(tmp_path: Path) -> None:
    candidate = tmp_path / "candidate"
    candidate.mkdir()
    alias = tmp_path / "candidate-alias"
    alias.symlink_to(candidate, target_is_directory=True)

    for repeat_candidate in (candidate, alias):
        with pytest.raises(GradeRefreshError, match="independent path"):
            triage_candidate(
                candidate=candidate,
                repeat_candidate=repeat_candidate,
                preflight={},
                repeatability={},
                seed_path=SEED,
                masked_path=MASKED,
            )


@pytest.mark.parametrize("preflight, repeatability", [([], {}), ({}, None)])
def test_triage_rejects_malformed_receipt_roots(
    preflight: object, repeatability: object, tmp_path: Path
) -> None:
    with pytest.raises(GradeRefreshError, match="receipt root must be a JSON object"):
        triage_candidate(
            candidate=tmp_path / "candidate",
            preflight=preflight,
            repeatability=repeatability,
            seed_path=SEED,
            masked_path=MASKED,
        )


def test_triage_rejects_malformed_candidate_manifest_root(tmp_path: Path) -> None:
    candidate = tmp_path / "candidate"
    candidate.mkdir()
    (candidate / "scan_results.json").write_text(json.dumps({"results": []}), encoding="utf-8")
    (candidate / "MANIFEST.json").write_text("[]\n", encoding="utf-8")

    with pytest.raises(GradeRefreshError, match="manifest root must be a JSON object"):
        triage_candidate(
            candidate=candidate,
            preflight={},
            repeatability={},
            seed_path=SEED,
            masked_path=MASKED,
        )


def test_triage_converts_deep_candidate_manifest_to_structured_error(
    tmp_path: Path,
) -> None:
    candidate = tmp_path / "candidate"
    candidate.mkdir()
    (candidate / "scan_results.json").write_text(json.dumps({"results": []}), encoding="utf-8")
    (candidate / "MANIFEST.json").write_text("[" * 1_100 + "0" + "]" * 1_100, encoding="utf-8")

    with pytest.raises(GradeRefreshError, match="unreadable JSON input"):
        triage_candidate(
            candidate=candidate,
            preflight={},
            repeatability={},
            seed_path=SEED,
            masked_path=MASKED,
        )


def test_inventory_classifies_every_catalog_entry() -> None:
    inventory = catalog_inventory(seed_path=SEED, masked_path=MASKED, policy_path=POLICY)

    assert inventory["catalog_denominator"] == 31
    assert len(inventory["entries"]) == 31
    assert inventory["counts"] == {
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
    assert all(row["live_credentials_allowed"] is False for row in inventory["entries"])
    assert all(row["broad_egress_allowed"] is False for row in inventory["entries"])


def test_policy_masking_must_match_operator_masking(tmp_path: Path) -> None:
    masked = tmp_path / "masked.json"
    masked.write_text("[]\n", encoding="utf-8")

    with pytest.raises(GradeRefreshError, match="masking does not match"):
        catalog_inventory(seed_path=SEED, masked_path=masked, policy_path=POLICY)


def test_policy_rejects_duplicate_masking_input(tmp_path: Path) -> None:
    masked = tmp_path / "masked.json"
    first = json.loads(MASKED.read_text(encoding="utf-8"))[0]
    masked.write_text(json.dumps([first, first]), encoding="utf-8")

    with pytest.raises(GradeRefreshError, match="contains duplicates"):
        catalog_inventory(seed_path=SEED, masked_path=masked, policy_path=POLICY)


def test_policy_rejects_execution_lists_that_do_not_match_exclusion_categories(
    tmp_path: Path,
) -> None:
    policy = json.loads(POLICY.read_text(encoding="utf-8"))
    moved = policy["blocked"].pop()
    policy["scannable"].append(moved)
    policy_path = tmp_path / "refresh-policy.json"
    policy_path.write_text(json.dumps(policy), encoding="utf-8")

    with pytest.raises(GradeRefreshError, match="category-derived execution boundary"):
        catalog_inventory(seed_path=SEED, masked_path=MASKED, policy_path=policy_path)


def test_source_binding_covers_the_full_tracked_tree() -> None:
    binding = grade_refresh.source_binding(ROOT)
    tracked = subprocess.run(
        ["git", "-C", str(ROOT), "ls-files"],
        text=True,
        capture_output=True,
        check=True,
    ).stdout.splitlines()

    assert set(binding["file_digests"]) == set(tracked)
    assert ".github/workflows/ci.yml" in binding["file_digests"]


def test_fixture_corpus_repeats_exactly() -> None:
    receipt = build_fixture_repeatability_receipt(
        seed_path=SEED,
        masked_path=MASKED,
        policy_path=POLICY,
        now=NOW,
    )

    assert receipt["status"] == "PASS"
    assert receipt["repeatable"] is True
    assert receipt["catalog_denominator"] == 31
    assert receipt["first_digest"] == receipt["second_digest"]
    assert receipt["claim_ceiling"].startswith("Fixture determinism only")


def _completed(args: list[str], *, stdout: str = "", returncode: int = 0):
    return subprocess.CompletedProcess(args, returncode, stdout=stdout, stderr="")


def _clean_source_binding() -> dict[str, object]:
    return {
        "repository": "https://github.com/saagpatel/mcp-trust.git",
        "revision": "a" * 40,
        "worktree_state": "clean",
        "source_tree_digest": "sha256:" + "b" * 64,
        "file_digests": {},
    }


def _engine_distribution_binding() -> dict[str, object]:
    return {
        "distribution": {
            "name": "mcp-audits",
            "version": "2.7.0",
            "metadata_version": "2.4",
            "installer": "uv",
            "record_path": "mcp_audits-2.7.0.dist-info/RECORD",
            "record_sha256": "sha256:" + "d" * 64,
            "record_size": 100,
        },
        "modules": [
            {
                "module": module,
                "path": module.replace(".", "/") + ".py",
                "origin": module.replace(".", "/") + ".py",
                "record_hash": "sha256=" + "A" * 43,
                "sha256": "sha256:" + f"{index:064x}",
                "size": index,
            }
            for index, module in enumerate(engine_runtime.MCP_AUDIT_RUNTIME_MODULES, start=1)
        ],
    }


def _ready_engine_receipt(
    monkeypatch: pytest.MonkeyPatch,
) -> dict[str, object]:
    monkeypatch.setattr(grade_refresh, "source_binding", lambda _root: _clean_source_binding())
    monkeypatch.setattr(grade_refresh, "_package_version", lambda _name: "2.7.0")
    monkeypatch.setattr(
        grade_refresh,
        "distribution_runtime_binding",
        lambda _name, _modules: _engine_distribution_binding(),
    )
    monkeypatch.setattr(
        grade_refresh,
        "_uv_binding",
        lambda _runner: {
            "version": "0.12.5",
            "executable": "uv",
            "executable_sha256": "sha256:" + "c" * 64,
        },
    )
    return grade_refresh.build_engine_materialization_receipt(
        repo_root=ROOT,
        now=NOW,
    )


def test_engine_lock_binding_is_exact_and_pypi_only() -> None:
    binding = grade_refresh._locked_engine_binding(ROOT)

    assert binding is not None
    assert binding["package"] == "mcp-audits"
    assert binding["version"] == "2.7.0"
    assert binding["registry"] == "https://pypi.org/simple"
    assert binding["source_policy"]["editable_project"] == "mcp-trust:."
    assert binding["source_policy"]["registry_packages"] > 1
    assert binding["source_policy"]["registry_artifacts"] > 1
    assert binding["artifacts"]["wheel"]["url"].endswith("-py3-none-any.whl")
    assert binding["artifacts"]["sdist"]["url"].endswith(".tar.gz")


def _write_engine_lock_fixture(
    root: Path,
    *,
    lock: str | None = None,
    project: str | None = None,
) -> None:
    (root / "uv.lock").write_text(
        lock if lock is not None else (ROOT / "uv.lock").read_text(encoding="utf-8"),
        encoding="utf-8",
    )
    (root / "pyproject.toml").write_text(
        (
            project
            if project is not None
            else (ROOT / "pyproject.toml").read_text(encoding="utf-8")
        ),
        encoding="utf-8",
    )


def test_engine_lock_binding_rejects_non_pypi_dependency_source(tmp_path: Path) -> None:
    lock = (
        (ROOT / "uv.lock")
        .read_text(encoding="utf-8")
        .replace(
            'source = { registry = "https://pypi.org/simple" }',
            'source = { registry = "https://example.invalid/simple" }',
            1,
        )
    )
    _write_engine_lock_fixture(tmp_path, lock=lock)

    assert grade_refresh._locked_engine_binding(tmp_path) is None


@pytest.mark.parametrize(
    ("original", "replacement"),
    [
        ("version = 1\n", "version = 2\n"),
        ('.whl", hash', '.whl?download=1", hash'),
        ('.tar.gz", hash', '.tar.gz#fragment", hash'),
        ("/packages/57/ba/", "/packages/57/../ba/"),
        ("/packages/57/ba/", "/packages/57%2f..%2fba/"),
    ],
)
def test_engine_lock_binding_rejects_format_and_noncanonical_urls(
    original: str,
    replacement: str,
    tmp_path: Path,
) -> None:
    lock = (ROOT / "uv.lock").read_text(encoding="utf-8")
    assert original in lock
    _write_engine_lock_fixture(
        tmp_path,
        lock=lock.replace(original, replacement, 1),
    )

    assert grade_refresh._locked_engine_binding(tmp_path) is None


@pytest.mark.parametrize(
    ("original", "replacement"),
    [
        (
            'engine = [\n    { name = "mcp-audits" },\n]',
            'engine = [\n]',
        ),
        (
            '{ name = "mcp-audits", marker = "extra == \'engine\'", '
            'specifier = ">=2.4.0,<3" },',
            '{ name = "mcp-audits", marker = "extra == \'dev\'", '
            'specifier = ">=2.4.0,<3" },',
        ),
        (
            'provides-extras = ["engine", "dev"]',
            'provides-extras = ["dev"]',
        ),
    ],
)
def test_engine_lock_binding_rejects_orphaned_engine_dependency_edge(
    original: str,
    replacement: str,
    tmp_path: Path,
) -> None:
    lock = (ROOT / "uv.lock").read_text(encoding="utf-8")
    assert original in lock
    _write_engine_lock_fixture(tmp_path, lock=lock.replace(original, replacement, 1))

    assert grade_refresh._locked_engine_binding(tmp_path) is None


def test_engine_lock_binding_rejects_duplicate_editable_project(tmp_path: Path) -> None:
    lock = (ROOT / "uv.lock").read_text(encoding="utf-8")
    editable = lock[lock.index('[[package]]\nname = "mcp-trust"') :]
    editable = editable[: editable.index("\n[[package]]", 1)]
    _write_engine_lock_fixture(tmp_path, lock=lock + "\n" + editable + "\n")

    assert grade_refresh._locked_engine_binding(tmp_path) is None


def test_engine_lock_binding_rejects_project_engine_requirement_drift(
    tmp_path: Path,
) -> None:
    project = (ROOT / "pyproject.toml").read_text(encoding="utf-8")
    assert grade_refresh.EXPECTED_MCP_AUDITS_REQUIREMENT in project
    _write_engine_lock_fixture(
        tmp_path,
        project=project.replace(
            grade_refresh.EXPECTED_MCP_AUDITS_REQUIREMENT,
            "mcp-audits>=2.6.0,<3",
            1,
        ),
    )

    assert grade_refresh._locked_engine_binding(tmp_path) is None


def test_uv_binding_is_digest_bound_and_timeout_safe(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    executable = tmp_path / "uv"
    executable.write_bytes(b"controlled-uv-fixture")
    monkeypatch.setattr(grade_refresh.shutil, "which", lambda _name: str(executable))

    def runner(args, **kwargs):
        assert args == [str(executable), "--version"]
        assert kwargs["timeout"] == 10
        return _completed(args, stdout="uv 0.12.5\n")

    binding = grade_refresh._uv_binding(runner)

    assert binding == {
        "version": "0.12.5",
        "executable": "uv",
        "executable_sha256": grade_refresh.digest_file(executable),
    }

    def timeout_runner(args, **_kwargs):
        raise subprocess.TimeoutExpired(args, 10)

    assert grade_refresh._uv_binding(timeout_runner) is None


def test_engine_materialization_missing_runtime_is_unknown(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(grade_refresh, "source_binding", lambda _root: _clean_source_binding())
    monkeypatch.setattr(grade_refresh, "_package_version", lambda _name: "UNKNOWN")
    monkeypatch.setattr(
        grade_refresh,
        "distribution_runtime_binding",
        lambda _name, _modules: None,
    )
    monkeypatch.setattr(grade_refresh, "_uv_binding", lambda _runner: None)

    receipt = grade_refresh.build_engine_materialization_receipt(
        repo_root=ROOT,
        now=NOW,
    )
    verification = grade_refresh.verify_engine_materialization_receipt(
        receipt,
        repo_root=ROOT,
        now=NOW,
    )

    assert receipt["status"] == "UNKNOWN"
    assert receipt["safe_to_execute"] is False
    assert receipt["exit_classification"] == "materialization-unknown"
    assert "mcp_audits_runtime_unavailable" in receipt["reasons"]
    assert verification["state"] == "UNKNOWN"
    assert verification["receipt_valid"] is True
    assert verification["materialization_ready"] is False
    assert receipt["authority"] == {
        "observation_only": True,
        "package_install_performed": False,
        "registry_request_performed": False,
        "docker_invoked": False,
        "mcp_execution": False,
        "publication_performed": False,
        "deployment_performed": False,
        "scheduler_change_performed": False,
    }


def test_engine_materialization_runner_is_observation_only(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    executable = tmp_path / "uv"
    executable.write_bytes(b"controlled-uv-fixture")
    monkeypatch.setattr(grade_refresh.shutil, "which", lambda _name: str(executable))
    monkeypatch.setattr(grade_refresh, "source_binding", lambda _root: _clean_source_binding())
    monkeypatch.setattr(grade_refresh, "_package_version", lambda _name: "2.7.0")
    monkeypatch.setattr(
        grade_refresh,
        "distribution_runtime_binding",
        lambda _name, _modules: _engine_distribution_binding(),
    )
    calls: list[list[str]] = []

    def runner(args, **_kwargs):
        calls.append(args)
        return _completed(args, stdout="uv 0.12.5\n")

    receipt = grade_refresh.build_engine_materialization_receipt(
        repo_root=ROOT,
        now=NOW,
        runner=runner,
    )

    assert calls == [[str(executable), "--version"]]
    assert receipt["status"] == "READY"
    assert receipt["authority"] == grade_refresh._ENGINE_MATERIALIZATION_AUTHORITY


def test_engine_materialization_integrity_mismatch_is_blocked(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(grade_refresh, "source_binding", lambda _root: _clean_source_binding())
    monkeypatch.setattr(grade_refresh, "_package_version", lambda _name: "2.7.0")
    monkeypatch.setattr(
        grade_refresh,
        "distribution_runtime_binding",
        lambda _name, _modules: None,
    )
    monkeypatch.setattr(
        grade_refresh,
        "_uv_binding",
        lambda _runner: {
            "version": "0.12.5",
            "executable": "uv",
            "executable_sha256": "sha256:" + "c" * 64,
        },
    )

    receipt = grade_refresh.build_engine_materialization_receipt(
        repo_root=ROOT,
        now=NOW,
    )
    verification = grade_refresh.verify_engine_materialization_receipt(
        receipt,
        repo_root=ROOT,
        now=NOW,
    )

    assert receipt["status"] == "BLOCKED"
    assert receipt["safe_to_execute"] is False
    assert receipt["reasons"] == ["mcp_audits_module_distribution_mismatch"]
    assert verification["state"] == "BLOCKED"
    assert verification["receipt_valid"] is True
    assert verification["materialization_ready"] is False


def test_engine_materialization_verifier_reproduces_blocked_receipt(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(grade_refresh, "source_binding", lambda _root: _clean_source_binding())
    monkeypatch.setattr(grade_refresh, "_package_version", lambda _name: "2.7.0")
    monkeypatch.setattr(
        grade_refresh,
        "_uv_binding",
        lambda _runner: {
            "version": "0.12.5",
            "executable": "uv",
            "executable_sha256": "sha256:" + "c" * 64,
        },
    )
    monkeypatch.setattr(
        grade_refresh,
        "distribution_runtime_binding",
        lambda _name, _modules: None,
    )
    receipt = grade_refresh.build_engine_materialization_receipt(
        repo_root=ROOT,
        now=NOW,
    )
    assert receipt["status"] == "BLOCKED"

    monkeypatch.setattr(
        grade_refresh,
        "distribution_runtime_binding",
        lambda _name, _modules: _engine_distribution_binding(),
    )
    verification = grade_refresh.verify_engine_materialization_receipt(
        receipt,
        repo_root=ROOT,
        now=NOW,
    )

    assert verification["state"] == "UNKNOWN"
    assert verification["receipt_valid"] is False
    assert verification["materialization_ready"] is False
    assert verification["reasons"] == ["current_environment_mismatch"]


def test_engine_materialization_ready_receipt_repeats_and_is_private(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    receipt = _ready_engine_receipt(monkeypatch)
    verification = grade_refresh.verify_engine_materialization_receipt(
        receipt,
        repo_root=ROOT,
        now=NOW,
    )

    assert receipt["status"] == "READY"
    assert receipt["safe_to_execute"] is True
    assert len(receipt["distribution_binding"]["modules"]) == 5
    assert verification["state"] == "READY"
    assert verification["receipt_valid"] is True
    assert verification["materialization_ready"] is True
    serialized = grade_refresh.canonical_bytes(receipt).decode("ascii")
    assert str(ROOT) not in serialized
    assert "/Users/" not in serialized


def test_engine_materialization_verifier_rejects_tamper_and_stale_receipt(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    receipt = _ready_engine_receipt(monkeypatch)
    tampered = json.loads(json.dumps(receipt))
    tampered["distribution_binding"]["modules"][0]["sha256"] = "sha256:" + "f" * 64
    tampered_unsigned = dict(tampered)
    tampered_unsigned.pop("receipt_digest")
    tampered["receipt_digest"] = grade_refresh.digest_bytes(
        grade_refresh.canonical_bytes(tampered_unsigned)
    )

    tampered_result = grade_refresh.verify_engine_materialization_receipt(
        tampered,
        repo_root=ROOT,
        now=NOW,
    )
    stale_result = grade_refresh.verify_engine_materialization_receipt(
        receipt,
        repo_root=ROOT,
        now=NOW + grade_refresh.timedelta(seconds=901),
    )

    assert tampered_result["materialization_ready"] is False
    assert tampered_result["reasons"] == ["current_environment_mismatch"]
    assert stale_result["materialization_ready"] is False
    assert stale_result["reasons"] == ["receipt_stale"]


def test_engine_materialization_verifier_rejects_rehashed_schema_or_authority_drift(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    receipt = _ready_engine_receipt(monkeypatch)
    receipt["authority"]["registry_request_performed"] = True
    unsigned = dict(receipt)
    unsigned.pop("receipt_digest")
    receipt["receipt_digest"] = grade_refresh.digest_bytes(grade_refresh.canonical_bytes(unsigned))

    verification = grade_refresh.verify_engine_materialization_receipt(
        receipt,
        repo_root=ROOT,
        now=NOW,
    )

    assert verification["state"] == "UNKNOWN"
    assert verification["receipt_valid"] is False
    assert verification["reasons"] == ["receipt_schema_invalid"]


def test_engine_materialization_verifier_fails_closed_for_non_json_shape(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    receipt = _ready_engine_receipt(monkeypatch)
    receipt["reasons"] = [{"not-json-serializable"}]

    verification = grade_refresh.verify_engine_materialization_receipt(
        receipt,
        repo_root=ROOT,
        now=NOW,
    )

    assert verification["state"] == "UNKNOWN"
    assert verification["receipt_valid"] is False
    assert verification["reasons"] == [
        "receipt_digest_invalid",
        "receipt_schema_invalid",
    ]


@pytest.mark.parametrize(("ready", "expected"), [(True, 0), (False, 2)])
def test_engine_materialization_cli_is_fail_closed(
    ready: bool,
    expected: int,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(
        grade_refresh_cli,
        "build_engine_materialization_receipt",
        lambda **_kwargs: {"safe_to_execute": ready},
    )
    monkeypatch.setattr(grade_refresh_cli, "_emit", lambda _payload, _out: None)

    assert grade_refresh_cli.main(["engine-materialization"]) == expected


@pytest.mark.parametrize(("ready", "expected"), [(True, 0), (False, 2)])
def test_engine_materialization_verifier_cli_is_fail_closed(
    ready: bool,
    expected: int,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    receipt = tmp_path / "receipt.json"
    receipt.write_text("{}\n", encoding="utf-8")
    monkeypatch.setattr(
        grade_refresh_cli,
        "verify_engine_materialization_receipt",
        lambda *_args, **_kwargs: {"materialization_ready": ready},
    )
    monkeypatch.setattr(grade_refresh_cli, "_emit", lambda _payload, _out: None)

    assert grade_refresh_cli.main(["verify-engine-materialization", str(receipt)]) == expected


def test_inventory_cli_executes_without_unowned_repo_root_argument(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    emitted: list[object] = []
    monkeypatch.setattr(
        grade_refresh_cli,
        "_emit",
        lambda payload, _out: emitted.append(payload),
    )

    assert grade_refresh_cli.main(["inventory"]) == 0
    assert emitted[0]["catalog_denominator"] == 31


def test_preflight_cli_requires_engine_materialization_receipt() -> None:
    with pytest.raises(SystemExit):
        grade_refresh_cli._parser().parse_args(["preflight"])


def test_qualification_capacity_cli_requires_exact_scope() -> None:
    parsed = grade_refresh_cli._parser().parse_args(  # noqa: SLF001
        [
            "qualification-capacity",
            "--operation",
            "qualification",
            "--receipt-set",
            "v122-test",
            "--cohort",
            "reference",
        ]
    )
    assert (parsed.operation, parsed.receipt_set, parsed.cohort) == (
        "qualification",
        "v122-test",
        "reference",
    )
    with pytest.raises(SystemExit):
        grade_refresh_cli._parser().parse_args(  # noqa: SLF001
            ["qualification-capacity", "--receipt-set", "v122-test"]
        )


def test_preflight_binds_verified_engine_materialization(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    materialization = _ready_engine_receipt(monkeypatch)
    monkeypatch.setattr(grade_refresh.shutil, "which", lambda _: None)

    receipt = build_preflight_receipt(
        repo_root=ROOT,
        seed_path=SEED,
        masked_path=MASKED,
        policy_path=POLICY,
        engine_materialization_receipt=materialization,
        host_capacity_receipt=host_capacity_receipt(observed_at=NOW),
        now=NOW,
    )

    assert receipt["engine_materialization"] == materialization
    assert not any(reason.startswith("engine_materialization") for reason in receipt["reasons"])


def test_preflight_fails_closed_without_engine_materialization(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(grade_refresh.shutil, "which", lambda _: None)

    receipt = build_preflight_receipt(
        repo_root=ROOT,
        seed_path=SEED,
        masked_path=MASKED,
        policy_path=POLICY,
        host_capacity_receipt=host_capacity_receipt(observed_at=NOW),
        now=NOW,
    )

    assert receipt["engine_materialization"] is None
    assert "engine_materialization_receipt_missing" in receipt["reasons"]
    assert receipt["safe_to_execute_catalog"] is False


def test_preflight_missing_capacity_never_probes_docker(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    materialization = _ready_engine_receipt(monkeypatch)

    def forbidden_docker_lookup(_name: str) -> str | None:
        raise AssertionError("Docker lookup must not run before capacity admission")

    monkeypatch.setattr(grade_refresh.shutil, "which", forbidden_docker_lookup)

    receipt = build_preflight_receipt(
        repo_root=ROOT,
        seed_path=SEED,
        masked_path=MASKED,
        policy_path=POLICY,
        engine_materialization_receipt=materialization,
        now=NOW,
    )

    assert "host_capacity_receipt_missing" in receipt["reasons"]
    assert receipt["safe_to_execute_catalog"] is False


def test_preflight_reports_every_missing_catalog_image(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(grade_refresh.shutil, "which", lambda _: "/usr/local/bin/docker")
    monkeypatch.setattr(grade_refresh, "_package_version", lambda _: "2.7.0")

    def runner(args, **_kwargs):
        if args[1:3] == ["context", "inspect"]:
            return _completed(args, stdout='"unix:///tmp/docker.sock"\n')
        if "version" in args:
            return _completed(
                args,
                stdout=json.dumps(
                    {"Client": {"Version": "29.7.2"}, "Server": {"Version": "29.5.2"}}
                ),
            )
        if "inspect" in args:
            return _completed(args, returncode=1)
        raise AssertionError(args)

    receipt = build_preflight_receipt(
        repo_root=ROOT,
        seed_path=SEED,
        masked_path=MASKED,
        policy_path=POLICY,
        host_capacity_receipt=host_capacity_receipt(observed_at=NOW),
        now=NOW,
        runner=runner,
    )

    assert receipt["status"] == "BLOCKED"
    assert receipt["safe_to_execute_catalog"] is False
    assert len(receipt["sandbox"]["image_bindings"]) == 5
    assert all(row["state"] == "MISSING" for row in receipt["sandbox"]["image_bindings"])
    assert sum(reason.startswith("catalog_image_missing:") for reason in receipt["reasons"]) == 5
    assert receipt["authority"]["publication"] is False


def test_preflight_rejects_mcp_audits_runtime_lock_mismatch(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(grade_refresh.shutil, "which", lambda _: None)
    monkeypatch.setattr(
        grade_refresh,
        "_package_version",
        lambda distribution: "2.6.0" if distribution == "mcp-audits" else "2.7.0",
    )

    receipt = build_preflight_receipt(
        repo_root=ROOT,
        seed_path=SEED,
        masked_path=MASKED,
        policy_path=POLICY,
        host_capacity_receipt=host_capacity_receipt(observed_at=NOW),
        now=NOW,
    )

    assert receipt["status"] == "BLOCKED"
    assert receipt["safe_to_execute_catalog"] is False
    assert receipt["tool_versions"]["mcp_audits"] == "2.6.0"
    assert receipt["tool_versions"]["mcp_audits_locked"] == "2.7.0"
    assert "mcp_audits_runtime_lock_mismatch" in receipt["reasons"]


def test_preflight_rejects_metadata_without_distribution_owned_module(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(grade_refresh.shutil, "which", lambda _: None)
    monkeypatch.setattr(grade_refresh, "_package_version", lambda _: "2.7.0")
    monkeypatch.setattr(
        grade_refresh,
        "modules_belong_to_distribution",
        lambda _distribution, _modules: False,
    )

    receipt = build_preflight_receipt(
        repo_root=ROOT,
        seed_path=SEED,
        masked_path=MASKED,
        policy_path=POLICY,
        host_capacity_receipt=host_capacity_receipt(observed_at=NOW),
        now=NOW,
    )

    assert receipt["status"] == "BLOCKED"
    assert receipt["safe_to_execute_catalog"] is False
    assert receipt["tool_versions"]["mcp_audits"] == "2.7.0"
    assert "mcp_audits_module_distribution_mismatch" in receipt["reasons"]


def test_module_binding_requires_all_distribution_owned_module_files(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    module_paths = {
        name: tmp_path
        / (name.replace(".", "/") + ("/__init__.py" if name == "mcp_audit" else ".py"))
        for name in engine_runtime.MCP_AUDIT_RUNTIME_MODULES
    }
    for module in module_paths.values():
        module.parent.mkdir(parents=True, exist_ok=True)
        module.write_text("", encoding="utf-8")
    record_path = tmp_path / "mcp_audits-2.7.0.dist-info/RECORD"
    record_path.parent.mkdir()
    record_path.write_text("fixture-record\n", encoding="utf-8")

    class FileHash:
        mode = "sha256"
        value = "47DEQpj8HBSa-_TImW-5JCeuQeRkm5NMpJWZG3hSuFU"

    class RecordedFile(str):
        hash = FileHash()
        size = 0

    class Distribution:
        metadata = {"Name": "mcp-audits", "Metadata-Version": "2.4"}
        version = "2.7.0"
        files = [
            RecordedFile("mcp_audits-2.7.0.dist-info/RECORD"),
            *(
                RecordedFile(path.relative_to(tmp_path).as_posix())
                for path in module_paths.values()
            ),
        ]

        @staticmethod
        def locate_file(item: str) -> Path:
            return tmp_path / item

        @staticmethod
        def read_text(name: str) -> str | None:
            return "uv" if name == "INSTALLER" else None

    class Spec:
        origin = str(module_paths["mcp_audit"])

    monkeypatch.setattr(engine_runtime.importlib.metadata, "distribution", lambda _: Distribution())
    monkeypatch.setattr(engine_runtime.importlib.util, "find_spec", lambda _: Spec())

    assert engine_runtime.modules_belong_to_distribution(
        "mcp-audits", engine_runtime.MCP_AUDIT_RUNTIME_MODULES
    )
    assert engine_runtime.distribution_module_bindings(
        "mcp-audits", engine_runtime.MCP_AUDIT_RUNTIME_MODULES
    ) == [
        {
            "module": module,
            "path": path.relative_to(tmp_path).as_posix(),
            "origin": path.relative_to(tmp_path).as_posix(),
            "record_hash": "sha256=47DEQpj8HBSa-_TImW-5JCeuQeRkm5NMpJWZG3hSuFU",
            "sha256": "sha256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
            "size": 0,
        }
        for module, path in module_paths.items()
    ]
    binding = engine_runtime.distribution_runtime_binding(
        "mcp-audits", engine_runtime.MCP_AUDIT_RUNTIME_MODULES
    )
    assert binding is not None
    assert binding["distribution"] == {
        "name": "mcp-audits",
        "version": "2.7.0",
        "metadata_version": "2.4",
        "installer": "uv",
        "record_path": "mcp_audits-2.7.0.dist-info/RECORD",
        "record_sha256": grade_refresh.digest_file(record_path),
        "record_size": len(b"fixture-record\n"),
    }

    class ShadowedSpec:
        origin = str(tmp_path / "shadowed" / "analyzer.py")

    original_path_finder = engine_runtime.importlib.machinery.PathFinder.find_spec
    monkeypatch.setattr(
        engine_runtime.importlib.machinery.PathFinder,
        "find_spec",
        lambda *_args: ShadowedSpec(),
    )
    assert not engine_runtime.modules_belong_to_distribution(
        "mcp-audits", engine_runtime.MCP_AUDIT_RUNTIME_MODULES
    )
    monkeypatch.setattr(
        engine_runtime.importlib.machinery.PathFinder,
        "find_spec",
        original_path_finder,
    )

    original_symlink_check = engine_runtime._has_symlink_component

    def raise_symlink_loop(_path: Path) -> bool:
        raise RuntimeError("symlink loop")

    monkeypatch.setattr(engine_runtime, "_has_symlink_component", raise_symlink_loop)
    assert not engine_runtime.modules_belong_to_distribution(
        "mcp-audits", engine_runtime.MCP_AUDIT_RUNTIME_MODULES
    )
    monkeypatch.setattr(engine_runtime, "_has_symlink_component", original_symlink_check)

    duplicate = Distribution.files[1]
    Distribution.files.append(duplicate)
    assert not engine_runtime.modules_belong_to_distribution(
        "mcp-audits", engine_runtime.MCP_AUDIT_RUNTIME_MODULES
    )
    Distribution.files.pop()

    RecordedFile.size = 1
    assert not engine_runtime.modules_belong_to_distribution(
        "mcp-audits", engine_runtime.MCP_AUDIT_RUNTIME_MODULES
    )
    RecordedFile.size = 0

    RecordedFile.size = True
    assert not engine_runtime.modules_belong_to_distribution(
        "mcp-audits", engine_runtime.MCP_AUDIT_RUNTIME_MODULES
    )
    RecordedFile.size = 0

    Distribution.metadata = {"Name": "different-project", "Metadata-Version": "2.4"}
    assert not engine_runtime.modules_belong_to_distribution(
        "mcp-audits", engine_runtime.MCP_AUDIT_RUNTIME_MODULES
    )
    Distribution.metadata = {"Name": "mcp-audits", "Metadata-Version": "2.4"}

    missing = Distribution.files.pop()
    assert not engine_runtime.modules_belong_to_distribution(
        "mcp-audits", engine_runtime.MCP_AUDIT_RUNTIME_MODULES
    )
    Distribution.files.append(missing)

    FileHash.value = "A" * 43
    assert not engine_runtime.modules_belong_to_distribution(
        "mcp-audits", engine_runtime.MCP_AUDIT_RUNTIME_MODULES
    )


def test_module_binding_rejects_symlinked_package_ancestor(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    outside = tmp_path / "outside"
    package = outside / "mcp_audit"
    package.mkdir(parents=True)
    paths = [
        package / "__init__.py",
        *(
            package / f"{name.rsplit('.', maxsplit=1)[1]}.py"
            for name in engine_runtime.MCP_AUDIT_RUNTIME_MODULES[1:]
        ),
    ]
    for path in paths:
        path.write_text("", encoding="utf-8")
    (tmp_path / "mcp_audit").symlink_to(package, target_is_directory=True)
    record_path = tmp_path / "mcp_audits-2.7.0.dist-info/RECORD"
    record_path.parent.mkdir()
    record_path.write_text("fixture-record\n", encoding="utf-8")

    class FileHash:
        mode = "sha256"
        value = "47DEQpj8HBSa-_TImW-5JCeuQeRkm5NMpJWZG3hSuFU"

    class RecordedFile(str):
        hash = FileHash()
        size = 0

    class Distribution:
        metadata = {"Name": "mcp-audits", "Metadata-Version": "2.4"}
        version = "2.7.0"
        files = [
            RecordedFile("mcp_audits-2.7.0.dist-info/RECORD"),
            RecordedFile("mcp_audit/__init__.py"),
            *(
                RecordedFile(f"mcp_audit/{name.rsplit('.', maxsplit=1)[1]}.py")
                for name in engine_runtime.MCP_AUDIT_RUNTIME_MODULES[1:]
            ),
        ]

        @staticmethod
        def locate_file(item: str) -> Path:
            return tmp_path / item

        @staticmethod
        def read_text(name: str) -> str | None:
            return "uv" if name == "INSTALLER" else None

    class Spec:
        origin = str(tmp_path / "mcp_audit" / "__init__.py")

    monkeypatch.setattr(engine_runtime.importlib.metadata, "distribution", lambda _: Distribution())
    monkeypatch.setattr(engine_runtime.importlib.util, "find_spec", lambda _: Spec())

    assert not engine_runtime.modules_belong_to_distribution(
        "mcp-audits", engine_runtime.MCP_AUDIT_RUNTIME_MODULES
    )


def test_module_binding_rejects_symlinked_install_root(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    actual_root = tmp_path / "actual-site-packages"
    package = actual_root / "mcp_audit"
    package.mkdir(parents=True)
    paths = [
        package / "__init__.py",
        *(
            package / f"{name.rsplit('.', maxsplit=1)[1]}.py"
            for name in engine_runtime.MCP_AUDIT_RUNTIME_MODULES[1:]
        ),
    ]
    for path in paths:
        path.write_text("", encoding="utf-8")
    alias = tmp_path / "site-packages"
    alias.symlink_to(actual_root, target_is_directory=True)

    class FileHash:
        mode = "sha256"
        value = "47DEQpj8HBSa-_TImW-5JCeuQeRkm5NMpJWZG3hSuFU"

    class RecordedFile(str):
        hash = FileHash()
        size = 0

    class Distribution:
        metadata = {"Name": "mcp-audits", "Metadata-Version": "2.4"}
        version = "2.7.0"
        files = [
            RecordedFile("mcp_audit/__init__.py"),
            *(
                RecordedFile(f"mcp_audit/{name.rsplit('.', maxsplit=1)[1]}.py")
                for name in engine_runtime.MCP_AUDIT_RUNTIME_MODULES[1:]
            ),
        ]

        @staticmethod
        def locate_file(item: str) -> Path:
            return alias / item

        @staticmethod
        def read_text(name: str) -> str | None:
            return "uv" if name == "INSTALLER" else None

    class Spec:
        origin = str(alias / "mcp_audit" / "__init__.py")

    monkeypatch.setattr(engine_runtime.importlib.metadata, "distribution", lambda _: Distribution())
    monkeypatch.setattr(engine_runtime.importlib.util, "find_spec", lambda _: Spec())

    assert not engine_runtime.modules_belong_to_distribution(
        "mcp-audits", engine_runtime.MCP_AUDIT_RUNTIME_MODULES
    )


def test_locked_package_version_fails_closed_on_ambiguous_lock(tmp_path: Path) -> None:
    (tmp_path / "uv.lock").write_text(
        '[[package]]\nname = "mcp-audits"\nversion = "2.7.0"\n'
        '[[package]]\nname = "mcp_audits"\nversion = "2.7.0"\n',
        encoding="utf-8",
    )

    assert grade_refresh._locked_package_version(tmp_path, "mcp-audits") == "UNKNOWN"


def test_preflight_binds_images_by_content_id(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    image_id = "sha256:" + "a" * 64
    monkeypatch.setattr(grade_refresh.shutil, "which", lambda _: "/usr/local/bin/docker")
    monkeypatch.setattr(grade_refresh, "_package_version", lambda _: "2.7.0")

    def runner(args, **_kwargs):
        if args[1:3] == ["context", "inspect"]:
            return _completed(args, stdout='"unix:///tmp/docker.sock"\n')
        if "version" in args:
            return _completed(
                args,
                stdout=json.dumps(
                    {"Client": {"Version": "29.7.2"}, "Server": {"Version": "29.5.2"}}
                ),
            )
        if "inspect" in args:
            return _completed(
                args,
                stdout=json.dumps(
                    [
                        {
                            "Id": image_id,
                            "RepoDigests": ["example.invalid/catalog@sha256:" + "b" * 64],
                            "Os": "linux",
                            "Architecture": "arm64",
                        }
                    ]
                ),
            )
        raise AssertionError(args)

    receipt = build_preflight_receipt(
        repo_root=ROOT,
        seed_path=SEED,
        masked_path=MASKED,
        policy_path=POLICY,
        host_capacity_receipt=host_capacity_receipt(observed_at=NOW),
        now=NOW,
        runner=runner,
    )

    assert receipt["status"] == "BLOCKED"
    assert receipt["safe_to_execute_catalog"] is False
    assert not any(
        reason.startswith("image_build_reproducibility_unknown:") for reason in receipt["reasons"]
    )
    assert (
        sum(
            reason.startswith("image_build_qualification_invalid:") for reason in receipt["reasons"]
        )
        == 5
    )
    assert all(
        row["image_id"] == image_id and row["sandbox_controls"]["all_required_controls"]
        for row in receipt["sandbox"]["image_bindings"]
    )


def _qualification_fixture(
    tmp_path: Path,
    *,
    docker_text: str | None = None,
    lock_payload: dict[str, object] | None = None,
) -> tuple[Path, dict[str, object], str]:
    base = "node@sha256:" + "b" * 64
    dockerfile = tmp_path / "Dockerfile"
    manifest = tmp_path / "package.json"
    lock = tmp_path / "package-lock.json"
    artifacts = tmp_path / "artifacts"
    artifacts.mkdir()
    bundle = artifacts / "npm.tar"
    descriptor = artifacts / "npm.json"
    receipt = tmp_path / "qualification.json"
    manifest.write_text(
        json.dumps(
            {
                "name": "qualification-fixture",
                "version": "1.0.0",
                "private": True,
                "dependencies": {"example": "1.0.0"},
            }
        ),
        encoding="utf-8",
    )
    valid_lock: dict[str, object] = {
        "name": "qualification-fixture",
        "version": "1.0.0",
        "lockfileVersion": 3,
        "requires": True,
        "packages": {
            "": {
                "name": "qualification-fixture",
                "version": "1.0.0",
                "dependencies": {"example": "1.0.0"},
            },
            "node_modules/example": {
                "version": "1.0.0",
                "resolved": "https://registry.npmjs.org/example/-/example-1.0.0.tgz",
                "integrity": "sha512-" + "A" * 86 + "==",
            },
        },
    }
    lock.write_text(json.dumps(lock_payload or valid_lock), encoding="utf-8")
    with tarfile.open(bundle, "w") as archive:
        content = b"offline artifact"
        info = tarfile.TarInfo("cache/example.tgz")
        info.size = len(content)
        info.mtime = 0
        archive.addfile(info, io.BytesIO(content))
    metadata = grade_refresh.dependency_bundle_metadata(bundle)
    descriptor_payload = {
        "schema": "McpTrustDependencyArtifactBundleV1",
        "kind": "npm",
        "registry_endpoints": ["https://registry.npmjs.org"],
        "lock_sha256": grade_refresh.digest_file(lock),
        "bundle_path": "artifacts/npm.tar",
        "bundle_sha256": grade_refresh.digest_file(bundle),
        "prepared_at": NOW.isoformat(),
        "tool_versions": {"node": "22.0.0", "npm": "10.0.0"},
        "preparation_network_policy": "registry-client-allowlist-no-package-code",
        "package_code_executed": False,
        **metadata,
    }
    descriptor.write_text(json.dumps(descriptor_payload), encoding="utf-8")
    dockerfile.write_text(
        docker_text
        or (
            f"FROM {base}\n"
            "COPY package.json /build/package.json\n"
            "COPY package-lock.json /build/package-lock.json\n"
            "COPY artifacts/npm.tar /offline/npm.tar\n"
            "RUN mkdir -p /offline/npm && tar -xf /offline/npm.tar -C /offline/npm "
            "&& npm ci --offline --cache /offline/npm\n"
        ),
        encoding="utf-8",
    )
    manifest_ref = {
        "path": "package.json",
        "sha256": grade_refresh.digest_file(manifest),
    }
    lock_ref = {
        "path": "package-lock.json",
        "sha256": grade_refresh.digest_file(lock),
    }
    artifact_ref = {
        "path": "artifacts/npm.json",
        "sha256": grade_refresh.digest_file(descriptor),
    }
    normalized_artifact = grade_refresh._dependency_artifact(
        repo_root=tmp_path,
        kind="npm",
        lock_sha256=lock_ref["sha256"],
        value=artifact_ref,
    )
    assert normalized_artifact is not None
    build_source_sha256 = grade_refresh.digest_file(dockerfile)
    build_options = {
        "builder": "buildx",
        "cache": "disabled",
        "load": False,
        "output": "oci",
        "pull": False,
        "provenance": False,
        "rewrite_timestamps": True,
        "sbom": False,
    }
    build_input = {
        "build_source_sha256": build_source_sha256,
        "base_images": [base],
        "platform": "linux/arm64",
        "dependency_manifests": {"npm": manifest_ref},
        "dependency_locks": {"package-lock.json": lock_ref["sha256"]},
        "dependency_artifacts": {"npm": normalized_artifact},
        "build_options": build_options,
        "execution_boundary": {
            "docker_context": "colima-mcp-trust-sandbox",
            "docker_transport": "local-unix",
            "builder_name": "colima-mcp-trust-sandbox",
            "builder_driver": "docker",
            "builder_endpoint_matches_context": True,
            "redirect_environment_policy": "exact-context-no-proxy",
            "tool_execution_policy": "owner-private-digest-pinned-copies",
        },
    }
    image_id = "sha256:" + "c" * 64
    command = [
        "docker-buildx",
        "build",
        "--builder",
        "colima-mcp-trust-sandbox",
        "--network",
        "none",
        "--pull=false",
        "--no-cache",
        "--platform",
        "linux/arm64",
        "--provenance=false",
        "--sbom=false",
        "--build-arg",
        "SOURCE_DATE_EPOCH=1710000000",
        "-f",
        "Dockerfile",
    ]
    payload: dict[str, object] = {
        "schema": grade_refresh.IMAGE_BUILD_QUALIFICATION_SCHEMA,
        "observed_at": NOW.isoformat(),
        "exit_classification": "QUALIFIED_REPEATABLE",
        "qualification_max_age_seconds": 86_400,
        "image_reference": "mcp-trust:test",
        "platform": "linux/arm64",
        "build_source_sha256": build_source_sha256,
        "build_input_digest": grade_refresh.digest_bytes(
            grade_refresh.canonical_bytes(build_input)
        ),
        "base_images": [base],
        "dependency_manifests": {"npm": manifest_ref},
        "dependency_locks": {"npm": lock_ref},
        "dependency_artifacts": {"npm": artifact_ref},
        "build_network_policy": ["none"],
        "build_options": build_options,
        "execution_boundary": {
            "docker_context": "colima-mcp-trust-sandbox",
            "docker_transport": "local-unix",
            "builder_name": "colima-mcp-trust-sandbox",
            "builder_driver": "docker",
            "builder_endpoint_matches_context": True,
            "redirect_environment_policy": "exact-context-no-proxy",
            "tool_execution_policy": "owner-private-digest-pinned-copies",
        },
        "build_commands": [],
        "load_commands": [],
        "tool_versions": {
            "docker_client": "29.5.2",
            "docker_server": "29.5.2",
            "docker_buildx": "v0.30.0",
            "buildkit_colima": "v0.25.1",
        },
        "tool_digests": {
            "docker": "sha256:" + "d" * 64,
            "docker_buildx": "sha256:" + "e" * 64,
        },
        "first_build_image_id": image_id,
        "second_build_image_id": image_id,
        "repeatable": True,
    }
    output_paths = ["tmp/qualification/test-first.tar", "tmp/qualification/test-second.tar"]
    payload["build_commands"] = [
        [
            *command,
            f"--output=type=oci,dest={output_paths[0]},rewrite-timestamp=true",
            "-t",
            "mcp-trust-qualification:v89-test-first",
            ".",
        ],
        [
            *command,
            f"--output=type=oci,dest={output_paths[1]},rewrite-timestamp=true",
            "-t",
            "mcp-trust:test",
            ".",
        ],
    ]
    payload["load_commands"] = [
        [
            "docker",
            "--context",
            "colima-mcp-trust-sandbox",
            "load",
            "-i",
            output_paths[0],
        ],
        [
            "docker",
            "--context",
            "colima-mcp-trust-sandbox",
            "load",
            "-i",
            output_paths[1],
        ],
    ]
    payload["receipt_digest"] = grade_refresh.digest_bytes(grade_refresh.canonical_bytes(payload))
    receipt.write_text(json.dumps(payload), encoding="utf-8")
    return receipt, payload, image_id


def _rewrite_receipt(path: Path, payload: dict[str, object]) -> None:
    unsigned = dict(payload)
    unsigned.pop("receipt_digest", None)
    payload["receipt_digest"] = grade_refresh.digest_bytes(grade_refresh.canonical_bytes(unsigned))
    path.write_text(json.dumps(payload), encoding="utf-8")


def _qualification(tmp_path: Path) -> dict[str, object] | None:
    return grade_refresh._image_build_qualification(
        repo_root=tmp_path,
        reference="mcp-trust:test",
        build_source="Dockerfile",
        build_source_sha256=grade_refresh.digest_file(tmp_path / "Dockerfile"),
        receipt_path="qualification.json",
        now=NOW,
    )


def _source_build_receipt_fixture(tmp_path: Path) -> tuple[Path, dict[str, object]]:
    input_path = tmp_path / "source-input.json"
    builder_path = tmp_path / "builder.py"
    receipt_path = tmp_path / "source-receipt.json"
    base = "python@sha256:" + "a" * 64
    wheels = {"legacy-1.0-py3-none-any.whl": "b" * 64}
    inputs = [{"filename": "legacy.tar.gz", "sha256": "c" * 64}]
    input_payload = {
        "schema": "McpTrustPythonSourceBuildInputsV1",
        "python_base": base,
        "platform": "linux/arm64",
        "source_date_epoch": 1710000000,
        "inputs": inputs,
        "expected_wheels": wheels,
    }
    input_path.write_text(json.dumps(input_payload), encoding="utf-8")
    builder_path.write_text("raise SystemExit('fixture only')\n", encoding="utf-8")
    payload: dict[str, object] = {
        "schema": "McpTrustPythonSourceBuildReceiptV1",
        "observed_at": NOW.isoformat(),
        "input_descriptor": {
            "path": input_path.name,
            "sha256": grade_refresh.digest_file(input_path),
        },
        "builder": {
            "path": builder_path.name,
            "sha256": grade_refresh.digest_file(builder_path),
        },
        "python_base": base,
        "platform": "linux/arm64",
        "source_date_epoch": 1710000000,
        "network_policy": "none-during-all-package-code-execution",
        "sandbox_controls": {
            "read_only_root": True,
            "cap_drop": ["ALL"],
            "no_new_privileges": True,
            "memory": "512m",
            "pids": 64,
            "cpus": 1,
            "writable_mounts": ["task-owned-/work", "ephemeral-/tmp"],
            "secrets": "none",
        },
        "input_artifacts": inputs,
        "first_build_wheels": wheels,
        "second_build_wheels": wheels,
        "repeatable": True,
        "package_code_executed": True,
        "exit_classification": "QUALIFIED_REPEATABLE_NETWORK_NONE",
        "tool_versions": {"python": "Python 3.12.14"},
    }
    payload["receipt_digest"] = grade_refresh.digest_bytes(grade_refresh.canonical_bytes(payload))
    receipt_path.write_text(json.dumps(payload), encoding="utf-8")
    return receipt_path, payload


def test_source_build_receipt_requires_network_none_and_repeatable_outputs(
    tmp_path: Path,
) -> None:
    receipt, payload = _source_build_receipt_fixture(tmp_path)
    value = {
        "path": receipt.name,
        "sha256": grade_refresh.digest_file(receipt),
    }
    assert grade_refresh._python_source_build_receipt(repo_root=tmp_path, value=value) is not None

    payload["network_policy"] = "bridge"
    _rewrite_receipt(receipt, payload)
    value["sha256"] = grade_refresh.digest_file(receipt)
    assert grade_refresh._python_source_build_receipt(repo_root=tmp_path, value=value) is None


def test_image_build_qualification_requires_identical_repeat_builds(tmp_path: Path) -> None:
    receipt, payload, image_id = _qualification_fixture(tmp_path)
    assert _qualification(tmp_path)["qualified_image_id"] == image_id

    payload["second_build_image_id"] = "sha256:" + "d" * 64
    _rewrite_receipt(receipt, payload)
    assert _qualification(tmp_path) is None


def test_image_build_qualification_rejects_empty_lock(tmp_path: Path) -> None:
    _qualification_fixture(tmp_path, lock_payload={"lockfileVersion": 3})
    assert _qualification(tmp_path) is None


def test_image_build_qualification_rejects_digest_only_in_comment(tmp_path: Path) -> None:
    base = "node@sha256:" + "b" * 64
    _qualification_fixture(
        tmp_path,
        docker_text=f"# intended base: {base}\nFROM node:24-slim\n",
    )
    assert _qualification(tmp_path) is None


def test_image_build_qualification_rejects_split_dynamic_install(tmp_path: Path) -> None:
    base = "node@sha256:" + "b" * 64
    _qualification_fixture(
        tmp_path,
        docker_text=(
            f"FROM {base}\n"
            "COPY package.json /build/package.json\n"
            "COPY package-lock.json /build/package-lock.json\n"
            "COPY artifacts/npm.tar /offline/npm.tar\n"
            "RUN npm \\\n"
            "    install some-package@1.0.0\n"
        ),
    )
    assert _qualification(tmp_path) is None


def test_image_build_qualification_rejects_missing_artifact_bundle(tmp_path: Path) -> None:
    _qualification_fixture(tmp_path)
    (tmp_path / "artifacts/npm.tar").unlink()
    assert _qualification(tmp_path) is None


def test_image_build_qualification_rejects_stale_receipt(tmp_path: Path) -> None:
    receipt, payload, _image_id = _qualification_fixture(tmp_path)
    payload["observed_at"] = datetime(2026, 8, 21, tzinfo=UTC).isoformat()
    _rewrite_receipt(receipt, payload)
    assert _qualification(tmp_path) is None


@pytest.mark.parametrize(
    "tool_versions",
    [
        {
            "docker_client": "29.5.2",
            "docker_server": "29.5.2",
            "docker_buildx": "v0.30.0",
            "buildkit_colima": (
                "BuildKit version: v0.25.1\n"
                "org.mobyproject.buildkit.worker.hostname: colima-private"
            ),
        },
        {
            "docker_client": "29.5.2",
            "docker_server": "29.5.2",
            "docker_buildx": "v0.30.0",
            "buildkit_colima": "v0.25.1",
            "builder_uuid": "2f09ce6e-dead-beef-acde-cd45923abc12",
        },
    ],
)
def test_image_build_qualification_rejects_non_version_tool_metadata(
    tmp_path: Path, tool_versions: dict[str, str]
) -> None:
    receipt, payload, _image_id = _qualification_fixture(tmp_path)
    payload["tool_versions"] = tool_versions
    _rewrite_receipt(receipt, payload)

    assert _qualification(tmp_path) is None


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("docker_context", "default"),
        ("docker_transport", "tcp"),
        ("builder_name", "remote"),
        ("builder_driver", "remote"),
        ("builder_endpoint_matches_context", False),
        ("redirect_environment_policy", "ambient"),
        ("tool_execution_policy", "ambient-path"),
    ],
)
def test_image_build_qualification_rejects_execution_boundary_drift(
    tmp_path: Path, field: str, value: object
) -> None:
    receipt, payload, _image_id = _qualification_fixture(tmp_path)
    boundary = payload["execution_boundary"]
    assert isinstance(boundary, dict)
    boundary[field] = value
    _rewrite_receipt(receipt, payload)

    assert _qualification(tmp_path) is None


def test_image_build_qualification_rejects_invalid_tool_digest(tmp_path: Path) -> None:
    receipt, payload, _image_id = _qualification_fixture(tmp_path)
    tool_digests = payload["tool_digests"]
    assert isinstance(tool_digests, dict)
    tool_digests["docker"] = "UNKNOWN"
    _rewrite_receipt(receipt, payload)

    assert _qualification(tmp_path) is None


def test_image_build_qualification_rejects_ambient_load_context(tmp_path: Path) -> None:
    receipt, payload, _image_id = _qualification_fixture(tmp_path)
    commands = payload["load_commands"]
    assert isinstance(commands, list)
    commands[0] = ["docker", "load", "-i", "tmp/qualification/test-first.tar"]
    _rewrite_receipt(receipt, payload)

    assert _qualification(tmp_path) is None


@pytest.mark.parametrize(
    "extra_tokens",
    [
        ["--network", "host"],
        ["--progress=plain"],
        ["--output=type=local,dest=tmp/escape"],
        ["-t", "mcp-trust-qualification:v89-shadow-first"],
    ],
)
def test_image_build_qualification_rejects_non_exact_build_command(
    tmp_path: Path, extra_tokens: list[str]
) -> None:
    receipt, payload, _image_id = _qualification_fixture(tmp_path)
    commands = payload["build_commands"]
    assert isinstance(commands, list) and isinstance(commands[0], list)
    commands[0][-1:-1] = extra_tokens
    _rewrite_receipt(receipt, payload)

    assert _qualification(tmp_path) is None


def test_image_build_qualification_rejects_absolute_buildx_host_path(
    tmp_path: Path,
) -> None:
    receipt, payload, _image_id = _qualification_fixture(tmp_path)
    commands = payload["build_commands"]
    assert isinstance(commands, list)
    for command in commands:
        assert isinstance(command, list)
        command[0] = "/Users/private/bin/docker-buildx"
    _rewrite_receipt(receipt, payload)

    assert _qualification(tmp_path) is None


def test_image_build_qualification_rejects_shell_indirection(tmp_path: Path) -> None:
    base = "node@sha256:" + "b" * 64
    _qualification_fixture(
        tmp_path,
        docker_text=(
            f"FROM {base}\n"
            "COPY package.json /build/package.json\n"
            "COPY package-lock.json /build/package-lock.json\n"
            "COPY artifacts/npm.tar /offline/npm.tar\n"
            "RUN sh -c 'npm ci --offline --cache /offline/npm'\n"
        ),
    )
    assert _qualification(tmp_path) is None


def test_scheduler_readback_reports_disabled_unloaded_definition_drift(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    repository_plist = tmp_path / "repo/deploy/launchd/com.d.mcp-trust-refresh.plist"
    repository_plist.parent.mkdir(parents=True)
    repository_plist.write_text("repository", encoding="utf-8")
    installed_plist = tmp_path / "Library/LaunchAgents/com.d.mcp-trust-refresh.plist"
    installed_plist.parent.mkdir(parents=True)
    installed_plist.write_text("installed-drift", encoding="utf-8")
    monkeypatch.setattr(grade_refresh.Path, "home", classmethod(lambda _cls: tmp_path))

    def runner(args, **_kwargs):
        if args[1] == "print-disabled":
            return _completed(
                args,
                stdout='disabled services = { "com.d.mcp-trust-refresh" => disabled }',
            )
        return _completed(args, returncode=1)

    receipt = scheduler_readback(repo_root=tmp_path / "repo", runner=runner)

    assert receipt["state"] == "DISABLED_UNLOADED"
    assert receipt["persistently_disabled"] is True
    assert receipt["loaded_domains"] == []
    assert receipt["definitions_match"] is False
    assert receipt["mutation_performed"] is False


def test_scheduler_readback_treats_missing_installed_definition_as_absent(
    tmp_path: Path, monkeypatch
) -> None:
    repository_plist = tmp_path / "repo/deploy/launchd/com.d.mcp-trust-refresh.plist"
    repository_plist.parent.mkdir(parents=True)
    repository_plist.write_text("source", encoding="utf-8")
    home = tmp_path / "empty-home"
    home.mkdir()
    monkeypatch.setattr(grade_refresh.Path, "home", lambda: home)

    def runner(command: list[str], **_kwargs):
        if command[1] == "print-disabled":
            return subprocess.CompletedProcess(
                command,
                0,
                'disabled services = { "com.d.mcp-trust-refresh" => disabled }',
                "",
            )
        return subprocess.CompletedProcess(command, 1, "", "not loaded")

    receipt = scheduler_readback(repo_root=tmp_path / "repo", runner=runner)

    assert receipt["state"] == "DISABLED_UNLOADED"
    assert receipt["installed_definition_state"] == "ABSENT"
    assert receipt["definitions_match"] == "NOT_APPLICABLE"
    assert receipt["installed_plist"] is None


def test_triage_flags_upgrades_masks_and_unknown_policy_baseline(tmp_path: Path) -> None:
    candidate = tmp_path / "candidate"
    candidate.mkdir()
    (candidate / "scan_results.json").write_text(
        json.dumps(
            {
                "results": [
                    {
                        "server_slug": "upgrade",
                        "state": "fresh",
                        "drift": {
                            "previous_grade": "F",
                            "current_grade": "B",
                            "surface_comparison": "unknown",
                            "cause": "undetermined",
                            "summary": "fixture comparison lacks comparable evidence",
                        },
                    },
                    {"server_slug": "masked", "state": "masked", "drift": None},
                ]
            }
        ),
        encoding="utf-8",
    )
    preflight = {
        "schema": "McpTrustGradeRefreshPreflightV3",
        "observed_at": NOW.isoformat(),
        "status": "READY",
        "safe_to_execute_catalog": True,
        "exit_classification": "ready",
        "source_binding": {
            "revision": "a" * 40,
            "source_tree_digest": "sha256:" + "1" * 64,
            "worktree_state": "clean",
        },
        "engine_materialization": None,
        "host_capacity": host_capacity_receipt(observed_at=NOW),
        "catalog": {
            "policy_digest": "sha256:" + "2" * 64,
            "seed_digest": grade_refresh.digest_file(SEED),
            "masking_digest": grade_refresh.digest_file(MASKED),
            "denominator": 31,
        },
        "sandbox": {},
        "tool_versions": {},
        "scheduler": {"state": "NOT_READ", "mutation_performed": False},
        "reasons": [],
        "authority": {
            "candidate_build": True,
            "publication": False,
            "deployment": False,
            "scheduler_change": False,
        },
    }
    preflight["receipt_digest"] = grade_refresh.digest_bytes(
        grade_refresh.canonical_bytes(preflight)
    )
    repeatability = {
        "schema": "McpTrustFixtureRepeatabilityV1",
        "observed_at": NOW.isoformat(),
        "status": "PASS",
        "fixture_kind": "deterministic-stub-no-process-no-network",
        "catalog_denominator": 31,
        "first_digest": "sha256:" + "3" * 64,
        "second_digest": "sha256:" + "3" * 64,
        "repeatable": True,
        "claim_ceiling": "Fixture determinism only",
    }
    repeatability["receipt_digest"] = grade_refresh.digest_bytes(
        grade_refresh.canonical_bytes(repeatability)
    )
    (candidate / "MANIFEST.json").write_text(
        json.dumps(
            {
                "candidate_state": "complete",
                "qualification": {
                    "preflight_receipt_digest": preflight["receipt_digest"],
                    "source_revision": preflight["source_binding"]["revision"],
                    "source_tree_digest": preflight["source_binding"]["source_tree_digest"],
                    "policy_digest": preflight["catalog"]["policy_digest"],
                },
            }
        ),
        encoding="utf-8",
    )

    verifier_kwargs: dict[str, object] = {}

    def candidate_verifier(*_args, **kwargs):
        verifier_kwargs.update(kwargs)
        return {
            "structural_valid": True,
            "publication_ready": True,
            "state": "complete",
            "errors": [],
        }

    triage = triage_candidate(
        candidate=candidate,
        preflight=preflight,
        repeatability=repeatability,
        seed_path=SEED,
        masked_path=MASKED,
        repo_root=ROOT,
        candidate_verifier=candidate_verifier,
    )

    codes = {finding["code"] for finding in triage["findings"]}
    assert triage["review_required"] is True
    assert triage["publication_allowed"] is False
    assert {"suspicious_upgrade", "large_grade_change", "missing_comparable_provenance"} <= codes
    assert "masked_result_requires_review" in codes
    assert "controlled_repeat_evidence_missing" in codes
    assert "baseline_policy_digest_unknown" in codes
    assert triage["candidate_verification"]["publication_ready"] is True
    assert verifier_kwargs["repo_root"] == ROOT
    state = build_state_card(
        preflight=preflight,
        repeatability=repeatability,
        triage=triage,
    )
    assert "controlled_repeat_evidence_missing" in state["outstanding_gates"]
    assert "controlled-sandbox-candidate-repeat" not in state["completed_controls"]


def test_triage_requires_review_for_inconsistent_controlled_repeats(
    tmp_path: Path,
) -> None:
    first = tmp_path / "first"
    second = tmp_path / "second"
    first.mkdir()
    second.mkdir()
    preflight = {
        "schema": "McpTrustGradeRefreshPreflightV3",
        "observed_at": NOW.isoformat(),
        "status": "READY",
        "safe_to_execute_catalog": True,
        "exit_classification": "ready",
        "source_binding": {
            "revision": "a" * 40,
            "source_tree_digest": "sha256:" + "1" * 64,
            "worktree_state": "clean",
        },
        "engine_materialization": None,
        "host_capacity": host_capacity_receipt(observed_at=NOW),
        "catalog": {
            "policy_digest": "sha256:" + "2" * 64,
            "seed_digest": grade_refresh.digest_file(SEED),
            "masking_digest": grade_refresh.digest_file(MASKED),
            "denominator": 31,
        },
        "sandbox": {},
        "tool_versions": {},
        "scheduler": {"state": "NOT_READ", "mutation_performed": False},
        "reasons": [],
        "authority": {
            "candidate_build": True,
            "publication": False,
            "deployment": False,
            "scheduler_change": False,
        },
    }
    preflight["receipt_digest"] = grade_refresh.digest_bytes(
        grade_refresh.canonical_bytes(preflight)
    )
    repeatability = {
        "schema": "McpTrustFixtureRepeatabilityV1",
        "observed_at": NOW.isoformat(),
        "status": "PASS",
        "fixture_kind": "deterministic-stub-no-process-no-network",
        "catalog_denominator": 31,
        "first_digest": "sha256:" + "3" * 64,
        "second_digest": "sha256:" + "3" * 64,
        "repeatable": True,
        "claim_ceiling": "Fixture determinism only",
    }
    repeatability["receipt_digest"] = grade_refresh.digest_bytes(
        grade_refresh.canonical_bytes(repeatability)
    )
    manifest = {
        "candidate_state": "partial",
        "catalog": {"server_count": 31},
        "masking": {"slugs": []},
        "sandbox": {"profiles": []},
        "qualification": {
            "preflight_receipt_digest": preflight["receipt_digest"],
            "source_revision": preflight["source_binding"]["revision"],
            "source_tree_digest": preflight["source_binding"]["source_tree_digest"],
            "policy_digest": preflight["catalog"]["policy_digest"],
        },
    }
    blocked_result = {
        "server_slug": "blocked",
        "state": "blocked-policy",
        "fresh_grade": None,
        "execution_disposition": "do-not-execute",
        "reason": "sandbox_image_qualification_unknown",
    }
    for candidate, reason in (
        (first, "sandbox_image_qualification_unknown"),
        (second, "different_repeat_reason"),
    ):
        (candidate / "MANIFEST.json").write_text(
            json.dumps(manifest),
            encoding="utf-8",
        )
        (candidate / "scan_results.json").write_text(
            json.dumps(
                {
                    "results": [
                        {
                            **blocked_result,
                            "reason": reason,
                        }
                    ]
                }
            ),
            encoding="utf-8",
        )

    verifier_calls: list[dict[str, object]] = []

    def candidate_verifier(*_args, **kwargs):
        verifier_calls.append(kwargs)
        return {
            "structural_valid": True,
            "publication_ready": False,
            "state": "partial",
            "errors": [],
        }

    alternate_root = tmp_path / "alternate-repo-root"
    triage = triage_candidate(
        candidate=first,
        repeat_candidate=second,
        preflight=preflight,
        repeatability=repeatability,
        seed_path=SEED,
        masked_path=MASKED,
        repo_root=alternate_root,
        candidate_verifier=candidate_verifier,
    )

    assert [call["repo_root"] for call in verifier_calls] == [
        alternate_root,
        alternate_root,
    ]

    assert any(
        finding
        == {
            "severity": "High",
            "code": "controlled_repeat_inconsistent",
            "slug": "blocked",
        }
        for finding in triage["findings"]
    )
    assert any(
        finding
        == {
            "severity": "Critical",
            "code": "repeat_candidate_not_publication_ready",
            "slug": "catalog",
        }
        for finding in triage["findings"]
    )
    assert triage["repeat_candidate_manifest_digest"] == grade_refresh.digest_file(
        second / "MANIFEST.json"
    )
    assert triage["publication_allowed"] is False
    state = build_state_card(
        preflight=preflight,
        repeatability=repeatability,
        triage=triage,
    )
    assert "grade-diff-review-triage-run" in state["completed_controls"]
    assert "controlled-sandbox-candidate-repeat" not in state["completed_controls"]
    assert "triage_receipt_invalid_or_unbound" not in state["outstanding_gates"]
    assert "candidate_review_required" in state["outstanding_gates"]
    assert "controlled_repeat_evidence_not_qualified" in state["outstanding_gates"]


def test_state_card_and_resume_capsule_keep_publication_waiting() -> None:
    preflight = {
        "safe_to_execute_catalog": False,
        "status": "BLOCKED",
        "exit_classification": "preflight-blocked",
        "reasons": [
            "catalog_image_missing:x",
            "image_build_reproducibility_unknown:x",
        ],
        "source_binding": {"revision": "abc", "source_tree_digest": "sha256:" + "a" * 64},
        "catalog": {"denominator": 31, "counts": {"scannable": 31}},
        "scheduler": {"state": "DISABLED_UNLOADED", "definitions_match": False},
    }
    preflight["engine_materialization"] = engine_materialization_receipt(
        source_binding=preflight["source_binding"],
        observed_at=NOW,
        repo_root=ROOT,
    )
    repeatability = {"status": "PASS"}
    state = build_state_card(preflight=preflight, repeatability=repeatability, triage=None)
    capsule = build_resume_capsule(task_id="task-1", state_card=state, now=NOW)

    assert state["production_freshness"] == "UNKNOWN"
    assert state["publication_state"] == "WAITING_FOR_EXPLICIT_APPROVAL"
    assert state["severity_findings"] == {
        "Critical": 1,
        "High": 2,
        "Medium": 2,
        "Low": 0,
    }
    assert [finding["severity"] for finding in state["findings"]] == [
        "Critical",
        "High",
        "High",
        "Medium",
        "Medium",
    ]
    assert state["scheduler_state"]["state"] == "DISABLED_UNLOADED"
    assert capsule["schema"] == "HumanGateResumeCapsuleV1"
    assert capsule["capsule"]["capsule_id"] == "mcp-trust-grade-refresh-deterministic-build-gate"
    assert (
        capsule["capsule"]["waiting_condition"]["code"]
        == "deterministic-image-build-approval-required"
    )
    assert capsule["capsule"]["resume_states"] == ["deterministic-image-build-authorized"]
    assert capsule["capsule"]["target"] == capsule["capsule"]["authorized_next_read"]["target"]
    assert capsule["observation"]["readback_status"] == "not_run"
    assert capsule["capsule"]["authority"]["boundary"] == (
        "Read task status only until exact V68 approval; no package install, registry or "
        "other network access, Docker or Colima, MCP execution, push, publication, deployment, "
        "public-route access, credentials, backing services, or scheduler effects."
    )
    assert len(capsule["capsule"]["claim_ceiling"]) <= 300


def test_state_card_and_resume_capsule_route_engine_materialization_first() -> None:
    preflight = {
        "status": "BLOCKED",
        "safe_to_execute_catalog": False,
        "reasons": [
            "catalog_image_missing:x",
            "engine_materialization_receipt_missing",
        ],
        "source_binding": {"revision": "abc", "source_tree_digest": "sha256:" + "a" * 64},
        "catalog": {"denominator": 31, "counts": {"scannable": 31}},
        "scheduler": {"state": "DISABLED_UNLOADED", "definitions_match": True},
    }
    state = build_state_card(
        preflight=preflight,
        repeatability={"status": "PASS"},
        triage=None,
    )
    capsule = build_resume_capsule(task_id="task-1", state_card=state, now=NOW)

    assert any(
        finding["code"] == "engine_materialization_not_ready"
        for finding in state["findings"]
    )
    assert "mcp-audits==2.7.0" in state["next_action"]
    assert "all five image cohorts" not in state["next_action"]
    assert (
        capsule["capsule"]["capsule_id"]
        == "mcp-trust-grade-refresh-engine-materialization-gate"
    )
    assert (
        capsule["capsule"]["waiting_condition"]["code"]
        == "exact-mcp-audits-materialization-approval-required"
    )
    assert capsule["capsule"]["resume_states"] == [
        "exact-mcp-audits-materialization-authorized"
    ]
    assert "until exact V68 approval" in capsule["capsule"]["authority"]["boundary"]
    assert "push, publication, deployment" in capsule["capsule"]["authority"]["boundary"]
    assert "credentials, backing services" in capsule["capsule"]["authority"]["boundary"]
    assert "Docker, MCP scans" in capsule["capsule"]["claim_ceiling"]
    assert "remain prohibited" in capsule["capsule"]["claim_ceiling"]


def test_state_card_derives_engine_gate_when_blocked_reason_omits_it() -> None:
    preflight = {
        "status": "BLOCKED",
        "safe_to_execute_catalog": False,
        "exit_classification": "preflight-blocked",
        "reasons": ["catalog_image_missing:x"],
        "engine_materialization": None,
        "source_binding": {"revision": "abc", "source_tree_digest": "sha256:" + "a" * 64},
        "catalog": {"denominator": 31, "counts": {"scannable": 31}},
        "scheduler": {"state": "DISABLED_UNLOADED", "definitions_match": True},
    }
    state = build_state_card(
        preflight=preflight,
        repeatability={"status": "PASS"},
        triage=None,
    )
    capsule = build_resume_capsule(task_id="task-1", state_card=state, now=NOW)

    assert "engine_materialization_not_ready" in state["outstanding_gates"]
    assert "blocked_preflight_engine_contract_invalid" in state["outstanding_gates"]
    assert "mcp-audits==2.7.0" in state["next_action"]
    assert "all five image cohorts" not in state["next_action"]
    assert (
        capsule["capsule"]["waiting_condition"]["code"]
        == "exact-mcp-audits-materialization-approval-required"
    )


def test_state_card_does_not_complete_image_preflight_with_invalid_ready_engine() -> None:
    preflight = {
        "status": "READY",
        "safe_to_execute_catalog": True,
        "exit_classification": "ready",
        "reasons": [],
        "engine_materialization": None,
        "source_binding": {"revision": "abc", "source_tree_digest": "sha256:" + "a" * 64},
        "catalog": {"denominator": 31, "counts": {"scannable": 31}},
        "scheduler": {"state": "DISABLED_UNLOADED", "definitions_match": True},
    }
    state = build_state_card(
        preflight=preflight,
        repeatability={"status": "PASS"},
        triage=None,
    )

    assert "engine_materialization_not_ready" in state["outstanding_gates"]
    assert "image-provenance-preflight-run" not in state["completed_controls"]


def test_state_card_and_resume_capsule_do_not_infer_broad_remediation_authority() -> None:
    preflight = {
        "status": "BLOCKED",
        "safe_to_execute_catalog": False,
        "reasons": ["unclassified_local_preflight_blocker"],
        "source_binding": {"revision": "abc", "source_tree_digest": "sha256:" + "a" * 64},
        "catalog": {"denominator": 31, "counts": {"scannable": 31}},
        "scheduler": {"state": "DISABLED_UNLOADED", "definitions_match": True},
    }
    preflight["engine_materialization"] = engine_materialization_receipt(
        source_binding=preflight["source_binding"],
        observed_at=NOW,
        repo_root=ROOT,
    )
    state = build_state_card(
        preflight=preflight,
        repeatability={"status": "PASS"},
        triage=None,
    )
    capsule = build_resume_capsule(task_id="task-1", state_card=state, now=NOW)

    assert "exact scoped approval" in state["next_action"]
    assert (
        capsule["capsule"]["capsule_id"]
        == "mcp-trust-grade-refresh-preflight-remediation-gate"
    )
    assert (
        capsule["capsule"]["waiting_condition"]["code"]
        == "preflight-remediation-review-required"
    )
    assert capsule["capsule"]["resume_states"] == ["preflight-remediation-authorized"]
    assert "grants no package, registry, Docker, MCP" in capsule["capsule"]["claim_ceiling"]


def test_state_card_rejects_self_digested_but_unbound_triage() -> None:
    preflight = {
        "status": "READY",
        "safe_to_execute_catalog": True,
        "reasons": [],
        "receipt_digest": "sha256:" + "1" * 64,
        "source_binding": {
            "revision": "a" * 40,
            "source_tree_digest": "sha256:" + "2" * 64,
        },
        "catalog": {"denominator": 31, "counts": {"scannable": 31}},
        "scheduler": {"state": "NOT_READ"},
    }
    repeatability = {
        "status": "PASS",
        "receipt_digest": "sha256:" + "3" * 64,
    }
    triage = {
        "schema": "McpTrustGradeDiffTriageV1",
        "candidate_manifest_digest": "sha256:" + "4" * 64,
        "repeat_candidate_manifest_digest": None,
        "preflight_receipt_digest": "sha256:" + "9" * 64,
        "repeatability_receipt_digest": repeatability["receipt_digest"],
        "review_required": False,
        "publication_allowed": False,
        "findings": [],
        "counts": {"Critical": 0, "High": 0, "Medium": 0, "Low": 0},
        "candidate_claimed_state": "complete",
        "candidate_verification": {
            "structural_valid": True,
            "publication_ready": True,
            "state": "complete",
            "errors": [],
        },
    }
    triage["receipt_digest"] = grade_refresh.digest_bytes(grade_refresh.canonical_bytes(triage))

    state = build_state_card(
        preflight=preflight,
        repeatability=repeatability,
        triage=triage,
    )

    assert "triage_receipt_invalid_or_unbound" in state["outstanding_gates"]
    assert "grade-diff-review-triage-run" not in state["completed_controls"]
    assert state["findings"][0]["code"] == "triage_receipt_invalid_or_unbound"


def test_state_card_rejects_triage_that_omits_required_repeat_finding() -> None:
    preflight = {
        "status": "READY",
        "safe_to_execute_catalog": True,
        "reasons": [],
        "receipt_digest": "sha256:" + "1" * 64,
        "source_binding": {
            "revision": "a" * 40,
            "source_tree_digest": "sha256:" + "2" * 64,
        },
        "catalog": {"denominator": 31, "counts": {"scannable": 31}},
        "scheduler": {"state": "NOT_READ"},
    }
    repeatability = {
        "status": "PASS",
        "receipt_digest": "sha256:" + "3" * 64,
    }
    triage = {
        "schema": "McpTrustGradeDiffTriageV1",
        "candidate_manifest_digest": "sha256:" + "4" * 64,
        "repeat_candidate_manifest_digest": None,
        "preflight_receipt_digest": preflight["receipt_digest"],
        "repeatability_receipt_digest": repeatability["receipt_digest"],
        "review_required": False,
        "publication_allowed": False,
        "findings": [],
        "counts": {"Critical": 0, "High": 0, "Medium": 0, "Low": 0},
        "candidate_claimed_state": "complete",
        "candidate_verification": {
            "structural_valid": True,
            "publication_ready": True,
            "state": "complete",
            "errors": [],
        },
    }
    triage["receipt_digest"] = grade_refresh.digest_bytes(grade_refresh.canonical_bytes(triage))

    state = build_state_card(
        preflight=preflight,
        repeatability=repeatability,
        triage=triage,
    )

    assert "triage_receipt_invalid_or_unbound" in state["outstanding_gates"]
    assert "grade-diff-review-triage-run" not in state["completed_controls"]
    assert "controlled-sandbox-candidate-repeat" not in state["completed_controls"]


def test_state_card_marks_only_qualified_controlled_repeat_complete() -> None:
    preflight = {
        "status": "READY",
        "safe_to_execute_catalog": True,
        "reasons": [],
        "receipt_digest": "sha256:" + "1" * 64,
        "source_binding": {
            "revision": "a" * 40,
            "source_tree_digest": "sha256:" + "2" * 64,
        },
        "catalog": {"denominator": 31, "counts": {"scannable": 31}},
        "scheduler": {"state": "NOT_READ"},
    }
    repeatability = {
        "status": "PASS",
        "receipt_digest": "sha256:" + "3" * 64,
    }
    triage = {
        "schema": "McpTrustGradeDiffTriageV1",
        "candidate_manifest_digest": "sha256:" + "4" * 64,
        "repeat_candidate_manifest_digest": "sha256:" + "5" * 64,
        "preflight_receipt_digest": preflight["receipt_digest"],
        "repeatability_receipt_digest": repeatability["receipt_digest"],
        "review_required": True,
        "publication_allowed": False,
        "findings": [
            {
                "severity": "High",
                "code": "masked_result_requires_review",
                "slug": "masked-server",
            }
        ],
        "counts": {"Critical": 0, "High": 1, "Medium": 0, "Low": 0},
        "candidate_claimed_state": "complete",
        "candidate_verification": {
            "structural_valid": True,
            "publication_ready": True,
            "state": "complete",
            "errors": [],
        },
    }
    triage["receipt_digest"] = grade_refresh.digest_bytes(
        grade_refresh.canonical_bytes(triage)
    )

    state = build_state_card(
        preflight=preflight,
        repeatability=repeatability,
        triage=triage,
    )

    assert "controlled-sandbox-candidate-repeat" in state["completed_controls"]
    assert "controlled_repeat_evidence_not_qualified" not in state["outstanding_gates"]


def test_state_card_fails_closed_for_malformed_triage_findings() -> None:
    preflight = {
        "status": "READY",
        "safe_to_execute_catalog": True,
        "reasons": [],
        "receipt_digest": "sha256:" + "1" * 64,
        "source_binding": {
            "revision": "a" * 40,
            "source_tree_digest": "sha256:" + "2" * 64,
        },
        "catalog": {"denominator": 31, "counts": {"scannable": 31}},
        "scheduler": {"state": "NOT_READ"},
    }
    repeatability = {
        "status": "PASS",
        "receipt_digest": "sha256:" + "3" * 64,
    }
    triage = {
        "schema": "McpTrustGradeDiffTriageV1",
        "candidate_manifest_digest": "sha256:" + "4" * 64,
        "repeat_candidate_manifest_digest": None,
        "preflight_receipt_digest": preflight["receipt_digest"],
        "repeatability_receipt_digest": repeatability["receipt_digest"],
        "review_required": True,
        "publication_allowed": False,
        "findings": None,
        "counts": {"Critical": 0, "High": 0, "Medium": 0, "Low": 0},
        "candidate_claimed_state": "complete",
        "candidate_verification": {
            "structural_valid": True,
            "publication_ready": True,
            "state": "complete",
            "errors": [],
        },
    }
    triage["receipt_digest"] = grade_refresh.digest_bytes(grade_refresh.canonical_bytes(triage))

    state = build_state_card(
        preflight=preflight,
        repeatability=repeatability,
        triage=triage,
    )

    assert "triage_receipt_invalid_or_unbound" in state["outstanding_gates"]
    assert "controlled-sandbox-candidate-repeat" not in state["completed_controls"]


@pytest.mark.parametrize(
    ("preflight", "repeatability", "triage", "expected_gate"),
    [
        ([], {"status": "PASS"}, None, "preflight_receipt_root_invalid"),
        ({"reasons": []}, None, None, "repeatability_receipt_root_invalid"),
        (
            {"reasons": []},
            {"status": "PASS"},
            "not-an-object",
            "triage_receipt_invalid_or_unbound",
        ),
    ],
)
def test_state_card_fails_closed_for_malformed_receipt_roots(
    preflight: object,
    repeatability: object,
    triage: object | None,
    expected_gate: str,
) -> None:
    state = build_state_card(
        preflight=preflight,
        repeatability=repeatability,
        triage=triage,
    )

    assert expected_gate in state["outstanding_gates"]
    assert state["production_freshness"] == "UNKNOWN"
    assert "controlled-sandbox-candidate-repeat" not in state["completed_controls"]
