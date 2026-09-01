from __future__ import annotations

import copy
import importlib.util
import json
import os
import socket
import stat
import subprocess
import sys
from datetime import UTC, datetime, timedelta
from pathlib import Path
from types import ModuleType

import pytest

from mcp_trust import dependency_boundary
from mcp_trust.host_capacity import (
    HOST_CAPACITY_MIN_AVAILABLE_BYTES,
    HostCapacitySample,
    build_qualification_capacity_receipt,
)
from tests.receipt_fixtures import host_capacity_receipt

ROOT = Path(__file__).resolve().parents[1]
CAPACITY_NOW = datetime(2026, 8, 30, 12, 0, tzinfo=UTC)
CAPACITY_DEVICE = 42
CAPACITY_TOTAL = 100 * 1024**3


def _script(name: str) -> ModuleType:
    path = ROOT / "scripts" / name
    spec = importlib.util.spec_from_file_location(path.stem, path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _inputs() -> dict[str, object]:
    return json.loads((ROOT / "docker/refresh/dependency-inputs.json").read_text())


def _tool_paths() -> dict[str, Path]:
    return {
        "docker": Path("/approved/tools/docker"),
        "docker-buildx": Path("/approved/tools/docker-buildx"),
    }


def _capacity_gate(
    module: ModuleType,
    *,
    receipt: object | None = None,
    now: datetime = CAPACITY_NOW,
    available_bytes: int = HOST_CAPACITY_MIN_AVAILABLE_BYTES,
) -> object:
    payload = (
        receipt
        if receipt is not None
        else host_capacity_receipt(
            observed_at=CAPACITY_NOW,
            device_id=CAPACITY_DEVICE,
            total_bytes=CAPACITY_TOTAL,
        )
    )
    return module.QualificationCapacityGate(
        receipt=payload,
        anchor=ROOT,
        clock=lambda: now,
        reader=lambda _anchor: HostCapacitySample(CAPACITY_DEVICE, CAPACITY_TOTAL, available_bytes),
    )


def _scoped_capacity(
    *,
    operation: str = "qualification",
    cohort: str = "reference",
    receipt_set: str = "v122-test",
) -> dict[str, object]:
    times = iter((CAPACITY_NOW - timedelta(seconds=30), CAPACITY_NOW))
    return build_qualification_capacity_receipt(
        anchor=ROOT,
        operation=operation,
        receipt_set=receipt_set,
        cohort=cohort,
        reader=lambda _anchor: HostCapacitySample(
            CAPACITY_DEVICE, CAPACITY_TOTAL, HOST_CAPACITY_MIN_AVAILABLE_BYTES
        ),
        clock=lambda: next(times),
        sleeper=lambda _seconds: None,
    )


def test_current_dependency_descriptors_and_locks_are_admitted() -> None:
    payload = dependency_boundary.validate_preparation_inputs(_inputs(), repo_root=ROOT)
    for cohort, config in payload["cohorts"].items():
        lock_root = ROOT / "docker/refresh/locks" / cohort
        if config["npm"]:
            dependency_boundary.validate_npm_lock(
                lock_root / "package.json", lock_root / "package-lock.json"
            )
        if config["python"]:
            dependency_boundary.validate_python_lock(
                lock_root / "requirements.in", lock_root / "requirements.lock"
            )
    source = json.loads(
        (ROOT / "docker/refresh/source-build-inputs/basic-memory.json").read_text()
    )
    assert dependency_boundary.validate_source_build_inputs(source) is source


@pytest.mark.parametrize("name", ["../escape", "/tmp/escape", "nested/name", "", "."])
def test_cohort_names_cannot_escape_output_roots(name: str) -> None:
    payload = _inputs()
    config = next(iter(payload["cohorts"].values()))
    payload["cohorts"] = {name: config}
    with pytest.raises(dependency_boundary.DependencyBoundaryError, match="cohort"):
        dependency_boundary.validate_preparation_inputs(payload, repo_root=ROOT)


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("node_base", "node:latest"),
        ("node_base", "--privileged"),
        ("python_base", "python:3.12"),
        ("image_reference", "registry.example/mcp-trust-scan:latest"),
        ("dockerfile", "/tmp/Dockerfile"),
        ("dockerfile", "../Dockerfile"),
    ],
)
def test_cohort_rejects_mutable_images_and_external_dockerfiles(
    field: str, value: str
) -> None:
    payload = _inputs()
    payload["cohorts"]["reference"][field] = value
    with pytest.raises(dependency_boundary.DependencyBoundaryError):
        dependency_boundary.validate_preparation_inputs(payload, repo_root=ROOT)


def test_repository_file_rejects_symlinks(tmp_path: Path) -> None:
    outside = tmp_path.parent / "outside-Dockerfile"
    outside.write_text("FROM python@sha256:" + "a" * 64 + "\n")
    (tmp_path / "Dockerfile").symlink_to(outside)
    with pytest.raises(dependency_boundary.DependencyBoundaryError, match="symlink"):
        dependency_boundary.repository_file(tmp_path, "Dockerfile")


def test_dockerfile_rejects_external_copy_source(tmp_path: Path) -> None:
    (tmp_path / "Dockerfile").write_text(
        "FROM python@sha256:" + "a" * 64 + " AS runtime\n"
        "COPY --from=registry.example/mutable:latest /payload /payload\n"
    )
    with pytest.raises(dependency_boundary.DependencyBoundaryError, match="COPY"):
        dependency_boundary.repository_dockerfile(tmp_path, "Dockerfile")


@pytest.mark.parametrize(
    "value",
    [
        "https://example.invalid/package.tgz",
        "git+https://example.invalid/repo.git",
        "file:../package",
        "npm:other@1.0.0",
        "latest",
        "^1.2.3",
    ],
)
def test_npm_sources_are_exact_semver_only(value: str) -> None:
    with pytest.raises(dependency_boundary.DependencyBoundaryError, match="exact semver"):
        dependency_boundary.npm_dependencies({"example": value})


@pytest.mark.parametrize(
    "value",
    [
        "example @ https://example.invalid/example.whl",
        "git+https://example.invalid/repo.git",
        "--extra-index-url=https://example.invalid/simple",
        "--find-links=/tmp/wheels",
        "--trusted-host=example.invalid",
        "-r nested.txt",
        "example>=1.0",
    ],
)
def test_python_sources_are_exact_pins_only(value: str) -> None:
    with pytest.raises(dependency_boundary.DependencyBoundaryError, match="exact pins"):
        dependency_boundary.python_requirements([value])


def test_lock_validators_reject_alternate_sources(tmp_path: Path) -> None:
    manifest = tmp_path / "requirements.in"
    lock = tmp_path / "requirements.lock"
    manifest.write_text("example==1.0.0\n")
    lock.write_text(
        "--extra-index-url https://example.invalid/simple\n"
        "example==1.0.0 --hash=sha256:" + "a" * 64 + "\n"
    )
    with pytest.raises(dependency_boundary.DependencyBoundaryError, match="source policy"):
        dependency_boundary.validate_python_lock(manifest, lock)

    package = tmp_path / "package.json"
    package_lock = tmp_path / "package-lock.json"
    package.write_text(json.dumps({"dependencies": {"example": "1.0.0"}}))
    package_lock.write_text(
        json.dumps(
            {
                "lockfileVersion": 3,
                "packages": {
                    "": {"dependencies": {"example": "1.0.0"}},
                    "node_modules/example": {
                        "version": "1.0.0",
                        "resolved": "https://example.invalid/example.tgz",
                        "integrity": "sha512-AAAA",
                    },
                },
            }
        )
    )
    with pytest.raises(dependency_boundary.DependencyBoundaryError, match="registry source"):
        dependency_boundary.validate_npm_lock(package, package_lock)


def test_locally_built_preparer_is_rebound_to_immutable_image_id(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    module = _script("prepare_refresh_dependencies.py")
    payload = _inputs()
    calls: list[tuple[list[str], bool]] = []
    image_id = "sha256:" + "a" * 64

    def fake_run(command: list[str], *, capture: bool = False) -> str:
        calls.append((command, capture))
        return image_id if capture else ""

    monkeypatch.setattr(module.shutil, "which", lambda _: "/approved/docker-buildx")
    monkeypatch.setattr(module, "_run", fake_run)
    assert module._build_uv_python_image(payload) == image_id
    assert calls[-1] == (
        [
            "docker",
            "image",
            "inspect",
            "--format",
            "{{.Id}}",
            "mcp-trust-dependency-prep:20260823",
        ],
        True,
    )


def test_qualify_rejects_unsafe_descriptor_before_any_subprocess(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    module = _script("qualify_refresh_images.py")
    payload = _inputs()
    config = copy.deepcopy(payload["cohorts"]["reference"])
    config["platform"] = payload["platform"]
    config["dockerfile"] = "/tmp/Dockerfile"
    monkeypatch.setattr(
        module,
        "_run",
        lambda *_args, **_kwargs: pytest.fail("subprocess crossed failed preflight"),
    )
    with pytest.raises(module.QualificationError):
        module.qualify(
            "../escape",
            config,
            buildx="docker-buildx",
            receipt_root=module.RECEIPT_ROOT,
            set_manifest={"receipt_digest": "sha256:" + "1" * 64},
            tools=_tool_paths(),
            capacity_gate=_capacity_gate(module),
        )


def test_qualify_validates_platform_separately_before_dependency_inputs(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    module = _script("qualify_refresh_images.py")
    payload = _inputs()
    config = copy.deepcopy(payload["cohorts"]["reference"])
    config["platform"] = payload["platform"]
    observed: dict[str, object] = {}

    class ValidationPassed(RuntimeError):
        pass

    def stop_after_validation(
        cohort: str, validated: dict[str, object]
    ) -> tuple[object, ...]:
        observed["cohort"] = cohort
        observed["config"] = validated
        raise ValidationPassed

    monkeypatch.setattr(module, "RECEIPT_ROOT", tmp_path)
    monkeypatch.setattr(module, "_require_safe_directory", lambda *_args, **_kwargs: None)
    monkeypatch.setattr(module, "_dependency_inputs", stop_after_validation)
    monkeypatch.setattr(
        module,
        "_run",
        lambda *_args, **_kwargs: pytest.fail("subprocess ran during validation"),
    )
    receipt_root = tmp_path / "v122-test"
    scoped = _scoped_capacity(receipt_set=receipt_root.name)
    gate = module.QualificationCapacityGate(
        receipt=scoped["host_capacity"],
        scope_receipt=scoped,
        anchor=ROOT,
    )

    with pytest.raises(ValidationPassed):
        module.qualify(
            "reference",
            config,
            buildx="docker-buildx",
            receipt_root=receipt_root,
            set_manifest={"receipt_digest": "sha256:" + "1" * 64},
            tools=_tool_paths(),
            capacity_gate=gate,
        )

    assert observed == {
        "cohort": "reference",
        "config": payload["cohorts"]["reference"],
    }
    assert config["platform"] == "linux/arm64"


@pytest.mark.parametrize("field", ["command", "extra", "source_date_epoch"])
def test_qualify_rejects_unexpected_cohort_keys_before_any_subprocess(
    monkeypatch: pytest.MonkeyPatch, field: str
) -> None:
    module = _script("qualify_refresh_images.py")
    payload = _inputs()
    config = copy.deepcopy(payload["cohorts"]["reference"])
    config["platform"] = payload["platform"]
    config[field] = "unexpected"
    monkeypatch.setattr(
        module,
        "_run",
        lambda *_args, **_kwargs: pytest.fail("subprocess crossed failed preflight"),
    )

    with pytest.raises(module.QualificationError, match="descriptor is invalid"):
        module.qualify(
            "reference",
            config,
            buildx="docker-buildx",
            receipt_root=module.RECEIPT_ROOT,
            set_manifest={"receipt_digest": "sha256:" + "1" * 64},
            tools=_tool_paths(),
            capacity_gate=_capacity_gate(module),
        )


@pytest.mark.parametrize("platform", [None, "linux/s390x"])
def test_qualify_rejects_missing_or_unsupported_platform_before_any_subprocess(
    monkeypatch: pytest.MonkeyPatch, platform: str | None
) -> None:
    module = _script("qualify_refresh_images.py")
    payload = _inputs()
    config = copy.deepcopy(payload["cohorts"]["reference"])
    if platform is not None:
        config["platform"] = platform
    monkeypatch.setattr(
        module,
        "_run",
        lambda *_args, **_kwargs: pytest.fail("subprocess crossed failed preflight"),
    )

    with pytest.raises(module.QualificationError, match="platform is unsupported"):
        module.qualify(
            "reference",
            config,
            buildx="docker-buildx",
            receipt_root=module.RECEIPT_ROOT,
            set_manifest={"receipt_digest": "sha256:" + "1" * 64},
            tools=_tool_paths(),
            capacity_gate=_capacity_gate(module),
        )


def test_qualification_checks_lock_source_policy_before_buildkit(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    module = _script("qualify_refresh_images.py")
    payload = _inputs()
    config = copy.deepcopy(payload["cohorts"]["reference"])
    config["platform"] = payload["platform"]
    called = False

    def reject_lock(*_args: object, **_kwargs: object) -> None:
        nonlocal called
        called = True
        raise dependency_boundary.DependencyBoundaryError("rejected test lock")

    monkeypatch.setattr(dependency_boundary, "validate_npm_lock", reject_lock)
    with pytest.raises(module.QualificationError, match="source policy"):
        module._dependency_inputs("reference", config)
    assert called is True


def test_qualification_tool_versions_serialize_only_stable_versions(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    module = _script("qualify_refresh_images.py")

    def result(
        command: list[str], *, tools: dict[str, Path], capture: bool = False, capacity_gate: object
    ) -> str:
        assert tools == _tool_paths()
        assert capacity_gate is not None
        assert capture is True
        if command[-1] == "version" and command[0] == "docker-buildx":
            return "github.com/docker/buildx v0.30.0-desktop.1 0123456789ab"
        if command[0] == "docker" and "version" in command:
            return "29.5.2"
        return (
            "Name: colima\n"
            "Endpoint: unix:///Users/example/.colima/docker.sock\n"
            "BuildKit version: v0.25.1\n"
            "Labels:\n"
            " containerd.uuid: 2f09ce6e-dead-beef-acde-cd45923abc12\n"
            " org.mobyproject.buildkit.worker.hostname: colima-mcp-trust-sandbox\n"
            " org.mobyproject.buildkit.worker.network: host\n"
            " org.mobyproject.buildkit.worker.moby.host-gateway-ip: 192.168.5.2\n"
        )

    monkeypatch.setattr(module, "_run", result)
    versions = module._tool_versions(
        "docker-buildx", tools=_tool_paths(), capacity_gate=_capacity_gate(module)
    )

    assert versions == {
        "docker_client": "29.5.2",
        "docker_server": "29.5.2",
        "docker_buildx": "v0.30.0-desktop.1",
        "buildkit_colima": "v0.25.1",
    }
    serialized = json.dumps(versions)
    assert "uuid" not in serialized
    assert "hostname" not in serialized
    assert "192.168.5.2" not in serialized
    assert "/Users/example" not in serialized


def test_qualification_accepts_homebrew_buildx_provenance_without_serializing_it() -> None:
    module = _script("qualify_refresh_images.py")

    assert module._buildx_version("github.com/docker/buildx v0.36.1 Homebrew") == "v0.36.1"


@pytest.mark.parametrize(
    "receipt_set", ["../escape", "/absolute", ".", "..", "bad\\name", "unversioned"]
)
def test_qualification_receipt_set_rejects_unsafe_names_before_execution(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    receipt_set: str,
) -> None:
    module = _script("qualify_refresh_images.py")
    root = tmp_path / "repo"
    receipt_root = root / "docker/refresh/qualification"
    receipt_root.mkdir(parents=True)
    monkeypatch.setattr(module, "ROOT", root)
    monkeypatch.setattr(module, "RECEIPT_ROOT", receipt_root)

    with pytest.raises(module.QualificationError, match="safe versioned"):
        module._receipt_set_root(receipt_set)


def test_qualification_receipt_set_refuses_legacy_or_symlink_targets(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    module = _script("qualify_refresh_images.py")
    root = tmp_path / "repo"
    receipt_root = root / "docker/refresh/qualification"
    receipt_root.mkdir(parents=True)
    (receipt_root / "v65-existing").mkdir(mode=0o700)
    (receipt_root / "v65-link").symlink_to(tmp_path / "outside", target_is_directory=True)
    monkeypatch.setattr(module, "ROOT", root)
    monkeypatch.setattr(module, "RECEIPT_ROOT", receipt_root)

    monkeypatch.setattr(module, "_expected_set_manifest", lambda **_kwargs: {})
    with pytest.raises(module.QualificationError, match="file is unsafe"):
        module._open_receipt_set("v65-existing", cohorts={}, platform="linux/arm64")
    with pytest.raises(module.QualificationError, match="symlink"):
        module._open_receipt_set("v65-link", cohorts={}, platform="linux/arm64")
    assert module._receipt_set_root("v65-new") == receipt_root / "v65-new"


def test_qualification_receipt_set_refuses_symlinked_parent(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    module = _script("qualify_refresh_images.py")
    root = tmp_path / "repo"
    outside = tmp_path / "outside"
    outside.mkdir()
    (root / "docker/refresh").mkdir(parents=True)
    receipt_root = root / "docker/refresh/qualification"
    receipt_root.symlink_to(outside, target_is_directory=True)
    monkeypatch.setattr(module, "ROOT", root)
    monkeypatch.setattr(module, "RECEIPT_ROOT", receipt_root)

    with pytest.raises(module.QualificationError, match="symlink"):
        module._receipt_set_root("v65-new")


def test_qualification_capacity_loader_rejects_generic_and_wrong_scope(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    module = _script("qualify_refresh_images.py")
    generic = tmp_path / "generic.json"
    generic.write_text(
        json.dumps(host_capacity_receipt(observed_at=CAPACITY_NOW)), encoding="utf-8"
    )
    with pytest.raises(module.QualificationError, match="unreadable or invalid"):
        module._load_capacity_gate(
            generic,
            operation="qualification",
            receipt_set="v122-test",
            cohort="reference",
        )

    scoped = tmp_path / "scoped.json"
    scoped.write_text(json.dumps(_scoped_capacity()), encoding="utf-8")
    with pytest.raises(module.QualificationError, match="unreadable or invalid"):
        module._load_capacity_gate(
            scoped,
            operation="cleanup",
            receipt_set="v122-test",
            cohort="reference",
        )
    monkeypatch.setattr(module, "ROOT", ROOT)
    assert isinstance(
        module._load_capacity_gate(
            scoped,
            operation="qualification",
            receipt_set="v122-test",
            cohort="reference",
        ),
        module.QualificationCapacityGate,
    )


def test_direct_qualifier_rejects_unscoped_gate_before_docker(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    module = _script("qualify_refresh_images.py")
    payload = _inputs()
    config = {**payload["cohorts"]["reference"], "platform": payload["platform"]}
    monkeypatch.setattr(module, "_require_safe_directory", lambda *_a, **_k: None)
    monkeypatch.setattr(
        module,
        "_image_id",
        lambda *_a, **_k: pytest.fail("Docker boundary crossed an unscoped gate"),
    )

    with pytest.raises(module.QualificationError, match="not scope-bound"):
        module.qualify(
            "reference",
            config,
            buildx="docker-buildx",
            receipt_root=tmp_path,
            set_manifest={"receipt_digest": "sha256:" + "1" * 64},
            tools=_tool_paths(),
            capacity_gate=_capacity_gate(module),
        )


def test_capacity_gate_rejects_divergent_scoped_and_dynamic_receipts() -> None:
    module = _script("qualify_refresh_images.py")
    scoped = _scoped_capacity()
    different = host_capacity_receipt(
        observed_at=CAPACITY_NOW,
        device_id=CAPACITY_DEVICE + 1,
        total_bytes=CAPACITY_TOTAL,
    )

    with pytest.raises(module.QualificationError, match="receipts differ"):
        module.QualificationCapacityGate(
            receipt=different,
            scope_receipt=scoped,
            anchor=ROOT,
        )


def test_append_only_set_blocks_retry_until_attempt_is_resolved(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    module = _script("qualify_refresh_images.py")
    monkeypatch.setattr(module, "ROOT", tmp_path)
    root = tmp_path / "v122-test"
    root.mkdir(mode=0o700)
    manifest = {
        "schema": module.QUALIFICATION_SET_SCHEMA,
        "receipt_digest": "sha256:" + "1" * 64,
        "cohort_bindings": {
            "reference": {"image_reference": "mcp-trust:test"}
        },
    }
    module._write_new(root / "qualification-set.json", manifest)
    scoped = _scoped_capacity()
    gate = module.QualificationCapacityGate(
        receipt=scoped["host_capacity"],
        scope_receipt=scoped,
        anchor=ROOT,
        clock=lambda: CAPACITY_NOW,
        reader=lambda _anchor: HostCapacitySample(
            CAPACITY_DEVICE, CAPACITY_TOTAL, HOST_CAPACITY_MIN_AVAILABLE_BYTES
        ),
    )
    tool_root = tmp_path / "tmp/qualification/tools"
    tool_root.mkdir(parents=True, mode=0o700)
    tools = {
        "docker": tool_root / "docker",
        "docker-buildx": tool_root / "docker-buildx",
    }
    for path in tools.values():
        path.write_bytes(path.name.encode())
        path.chmod(0o500)
    attempt_id = module._attempt_id(
        set_manifest=manifest, cohort="reference", capacity_gate=gate
    )
    temporary_reference = f"mcp-trust-qualification:v0-{attempt_id}-first"

    attempt_path, attempt = module._begin_attempt(
        root=root,
        set_manifest=manifest,
        cohort="reference",
        attempt_id=attempt_id,
        capacity_gate=gate,
        image_reference="mcp-trust:test",
        temporary_reference=temporary_reference,
        previous_final_image_id=None,
        output_paths=[
            "tmp/qualification/reference-first.oci.tar",
            "tmp/qualification/reference-second.oci.tar",
        ],
        tools=tools,
    )

    assert attempt_path.is_file()
    assert attempt["exit_classification"] == "PENDING_DOCKER_MUTATION_CLEANUP"
    before = {path.name for path in root.iterdir()}
    with pytest.raises(module.QualificationError, match="cleanup is required"):
        module._begin_attempt(
            root=root,
            set_manifest=manifest,
            cohort="reference",
            attempt_id=attempt_id,
            capacity_gate=gate,
            image_reference="mcp-trust:test",
            temporary_reference=temporary_reference,
            previous_final_image_id=None,
            output_paths=[
                "tmp/qualification/reference-first.oci.tar",
                "tmp/qualification/reference-second.oci.tar",
            ],
            tools=tools,
        )
    assert {path.name for path in root.iterdir()} == before


def test_append_only_set_rejects_unknown_artifact(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    module = _script("qualify_refresh_images.py")
    monkeypatch.setattr(module, "ROOT", tmp_path)
    root = tmp_path / "v122-test"
    root.mkdir(mode=0o700)
    unknown = root / "surprise.json"
    unknown.write_text("{}", encoding="utf-8")
    unknown.chmod(0o600)

    with pytest.raises(module.QualificationError, match="unknown artifact"):
        module._validated_set_attempts(
            root,
            cohort="reference",
            set_manifest={"receipt_digest": "sha256:" + "1" * 64},
        )


def test_append_only_set_rejects_reused_underlying_capacity_observation(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    module = _script("qualify_refresh_images.py")
    monkeypatch.setattr(module, "ROOT", tmp_path)
    root = tmp_path / "v122-test"
    root.mkdir(mode=0o700)
    for cohort in ("reference", "batch3"):
        capacity = _scoped_capacity(cohort=cohort)
        digest = capacity["receipt_digest"].removeprefix("sha256:")
        module._write_new(root / f"capacity-{cohort}-{digest}.json", capacity)

    with pytest.raises(module.QualificationError, match="observation was reused"):
        module._validated_set_attempts(
            root,
            cohort="reference",
            set_manifest={"receipt_digest": "sha256:" + "1" * 64},
        )


def test_set_graph_rejects_orphan_receipt(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    module = _script("qualify_refresh_images.py")
    monkeypatch.setattr(module, "ROOT", tmp_path)
    root = tmp_path / "v122-test"
    root.mkdir(mode=0o700)
    receipt = root / "reference.json"
    receipt.write_text("{}", encoding="utf-8")
    receipt.chmod(0o600)

    with pytest.raises(module.QualificationError, match="lacks one completion graph"):
        module._validate_set_graph(
            root,
            set_manifest={
                "receipt_digest": "sha256:" + "1" * 64,
                "cohort_bindings": {},
            },
        )


def test_set_graph_rejects_orphan_completion(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    module = _script("qualify_refresh_images.py")
    monkeypatch.setattr(module, "ROOT", tmp_path)
    root = tmp_path / "v122-test"
    root.mkdir(mode=0o700)
    attempt_id = "1" * 64
    payload = {
        "schema": module.QUALIFICATION_COMPLETION_SCHEMA,
        "cohort": "reference",
        "attempt_id": attempt_id,
        "attempt_path": f"attempt-reference-{attempt_id}.json",
        "attempt_sha256": "sha256:" + "2" * 64,
        "qualification_receipt": "reference.json",
        "qualification_receipt_sha256": "sha256:" + "3" * 64,
        "qualification_receipt_digest": "sha256:" + "4" * 64,
        "exit_classification": "QUALIFIED_REPEATABLE",
    }
    payload["receipt_digest"] = module._unsigned_digest(payload)
    module._write_new(root / f"complete-reference-{attempt_id}.json", payload)

    with pytest.raises(module.QualificationError, match="orphan completion"):
        module._validate_set_graph(
            root,
            set_manifest={
                "receipt_digest": "sha256:" + "5" * 64,
                "cohort_bindings": {},
            },
        )


def test_set_graph_rejects_orphan_capacity(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    module = _script("qualify_refresh_images.py")
    monkeypatch.setattr(module, "ROOT", tmp_path)
    root = tmp_path / "v122-test"
    root.mkdir(mode=0o700)
    capacity = _scoped_capacity(receipt_set="v122-test")
    digest = capacity["receipt_digest"].removeprefix("sha256:")
    module._write_new(root / f"capacity-reference-{digest}.json", capacity)

    with pytest.raises(module.QualificationError, match="orphan capacity"):
        module._validate_set_graph(
            root,
            set_manifest={
                "receipt_digest": "sha256:" + "1" * 64,
                "cohort_bindings": {},
            },
        )


def test_set_graph_rejects_completion_without_ownership(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    module = _script("qualify_refresh_images.py")
    monkeypatch.setattr(module, "ROOT", tmp_path)
    root = tmp_path / "v122-test"
    root.mkdir(mode=0o700)
    attempt_id = "1" * 64
    attempt_path = root / f"attempt-reference-{attempt_id}.json"
    attempt_path.write_text("{}\n", encoding="utf-8")
    attempt_path.chmod(0o600)
    attempt = {
        "cohort": "reference",
        "attempt_id": attempt_id,
        "capacity_receipt": "capacity-reference-test.json",
    }

    def artifacts(
        _root: Path, *, cohort: str, set_manifest: dict[str, object]
    ) -> tuple[
        list[tuple[Path, dict[str, object]]], set[str], set[str], set[str]
    ]:
        assert set_manifest["receipt_digest"] == "sha256:" + "5" * 64
        attempts = [(attempt_path, attempt)] if cohort == "reference" else []
        return attempts, {attempt_id}, set(), set()

    monkeypatch.setattr(module, "_validated_set_attempts", artifacts)

    with pytest.raises(module.QualificationError, match="lacks final-tag ownership"):
        module._validate_set_graph(
            root,
            set_manifest={
                "receipt_digest": "sha256:" + "5" * 64,
                "cohort_bindings": {},
            },
        )


def test_owned_final_image_id_rejects_malformed_marker(tmp_path: Path) -> None:
    module = _script("qualify_refresh_images.py")
    root = tmp_path / "v122-test"
    root.mkdir(mode=0o700)
    attempt_id = "1" * 64
    attempt_path = root / f"attempt-reference-{attempt_id}.json"
    attempt_path.write_text("{}\n", encoding="utf-8")
    attempt_path.chmod(0o600)
    attempt = {"cohort": "reference", "attempt_id": attempt_id}
    ownership = {
        "schema": module.QUALIFICATION_OWNERSHIP_SCHEMA,
        "cohort": "reference",
        "attempt_id": attempt_id,
        "attempt_path": attempt_path.name,
        "attempt_sha256": "sha256:" + "2" * 64,
        "owned_final_image_id": "sha256:" + "3" * 64,
        "exit_classification": "FINAL_TAG_MUTATION_AUTHORIZED",
    }
    ownership["receipt_digest"] = module._unsigned_digest(ownership)
    module._write_new(
        root / f"ownership-reference-{attempt_id}.json", ownership
    )

    with pytest.raises(module.QualificationError, match="ownership receipt is invalid"):
        module._owned_final_image_id(
            root, attempt_path=attempt_path, attempt=attempt
        )


@pytest.mark.parametrize("name", ["../outside.json", "/tmp/outside.json", "a/b.json"])
def test_set_artifact_references_must_be_contained_children(
    tmp_path: Path, name: str
) -> None:
    module = _script("qualify_refresh_images.py")
    with pytest.raises(module.QualificationError, match="contained set file"):
        module._safe_set_child(tmp_path, name, label="fixture")


def test_final_tag_containment_refuses_concurrent_ownership(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    module = _script("qualify_refresh_images.py")
    previous = "sha256:" + "a" * 64
    owned = "sha256:" + "b" * 64
    concurrent = "sha256:" + "c" * 64
    monkeypatch.setattr(module, "_image_id", lambda *_a, **_k: concurrent)
    monkeypatch.setattr(
        module,
        "_run",
        lambda *_a, **_k: pytest.fail("ambiguous final tag was overwritten"),
    )

    with pytest.raises(module.QualificationError, match="ownership is ambiguous"):
        module._final_tag_state(
            "mcp-trust:test",
            previous,
            owned_final_image_id=owned,
            tools=_tool_paths(),
            capacity_gate=_capacity_gate(module),
        )


def test_interruption_residue_cleanup_is_exact_and_complete(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    module = _script("qualify_refresh_images.py")
    monkeypatch.setattr(module, "ROOT", tmp_path)
    output_root = tmp_path / "tmp/qualification"
    tools_root = output_root / "tools"
    tools_root.mkdir(parents=True, mode=0o700)
    snapshot: dict[str, dict[str, str]] = {}
    for name in ("docker", "docker-buildx"):
        path = tools_root / name
        path.write_bytes(name.encode())
        path.chmod(0o500)
        snapshot[name] = {
            "path": f"tmp/qualification/tools/{name}",
            "sha256": module.grade_refresh.digest_file(path),
        }
    for name in (
        "reference-first.oci.tar",
        "reference-second.oci.tar",
        "reference-receipt.json",
    ):
        path = output_root / name
        path.write_bytes(b"task-owned")
        path.chmod(0o600)
    attempt = {
        "cohort": "reference",
        "oci_outputs": [
            "tmp/qualification/reference-first.oci.tar",
            "tmp/qualification/reference-second.oci.tar",
        ],
        "validation_receipt": "tmp/qualification/reference-receipt.json",
        "tool_snapshot": snapshot,
    }

    module._remove_attempt_outputs(attempt)

    assert list(output_root.iterdir()) == []


def test_cohort_lock_rejects_concurrent_invocation(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    module = _script("qualify_refresh_images.py")
    monkeypatch.setattr(module, "ROOT", tmp_path)
    with module._cohort_lock("v122-test", "reference"):
        with pytest.raises(module.QualificationError, match="already active"):
            with module._cohort_lock("v122-test", "reference"):
                pytest.fail("concurrent cohort lock was admitted")


def test_cohort_lock_rejects_symlink_path(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    module = _script("qualify_refresh_images.py")
    monkeypatch.setattr(module, "ROOT", tmp_path)
    lock_root = tmp_path / "tmp/qualification-locks"
    lock_root.mkdir(parents=True, mode=0o700)
    lock_id = module.grade_refresh.digest_bytes(
        module.grade_refresh.canonical_bytes({"receipt_set": "v122-test"})
    ).removeprefix("sha256:")
    (lock_root / f"{lock_id}.lock").symlink_to(tmp_path / "outside")

    with pytest.raises(module.QualificationError, match="lock is a symlink"):
        with module._cohort_lock("v122-test", "reference"):
            pytest.fail("symlinked lock was admitted")


def test_cleanup_residue_waits_for_dynamic_capacity(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    module = _script("qualify_refresh_images.py")
    gate = _capacity_gate(module, now=CAPACITY_NOW + timedelta(seconds=121))
    monkeypatch.setattr(
        module,
        "_remove_attempt_outputs",
        lambda _attempt: pytest.fail("residue changed before dynamic capacity"),
    )

    with pytest.raises(module.QualificationError, match="not READY"):
        module._admit_cleanup_residue(capacity_gate=gate, attempt={})


def test_expired_cleanup_capacity_emits_no_completion_or_docker_call(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    module = _script("qualify_refresh_images.py")
    monkeypatch.setattr(module, "ROOT", tmp_path)
    root = tmp_path / "v122-test"
    root.mkdir(mode=0o700)
    attempt_path = root / ("attempt-reference-" + "1" * 64 + ".json")
    attempt_path.write_text("{}", encoding="utf-8")
    attempt_path.chmod(0o600)
    attempt = {
        "cohort": "reference",
        "attempt_id": "1" * 64,
        "set_receipt_digest": "sha256:" + "2" * 64,
        "image_reference": "mcp-trust:test",
        "temporary_reference": "mcp-trust-qualification:v0-" + "1" * 64 + "-first",
        "exit_classification": "PENDING_DOCKER_MUTATION_CLEANUP",
    }
    monkeypatch.setattr(
        module,
        "_unresolved_attempts",
        lambda *_a, **_k: [(attempt_path, attempt)],
    )
    scoped = _scoped_capacity(
        operation="cleanup", receipt_set="v122-test"
    )
    gate = module.QualificationCapacityGate(
        receipt=scoped["host_capacity"],
        scope_receipt=scoped,
        anchor=tmp_path,
        clock=lambda: CAPACITY_NOW + timedelta(seconds=121),
        reader=lambda _anchor: HostCapacitySample(
            CAPACITY_DEVICE, CAPACITY_TOTAL, HOST_CAPACITY_MIN_AVAILABLE_BYTES
        ),
    )
    monkeypatch.setattr(
        module.subprocess,
        "run",
        lambda *_a, **_k: pytest.fail("Docker subprocess crossed expired cleanup gate"),
    )

    with pytest.raises(module.QualificationError, match="not READY"):
        module.cleanup_interrupted(
            "reference",
            receipt_root=root,
            set_manifest={
                "receipt_digest": "sha256:" + "2" * 64,
                "cohort_bindings": {
                    "reference": {"image_reference": "mcp-trust:test"}
                },
            },
            tools=_tool_paths(),
            capacity_gate=gate,
            buildx="docker-buildx",
        )
    assert list(root.glob("cleanup-*.json")) == []


def test_cleanup_success_binds_owned_final_tag_and_appends_receipt(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    module = _script("qualify_refresh_images.py")
    monkeypatch.setattr(module, "ROOT", tmp_path)
    root = tmp_path / "v122-test"
    root.mkdir(mode=0o700)
    attempt_id = "1" * 64
    attempt_path = root / f"attempt-reference-{attempt_id}.json"
    attempt_path.write_text("{}", encoding="utf-8")
    attempt_path.chmod(0o600)
    previous = "sha256:" + "a" * 64
    owned = "sha256:" + "b" * 64
    attempt = {
        "cohort": "reference",
        "attempt_id": attempt_id,
        "set_receipt_digest": "sha256:" + "2" * 64,
        "image_reference": "mcp-trust:test",
        "temporary_reference": f"mcp-trust-qualification:v0-{attempt_id}-first",
        "previous_final_image_id": previous,
        "oci_outputs": [
            "tmp/qualification/reference-first.oci.tar",
            "tmp/qualification/reference-second.oci.tar",
        ],
        "exit_classification": "PENDING_DOCKER_MUTATION_CLEANUP",
    }
    monkeypatch.setattr(
        module,
        "_unresolved_attempts",
        lambda *_a, **_k: [(attempt_path, attempt)],
    )
    scoped = _scoped_capacity(operation="cleanup", receipt_set="v122-test")
    capacity_path = root / "capacity-cleanup.json"
    capacity_path.write_text(json.dumps(scoped), encoding="utf-8")
    capacity_path.chmod(0o600)
    monkeypatch.setattr(
        module, "_capacity_snapshot", lambda **_kwargs: (capacity_path, scoped)
    )
    monkeypatch.setattr(
        module,
        "_execution_boundary",
        lambda *_a, **_k: dict(module.EXECUTION_BOUNDARY),
    )
    versions = {
        "docker_client": "1.0.0",
        "docker_server": "1.0.0",
        "docker_buildx": "v1.0.0",
        "buildkit_colima": "v1.0.0",
    }
    digests = {
        "docker": "sha256:" + "c" * 64,
        "docker_buildx": "sha256:" + "d" * 64,
    }
    monkeypatch.setattr(module, "_tool_versions", lambda *_a, **_k: versions)
    monkeypatch.setattr(module, "_tool_digests", lambda *_a, **_k: digests)
    monkeypatch.setattr(module, "_remove_tag", lambda *_a, **_k: None)
    monkeypatch.setattr(module, "_owned_final_image_id", lambda *_a, **_k: owned)
    observed: list[tuple[str | None, str | None]] = []
    monkeypatch.setattr(
        module,
        "_final_tag_state",
        lambda _reference, prior, *, owned_final_image_id, **_kwargs: (
            observed.append((prior, owned_final_image_id))
            or "TASK_OWNED_RETAINED"
        ),
    )
    reads = iter((None,))
    monkeypatch.setattr(module, "_image_id", lambda *_a, **_k: next(reads))
    gate = module.QualificationCapacityGate(
        receipt=scoped["host_capacity"],
        scope_receipt=scoped,
        anchor=tmp_path,
    )

    receipt = module.cleanup_interrupted(
        "reference",
        receipt_root=root,
        set_manifest={
            "receipt_digest": "sha256:" + "2" * 64,
            "cohort_bindings": {
                "reference": {"image_reference": "mcp-trust:test"}
            },
        },
        tools=_tool_paths(),
        capacity_gate=gate,
        buildx="docker-buildx",
    )

    assert observed == [(previous, owned)]
    payload = json.loads(receipt.read_text(encoding="utf-8"))
    assert payload["exit_classification"] == "CLEANUP_CONFIRMED"
    assert payload["temporary_tag_absent"] is True
    assert payload["final_tag_state"] == "TASK_OWNED_RETAINED"


def test_qualification_safely_creates_missing_ignored_output_root(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    module = _script("qualify_refresh_images.py")
    root = tmp_path / "repo"
    root.mkdir()
    monkeypatch.setattr(module, "ROOT", root)
    output_root = root / "tmp/qualification"

    module._ensure_safe_directory(output_root, label="qualification OCI output root")

    assert output_root.is_dir()
    assert output_root.is_symlink() is False
    module._require_private_directory(output_root, label="qualification OCI output root")


def test_qualification_rejects_nonprivate_or_nonempty_output_root(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    module = _script("qualify_refresh_images.py")
    root = tmp_path / "repo"
    output_root = root / "tmp/qualification"
    output_root.mkdir(parents=True, mode=0o700)
    monkeypatch.setattr(module, "ROOT", root)

    output_root.chmod(0o755)
    with pytest.raises(module.QualificationError, match="owner-private"):
        module._require_empty_directory(output_root, label="qualification OCI output root")

    output_root.chmod(0o700)
    (output_root / "operator-file").write_text("private", encoding="utf-8")
    with pytest.raises(module.QualificationError, match="must be empty"):
        module._require_empty_directory(output_root, label="qualification OCI output root")


def test_qualification_binds_exact_local_context_and_builder(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    module = _script("qualify_refresh_images.py")
    socket_path = Path("/tmp") / f"mcp-trust-test-{os.getpid()}.sock"
    listener = socket.socket(socket.AF_UNIX)
    try:
        listener.bind(socket_path.as_posix())
        expected_host = "unix://" + socket_path.as_posix()
        monkeypatch.setattr(module, "EXPECTED_DOCKER_HOST", expected_host)

        def result(
            command: list[str],
            *,
            tools: dict[str, Path],
            capacity_gate: object,
            capture: bool = False,
            timeout: int = 60,
        ) -> str:
            assert tools == _tool_paths()
            assert capacity_gate is not None
            assert capture is True
            assert timeout == 60
            if command[0:3] == ["docker", "context", "inspect"]:
                return json.dumps(expected_host)
            return (
                "Name: colima-mcp-trust-sandbox\n"
                "Driver: docker\n"
                "Nodes:\n"
                "Name: colima-mcp-trust-sandbox\n"
                "Endpoint: colima-mcp-trust-sandbox\n"
                "Status: running\n"
                "BuildKit version: v0.30.0\n"
            )

        monkeypatch.setattr(module, "_run", result)
        assert (
            module._execution_boundary(
                "docker-buildx",
                tools=_tool_paths(),
                capacity_gate=_capacity_gate(module),
            )
            == module.EXECUTION_BOUNDARY
        )
    finally:
        listener.close()
        socket_path.unlink(missing_ok=True)


def test_qualification_rejects_remote_context_before_builder_inspection(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    module = _script("qualify_refresh_images.py")
    calls: list[list[str]] = []

    def result(
        command: list[str],
        *,
        tools: dict[str, Path],
        capacity_gate: object,
        capture: bool = False,
        timeout: int = 60,
    ) -> str:
        assert tools == _tool_paths()
        assert capacity_gate is not None
        calls.append(command)
        return json.dumps("tcp://builder.example:2376")

    monkeypatch.setattr(module, "_run", result)
    with pytest.raises(module.QualificationError, match="local Unix"):
        module._execution_boundary(
            "docker-buildx",
            tools=_tool_paths(),
            capacity_gate=_capacity_gate(module),
        )
    assert len(calls) == 1


def test_qualification_subprocess_environment_pins_context_and_clears_redirects(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    module = _script("qualify_refresh_images.py")
    observed: dict[str, str] = {}

    def run(command: list[str], **kwargs: object) -> subprocess.CompletedProcess[str]:
        assert command[0] == "/approved/tools/docker-buildx"
        environment = kwargs["env"]
        assert isinstance(environment, dict)
        observed.update(environment)
        return subprocess.CompletedProcess(command, 0, stdout="", stderr="")

    monkeypatch.setenv("DOCKER_HOST", "tcp://remote.example:2376")
    monkeypatch.setenv("HTTP_PROXY", "http://proxy.example")
    monkeypatch.setattr(module.subprocess, "run", run)
    module._completed(
        ["docker-buildx", "version"],
        tools=_tool_paths(),
        capacity_gate=_capacity_gate(module),
        capture=True,
    )

    assert observed["DOCKER_CONTEXT"] == "colima-mcp-trust-sandbox"
    assert observed["PATH"] == "/approved/tools"
    assert "DOCKER_HOST" not in observed
    assert "HTTP_PROXY" not in observed


def test_qualification_cli_requires_host_capacity_before_subprocess(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    module = _script("qualify_refresh_images.py")
    monkeypatch.setattr(
        module.subprocess,
        "run",
        lambda *_args, **_kwargs: pytest.fail("subprocess ran without capacity receipt"),
    )
    monkeypatch.setattr(
        sys,
        "argv",
        [
            "qualify_refresh_images.py",
            "--cohort",
            "reference",
            "--receipt-set",
            "v116-test",
        ],
    )

    with pytest.raises(SystemExit) as exc:
        module.main()
    assert exc.value.code == 2


@pytest.mark.parametrize(
    ("receipt", "now", "available_bytes"),
    [
        (None, CAPACITY_NOW, HOST_CAPACITY_MIN_AVAILABLE_BYTES),
        ({}, CAPACITY_NOW, HOST_CAPACITY_MIN_AVAILABLE_BYTES),
        (
            host_capacity_receipt(
                observed_at=CAPACITY_NOW - timedelta(seconds=121),
                device_id=CAPACITY_DEVICE,
                total_bytes=CAPACITY_TOTAL,
            ),
            CAPACITY_NOW,
            HOST_CAPACITY_MIN_AVAILABLE_BYTES,
        ),
        (
            host_capacity_receipt(
                observed_at=CAPACITY_NOW,
                device_id=CAPACITY_DEVICE,
                total_bytes=CAPACITY_TOTAL,
            ),
            CAPACITY_NOW,
            HOST_CAPACITY_MIN_AVAILABLE_BYTES - 1,
        ),
        (
            host_capacity_receipt(
                observed_at=CAPACITY_NOW,
                device_id=CAPACITY_DEVICE,
                total_bytes=CAPACITY_TOTAL,
            ),
            CAPACITY_NOW,
            0,
        ),
    ],
    ids=("missing", "malformed", "stale", "below-floor", "full"),
)
def test_qualification_capacity_gate_blocks_before_subprocess(
    monkeypatch: pytest.MonkeyPatch,
    receipt: object,
    now: datetime,
    available_bytes: int,
) -> None:
    module = _script("qualify_refresh_images.py")
    calls: list[list[str]] = []
    gate = module.QualificationCapacityGate(
        receipt=receipt,
        anchor=ROOT,
        clock=lambda: now,
        reader=lambda _anchor: HostCapacitySample(CAPACITY_DEVICE, CAPACITY_TOTAL, available_bytes),
    )

    def run(command: list[str], **_kwargs: object) -> subprocess.CompletedProcess[str]:
        calls.append(command)
        return subprocess.CompletedProcess(command, 0, stdout="", stderr="")

    monkeypatch.setattr(module.subprocess, "run", run)
    with pytest.raises(module.QualificationError, match="host capacity is not READY"):
        module._completed(
            ["docker-buildx", "version"],
            tools=_tool_paths(),
            capacity_gate=gate,
            capture=True,
        )
    assert calls == []


def test_qualification_rejects_noop_capacity_gate_before_subprocess(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    module = _script("qualify_refresh_images.py")
    calls: list[list[str]] = []

    class NoopGate:
        def require_current(self) -> None:
            return None

    def run(command: list[str], **_kwargs: object) -> subprocess.CompletedProcess[str]:
        calls.append(command)
        return subprocess.CompletedProcess(command, 0, stdout="", stderr="")

    monkeypatch.setattr(module.subprocess, "run", run)
    with pytest.raises(module.QualificationError, match="gate is not bound"):
        module._completed(
            ["docker-buildx", "version"],
            tools=_tool_paths(),
            capacity_gate=NoopGate(),
            capture=True,
        )
    assert calls == []


def test_qualification_capacity_gate_accepts_exact_age_limit(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    module = _script("qualify_refresh_images.py")
    calls: list[list[str]] = []
    gate = _capacity_gate(module, now=CAPACITY_NOW + timedelta(seconds=120))

    def run(command: list[str], **_kwargs: object) -> subprocess.CompletedProcess[str]:
        calls.append(command)
        return subprocess.CompletedProcess(command, 0, stdout="", stderr="")

    monkeypatch.setattr(module.subprocess, "run", run)
    completed = module._completed(
        ["docker-buildx", "version"],
        tools=_tool_paths(),
        capacity_gate=gate,
        capture=True,
    )
    assert completed.returncode == 0
    assert calls == [["/approved/tools/docker-buildx", "version"]]


def test_qualification_capacity_gate_rechecks_before_each_subprocess(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    module = _script("qualify_refresh_images.py")
    calls: list[list[str]] = []
    times = iter((CAPACITY_NOW, CAPACITY_NOW + timedelta(seconds=121)))
    gate = module.QualificationCapacityGate(
        receipt=host_capacity_receipt(
            observed_at=CAPACITY_NOW,
            device_id=CAPACITY_DEVICE,
            total_bytes=CAPACITY_TOTAL,
        ),
        anchor=ROOT,
        clock=lambda: next(times),
        reader=lambda _anchor: HostCapacitySample(
            CAPACITY_DEVICE, CAPACITY_TOTAL, HOST_CAPACITY_MIN_AVAILABLE_BYTES
        ),
    )

    def run(command: list[str], **_kwargs: object) -> subprocess.CompletedProcess[str]:
        calls.append(command)
        return subprocess.CompletedProcess(command, 0, stdout="", stderr="")

    monkeypatch.setattr(module.subprocess, "run", run)
    module._completed(
        ["docker-buildx", "version"],
        tools=_tool_paths(),
        capacity_gate=gate,
        capture=True,
    )
    with pytest.raises(module.QualificationError, match="host capacity is not READY"):
        module._completed(
            ["docker", "--context", module.DOCKER_CONTEXT, "info"],
            tools=_tool_paths(),
            capacity_gate=gate,
            capture=True,
        )
    assert calls == [["/approved/tools/docker-buildx", "version"]]


def test_qualification_snapshots_tools_into_private_digest_pinned_copies(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    module = _script("qualify_refresh_images.py")
    root = tmp_path / "repo"
    output_root = root / "tmp/qualification"
    output_root.mkdir(parents=True, mode=0o700)
    sources = tmp_path / "sources"
    sources.mkdir()
    docker = sources / "docker"
    buildx = sources / "docker-buildx"
    docker.write_bytes(b"docker-tool")
    buildx.write_bytes(b"buildx-tool")
    docker.chmod(0o500)
    buildx.chmod(0o500)
    monkeypatch.setattr(module, "ROOT", root)
    monkeypatch.setattr(
        module,
        "_resolved_tool",
        lambda name: {"docker": docker, "docker-buildx": buildx}[name],
    )

    tools = module._snapshot_tools(output_root, "docker-buildx")

    assert {name: path.read_bytes() for name, path in tools.items()} == {
        "docker": b"docker-tool",
        "docker-buildx": b"buildx-tool",
    }
    assert all(stat.S_IMODE(path.stat().st_mode) == 0o500 for path in tools.values())
    module._cleanup_tool_snapshot(tools)
    assert list(output_root.iterdir()) == []


def test_qualification_cleans_only_exact_pre_intent_tool_snapshot(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    module = _script("qualify_refresh_images.py")
    root = tmp_path / "repo"
    output_root = root / "tmp/qualification"
    snapshot_root = output_root / "tools"
    snapshot_root.mkdir(parents=True, mode=0o700)
    sources = tmp_path / "sources"
    sources.mkdir()
    source_paths: dict[str, Path] = {}
    for name in ("docker", "docker-buildx"):
        source = sources / name
        source.write_bytes(name.encode())
        source.chmod(0o500)
        snapshot = snapshot_root / name
        snapshot.write_bytes(source.read_bytes())
        snapshot.chmod(0o500)
        source_paths[name] = source
    monkeypatch.setattr(module, "ROOT", root)
    monkeypatch.setattr(module, "_resolved_tool", lambda name: source_paths[name])

    module._cleanup_orphan_tool_snapshot(output_root, "docker-buildx")

    assert list(output_root.iterdir()) == []


def test_qualification_rejects_group_writable_docker_socket(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    module = _script("qualify_refresh_images.py")
    socket_path = Path("/tmp") / f"mcp-trust-writable-{os.getpid()}.sock"
    listener = socket.socket(socket.AF_UNIX)
    try:
        listener.bind(socket_path.as_posix())
        socket_path.chmod(0o770)
        expected_host = "unix://" + socket_path.as_posix()
        monkeypatch.setattr(module, "EXPECTED_DOCKER_HOST", expected_host)
        monkeypatch.setattr(
            module,
            "_run",
            lambda *_args, **_kwargs: json.dumps(expected_host),
        )
        with pytest.raises(module.QualificationError, match="owner-bound"):
            module._execution_boundary(
                "docker-buildx",
                tools=_tool_paths(),
                capacity_gate=_capacity_gate(module),
            )
    finally:
        listener.close()
        socket_path.unlink(missing_ok=True)


def test_qualification_retains_only_owned_final_tag_after_post_load_failure(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    module = _script("qualify_refresh_images.py")
    payload = _inputs()
    config = copy.deepcopy(payload["cohorts"]["reference"])
    config["platform"] = payload["platform"]
    previous = "sha256:" + "a" * 64
    rebuilt = "sha256:" + "b" * 64
    final_reads = iter([previous, rebuilt, rebuilt])
    first_reads = iter([None, rebuilt])
    commands: list[list[str]] = []
    boundary_reads = 0

    def image_id(
        reference: str,
        *,
        tools: dict[str, Path],
        capacity_gate: object,
        required: bool = True,
    ) -> str | None:
        assert tools == _tool_paths()
        assert capacity_gate is gate
        reads = (
            first_reads
            if reference.startswith("mcp-trust-qualification:")
            else final_reads
        )
        return next(reads)

    def boundary(
        _buildx: str, *, tools: dict[str, Path], capacity_gate: object
    ) -> dict[str, object]:
        nonlocal boundary_reads
        assert tools == _tool_paths()
        assert capacity_gate is gate
        boundary_reads += 1
        if boundary_reads == 2:
            raise module.QualificationError("post-load boundary failure")
        return dict(module.EXECUTION_BOUNDARY)

    def run(command: list[str], **_kwargs: object) -> str:
        commands.append(command)
        return ""

    monkeypatch.setattr(module, "_require_safe_directory", lambda *_a, **_k: None)
    monkeypatch.setattr(module, "_require_private_directory", lambda *_a, **_k: None)
    monkeypatch.setattr(module, "_image_id", image_id)
    monkeypatch.setattr(module, "_execution_boundary", boundary)
    monkeypatch.setattr(
        module,
        "_tool_digests",
        lambda *_a, **_k: {"docker": previous, "docker_buildx": rebuilt},
    )
    monkeypatch.setattr(
        module,
        "_tool_versions",
        lambda *_a, **_k: {
            "docker_client": "1.0.0",
            "docker_server": "1.0.0",
            "docker_buildx": "v1.0.0",
            "buildkit_colima": "v1.0.0",
        },
    )
    monkeypatch.setattr(module, "_remove_tag", lambda *_a, **_k: None)
    monkeypatch.setattr(
        module,
        "_begin_attempt",
        lambda **_kwargs: (
            tmp_path / "attempt.json",
            {"cohort": "reference", "attempt_id": "1" * 64},
        ),
    )
    monkeypatch.setattr(module, "_write_ownership", lambda **_kwargs: tmp_path)
    monkeypatch.setattr(module, "_run", run)
    receipt_root = tmp_path / "v122-test"
    scoped = _scoped_capacity(receipt_set=receipt_root.name)
    gate = module.QualificationCapacityGate(
        receipt=scoped["host_capacity"],
        scope_receipt=scoped,
        anchor=ROOT,
        clock=lambda: CAPACITY_NOW,
        reader=lambda _anchor: HostCapacitySample(
            CAPACITY_DEVICE, CAPACITY_TOTAL, HOST_CAPACITY_MIN_AVAILABLE_BYTES
        ),
    )

    with pytest.raises(module.QualificationError, match="post-load"):
        module.qualify(
            "reference",
            config,
            buildx="docker-buildx",
            receipt_root=receipt_root,
            set_manifest={"receipt_digest": "sha256:" + "1" * 64},
            tools=_tool_paths(),
            capacity_gate=gate,
        )

    assert [
        "docker",
        "--context",
        "colima-mcp-trust-sandbox",
        "tag",
        previous,
        "mcp-trust-scan:corpus-2026-07-03",
    ] not in commands


def test_qualification_distinguishes_missing_image_from_daemon_failure(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    module = _script("qualify_refresh_images.py")

    def completed(stderr: str) -> subprocess.CompletedProcess[str]:
        return subprocess.CompletedProcess(
            ["docker", "image", "inspect"], 1, stdout="", stderr=stderr
        )

    monkeypatch.setattr(
        module,
        "_completed",
        lambda *_args, **_kwargs: completed(
            "Error response from daemon: No such image: mcp-trust:test"
        ),
    )
    assert (
        module._image_id(
            "mcp-trust:test",
            tools=_tool_paths(),
            capacity_gate=_capacity_gate(module),
            required=False,
        )
        is None
    )

    monkeypatch.setattr(
        module,
        "_completed",
        lambda *_args, **_kwargs: completed(
            "Cannot connect to the Docker daemon at unix:///tmp/docker.sock"
        ),
    )
    with pytest.raises(module.QualificationError, match="inspection failed"):
        module._image_id(
            "mcp-trust:test",
            tools=_tool_paths(),
            capacity_gate=_capacity_gate(module),
            required=False,
        )


def test_docker_context_excludes_qualification_outputs() -> None:
    assert "tmp/" in (ROOT / ".dockerignore").read_text(encoding="utf-8").splitlines()


@pytest.mark.parametrize(
    ("buildx_version", "inspect", "message"),
    [
        (
            "github.com/docker/buildx v0.30.0 0123456789ab",
            "Name: colima\nEndpoint: unix:///tmp/docker.sock\n",
            "BuildKit inspect",
        ),
        (
            "github.com/docker/buildx v0.30.0 0123456789ab",
            "BuildKit version: v0.25.1\nBuildKit version: v0.25.2\n",
            "BuildKit inspect",
        ),
        (
            "github.com/docker/buildx v0.30.0.999",
            "BuildKit version: v0.25.1\n",
            "docker buildx",
        ),
        (
            "release-v0.30.0",
            "BuildKit version: v0.25.1\n",
            "docker buildx",
        ),
    ],
)
def test_qualification_tool_versions_fail_closed_on_malformed_or_ambiguous_output(
    monkeypatch: pytest.MonkeyPatch,
    buildx_version: str,
    inspect: str,
    message: str,
) -> None:
    module = _script("qualify_refresh_images.py")

    def result(
        command: list[str],
        *,
        tools: dict[str, Path],
        capacity_gate: object,
        capture: bool = False,
    ) -> str:
        assert tools == _tool_paths()
        assert capacity_gate is not None
        assert capture is True
        if command[-1] == "version" and command[0] == "docker-buildx":
            return buildx_version
        if command[0] == "docker" and "version" in command:
            return "29.5.2"
        return inspect

    monkeypatch.setattr(module, "_run", result)
    with pytest.raises(module.QualificationError, match=message):
        module._tool_versions(
            "docker-buildx",
            tools=_tool_paths(),
            capacity_gate=_capacity_gate(module),
        )


def test_basic_memory_mutable_base_is_rejected_before_execution() -> None:
    payload = json.loads(
        (ROOT / "docker/refresh/source-build-inputs/basic-memory.json").read_text()
    )
    payload["python_base"] = "python:3.12"
    with pytest.raises(dependency_boundary.DependencyBoundaryError, match="immutable"):
        dependency_boundary.validate_source_build_inputs(payload)
