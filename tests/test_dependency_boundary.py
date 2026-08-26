from __future__ import annotations

import copy
import importlib.util
import json
from pathlib import Path
from types import ModuleType

import pytest

from mcp_trust import dependency_boundary

ROOT = Path(__file__).resolve().parents[1]


def _script(name: str) -> ModuleType:
    path = ROOT / "scripts" / name
    spec = importlib.util.spec_from_file_location(path.stem, path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _inputs() -> dict[str, object]:
    return json.loads((ROOT / "docker/refresh/dependency-inputs.json").read_text())


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
        module.qualify("../escape", config, buildx="docker-buildx")


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


def test_basic_memory_mutable_base_is_rejected_before_execution() -> None:
    payload = json.loads(
        (ROOT / "docker/refresh/source-build-inputs/basic-memory.json").read_text()
    )
    payload["python_base"] = "python:3.12"
    with pytest.raises(dependency_boundary.DependencyBoundaryError, match="immutable"):
        dependency_boundary.validate_source_build_inputs(payload)
