#!/usr/bin/env python3
"""Prepare locked offline dependency bundles for the review-only refresh images.

Preparation uses only pinned official tool images. Registry clients are pointed
at the declared npm/PyPI endpoints and package lifecycle/build code is disabled.
The resulting bundles are local ignored artifacts; their tracked descriptors
bind every byte consumed by the later network-none qualification builds.
"""

from __future__ import annotations

import argparse
import hashlib
import io
import json
import os
import shutil
import subprocess
import tarfile
import tempfile
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from mcp_trust import dependency_boundary

ROOT = Path(__file__).resolve().parents[1]
INPUTS = ROOT / "docker/refresh/dependency-inputs.json"
LOCK_ROOT = ROOT / "docker/refresh/locks"
ARTIFACT_ROOT = ROOT / "docker/refresh/.artifacts"
DESCRIPTOR_ROOT = ROOT / "docker/refresh/artifact-manifests"
SCHEMA = "McpTrustDependencyPreparationInputsV1"


class PreparationError(RuntimeError):
    pass


def _canonical(payload: object) -> bytes:
    return (
        json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode()
        + b"\n"
    )


def _digest(content: bytes) -> str:
    return "sha256:" + hashlib.sha256(content).hexdigest()


def _digest_file(path: Path) -> str:
    return _digest(path.read_bytes())


def _write_new(path: Path, content: bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    try:
        written = os.write(descriptor, content)
        if written != len(content):
            raise OSError("short write")
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def _run(command: list[str], *, capture: bool = False) -> str:
    completed = subprocess.run(
        command,
        text=True,
        capture_output=capture,
        check=False,
    )
    if completed.returncode != 0:
        detail = completed.stderr.strip() if capture else "see command output"
        raise PreparationError(
            f"command failed ({completed.returncode}): {command[0]} {command[1]}; {detail}"
        )
    return completed.stdout.strip() if capture else ""


def _container_prefix(*, image: str, work: Path | None, network: str) -> list[str]:
    command = [
        "docker",
        "run",
        "--rm",
        "--network",
        network,
        "--read-only",
        "--cap-drop",
        "ALL",
        "--security-opt",
        "no-new-privileges",
        "--memory",
        "2g",
        "--memory-swap",
        "2g",
        "--pids-limit",
        "256",
        "--cpus",
        "2",
        "--tmpfs",
        "/tmp:rw,size=1g,mode=1777",
        "--env",
        "HOME=/tmp",
        "--env",
        "NPM_CONFIG_AUDIT=false",
        "--env",
        "NPM_CONFIG_FUND=false",
        "--env",
        "UV_CACHE_DIR=/tmp/uv-cache",
        "--user",
        f"{os.getuid()}:{os.getgid()}",
    ]
    if work is not None:
        command += [
            "--mount",
            f"type=bind,src={work.resolve()},dst=/work",
            "--workdir",
            "/work",
        ]
    return [*command, image]


def _tool_version(image: str, command: list[str]) -> str:
    return _run(
        [*_container_prefix(image=image, work=None, network="none"), *command],
        capture=True,
    )


def _build_uv_python_image(payload: dict[str, Any]) -> str:
    preparation = payload.get("preparation_images")
    if not isinstance(preparation, dict) or set(preparation) != {
        "uv_python_dockerfile",
        "uv_python_reference",
    }:
        raise PreparationError("uv preparation image descriptor is invalid")
    try:
        dockerfile = dependency_boundary.repository_file(
            ROOT, preparation["uv_python_dockerfile"]
        )
        reference = dependency_boundary.local_image_tag(
            preparation["uv_python_reference"], prefix="mcp-trust-dependency-prep:"
        )
    except dependency_boundary.DependencyBoundaryError as exc:
        raise PreparationError("uv preparation image source is invalid") from exc
    buildx = shutil.which("docker-buildx")
    if buildx is None:
        raise PreparationError("docker-buildx executable is unavailable")
    _run(
        [
            buildx,
            "build",
            "--builder",
            "colima",
            "--network",
            "none",
            "--pull=false",
            "--no-cache",
            "--platform",
            str(payload["platform"]),
            "--provenance=false",
            "--sbom=false",
            "--load",
            "-f",
            dockerfile,
            "-t",
            reference,
            ".",
        ]
    )
    try:
        return dependency_boundary.immutable_image_id(
            _run(
                ["docker", "image", "inspect", "--format", "{{.Id}}", reference],
                capture=True,
            )
        )
    except dependency_boundary.DependencyBoundaryError as exc:
        raise PreparationError("uv preparation image id is invalid") from exc


def _bundle_tree(source: Path, target: Path) -> dict[str, Any]:
    rows: list[dict[str, Any]] = []
    with tarfile.open(target, "w") as archive:
        for path in sorted(item for item in source.rglob("*") if item.is_file()):
            relative = path.relative_to(source).as_posix()
            content = path.read_bytes()
            info = tarfile.TarInfo(relative)
            info.size = len(content)
            info.mtime = 0
            info.uid = 0
            info.gid = 0
            info.uname = ""
            info.gname = ""
            info.mode = 0o644
            archive.addfile(info, fileobj=io.BytesIO(content))
            rows.append({"path": relative, "size": len(content), "sha256": _digest(content)})
    if not rows:
        raise PreparationError(f"offline dependency tree is empty: {source.name}")
    return {
        "bundle_size": target.stat().st_size,
        "file_count": len(rows),
        "content_digest": _digest(_canonical(rows)),
    }


def _normalize_npm_cache(cache: Path, *, source_date_epoch: int) -> None:
    """Remove fetch-time-only cacache metadata while preserving offline keys."""
    index = cache / "index-v5"
    if not index.is_dir():
        raise PreparationError("npm cache index is absent")
    fixed_milliseconds = source_date_epoch * 1000
    for path in sorted(item for item in index.rglob("*") if item.is_file()):
        normalized: dict[str, dict[str, Any]] = {}
        try:
            lines = path.read_text(encoding="utf-8").splitlines()
        except (OSError, UnicodeError) as exc:
            raise PreparationError("npm cache index is unreadable") from exc
        for line in lines:
            if not line:
                continue
            try:
                _, raw = line.split("\t", 1)
                entry = json.loads(raw)
                key = entry["key"]
                integrity = entry["integrity"]
                size = entry["size"]
            except (KeyError, TypeError, ValueError, json.JSONDecodeError) as exc:
                raise PreparationError("npm cache index entry is invalid") from exc
            metadata = entry.get("metadata")
            url = metadata.get("url") if isinstance(metadata, dict) else None
            if (
                not isinstance(key, str)
                or not key.startswith("make-fetch-happen:request-cache:https://registry.npmjs.org/")
                or not isinstance(integrity, str)
                or not integrity.startswith("sha512-")
                or type(size) is not int
                or size <= 0
                or not isinstance(url, str)
                or not url.startswith("https://registry.npmjs.org/")
            ):
                raise PreparationError("npm cache index entry escapes the registry policy")
            normalized[key] = {
                "key": key,
                "integrity": integrity,
                "time": fixed_milliseconds,
                "size": size,
                "metadata": {
                    "time": fixed_milliseconds,
                    "url": url,
                    "reqHeaders": {},
                    "resHeaders": {"content-type": "application/octet-stream"},
                    "options": {"compress": True},
                },
            }
        content = bytearray()
        for key in sorted(normalized):
            raw = json.dumps(
                normalized[key], sort_keys=True, separators=(",", ":")
            ).encode()
            checksum = hashlib.sha1(raw, usedforsecurity=False).hexdigest().encode()
            content.extend(b"\n" + checksum + b"\t" + raw)
        if not content:
            raise PreparationError("npm cache index file has no entries")
        path.write_bytes(content)


def _package_json(cohort: str, packages: dict[str, str]) -> dict[str, Any]:
    return {
        "name": f"mcp-trust-refresh-{cohort}",
        "version": "1.0.0",
        "private": True,
        "dependencies": dict(sorted(packages.items())),
    }


def _prepare_npm(
    *,
    cohort: str,
    config: dict[str, Any],
    work: Path,
    prepared_at: str,
    source_date_epoch: int,
) -> tuple[dict[str, bytes], bytes, dict[str, Any]]:
    node_image = str(config["node_base"])
    package_json = work / "package.json"
    package_lock = work / "package-lock.json"
    cache = work / "npm-cache"
    package_json.write_bytes(_canonical(_package_json(cohort, config["npm"])))
    prefix = _container_prefix(image=node_image, work=work, network="bridge")
    _run(
        [
            *prefix,
            "npm",
            "install",
            "--package-lock-only",
            "--ignore-scripts",
            "--registry=https://registry.npmjs.org",
            "--no-audit",
            "--no-fund",
        ]
    )
    try:
        dependency_boundary.validate_npm_lock(package_json, package_lock)
    except dependency_boundary.DependencyBoundaryError as exc:
        raise PreparationError("generated npm lock escapes the source policy") from exc
    _run(
        [
            *prefix,
            "npm",
            "ci",
            "--ignore-scripts",
            "--registry=https://registry.npmjs.org",
            "--cache=/work/npm-cache",
            "--no-audit",
            "--no-fund",
        ]
    )
    cacache = cache / "_cacache"
    _normalize_npm_cache(cacache, source_date_epoch=source_date_epoch)
    bundle = work / "npm-cache.tar"
    metadata = _bundle_tree(cacache, bundle)
    lock_digest = _digest_file(package_lock)
    descriptor = {
        "schema": "McpTrustDependencyArtifactBundleV1",
        "kind": "npm",
        "registry_endpoints": ["https://registry.npmjs.org"],
        "lock_sha256": lock_digest,
        "bundle_path": f"docker/refresh/.artifacts/{cohort}/npm-cache.tar",
        "bundle_sha256": _digest_file(bundle),
        "prepared_at": prepared_at,
        "tool_versions": {
            "node": _tool_version(node_image, ["node", "--version"]),
            "npm": _tool_version(node_image, ["npm", "--version"]),
        },
        "preparation_network_policy": "registry-client-allowlist-no-package-code",
        "package_code_executed": False,
        **metadata,
    }
    tracked = {
        "package.json": package_json.read_bytes(),
        "package-lock.json": package_lock.read_bytes(),
    }
    return tracked, bundle.read_bytes(), descriptor


def _prepare_python(
    *,
    cohort: str,
    requirements: list[str],
    python_base: str,
    uv_image: str,
    python_version: str,
    platform_name: str,
    work: Path,
    prepared_at: str,
) -> tuple[dict[str, bytes], bytes, dict[str, Any]] | None:
    if not requirements:
        return None
    requirements_in = work / "requirements.in"
    requirements_lock = work / "requirements.lock"
    wheelhouse = work / "wheelhouse"
    wheelhouse.mkdir()
    requirements_in.write_text("\n".join(requirements) + "\n", encoding="utf-8")
    uv_platform = {
        "linux/arm64": "aarch64-manylinux_2_17",
        "linux/amd64": "x86_64-manylinux_2_17",
    }[platform_name]
    _run(
        [
            *_container_prefix(image=uv_image, work=work, network="bridge"),
            "pip",
            "compile",
            "requirements.in",
            "--output-file",
            "requirements.lock",
            "--generate-hashes",
            "--no-annotate",
            "--no-header",
            "--only-binary",
            ":all:",
            "--no-sources",
            "--python-version",
            python_version,
            "--python-platform",
            uv_platform,
            "--exclude-newer",
            "2026-08-23T00:00:00Z",
            "--default-index",
            "https://pypi.org/simple",
            "--no-progress",
        ]
    )
    try:
        dependency_boundary.validate_python_lock(requirements_in, requirements_lock)
    except dependency_boundary.DependencyBoundaryError as exc:
        raise PreparationError("generated python lock escapes the source policy") from exc
    _run(
        [
            *_container_prefix(image=python_base, work=work, network="bridge"),
            "python",
            "-m",
            "pip",
            "download",
            "--require-hashes",
            "--only-binary=:all:",
            "--no-deps",
            "--dest",
            "/work/wheelhouse",
            "--index-url",
            "https://pypi.org/simple",
            "-r",
            "/work/requirements.lock",
        ]
    )
    bundle = work / "python-wheels.tar"
    metadata = _bundle_tree(wheelhouse, bundle)
    descriptor = {
        "schema": "McpTrustDependencyArtifactBundleV1",
        "kind": "python",
        "registry_endpoints": [
            "https://files.pythonhosted.org",
            "https://pypi.org/simple",
        ],
        "lock_sha256": _digest_file(requirements_lock),
        "bundle_path": f"docker/refresh/.artifacts/{cohort}/python-wheels.tar",
        "bundle_sha256": _digest_file(bundle),
        "prepared_at": prepared_at,
        "tool_versions": {
            "python": _tool_version(python_base, ["python", "--version"]),
            "pip": _tool_version(python_base, ["python", "-m", "pip", "--version"]),
            "uv": _tool_version(uv_image, ["--version"]),
        },
        "preparation_network_policy": "registry-client-allowlist-no-package-code",
        "package_code_executed": False,
        **metadata,
    }
    tracked = {
        "requirements.in": requirements_in.read_bytes(),
        "requirements.lock": requirements_lock.read_bytes(),
    }
    return tracked, bundle.read_bytes(), descriptor


def _validate_inputs(payload: object) -> dict[str, Any]:
    try:
        return dependency_boundary.validate_preparation_inputs(payload, repo_root=ROOT)
    except dependency_boundary.DependencyBoundaryError as exc:
        raise PreparationError(str(exc)) from exc


def _validate_tracked_dependency_inputs(cohort: str, config: dict[str, Any]) -> None:
    try:
        if config["npm"]:
            manifest = dependency_boundary.repository_file(
                ROOT, f"docker/refresh/locks/{cohort}/package.json"
            )
            lock = dependency_boundary.repository_file(
                ROOT, f"docker/refresh/locks/{cohort}/package-lock.json"
            )
            dependency_boundary.validate_npm_lock(
                ROOT / manifest,
                ROOT / lock,
            )
        if config["python"]:
            manifest = dependency_boundary.repository_file(
                ROOT, f"docker/refresh/locks/{cohort}/requirements.in"
            )
            lock = dependency_boundary.repository_file(
                ROOT, f"docker/refresh/locks/{cohort}/requirements.lock"
            )
            dependency_boundary.validate_python_lock(
                ROOT / manifest,
                ROOT / lock,
            )
    except dependency_boundary.DependencyBoundaryError as exc:
        raise PreparationError(f"dependency source policy failed: {cohort}") from exc


def _verify_materialized_bundle(
    *, cohort: str, kind: str, lock_path: Path, bundle: Path, metadata: dict[str, Any]
) -> None:
    descriptor_path = DESCRIPTOR_ROOT / cohort / f"{kind}.json"
    try:
        descriptor = json.loads(descriptor_path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise PreparationError(f"artifact descriptor is unreadable: {cohort}/{kind}") from exc
    expected = {
        "lock_sha256": _digest_file(lock_path),
        "bundle_sha256": _digest_file(bundle),
        **metadata,
    }
    if any(descriptor.get(key) != value for key, value in expected.items()):
        raise PreparationError(f"materialized bundle differs from descriptor: {cohort}/{kind}")


def materialize(*, inputs_path: Path, cohorts: list[str] | None = None) -> dict[str, Any]:
    """Recreate ignored bundles from committed locks without resolving versions."""
    payload = _validate_inputs(json.loads(inputs_path.read_text(encoding="utf-8")))
    selected = cohorts or sorted(
        name
        for name, config in payload["cohorts"].items()
        if "source_build_preparer" not in config
    )
    unknown = sorted(set(selected) - set(payload["cohorts"]))
    if unknown:
        raise PreparationError("unknown dependency cohort requested")
    if any("source_build_preparer" in payload["cohorts"][name] for name in selected):
        raise PreparationError("source-build cohort requires its dedicated preparer")
    collisions = [ARTIFACT_ROOT / name for name in selected if (ARTIFACT_ROOT / name).exists()]
    if collisions:
        raise PreparationError("dependency artifacts already exist; preserve and review them")
    staged: dict[str, dict[str, bytes]] = {}
    temporary_parent = ROOT / "tmp"
    temporary_parent.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(
        prefix="mcp-trust-dependency-materialize-", dir=temporary_parent
    ) as temp:
        temporary = Path(temp)
        for name in selected:
            config = payload["cohorts"][name]
            _validate_tracked_dependency_inputs(name, config)
            work = temporary / name
            work.mkdir()
            package_json = LOCK_ROOT / name / "package.json"
            package_lock = LOCK_ROOT / name / "package-lock.json"
            shutil.copyfile(package_json, work / "package.json")
            shutil.copyfile(package_lock, work / "package-lock.json")
            prefix = _container_prefix(
                image=str(config["node_base"]), work=work, network="bridge"
            )
            _run(
                [
                    *prefix,
                    "npm",
                    "ci",
                    "--ignore-scripts",
                    "--registry=https://registry.npmjs.org",
                    "--cache=/work/npm-cache",
                    "--no-audit",
                    "--no-fund",
                ]
            )
            cacache = work / "npm-cache/_cacache"
            _normalize_npm_cache(
                cacache, source_date_epoch=payload["source_date_epoch"]
            )
            npm_bundle = work / "npm-cache.tar"
            npm_metadata = _bundle_tree(cacache, npm_bundle)
            _verify_materialized_bundle(
                cohort=name,
                kind="npm",
                lock_path=package_lock,
                bundle=npm_bundle,
                metadata=npm_metadata,
            )
            bundles = {"npm-cache.tar": npm_bundle.read_bytes()}
            if config["python"]:
                requirements_lock = LOCK_ROOT / name / "requirements.lock"
                shutil.copyfile(requirements_lock, work / "requirements.lock")
                wheelhouse = work / "wheelhouse"
                wheelhouse.mkdir()
                _run(
                    [
                        *_container_prefix(
                            image=str(config["python_base"]),
                            work=work,
                            network="bridge",
                        ),
                        "python",
                        "-m",
                        "pip",
                        "download",
                        "--require-hashes",
                        "--only-binary=:all:",
                        "--no-deps",
                        "--dest",
                        "/work/wheelhouse",
                        "--index-url",
                        "https://pypi.org/simple",
                        "-r",
                        "/work/requirements.lock",
                    ]
                )
                python_bundle = work / "python-wheels.tar"
                python_metadata = _bundle_tree(wheelhouse, python_bundle)
                _verify_materialized_bundle(
                    cohort=name,
                    kind="python",
                    lock_path=requirements_lock,
                    bundle=python_bundle,
                    metadata=python_metadata,
                )
                bundles["python-wheels.tar"] = python_bundle.read_bytes()
            staged[name] = bundles
    for name in selected:
        for filename, content in staged[name].items():
            _write_new(ARTIFACT_ROOT / name / filename, content)
    return {
        "schema": "McpTrustDependencyMaterializationReceiptV1",
        "status": "MATERIALIZED",
        "cohorts": selected,
        "package_code_executed": False,
        "network_policy": "registry-client-endpoints-no-package-code",
        "publication_allowed": False,
        "deployment_allowed": False,
    }


def prepare(*, inputs_path: Path, cohorts: list[str] | None = None) -> dict[str, Any]:
    payload = _validate_inputs(json.loads(inputs_path.read_text(encoding="utf-8")))
    selected = cohorts or sorted(
        name
        for name, config in payload["cohorts"].items()
        if "source_build_preparer" not in config
    )
    unknown = sorted(set(selected) - set(payload["cohorts"]))
    if unknown:
        raise PreparationError("unknown dependency cohort requested")
    if any("source_build_preparer" in payload["cohorts"][name] for name in selected):
        raise PreparationError("source-build cohort requires its dedicated preparer")
    collisions = [
        path
        for name in selected
        for path in (LOCK_ROOT / name, ARTIFACT_ROOT / name, DESCRIPTOR_ROOT / name)
        if path.exists()
    ]
    if collisions:
        raise PreparationError("dependency outputs already exist; preserve and review them")
    uv_image = _build_uv_python_image(payload)
    prepared_at = datetime.now(tz=UTC).isoformat()
    staged: dict[str, dict[str, Any]] = {}
    temporary_parent = ROOT / "tmp"
    temporary_parent.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(
        prefix="mcp-trust-dependency-prep-", dir=temporary_parent
    ) as temp:
        temporary = Path(temp)
        for name in selected:
            config = payload["cohorts"][name]
            work = temporary / name
            work.mkdir()
            npm_tracked, npm_bundle, npm_descriptor = _prepare_npm(
                cohort=name,
                config=config,
                work=work,
                prepared_at=prepared_at,
                source_date_epoch=payload["source_date_epoch"],
            )
            python_result = _prepare_python(
                cohort=name,
                requirements=config["python"],
                python_base=config["python_base"],
                uv_image=uv_image,
                python_version=config["python_version"],
                platform_name=payload["platform"],
                work=work,
                prepared_at=prepared_at,
            )
            tracked = dict(npm_tracked)
            bundles = {"npm-cache.tar": npm_bundle}
            descriptors = {"npm.json": _canonical(npm_descriptor)}
            if python_result is not None:
                python_tracked, python_bundle, python_descriptor = python_result
                tracked.update(python_tracked)
                bundles["python-wheels.tar"] = python_bundle
                descriptors["python.json"] = _canonical(python_descriptor)
            staged[name] = {
                "tracked": tracked,
                "bundles": bundles,
                "descriptors": descriptors,
            }
    for name in selected:
        for filename, content in staged[name]["tracked"].items():
            _write_new(LOCK_ROOT / name / filename, content)
        for filename, content in staged[name]["bundles"].items():
            _write_new(ARTIFACT_ROOT / name / filename, content)
        for filename, content in staged[name]["descriptors"].items():
            _write_new(DESCRIPTOR_ROOT / name / filename, content)
    return {
        "schema": "McpTrustDependencyPreparationReceiptV1",
        "status": "PREPARED",
        "prepared_at": prepared_at,
        "cohorts": selected,
        "package_code_executed": False,
        "network_policy": "registry-client-allowlist-no-package-code",
        "publication_allowed": False,
        "deployment_allowed": False,
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--inputs", type=Path, default=INPUTS)
    parser.add_argument("--cohort", action="append", dest="cohorts")
    parser.add_argument(
        "--materialize",
        action="store_true",
        help="recreate ignored bundles from existing committed locks",
    )
    args = parser.parse_args()
    try:
        receipt = (
            materialize(inputs_path=args.inputs, cohorts=args.cohorts)
            if args.materialize
            else prepare(inputs_path=args.inputs, cohorts=args.cohorts)
        )
    except (OSError, UnicodeError, json.JSONDecodeError, PreparationError) as exc:
        print(
            json.dumps(
                {
                    "schema": "McpTrustDependencyPreparationErrorV1",
                    "status": "UNKNOWN",
                    "error": str(exc),
                    "publication_allowed": False,
                    "deployment_allowed": False,
                },
                sort_keys=True,
            )
        )
        return 2
    print(json.dumps(receipt, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
