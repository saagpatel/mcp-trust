#!/usr/bin/env python3
"""Prepare the basic-memory offline bundle with sandboxed source builds.

Only exact URL/digest pairs are fetched.  The two source distributions execute
twice in separate, network-none, read-only-root containers.  Remaining wheels
are downloaded by hash with binary-only/no-dependency pip semantics; package
code is not executed in that networked step.
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
import urllib.request
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from mcp_trust import dependency_boundary

ROOT = Path(__file__).resolve().parents[1]
INPUT = ROOT / "docker/refresh/source-build-inputs/basic-memory.json"
LOCK_ROOT = ROOT / "docker/refresh/locks/basic-memory"
ARTIFACT = ROOT / "docker/refresh/.artifacts/basic-memory/python-wheels.tar"
DESCRIPTOR = ROOT / "docker/refresh/artifact-manifests/basic-memory/python.json"
RECEIPT = ROOT / "docker/refresh/source-builds/basic-memory.json"
BUILDER = ROOT / "scripts/build_legacy_python_wheels.py"


class PreparationError(RuntimeError):
    pass


def _canonical(payload: object) -> bytes:
    return json.dumps(payload, sort_keys=True, separators=(",", ":")).encode() + b"\n"


def _digest(content: bytes) -> str:
    return "sha256:" + hashlib.sha256(content).hexdigest()


def _digest_file(path: Path) -> str:
    return _digest(path.read_bytes())


def _write_new(path: Path, content: bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    try:
        if os.write(descriptor, content) != len(content):
            raise OSError("short write")
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def _run(command: list[str], *, capture: bool = False) -> str:
    completed = subprocess.run(command, text=True, capture_output=capture, check=False)
    if completed.returncode != 0:
        detail = completed.stderr.strip() if capture else "see command output"
        raise PreparationError(f"command failed ({completed.returncode}): {command[:3]}; {detail}")
    return completed.stdout.strip() if capture else ""


def _load_input() -> dict[str, Any]:
    payload = json.loads(INPUT.read_text(encoding="utf-8"))
    try:
        return dependency_boundary.validate_source_build_inputs(payload)
    except dependency_boundary.DependencyBoundaryError as exc:
        raise PreparationError(str(exc)) from exc


def _fetch_inputs(payload: dict[str, Any], destination: Path) -> None:
    destination.mkdir()
    for item in payload["inputs"]:
        request = urllib.request.Request(
            item["url"], headers={"User-Agent": "mcp-trust-review-only-preparer/1"}
        )
        with urllib.request.urlopen(request, timeout=60) as response:  # noqa: S310
            if response.geturl() != item["url"]:
                raise PreparationError("source input redirected outside its exact binding")
            content = response.read(5_000_001)
        if len(content) > 5_000_000 or hashlib.sha256(content).hexdigest() != item["sha256"]:
            raise PreparationError(f"source input digest mismatch: {item['filename']}")
        (destination / item["filename"]).write_bytes(content)


def _container_prefix(payload: dict[str, Any], work: Path, *, network: str) -> list[str]:
    return [
        "docker", "run", "--rm", "--network", network, "--read-only",
        "--cap-drop", "ALL", "--security-opt", "no-new-privileges",
        "--memory", "512m", "--memory-swap", "512m", "--pids-limit", "64",
        "--cpus", "1", "--tmpfs", "/tmp:rw,size=1g,mode=1777",
        "--env", "HOME=/tmp", "--env", "PYTHONDONTWRITEBYTECODE=1",
        "--env", "PYTHONHASHSEED=0", "--env", "SOURCE_DATE_EPOCH=1710000000",
        "--user", f"{os.getuid()}:{os.getgid()}",
        "--mount", f"type=bind,src={work.resolve()},dst=/work",
        "--workdir", "/work", payload["python_base"],
    ]


def _build_once(payload: dict[str, Any], source_inputs: Path, work: Path) -> dict[str, str]:
    shutil.copytree(source_inputs, work / "inputs")
    shutil.copyfile(BUILDER, work / "build_legacy_python_wheels.py")
    tools = [item for item in payload["inputs"] if item["role"] == "build-tool"]
    _run([
        *_container_prefix(payload, work, network="none"), "python", "-m", "pip", "install",
        "--disable-pip-version-check", "--quiet", "--no-index", "--no-deps", "--no-compile",
        "--target", "/work/build-tools",
        *[f"/work/inputs/{item['filename']}" for item in tools],
    ])
    _run([
        *_container_prefix(payload, work, network="none"), "env",
        "PYTHONPATH=/work/build-tools", "python", "/work/build_legacy_python_wheels.py",
    ])
    actual = {
        path.name: hashlib.sha256(path.read_bytes()).hexdigest()
        for path in sorted((work / "out").glob("*.whl"))
    }
    if actual != payload["expected_wheels"]:
        raise PreparationError(f"source-built wheel mismatch: {actual}")
    return actual


def _bundle_tree(source: Path, target: Path) -> dict[str, Any]:
    rows: list[dict[str, Any]] = []
    with tarfile.open(target, "w") as archive:
        for path in sorted(source.glob("*.whl")):
            content = path.read_bytes()
            info = tarfile.TarInfo(path.name)
            info.size = len(content)
            info.mtime = 0
            info.uid = info.gid = 0
            info.uname = info.gname = ""
            info.mode = 0o644
            archive.addfile(info, io.BytesIO(content))
            rows.append({"path": path.name, "size": len(content), "sha256": _digest(content)})
    if len(rows) != 167:
        raise PreparationError(f"wheelhouse denominator mismatch: {len(rows)}")
    return {
        "bundle_size": target.stat().st_size,
        "file_count": len(rows),
        "content_digest": _digest(_canonical(rows)),
    }


def _receipt(payload: dict[str, Any], wheels: dict[str, str], observed_at: str) -> dict[str, Any]:
    value: dict[str, Any] = {
        "schema": "McpTrustPythonSourceBuildReceiptV1",
        "observed_at": observed_at,
        "input_descriptor": {
            "path": INPUT.relative_to(ROOT).as_posix(), "sha256": _digest_file(INPUT)
        },
        "builder": {
            "path": BUILDER.relative_to(ROOT).as_posix(), "sha256": _digest_file(BUILDER)
        },
        "python_base": payload["python_base"],
        "platform": payload["platform"],
        "source_date_epoch": payload["source_date_epoch"],
        "network_policy": "none-during-all-package-code-execution",
        "sandbox_controls": {
            "read_only_root": True, "cap_drop": ["ALL"], "no_new_privileges": True,
            "memory": "512m", "pids": 64, "cpus": 1,
            "writable_mounts": ["task-owned-/work", "ephemeral-/tmp"], "secrets": "none",
        },
        "input_artifacts": payload["inputs"],
        "first_build_wheels": wheels,
        "second_build_wheels": wheels,
        "repeatable": True,
        "package_code_executed": True,
        "exit_classification": "QUALIFIED_REPEATABLE_NETWORK_NONE",
        "tool_versions": {
            "python": "Python 3.12.14",
            "pip": "pip 25.0.1",
            "setuptools": "80.9.0",
            "wheel": "0.45.1",
        },
    }
    value["receipt_digest"] = _digest(_canonical(value))
    return value


def prepare(*, create_receipts: bool) -> dict[str, Any]:
    payload = _load_input()
    if ARTIFACT.exists():
        raise PreparationError("basic-memory artifact already exists; preserve and review it")
    if create_receipts and (DESCRIPTOR.exists() or RECEIPT.exists()):
        raise PreparationError("source-build receipts already exist; preserve and review them")
    if not create_receipts and (not DESCRIPTOR.is_file() or not RECEIPT.is_file()):
        raise PreparationError("tracked source-build receipts are absent")
    with tempfile.TemporaryDirectory(prefix="mcp-trust-basic-memory-", dir=ROOT / "tmp") as temp:
        root = Path(temp)
        inputs = root / "inputs"
        _fetch_inputs(payload, inputs)
        first = root / "first"
        first.mkdir()
        second = root / "second"
        second.mkdir()
        first_wheels = _build_once(payload, inputs, first)
        second_wheels = _build_once(payload, inputs, second)
        if first_wheels != second_wheels:
            raise PreparationError("source wheel repeatability mismatch")
        wheelhouse = root / "wheelhouse"
        wheelhouse.mkdir()
        requirements_in = LOCK_ROOT / "requirements.in"
        requirements_lock = LOCK_ROOT / "requirements.lock"
        try:
            manifest = dependency_boundary.repository_file(
                ROOT, requirements_in.relative_to(ROOT).as_posix()
            )
            lock = dependency_boundary.repository_file(
                ROOT, requirements_lock.relative_to(ROOT).as_posix()
            )
            dependency_boundary.validate_python_lock(ROOT / manifest, ROOT / lock)
        except dependency_boundary.DependencyBoundaryError as exc:
            raise PreparationError("basic-memory lock escapes the source policy") from exc
        shutil.copyfile(requirements_lock, root / "requirements.lock")
        for path in (second / "out").glob("*.whl"):
            shutil.copyfile(path, wheelhouse / path.name)
        _run([
            *_container_prefix(payload, root, network="bridge"), "python", "-m", "pip", "download",
            "--disable-pip-version-check", "--quiet", "--require-hashes",
            "--only-binary=:all:", "--no-deps", "--dest", "/work/wheelhouse",
            "--find-links", "/work/wheelhouse", "--index-url", "https://pypi.org/simple",
            "-r", "/work/requirements.lock",
        ])
        bundle = root / "python-wheels.tar"
        metadata = _bundle_tree(wheelhouse, bundle)
        observed_at = datetime.now(tz=UTC).isoformat()
        source_receipt = _receipt(payload, first_wheels, observed_at)
        source_receipt_bytes = (
            json.dumps(source_receipt, indent=2, sort_keys=True).encode() + b"\n"
        )
        descriptor: dict[str, Any] = {
            "schema": "McpTrustDependencyArtifactBundleV1", "kind": "python",
            "registry_endpoints": ["https://files.pythonhosted.org", "https://pypi.org/simple"],
            "lock_sha256": _digest_file(LOCK_ROOT / "requirements.lock"),
            "bundle_path": ARTIFACT.relative_to(ROOT).as_posix(),
            "bundle_sha256": _digest_file(bundle), "prepared_at": observed_at,
            "tool_versions": {"python": "Python 3.12.14", "pip": "pip 25.0.1"},
            "preparation_network_policy": "registry-client-allowlist-build-code-network-none",
            "package_code_executed": True,
            "source_build_receipt": {
                "path": RECEIPT.relative_to(ROOT).as_posix(),
                "sha256": (
                    _digest(source_receipt_bytes)
                    if create_receipts
                    else _digest_file(RECEIPT)
                ),
            },
            **metadata,
        }
        if create_receipts:
            _write_new(
                RECEIPT,
                source_receipt_bytes,
            )
            _write_new(
                DESCRIPTOR,
                json.dumps(descriptor, indent=2, sort_keys=True).encode() + b"\n",
            )
        else:
            actual_receipt = json.loads(RECEIPT.read_text(encoding="utf-8"))
            actual_descriptor = json.loads(DESCRIPTOR.read_text(encoding="utf-8"))
            receipt_keys = (
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
            )
            for key in receipt_keys:
                if actual_receipt.get(key) != source_receipt.get(key):
                    raise PreparationError(f"source-build receipt drift: {key}")
            descriptor_keys = (
                "lock_sha256",
                "bundle_sha256",
                "bundle_size",
                "file_count",
                "content_digest",
                "source_build_receipt",
            )
            for key in descriptor_keys:
                if actual_descriptor.get(key) != descriptor.get(key):
                    raise PreparationError(f"materialized bundle drift: {key}")
        _write_new(ARTIFACT, bundle.read_bytes())
    return {
        "schema": "McpTrustBasicMemoryDependencyPreparationReceiptV1",
        "status": "PREPARED" if create_receipts else "MATERIALIZED",
        "source_build_repeatable": True, "package_code_network_policy": "none",
        "wheel_count": 167, "publication_allowed": False, "deployment_allowed": False,
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("mode", choices=("prepare", "materialize"))
    args = parser.parse_args()
    print(json.dumps(prepare(create_receipts=args.mode == "prepare"), sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
