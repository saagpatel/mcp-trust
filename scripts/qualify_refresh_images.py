#!/usr/bin/env python3
"""Build each approved refresh image twice and emit fail-closed receipts.

The builds consume only prepared local artifacts, run with BuildKit network
mode ``none``, bypass caches, and never publish an image or catalog artifact.
"""

from __future__ import annotations

import argparse
import json
import os
import re
import shutil
import subprocess
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from mcp_trust import grade_refresh

ROOT = Path(__file__).resolve().parents[1]
INPUTS = ROOT / "docker/refresh/dependency-inputs.json"
RECEIPT_ROOT = ROOT / "docker/refresh/qualification"
BUILD_OPTIONS = {
    "builder": "buildx",
    "cache": "disabled",
    "load": False,
    "output": "oci",
    "pull": False,
    "provenance": False,
    "rewrite_timestamps": True,
    "sbom": False,
}


class QualificationError(RuntimeError):
    pass


def _run(command: list[str], *, capture: bool = False) -> str:
    completed = subprocess.run(
        command,
        cwd=ROOT,
        text=True,
        capture_output=capture,
        check=False,
    )
    if completed.returncode != 0:
        detail = completed.stderr.strip() if capture else "see command output"
        raise QualificationError(
            f"command failed ({completed.returncode}): {command[0]} {command[1]}; {detail}"
        )
    return completed.stdout.strip() if capture else ""


def _write_new(path: Path, payload: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    content = json.dumps(payload, indent=2, sort_keys=True).encode() + b"\n"
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    try:
        written = os.write(descriptor, content)
        if written != len(content):
            raise OSError("short write")
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def _reference(path: str) -> dict[str, str]:
    absolute = ROOT / path
    if not absolute.is_file():
        raise QualificationError(f"required qualification input is absent: {path}")
    return {"path": path, "sha256": grade_refresh.digest_file(absolute)}


def _tool_versions(buildx: str) -> dict[str, str]:
    return {
        "docker_client": _run(
            ["docker", "version", "--format", "{{.Client.Version}}"], capture=True
        ),
        "docker_server": _run(
            ["docker", "version", "--format", "{{.Server.Version}}"], capture=True
        ),
        "docker_buildx": _run([buildx, "version"], capture=True),
        "buildkit_colima": _run([buildx, "inspect", "colima"], capture=True),
    }


def _dependency_inputs(
    cohort: str, config: dict[str, Any]
) -> tuple[
    dict[str, dict[str, str]],
    dict[str, dict[str, str]],
    dict[str, dict[str, str]],
    dict[str, str],
    dict[str, dict[str, Any]],
]:
    manifests: dict[str, dict[str, str]] = {}
    locks: dict[str, dict[str, str]] = {}
    artifacts: dict[str, dict[str, str]] = {}
    normalized_locks: dict[str, str] = {}
    normalized_artifacts: dict[str, dict[str, Any]] = {}
    kinds = [kind for kind in ("npm", "python") if config.get(kind)]
    if not kinds:
        raise QualificationError(f"cohort has no dependencies: {cohort}")
    for kind in kinds:
        if kind == "npm":
            manifest_path = f"docker/refresh/locks/{cohort}/package.json"
            lock_path = f"docker/refresh/locks/{cohort}/package-lock.json"
        else:
            manifest_path = f"docker/refresh/locks/{cohort}/requirements.in"
            lock_path = f"docker/refresh/locks/{cohort}/requirements.lock"
        descriptor_path = f"docker/refresh/artifact-manifests/{cohort}/{kind}.json"
        manifest_ref = _reference(manifest_path)
        lock_ref = _reference(lock_path)
        artifact_ref = _reference(descriptor_path)
        normalized = grade_refresh._dependency_artifact(
            repo_root=ROOT,
            kind=kind,
            lock_sha256=lock_ref["sha256"],
            value=artifact_ref,
        )
        if normalized is None:
            raise QualificationError(f"dependency artifact failed verification: {cohort}/{kind}")
        manifests[kind] = manifest_ref
        locks[kind] = lock_ref
        artifacts[kind] = artifact_ref
        normalized_locks[lock_path] = lock_ref["sha256"]
        normalized_artifacts[kind] = normalized
    return manifests, locks, artifacts, normalized_locks, normalized_artifacts


def _image_id(reference: str) -> str:
    image_id = _run(
        ["docker", "image", "inspect", "--format", "{{.Id}}", reference],
        capture=True,
    )
    if re.fullmatch(r"sha256:[0-9a-f]{64}", image_id) is None:
        raise QualificationError(f"invalid local image id for {reference}")
    return image_id


def qualify(cohort: str, config: dict[str, Any], *, buildx: str) -> Path:
    receipt = RECEIPT_ROOT / f"{cohort}.json"
    if receipt.exists():
        raise QualificationError(f"qualification receipt already exists: {receipt.name}")
    image_reference = str(config["image_reference"])
    dockerfile = str(config["dockerfile"])
    build_source_sha256 = grade_refresh.digest_file(ROOT / dockerfile)
    base_images = sorted({str(config["node_base"]), str(config["python_base"])})
    manifests, locks, artifacts, normalized_locks, normalized_artifacts = (
        _dependency_inputs(cohort, config)
    )
    platform_name = str(config["platform"])
    build_input = {
        "build_source_sha256": build_source_sha256,
        "base_images": base_images,
        "platform": platform_name,
        "dependency_manifests": manifests,
        "dependency_locks": dict(sorted(normalized_locks.items())),
        "dependency_artifacts": normalized_artifacts,
        "build_options": BUILD_OPTIONS,
    }
    common = [
        buildx,
        "build",
        "--builder",
        "colima",
        "--network",
        "none",
        "--pull=false",
        "--no-cache",
        "--platform",
        platform_name,
        "--provenance=false",
        "--sbom=false",
        "--build-arg",
        "SOURCE_DATE_EPOCH=1710000000",
        "-f",
        dockerfile,
    ]
    output_root = ROOT / "tmp/qualification"
    output_root.mkdir(parents=True, exist_ok=True)
    first_output = f"tmp/qualification/{cohort}-first.oci.tar"
    second_output = f"tmp/qualification/{cohort}-second.oci.tar"
    if (ROOT / first_output).exists() or (ROOT / second_output).exists():
        raise QualificationError(f"qualification output already exists: {cohort}")
    first_reference = f"mcp-trust-qualification:{cohort}-first"
    first_command = [
        *common,
        f"--output=type=oci,dest={first_output},rewrite-timestamp=true",
        "-t",
        first_reference,
        ".",
    ]
    second_command = [
        *common,
        f"--output=type=oci,dest={second_output},rewrite-timestamp=true",
        "-t",
        image_reference,
        ".",
    ]
    first_load = ["docker", "load", "-i", first_output]
    second_load = ["docker", "load", "-i", second_output]
    _run(first_command)
    _run(first_load)
    first_id = _image_id(first_reference)
    _run(second_command)
    _run(second_load)
    second_id = _image_id(image_reference)
    if first_id != second_id:
        raise QualificationError(
            f"repeat builds differed for {cohort}: {first_id} != {second_id}"
        )
    payload: dict[str, Any] = {
        "schema": grade_refresh.IMAGE_BUILD_QUALIFICATION_SCHEMA,
        "observed_at": datetime.now(tz=UTC).isoformat(),
        "exit_classification": "QUALIFIED_REPEATABLE",
        "qualification_max_age_seconds": 86_400,
        "image_reference": image_reference,
        "platform": platform_name,
        "build_source_sha256": build_source_sha256,
        "build_input_digest": grade_refresh.digest_bytes(
            grade_refresh.canonical_bytes(build_input)
        ),
        "base_images": base_images,
        "dependency_manifests": manifests,
        "dependency_locks": locks,
        "dependency_artifacts": artifacts,
        "build_network_policy": ["none"],
        "build_options": BUILD_OPTIONS,
        "build_commands": [first_command, second_command],
        "load_commands": [first_load, second_load],
        "tool_versions": _tool_versions(buildx),
        "first_build_image_id": first_id,
        "second_build_image_id": second_id,
        "repeatable": True,
    }
    payload["receipt_digest"] = grade_refresh.digest_bytes(
        grade_refresh.canonical_bytes(payload)
    )
    _write_new(receipt, payload)
    validated = grade_refresh._image_build_qualification(
        repo_root=ROOT,
        reference=image_reference,
        build_source=dockerfile,
        build_source_sha256=build_source_sha256,
        receipt_path=receipt.relative_to(ROOT).as_posix(),
    )
    if validated is None:
        raise QualificationError(f"generated receipt failed readback verification: {cohort}")
    (ROOT / first_output).unlink()
    (ROOT / second_output).unlink()
    return receipt


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--cohort",
        action="append",
        choices=("reference", "live-batch", "batch3", "batch4"),
        help="qualify only the named cohort; may be repeated",
    )
    args = parser.parse_args()
    payload = grade_refresh.load_json(INPUTS)
    if not isinstance(payload, dict) or payload.get("schema") != (
        "McpTrustDependencyPreparationInputsV1"
    ):
        raise QualificationError("dependency preparation input schema is invalid")
    cohorts = payload.get("cohorts")
    if not isinstance(cohorts, dict):
        raise QualificationError("dependency cohort input is invalid")
    buildx = shutil.which("docker-buildx")
    if buildx is None:
        raise QualificationError("docker-buildx executable is unavailable")
    names = args.cohort or ["reference", "live-batch", "batch3", "batch4"]
    for name in names:
        config = cohorts.get(name)
        if not isinstance(config, dict):
            raise QualificationError(f"dependency cohort is unavailable: {name}")
        config = {**config, "platform": payload.get("platform")}
        receipt = qualify(name, config, buildx=buildx)
        print(f"QUALIFIED {name} {receipt.relative_to(ROOT)}")
    print("NO_PUBLICATION NO_DEPLOYMENT NO_SCHEDULER_MUTATION")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
