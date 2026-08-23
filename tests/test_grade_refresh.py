from __future__ import annotations

import io
import json
import subprocess
import tarfile
from datetime import UTC, datetime
from pathlib import Path

import pytest

import mcp_trust.grade_refresh as grade_refresh
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

ROOT = Path(__file__).resolve().parents[1]
SEED = ROOT / "src/mcp_trust/catalog/seed_servers.json"
MASKED = ROOT / "masked-grades.json"
POLICY = ROOT / "src/mcp_trust/catalog/refresh_policy.json"
NOW = datetime(2026, 8, 23, 13, 0, tzinfo=UTC)


def test_inventory_classifies_every_catalog_entry() -> None:
    inventory = catalog_inventory(seed_path=SEED, masked_path=MASKED, policy_path=POLICY)

    assert inventory["catalog_denominator"] == 31
    assert len(inventory["entries"]) == 31
    assert inventory["counts"] == {
        "scannable": 30,
        "blocked": 1,
        "intentionally_masked": 8,
        "unsupported_upstream": 8,
        "credential_dependent": 7,
        "backing_service_dependent": 10,
        "unsafe_to_execute_unsandboxed": 31,
        "missing_image_build_source": 0,
        "unqualified_image_build_source": 1,
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
        now=NOW,
        runner=runner,
    )

    assert receipt["status"] == "BLOCKED"
    assert receipt["safe_to_execute_catalog"] is False
    assert len(receipt["sandbox"]["image_bindings"]) == 4
    assert all(row["state"] == "MISSING" for row in receipt["sandbox"]["image_bindings"])
    assert sum(reason.startswith("catalog_image_missing:") for reason in receipt["reasons"]) == 4
    assert receipt["authority"]["publication"] is False


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
        now=NOW,
        runner=runner,
    )

    assert receipt["status"] == "BLOCKED"
    assert receipt["safe_to_execute_catalog"] is False
    assert not any(
        reason.startswith("image_build_reproducibility_unknown:")
        for reason in receipt["reasons"]
    )
    assert sum(
        reason.startswith("image_build_qualification_invalid:")
        for reason in receipt["reasons"]
    ) == 4
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
    }
    image_id = "sha256:" + "c" * 64
    command = [
        "docker-buildx",
        "build",
        "--network",
        "none",
        "--pull=false",
        "--no-cache",
        "--platform",
        "linux/arm64",
        "--provenance=false",
        "--sbom=false",
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
        "build_commands": [],
        "load_commands": [],
        "tool_versions": {"docker": "29.5.2"},
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
            "mcp-trust-qualification:test-first",
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
        ["docker", "load", "-i", output_paths[0]],
        ["docker", "load", "-i", output_paths[1]],
    ]
    payload["receipt_digest"] = grade_refresh.digest_bytes(
        grade_refresh.canonical_bytes(payload)
    )
    receipt.write_text(json.dumps(payload), encoding="utf-8")
    return receipt, payload, image_id


def _rewrite_receipt(path: Path, payload: dict[str, object]) -> None:
    unsigned = dict(payload)
    unsigned.pop("receipt_digest", None)
    payload["receipt_digest"] = grade_refresh.digest_bytes(
        grade_refresh.canonical_bytes(unsigned)
    )
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
        "schema": "McpTrustGradeRefreshPreflightV1",
        "observed_at": NOW.isoformat(),
        "status": "READY",
        "safe_to_execute_catalog": True,
        "exit_classification": "ready",
        "source_binding": {
            "revision": "a" * 40,
            "source_tree_digest": "sha256:" + "1" * 64,
            "worktree_state": "clean",
        },
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
                    "source_tree_digest": preflight["source_binding"][
                        "source_tree_digest"
                    ],
                    "policy_digest": preflight["catalog"]["policy_digest"],
                },
            }
        ),
        encoding="utf-8",
    )

    triage = triage_candidate(
        candidate=candidate,
        preflight=preflight,
        repeatability=repeatability,
        seed_path=SEED,
        masked_path=MASKED,
        candidate_verifier=lambda *_args, **_kwargs: {
            "structural_valid": True,
            "publication_ready": True,
            "state": "complete",
            "errors": [],
        },
    )

    codes = {finding["code"] for finding in triage["findings"]}
    assert triage["review_required"] is True
    assert triage["publication_allowed"] is False
    assert {"suspicious_upgrade", "large_grade_change", "missing_comparable_provenance"} <= codes
    assert "masked_result_requires_review" in codes
    assert "baseline_policy_digest_unknown" in codes
    assert triage["candidate_verification"]["publication_ready"] is True


def test_state_card_and_resume_capsule_keep_publication_waiting() -> None:
    preflight = {
        "safe_to_execute_catalog": False,
        "reasons": [
            "catalog_image_missing:x",
            "image_build_reproducibility_unknown:x",
        ],
        "source_binding": {"revision": "abc", "source_tree_digest": "sha256:" + "a" * 64},
        "catalog": {"denominator": 31, "counts": {"scannable": 31}},
        "scheduler": {"state": "DISABLED_UNLOADED", "definitions_match": False},
    }
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
    assert (
        capsule["capsule"]["capsule_id"]
        == "mcp-trust-grade-refresh-deterministic-build-gate"
    )
    assert (
        capsule["capsule"]["waiting_condition"]["code"]
        == "deterministic-image-build-approval-required"
    )
    assert capsule["capsule"]["resume_states"] == [
        "deterministic-image-build-authorized"
    ]
    assert capsule["capsule"]["target"] == capsule["capsule"]["authorized_next_read"]["target"]
    assert capsule["observation"]["readback_status"] == "not_run"
    assert capsule["capsule"]["authority"]["boundary"].startswith("Read this Codex task")
    assert len(capsule["capsule"]["claim_ceiling"]) <= 300


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
    triage["receipt_digest"] = grade_refresh.digest_bytes(
        grade_refresh.canonical_bytes(triage)
    )

    state = build_state_card(
        preflight=preflight,
        repeatability=repeatability,
        triage=triage,
    )

    assert "triage_receipt_invalid_or_unbound" in state["outstanding_gates"]
    assert "grade-diff-review-triage-run" not in state["completed_controls"]
    assert state["findings"][0]["code"] == "triage_receipt_invalid_or_unbound"
