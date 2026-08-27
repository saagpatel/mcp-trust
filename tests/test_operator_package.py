from __future__ import annotations

import json
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest

import mcp_trust.grade_refresh as grade_refresh
import mcp_trust.operator_package as operator_package
from mcp_trust.operator_package import (
    OPERATOR_PACKAGE_MANIFEST,
    OperatorPackageError,
    build_operator_review_package,
    verify_operator_review_package,
)
from tests.receipt_fixtures import engine_materialization_receipt

ROOT = Path(__file__).resolve().parents[1]
SEED = ROOT / "src/mcp_trust/catalog/seed_servers.json"
MASKED = ROOT / "masked-grades.json"
POLICY = ROOT / "src/mcp_trust/catalog/refresh_policy.json"
NOW = datetime.now(tz=UTC).replace(microsecond=0)
TEST_SOURCE = {
    "revision": "a" * 40,
    "source_tree_digest": "sha256:" + "b" * 64,
    "worktree_state": "clean",
}
REAL_CURRENT_PREFLIGHT_EVIDENCE = operator_package._current_preflight_evidence


@pytest.fixture(autouse=True)
def _stable_source_binding(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(
        operator_package,
        "source_binding",
        lambda _repo_root: dict(TEST_SOURCE),
    )
    monkeypatch.setattr(
        operator_package,
        "_current_preflight_evidence",
        lambda **kwargs: dict(kwargs["supplied_preflight"]),
    )


def _write_json(path: Path, payload: object) -> None:
    path.write_bytes(grade_refresh.canonical_bytes(payload))


def _receipts(
    tmp_path: Path,
    *,
    scheduler: dict[str, object] | None = None,
    with_triage: bool = False,
) -> tuple[Path, Path, Path | None, dict[str, object] | None]:
    inventory = grade_refresh.catalog_inventory(
        seed_path=SEED, masked_path=MASKED, policy_path=POLICY
    )
    scannable = sorted(row["slug"] for row in inventory["entries"] if row["scannable"])
    blocked = sorted(row["slug"] for row in inventory["entries"] if not row["scannable"])
    image_references = sorted(
        {
            row["sandbox_image"]
            for row in inventory["entries"]
            if row["scannable"] and isinstance(row["sandbox_image"], str)
        }
    )
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
    image_ids = {
        reference: "sha256:" + f"{index + 1:x}" * 64
        for index, reference in enumerate(image_references)
    }
    image_sources: dict[str, dict[str, object]] = {}
    source_files: dict[str, str] = {
        "src/mcp_trust/catalog/refresh_policy.json": grade_refresh.digest_file(POLICY)
    }
    for index, reference in enumerate(image_references):
        build_path = f"docker/refresh/{index}/Dockerfile"
        qualification_path = f"docker/refresh/qualification/test-{index}.json"
        tracked_path = f"docker/refresh/locks/test-{index}.lock"
        build_sha256 = "sha256:" + "8" * 64
        qualification_sha256 = "sha256:" + f"{index + 6:x}"[-1] * 64
        tracked_sha256 = "sha256:" + f"{index + 10:x}"[-1] * 64
        source_files.update(
            {
                build_path: build_sha256,
                qualification_path: qualification_sha256,
                tracked_path: tracked_sha256,
            }
        )
        image_sources[reference] = {
            "path": build_path,
            "sha256": build_sha256,
            "provenance_status": "SOURCE_CONTROLLED",
            "reproducibility_status": "VERIFIED",
            "qualification": {
                "path": qualification_path,
                "sha256": qualification_sha256,
                "receipt_digest": "sha256:" + "c" * 64,
                "qualified_image_id": image_ids[reference],
                "build_input_digest": "sha256:" + "d" * 64,
                "dependency_locks": {"fixture": tracked_sha256},
                "dependency_artifacts": {},
                "tracked_inputs": {tracked_path: tracked_sha256},
                "state": "VERIFIED",
            },
            "state": "BOUND",
        }
    preflight_source: dict[str, object] = {
        **TEST_SOURCE,
        "file_digests": source_files,
    }
    preflight: dict[str, object] = {
        "schema": grade_refresh.PREFLIGHT_SCHEMA,
        "observed_at": (NOW - timedelta(minutes=1)).isoformat(),
        "status": "READY",
        "safe_to_execute_catalog": True,
        "exit_classification": "ready",
        "source_binding": preflight_source,
        "engine_materialization": engine_materialization_receipt(
            source_binding=preflight_source,
            observed_at=NOW - timedelta(minutes=1),
            repo_root=ROOT,
        ),
        "catalog": {
            "policy_digest": grade_refresh.digest_file(POLICY),
            "seed_digest": grade_refresh.digest_file(SEED),
            "masking_digest": grade_refresh.digest_file(MASKED),
            "inventory_digest": grade_refresh.digest_bytes(
                grade_refresh.canonical_bytes(inventory)
            ),
            "denominator": inventory["catalog_denominator"],
            "counts": inventory["counts"],
            "execution_boundary": {
                "schema": "McpTrustRefreshExecutionBoundaryV1",
                "scannable": scannable,
                "blocked": blocked,
            },
            "image_build_sources": image_sources,
        },
        "sandbox": {
            "docker_host_kind": "local-unix",
            "image_bindings": [
                {
                    "reference": reference,
                    "state": "BOUND",
                    "image_id": image_ids[reference],
                    "repo_digests": [],
                    "platform": "linux/arm64",
                    "sandbox_controls": {
                        "controls": dict(controls),
                        "all_required_controls": True,
                    },
                }
                for reference in image_references
            ],
            "network_policy": "none",
            "filesystem_policy": "read-only-root-bounded-tmpfs-no-host-mounts",
            "resource_policy": "cpu-memory-pids-timeout-required",
            "secret_policy": "no-live-secrets-dummy-network-off-only",
        },
        "tool_versions": {
            "python": "3.11.15",
            "python_executable": "python3.11",
            "mcp_audits": "2.7.0",
            "mcp_audits_locked": "2.7.0",
            "mcp_trust": "0.1.0",
            "docker_client": "29.7.2",
            "docker_server": "29.5.2",
        },
        "scheduler": scheduler or {"state": "NOT_READ", "mutation_performed": False},
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
    repeatability: dict[str, object] = {
        "schema": grade_refresh.REPEATABILITY_SCHEMA,
        "observed_at": NOW.isoformat(),
        "status": "PASS",
        "fixture_kind": "deterministic-stub-no-process-no-network",
        "catalog_denominator": 31,
        "first_digest": "sha256:" + "f" * 64,
        "second_digest": "sha256:" + "f" * 64,
        "repeatable": True,
        "claim_ceiling": ("Fixture determinism only; no real server or sandbox runtime proof."),
    }
    repeatability["receipt_digest"] = grade_refresh.digest_bytes(
        grade_refresh.canonical_bytes(repeatability)
    )
    preflight_path = tmp_path / "preflight.json"
    repeatability_path = tmp_path / "repeatability.json"
    _write_json(preflight_path, preflight)
    _write_json(repeatability_path, repeatability)
    if not with_triage:
        return preflight_path, repeatability_path, None, None
    triage: dict[str, object] = {
        "schema": grade_refresh.TRIAGE_SCHEMA,
        "candidate_manifest_digest": "sha256:" + "1" * 64,
        "repeat_candidate_manifest_digest": "sha256:" + "2" * 64,
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
    triage_path = tmp_path / "triage.json"
    _write_json(triage_path, triage)
    return preflight_path, repeatability_path, triage_path, triage


def _build(
    tmp_path: Path,
    *,
    name: str = "package",
    scheduler: dict[str, object] | None = None,
) -> tuple[Path, Path, Path]:
    preflight, repeatability, _, _ = _receipts(tmp_path, scheduler=scheduler)
    output = tmp_path / name
    build_operator_review_package(
        output_path=output,
        task_id="task-fixture",
        preflight_path=preflight,
        repeatability_path=repeatability,
        seed_path=SEED,
        masked_path=MASKED,
    )
    return output, preflight, repeatability


def _tree_bytes(root: Path) -> dict[str, bytes]:
    return {path.name: path.read_bytes() for path in sorted(root.iterdir())}


def test_operator_package_is_deterministic_and_independently_verifiable(
    tmp_path: Path,
) -> None:
    first_root = tmp_path / "first-inputs"
    second_root = tmp_path / "second-inputs"
    first_root.mkdir()
    second_root.mkdir()
    first, first_preflight, first_repeatability = _build(first_root)
    second, _, _ = _build(second_root)

    assert _tree_bytes(first) == _tree_bytes(second)
    verified = verify_operator_review_package(
        first,
        task_id="task-fixture",
        preflight_path=first_preflight,
        repeatability_path=first_repeatability,
        seed_path=SEED,
        masked_path=MASKED,
    )
    assert verified["state"] == "LOCAL_REVIEW_ONLY"
    assert verified["file_count"] == 4
    assert verified["privacy_validated"] is True
    assert verified["publication_allowed"] is False
    assert verified["deployment_allowed"] is False


def test_operator_package_binds_exact_candidate_and_rollback_lineage(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    preflight, repeatability, triage_path, triage = _receipts(tmp_path, with_triage=True)
    assert triage_path is not None and triage is not None
    candidate = tmp_path / "candidate"
    repeat = tmp_path / "repeat"
    candidate.mkdir()
    repeat.mkdir()
    triage_kwargs: dict[str, object] = {}

    def recompute_triage(**kwargs):
        triage_kwargs.update(kwargs)
        return triage

    monkeypatch.setattr(operator_package, "triage_candidate", recompute_triage)
    output = tmp_path / "package"

    build_operator_review_package(
        output_path=output,
        task_id="task-fixture",
        preflight_path=preflight,
        repeatability_path=repeatability,
        triage_path=triage_path,
        candidate_path=candidate,
        repeat_candidate_path=repeat,
        seed_path=SEED,
        masked_path=MASKED,
        repo_root=ROOT,
    )

    assert triage_kwargs["repo_root"] == ROOT

    manifest = json.loads((output / OPERATOR_PACKAGE_MANIFEST).read_text())
    rollback = (output / "rollback.md").read_text()
    assert manifest["lineage"]["triage"]["candidate_manifest_digest"] in rollback
    assert manifest["lineage"]["triage"]["repeat_candidate_manifest_digest"] in rollback
    assert manifest["lineage"]["lineage_digest"] in rollback
    catalog = manifest["lineage"]["catalog"]
    assert catalog["inventory_digest"] in rollback
    assert f"Catalog denominator: `{catalog['denominator']}`" in rollback
    assert set(catalog) == {
        "policy_digest",
        "seed_digest",
        "masking_digest",
        "inventory_digest",
        "denominator",
        "counts",
        "execution_boundary",
    }


def test_operator_package_rejects_tampering_and_extra_files(tmp_path: Path) -> None:
    output, preflight, repeatability = _build(tmp_path)
    output.chmod(0o700)
    state = output / "state-card.json"
    state.chmod(0o600)
    state.write_text("{}\n", encoding="utf-8")

    with pytest.raises(OperatorPackageError, match="binding changed|generated content"):
        verify_operator_review_package(
            output,
            task_id="task-fixture",
            preflight_path=preflight,
            repeatability_path=repeatability,
            seed_path=SEED,
            masked_path=MASKED,
        )

    state.unlink()
    state.write_bytes(grade_refresh.canonical_bytes({}))
    extra = output / "unbound.txt"
    extra.write_text("unbound\n", encoding="utf-8")
    with pytest.raises(OperatorPackageError, match="content file set"):
        verify_operator_review_package(
            output,
            task_id="task-fixture",
            preflight_path=preflight,
            repeatability_path=repeatability,
            seed_path=SEED,
            masked_path=MASKED,
        )


def test_operator_package_rejects_self_digested_manifest_policy_tamper(
    tmp_path: Path,
) -> None:
    output, preflight, repeatability = _build(tmp_path)
    output.chmod(0o700)
    manifest_path = output / OPERATOR_PACKAGE_MANIFEST
    manifest_path.chmod(0o600)
    manifest = json.loads(manifest_path.read_text())
    manifest["claim_ceiling"] = "publication is safe"
    manifest.pop("receipt_digest")
    manifest["receipt_digest"] = grade_refresh.digest_bytes(grade_refresh.canonical_bytes(manifest))
    _write_json(manifest_path, manifest)

    with pytest.raises(OperatorPackageError, match="binding changed"):
        verify_operator_review_package(
            output,
            task_id="task-fixture",
            preflight_path=preflight,
            repeatability_path=repeatability,
            seed_path=SEED,
            masked_path=MASKED,
        )


def test_operator_package_rejects_input_drift_and_output_collision(tmp_path: Path) -> None:
    output, preflight, repeatability = _build(tmp_path)
    payload = json.loads(preflight.read_text())
    payload["observed_at"] = (NOW - timedelta(minutes=2)).isoformat()
    payload.pop("receipt_digest")
    payload["receipt_digest"] = grade_refresh.digest_bytes(grade_refresh.canonical_bytes(payload))
    _write_json(preflight, payload)

    with pytest.raises(OperatorPackageError, match="binding changed|generated content"):
        verify_operator_review_package(
            output,
            task_id="task-fixture",
            preflight_path=preflight,
            repeatability_path=repeatability,
            seed_path=SEED,
            masked_path=MASKED,
        )
    with pytest.raises(OperatorPackageError, match="must not already exist"):
        build_operator_review_package(
            output_path=output,
            task_id="task-fixture",
            preflight_path=preflight,
            repeatability_path=repeatability,
            seed_path=SEED,
            masked_path=MASKED,
        )


@pytest.mark.parametrize(
    ("receipt_name", "updates", "message"),
    [
        (
            "repeatability",
            {"status": "PASS", "repeatable": False},
            "repeatability semantics",
        ),
        (
            "preflight",
            {"status": "BLOCKED", "safe_to_execute_catalog": True},
            "preflight semantics",
        ),
        (
            "repeatability",
            {"fixture_kind": "provider-runtime-scan"},
            "repeatability claim",
        ),
        (
            "repeatability",
            {"claim_ceiling": "provider runtime proven safe"},
            "repeatability claim",
        ),
    ],
)
def test_operator_package_rejects_self_digested_semantic_contradictions(
    tmp_path: Path, receipt_name: str, updates: dict[str, object], message: str
) -> None:
    preflight, repeatability, _, _ = _receipts(tmp_path)
    target = preflight if receipt_name == "preflight" else repeatability
    payload = json.loads(target.read_text())
    payload.update(updates)
    payload.pop("receipt_digest")
    payload["receipt_digest"] = grade_refresh.digest_bytes(grade_refresh.canonical_bytes(payload))
    _write_json(target, payload)

    with pytest.raises(OperatorPackageError, match=message):
        build_operator_review_package(
            output_path=tmp_path / "package",
            task_id="task-fixture",
            preflight_path=preflight,
            repeatability_path=repeatability,
            seed_path=SEED,
            masked_path=MASKED,
            now=NOW,
        )


@pytest.mark.parametrize("case", ["sandbox", "control", "tool"])
def test_operator_package_rejects_self_digested_ready_evidence_gaps(
    tmp_path: Path, case: str
) -> None:
    preflight, repeatability, _, _ = _receipts(tmp_path)
    payload = json.loads(preflight.read_text())
    if case == "sandbox":
        payload["sandbox"] = {}
    elif case == "control":
        payload["sandbox"]["image_bindings"][0]["sandbox_controls"]["controls"]["network_none"] = (
            False
        )
    else:
        payload["tool_versions"]["mcp_audits"] = "UNKNOWN"
    payload.pop("receipt_digest")
    payload["receipt_digest"] = grade_refresh.digest_bytes(grade_refresh.canonical_bytes(payload))
    _write_json(preflight, payload)

    with pytest.raises(OperatorPackageError, match="READY .* invalid"):
        build_operator_review_package(
            output_path=tmp_path / "package",
            task_id="task-fixture",
            preflight_path=preflight,
            repeatability_path=repeatability,
            seed_path=SEED,
            masked_path=MASKED,
            policy_path=POLICY,
            now=NOW,
        )


def test_operator_package_rejects_self_digested_alternate_image_bindings(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    preflight, repeatability, _, _ = _receipts(tmp_path)
    current = json.loads(preflight.read_text())
    supplied = json.loads(preflight.read_text())
    for index, binding in enumerate(supplied["sandbox"]["image_bindings"]):
        alternate_id = "sha256:" + f"{index + 10:x}"[-1] * 64
        binding["image_id"] = alternate_id
        supplied["catalog"]["image_build_sources"][binding["reference"]]["qualification"][
            "qualified_image_id"
        ] = alternate_id
    supplied.pop("receipt_digest")
    supplied["receipt_digest"] = grade_refresh.digest_bytes(grade_refresh.canonical_bytes(supplied))
    _write_json(preflight, supplied)
    monkeypatch.setattr(
        operator_package,
        "_current_preflight_evidence",
        lambda **_kwargs: current,
    )

    with pytest.raises(OperatorPackageError, match="current preflight evidence changed"):
        build_operator_review_package(
            output_path=tmp_path / "package",
            task_id="task-fixture",
            preflight_path=preflight,
            repeatability_path=repeatability,
            seed_path=SEED,
            masked_path=MASKED,
            policy_path=POLICY,
            now=NOW,
        )

    assert not (tmp_path / "package").exists()


def test_operator_package_rejects_stale_scheduler_claim(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    preflight, repeatability, _, _ = _receipts(tmp_path)
    current = json.loads(preflight.read_text())
    supplied = json.loads(preflight.read_text())
    supplied["scheduler"] = {
        "state": "DISABLED_UNLOADED",
        "mutation_performed": False,
    }
    supplied.pop("receipt_digest")
    supplied["receipt_digest"] = grade_refresh.digest_bytes(grade_refresh.canonical_bytes(supplied))
    _write_json(preflight, supplied)
    monkeypatch.setattr(
        operator_package,
        "_current_preflight_evidence",
        lambda **_kwargs: current,
    )

    with pytest.raises(OperatorPackageError, match="current preflight evidence changed"):
        build_operator_review_package(
            output_path=tmp_path / "package",
            task_id="task-fixture",
            preflight_path=preflight,
            repeatability_path=repeatability,
            seed_path=SEED,
            masked_path=MASKED,
            policy_path=POLICY,
            now=NOW,
        )


def test_current_preflight_revalidation_preserves_scheduler_readback_contract(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    expected = {
        "scheduler": {
            "state": "DISABLED_UNLOADED",
            "mutation_performed": False,
        }
    }

    def fake_preflight(**kwargs: object) -> dict[str, object]:
        assert kwargs["include_scheduler_readback"] is True
        assert kwargs["engine_materialization_receipt"] is None
        return expected

    monkeypatch.setattr(operator_package, "build_preflight_receipt", fake_preflight)
    result = REAL_CURRENT_PREFLIGHT_EVIDENCE(
        supplied_preflight=expected,
        repo_root=ROOT,
        seed_path=SEED,
        masked_path=MASKED,
        policy_path=POLICY,
        now=NOW,
    )

    assert result is expected


def test_operator_package_wraps_current_preflight_revalidation_failure(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    preflight, repeatability, _, _ = _receipts(tmp_path)

    def fail_revalidation(**_kwargs: object) -> dict[str, object]:
        raise grade_refresh.GradeRefreshError("fixture preflight failure")

    monkeypatch.setattr(operator_package, "_current_preflight_evidence", fail_revalidation)
    with pytest.raises(OperatorPackageError, match="current preflight revalidation failed"):
        build_operator_review_package(
            output_path=tmp_path / "package",
            task_id="task-fixture",
            preflight_path=preflight,
            repeatability_path=repeatability,
            seed_path=SEED,
            masked_path=MASKED,
            policy_path=POLICY,
            now=NOW,
        )

    assert not (tmp_path / "package").exists()


def test_operator_package_blocked_preflight_withholds_image_control(tmp_path: Path) -> None:
    preflight, repeatability, _, _ = _receipts(tmp_path)
    payload = json.loads(preflight.read_text())
    payload.update(
        {
            "status": "BLOCKED",
            "safe_to_execute_catalog": False,
            "exit_classification": "preflight-blocked",
            "reasons": ["fixture_runtime_unavailable"],
            "sandbox": {},
            "tool_versions": {},
        }
    )
    payload["authority"]["candidate_build"] = False
    payload.pop("receipt_digest")
    payload["receipt_digest"] = grade_refresh.digest_bytes(grade_refresh.canonical_bytes(payload))
    _write_json(preflight, payload)

    output = tmp_path / "package"
    build_operator_review_package(
        output_path=output,
        task_id="task-fixture",
        preflight_path=preflight,
        repeatability_path=repeatability,
        seed_path=SEED,
        masked_path=MASKED,
        policy_path=POLICY,
        now=NOW,
    )

    state = json.loads((output / "state-card.json").read_text())
    assert state["safe_to_execute_catalog"] is False
    assert "image-provenance-preflight-run" not in state["completed_controls"]


def test_operator_package_routes_missing_engine_materialization_before_images(
    tmp_path: Path,
) -> None:
    preflight, repeatability, _, _ = _receipts(tmp_path)
    payload = json.loads(preflight.read_text())
    payload.update(
        {
            "status": "BLOCKED",
            "safe_to_execute_catalog": False,
            "exit_classification": "preflight-blocked",
            "reasons": ["engine_materialization_receipt_missing"],
            "engine_materialization": None,
        }
    )
    payload["authority"]["candidate_build"] = False
    payload.pop("receipt_digest")
    payload["receipt_digest"] = grade_refresh.digest_bytes(
        grade_refresh.canonical_bytes(payload)
    )
    _write_json(preflight, payload)

    output = tmp_path / "package"
    build_operator_review_package(
        output_path=output,
        task_id="task-fixture",
        preflight_path=preflight,
        repeatability_path=repeatability,
        seed_path=SEED,
        masked_path=MASKED,
        policy_path=POLICY,
        now=NOW,
    )

    state = json.loads((output / "state-card.json").read_text())
    capsule = json.loads((output / "HumanGateResumeCapsuleV1.json").read_text())
    assert "mcp-audits==2.7.0" in state["next_action"]
    assert "all five image cohorts" not in state["next_action"]
    assert (
        capsule["capsule"]["waiting_condition"]["code"]
        == "exact-mcp-audits-materialization-approval-required"
    )
    assert capsule["capsule"]["resume_states"] == [
        "exact-mcp-audits-materialization-authorized"
    ]


@pytest.mark.parametrize(
    "digest_key",
    ["seed_digest", "masking_digest", "policy_digest", "inventory_digest"],
)
def test_operator_package_recomputes_catalog_bindings(tmp_path: Path, digest_key: str) -> None:
    preflight, repeatability, _, _ = _receipts(tmp_path)
    payload = json.loads(preflight.read_text())
    payload["catalog"][digest_key] = "sha256:" + "9" * 64
    payload.pop("receipt_digest")
    payload["receipt_digest"] = grade_refresh.digest_bytes(grade_refresh.canonical_bytes(payload))
    _write_json(preflight, payload)

    with pytest.raises(OperatorPackageError, match="catalog binding is invalid"):
        build_operator_review_package(
            output_path=tmp_path / "package",
            task_id="task-fixture",
            preflight_path=preflight,
            repeatability_path=repeatability,
            seed_path=SEED,
            masked_path=MASKED,
            policy_path=POLICY,
            now=NOW,
        )


def test_operator_package_recomputes_clean_source_binding(tmp_path: Path) -> None:
    preflight, repeatability, _, _ = _receipts(tmp_path)
    payload = json.loads(preflight.read_text())
    payload["source_binding"]["revision"] = "9" * 40
    materialization = payload["engine_materialization"]
    materialization["source_binding"]["revision"] = "9" * 40
    materialization.pop("receipt_digest")
    materialization["receipt_digest"] = grade_refresh.digest_bytes(
        grade_refresh.canonical_bytes(materialization)
    )
    payload.pop("receipt_digest")
    payload["receipt_digest"] = grade_refresh.digest_bytes(grade_refresh.canonical_bytes(payload))
    _write_json(preflight, payload)

    with pytest.raises(OperatorPackageError, match="current source binding is invalid"):
        build_operator_review_package(
            output_path=tmp_path / "package",
            task_id="task-fixture",
            preflight_path=preflight,
            repeatability_path=repeatability,
            seed_path=SEED,
            masked_path=MASKED,
            policy_path=POLICY,
            now=NOW,
        )


@pytest.mark.parametrize(
    "observed_at",
    [NOW + timedelta(minutes=2), NOW - timedelta(days=2)],
)
def test_operator_package_rejects_future_or_stale_receipts(
    tmp_path: Path, observed_at: datetime
) -> None:
    preflight, repeatability, _, _ = _receipts(tmp_path)
    payload = json.loads(preflight.read_text())
    payload["observed_at"] = observed_at.isoformat()
    payload.pop("receipt_digest")
    payload["receipt_digest"] = grade_refresh.digest_bytes(grade_refresh.canonical_bytes(payload))
    _write_json(preflight, payload)

    with pytest.raises(OperatorPackageError, match="freshness is invalid"):
        build_operator_review_package(
            output_path=tmp_path / "package",
            task_id="task-fixture",
            preflight_path=preflight,
            repeatability_path=repeatability,
            seed_path=SEED,
            masked_path=MASKED,
            now=NOW,
        )


def test_operator_package_no_replace_collision_preserves_foreign_output(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    preflight, repeatability, _, _ = _receipts(tmp_path)
    output = tmp_path / "package"
    real_rename = operator_package._rename_no_replace

    def collide(source: Path, destination: Path) -> None:
        destination.mkdir()
        (destination / "foreign.txt").write_text("foreign\n", encoding="utf-8")
        real_rename(source, destination)

    monkeypatch.setattr(operator_package, "_rename_no_replace", collide)
    with pytest.raises(OperatorPackageError, match="collision detected"):
        build_operator_review_package(
            output_path=output,
            task_id="task-fixture",
            preflight_path=preflight,
            repeatability_path=repeatability,
            seed_path=SEED,
            masked_path=MASKED,
            now=NOW,
        )

    assert (output / "foreign.txt").read_text() == "foreign\n"
    assert not list(tmp_path.glob(".package.tmp-*"))


def test_operator_package_wraps_ctypes_loader_failure(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    preflight, repeatability, _, _ = _receipts(tmp_path)

    def fail_loader(*_args: object, **_kwargs: object) -> object:
        raise OSError("fixture libc unavailable")

    monkeypatch.setattr(operator_package, "CDLL", fail_loader)
    with pytest.raises(OperatorPackageError, match="no-replace runtime is unavailable"):
        build_operator_review_package(
            output_path=tmp_path / "package",
            task_id="task-fixture",
            preflight_path=preflight,
            repeatability_path=repeatability,
            seed_path=SEED,
            masked_path=MASKED,
            policy_path=POLICY,
            now=NOW,
        )

    assert not (tmp_path / "package").exists()


def test_operator_package_rejects_privacy_leak_before_finalization(tmp_path: Path) -> None:
    scheduler = {
        "state": "DISABLED_UNLOADED",
        "note": "inspect /Users/private/Library/LaunchAgents/example.plist",
        "mutation_performed": False,
    }
    preflight, repeatability, _, _ = _receipts(tmp_path, scheduler=scheduler)
    output = tmp_path / "package"

    with pytest.raises(OperatorPackageError, match="host-specific absolute path"):
        build_operator_review_package(
            output_path=output,
            task_id="task-fixture",
            preflight_path=preflight,
            repeatability_path=repeatability,
            seed_path=SEED,
            masked_path=MASKED,
        )

    assert not output.exists()
    assert not list(tmp_path.glob(".package.tmp-*"))


def test_operator_package_rejects_disguised_sensitive_key(tmp_path: Path) -> None:
    scheduler = {
        "state": "NOT_READ",
        "api-key": "fixture-value",
        "mutation_performed": False,
    }
    preflight, repeatability, _, _ = _receipts(tmp_path, scheduler=scheduler)

    with pytest.raises(OperatorPackageError, match="privacy-forbidden field"):
        build_operator_review_package(
            output_path=tmp_path / "package",
            task_id="task-fixture",
            preflight_path=preflight,
            repeatability_path=repeatability,
            seed_path=SEED,
            masked_path=MASKED,
            now=NOW,
        )


def test_operator_package_cleans_interrupted_staging(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    preflight, repeatability, _, _ = _receipts(tmp_path)
    output = tmp_path / "package"
    real_write = operator_package._write_file
    calls = 0

    def fail_second(path: Path, content: bytes) -> None:
        nonlocal calls
        calls += 1
        if calls == 2:
            raise OperatorPackageError("fixture interruption")
        real_write(path, content)

    monkeypatch.setattr(operator_package, "_write_file", fail_second)
    with pytest.raises(OperatorPackageError, match="fixture interruption"):
        build_operator_review_package(
            output_path=output,
            task_id="task-fixture",
            preflight_path=preflight,
            repeatability_path=repeatability,
            seed_path=SEED,
            masked_path=MASKED,
        )

    assert not output.exists()
    assert not list(tmp_path.glob(".package.tmp-*"))


def test_operator_package_wraps_directory_fsync_failure(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    preflight, repeatability, _, _ = _receipts(tmp_path)
    real_fsync = operator_package.os.fsync

    def fail_directory(descriptor: int) -> None:
        if operator_package.stat.S_ISDIR(operator_package.os.fstat(descriptor).st_mode):
            raise OSError("fixture unsupported directory fsync")
        real_fsync(descriptor)

    monkeypatch.setattr(operator_package.os, "fsync", fail_directory)
    with pytest.raises(OperatorPackageError, match="directory fsync failed"):
        build_operator_review_package(
            output_path=tmp_path / "package",
            task_id="task-fixture",
            preflight_path=preflight,
            repeatability_path=repeatability,
            seed_path=SEED,
            masked_path=MASKED,
            policy_path=POLICY,
            now=NOW,
        )

    assert not (tmp_path / "package").exists()


def test_operator_package_removes_output_when_post_finalize_readback_fails(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    preflight, repeatability, _, _ = _receipts(tmp_path)
    output = tmp_path / "package"
    real_verify = operator_package.verify_operator_review_package
    calls = 0

    def fail_final(*args: object, **kwargs: object) -> dict[str, object]:
        nonlocal calls
        calls += 1
        if calls == 2:
            raise OperatorPackageError("fixture final readback failure")
        return real_verify(*args, **kwargs)

    monkeypatch.setattr(operator_package, "verify_operator_review_package", fail_final)
    with pytest.raises(OperatorPackageError, match="final readback failure"):
        build_operator_review_package(
            output_path=output,
            task_id="task-fixture",
            preflight_path=preflight,
            repeatability_path=repeatability,
            seed_path=SEED,
            masked_path=MASKED,
        )

    assert not output.exists()
    assert not list(tmp_path.glob(".package.tmp-*"))


def test_operator_package_converts_malformed_nested_receipt_to_structured_error(
    tmp_path: Path,
) -> None:
    preflight, repeatability, _, _ = _receipts(tmp_path)
    payload = json.loads(preflight.read_text())
    payload["catalog"]["counts"] = "not-an-object"
    payload.pop("receipt_digest")
    payload["receipt_digest"] = grade_refresh.digest_bytes(grade_refresh.canonical_bytes(payload))
    _write_json(preflight, payload)

    with pytest.raises(OperatorPackageError, match="binding is invalid|semantics are invalid"):
        build_operator_review_package(
            output_path=tmp_path / "package",
            task_id="task-fixture",
            preflight_path=preflight,
            repeatability_path=repeatability,
            seed_path=SEED,
            masked_path=MASKED,
        )


def test_operator_package_rejects_malformed_receipt_root(tmp_path: Path) -> None:
    preflight = tmp_path / "preflight.json"
    repeatability = tmp_path / "repeatability.json"
    preflight.write_text("[]\n", encoding="utf-8")
    repeatability.write_text("{}\n", encoding="utf-8")

    with pytest.raises(OperatorPackageError, match="must be a JSON object"):
        build_operator_review_package(
            output_path=tmp_path / "package",
            task_id="task-fixture",
            preflight_path=preflight,
            repeatability_path=repeatability,
            seed_path=SEED,
            masked_path=MASKED,
        )


def test_operator_package_converts_deep_catalog_json_to_structured_error(
    tmp_path: Path,
) -> None:
    preflight, repeatability, _, _ = _receipts(tmp_path)
    deep_seed = tmp_path / "deep-seed.json"
    deep_seed.write_text("[" * 1_100 + "0" + "]" * 1_100, encoding="utf-8")

    with pytest.raises(OperatorPackageError, match="unreadable JSON input"):
        build_operator_review_package(
            output_path=tmp_path / "package",
            task_id="task-fixture",
            preflight_path=preflight,
            repeatability_path=repeatability,
            seed_path=deep_seed,
            masked_path=MASKED,
            policy_path=POLICY,
            now=NOW,
        )

    assert not (tmp_path / "package").exists()
