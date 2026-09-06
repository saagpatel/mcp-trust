from __future__ import annotations

import copy
import json
from pathlib import Path

import pytest

import mcp_trust.grade_refresh as grade_refresh
from mcp_trust.grade_refresh import (
    GradeRefreshError,
    build_publication_review_decision,
    build_publication_review_state_card,
    canonical_bytes,
)

ROOT = Path(__file__).resolve().parents[1]
SEED = ROOT / "src/mcp_trust/catalog/seed_servers.json"
MASKED = ROOT / "masked-grades.json"
POLICY = ROOT / "src/mcp_trust/catalog/refresh_policy.json"
DISPOSITIONS = ROOT / "src/mcp_trust/catalog/refresh_disposition_policy.json"
BUNDLED_ACCEPTED_REVIEW = (
    ROOT / "src/mcp_trust/catalog/accepted_publication_review_v38.json"
)
BUNDLED_ACCEPTED_DISPOSITION = (
    ROOT / "src/mcp_trust/catalog/accepted_disposition_artifact_v38.json"
)
CATALOG_INVENTORY = grade_refresh.catalog_inventory


def _inputs() -> tuple[
    dict[str, object],
    dict[str, object],
    dict[str, object],
    dict[str, dict[str, object]],
]:
    historical_policy = json.loads(DISPOSITIONS.read_text(encoding="utf-8"))
    masked = sorted(entry["slug"] for entry in historical_policy["entries"])
    image_id = "sha256:" + "a" * 64
    preflight: dict[str, object] = {
        "status": "READY",
        "safe_to_execute_catalog": True,
        "receipt_digest": "sha256:" + "1" * 64,
        "source_binding": {
            "revision": "b" * 40,
            "source_tree_digest": "sha256:" + "2" * 64,
        },
        "catalog": {
            "policy_digest": grade_refresh.digest_file(POLICY),
            "seed_digest": grade_refresh.digest_file(SEED),
            "masking_digest": grade_refresh.digest_file(MASKED),
            "denominator": 31,
        },
        "sandbox": {
            "image_bindings": [
                {
                    "reference": f"mcp-trust:test-{index}",
                    "image_id": image_id,
                    "state": "BOUND",
                    "sandbox_controls": {"all_required_controls": True},
                }
                for index in range(5)
            ]
        },
        "scheduler": {
            "state": "DISABLED_UNLOADED",
            "persistently_disabled": True,
            "loaded_domains": [],
            "definitions_match": False,
            "installed_plist_sha256": "sha256:" + "3" * 64,
            "repository_plist_sha256": "sha256:" + "4" * 64,
            "mutation_performed": False,
        },
        "tool_versions": {
            "mcp_audits": "2.7.0",
            "python": "3.11.15",
            "python_executable": "/fixture/python3.11",
        },
    }
    repeatability = {"receipt_digest": "sha256:" + "5" * 64}
    findings = [
        {
            "severity": "High",
            "code": "masked_result_requires_review",
            "slug": slug,
        }
        for slug in masked
    ]
    findings.extend(
        {
            "severity": "Medium",
            "code": "baseline_or_drift_unknown",
            "slug": slug,
        }
        for slug in masked
    )
    findings.append(
        {
            "severity": "Medium",
            "code": "baseline_policy_digest_unknown",
            "slug": "catalog",
        }
    )
    triage: dict[str, object] = {
        "counts": {"Critical": 0, "High": 8, "Medium": 9, "Low": 0},
        "findings": findings,
        "candidate_manifest_digest": "sha256:" + "6" * 64,
        "repeat_candidate_manifest_digest": "sha256:" + "7" * 64,
        "receipt_digest": "sha256:" + "8" * 64,
    }
    projections = {
        slug: {
            "state": "masked",
            "proof_outcome": "scan_succeeded",
            "evidence_present": True,
            "engine_name": "mcpaudit",
            "engine_version": "2.7.0",
            "sandbox": {
                "MCP_TRUST_SANDBOX": "docker",
                "MCP_TRUST_SANDBOX_IMAGE": image_id,
                "MCP_TRUST_SANDBOX_NETWORK": "none",
                "MCP_TRUST_SCAN_CREDENTIALS": "dummy",
            },
        }
        for slug in masked
    }
    projections.update(
        {
            f"fresh-fixture-{index:02d}": {
                "state": "fresh",
                "fresh_grade": "B",
                "transparency": "high",
            }
            for index in range(23)
        }
    )
    return preflight, repeatability, triage, projections


def _legacy_v38_inventory() -> dict[str, object]:
    """Project the retained V38 masking boundary without changing current policy."""
    inventory = copy.deepcopy(
        CATALOG_INVENTORY(
            seed_path=SEED, masked_path=MASKED, policy_path=POLICY
        )
    )
    promoted = {
        "io-github-chromedevtools-chrome-devtools-mcp-1-5-0",
        "io-github-discourse-mcp-0-2-9",
        "io-github-microsoft-playwright-mcp-0-0-77",
        "io-github-nvidia-elements-2-1-4",
    }
    historical_backing = {
        "io-github-chromedevtools-chrome-devtools-mcp-1-5-0",
        "io-github-microsoft-playwright-mcp-0-0-77",
    }
    for row in inventory["entries"]:
        if row["slug"] in promoted:
            row["scannable"] = False
            row["intentionally_masked"] = True
            if row["slug"] in historical_backing:
                row["backing_service_dependent"] = True
            row["execution_disposition"] = "do-not-execute"
    inventory["counts"] = {
        **inventory["counts"],
        "scannable": 18,
        "blocked": 13,
        "intentionally_masked": 8,
        "backing_service_dependent": 10,
    }
    return inventory


def _v131_inventory() -> dict[str, object]:
    """Project the accepted V131 boundary without changing current V132 policy."""
    inventory = copy.deepcopy(
        CATALOG_INVENTORY(seed_path=SEED, masked_path=MASKED, policy_path=POLICY)
    )
    v132_promoted = {
        "io-github-chromedevtools-chrome-devtools-mcp-1-5-0",
        "io-github-microsoft-playwright-mcp-0-0-77",
    }
    for row in inventory["entries"]:
        if row["slug"] in v132_promoted:
            row["scannable"] = False
            row["intentionally_masked"] = True
            row["backing_service_dependent"] = True
            row["execution_disposition"] = "do-not-execute"
    inventory["counts"] = {
        **inventory["counts"],
        "scannable": 20,
        "blocked": 11,
        "intentionally_masked": 6,
        "backing_service_dependent": 10,
    }
    return inventory


def test_publication_review_rejects_same_candidate_path(tmp_path: Path) -> None:
    candidate = tmp_path / "candidate"
    candidate.mkdir()

    with pytest.raises(GradeRefreshError, match="independent path"):
        build_publication_review_decision(
            candidate=candidate,
            repeat_candidate=candidate,
            preflight={},
            repeatability={},
            triage={},
            seed_path=SEED,
            masked_path=MASKED,
            policy_path=POLICY,
            disposition_path=DISPOSITIONS,
        )


def _build(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    *,
    projections: dict[str, dict[str, object]] | None = None,
    disposition_path: Path = DISPOSITIONS,
    accepted_review_path: Path | None = None,
) -> dict[str, object]:
    preflight, repeatability, triage, default_projections = _inputs()
    projection = projections or default_projections
    def recompute_triage(**kwargs):
        assert kwargs["repo_root"] == ROOT
        return triage

    monkeypatch.setattr(grade_refresh, "triage_candidate", recompute_triage)
    monkeypatch.setattr(
        grade_refresh, "catalog_inventory", lambda **_kwargs: _legacy_v38_inventory()
    )
    if disposition_path == DISPOSITIONS and accepted_review_path is None:
        proposed_policy = json.loads(DISPOSITIONS.read_text(encoding="utf-8"))
        proposed_policy["review_state"] = "PROPOSED"
        proposed_policy["forward_baseline"] = {
            "state": "PROPOSED",
            "disposition": "adopt-exact-candidate-bindings-after-operator-acceptance",
        }
        proposed_policy.pop("acceptance")
        proposed_policy_path = tmp_path / "proposed-dispositions.json"
        proposed_policy_path.write_text(
            json.dumps(proposed_policy), encoding="utf-8"
        )
        proposed = build_publication_review_decision(
            candidate=tmp_path / "first",
            repeat_candidate=tmp_path / "second",
            preflight=preflight,
            repeatability=repeatability,
            triage=triage,
            seed_path=SEED,
            masked_path=MASKED,
            policy_path=POLICY,
            repo_root=ROOT,
            disposition_path=proposed_policy_path,
            projection_builder=lambda _path: projection,
        )
        accepted_review_path = tmp_path / "accepted_publication_review_v38.json"
        accepted_review_path.write_bytes(canonical_bytes(proposed))
        artifact: dict[str, object] = {
            "schema": "McpTrustAcceptedDispositionArtifactV1",
            "decision": "OPERATOR_ACCEPTED_EXACT_V38",
            "acceptance": {
                "state": "ACCEPTED_EXACT_V38",
                "scope": (
                    "all-eight-current-masked-dispositions-and-exact-v37-forward-baseline"
                ),
                "proposal_policy_sha256": proposed["disposition_policy"]["sha256"],
            },
            "forward_baseline": {
                **proposed["forward_baseline"],
                "state": "OPERATOR_ACCEPTED_EXACT_V38_LOCAL_REVIEW_ONLY",
            },
            "historical_baseline": proposed["historical_baseline"],
            "masked_dispositions": {
                "count": 8,
                "acceptance_state": "ACCEPTED_EXACT_V38_RETAIN_MASKED",
                "projection_repeatability": "PASS",
                "entries": [
                    {
                        "slug": entry["slug"],
                        "disposition": entry["disposition"],
                        "rationale_code": entry["rationale_code"],
                        "next_review_condition": entry["next_review_condition"],
                        "projection_digest": entry["controlled_evidence"][
                            "projection_digest"
                        ],
                    }
                    for entry in proposed["entry_dispositions"]
                ],
            },
            "privacy": {
                "host_specific_path_matches": 0,
                "credential_values_present": False,
                "masked_grade_risk_finding_or_receipt_fields_present": False,
                "raw_candidate_transfer_allowed": False,
            },
            "separate_public_state": {
                "production_freshness": "UNKNOWN",
                "production_source_binding": "UNKNOWN",
                "production_deployment_revision": "UNKNOWN",
                "relationship_to_v38": "NOT_PUBLISHED_AND_NOT_DEPLOYED",
            },
        }
        artifact["receipt_digest"] = grade_refresh.digest_bytes(
            canonical_bytes(artifact)
        )
        artifact_path = tmp_path / "accepted_disposition_artifact_v38.json"
        artifact_path.write_bytes(canonical_bytes(artifact))
        accepted_policy = json.loads(DISPOSITIONS.read_text(encoding="utf-8"))
        accepted_policy["acceptance"]["accepted_review_receipt_digest"] = proposed[
            "receipt_digest"
        ]
        accepted_policy["acceptance"]["accepted_review_artifact_sha256"] = (
            grade_refresh.digest_file(accepted_review_path)
        )
        accepted_policy["acceptance"]["accepted_review_path"] = (
            accepted_review_path.name
        )
        accepted_policy["acceptance"]["accepted_review_policy_sha256"] = proposed[
            "disposition_policy"
        ]["sha256"]
        accepted_policy["acceptance"]["accepted_disposition_receipt_digest"] = (
            artifact["receipt_digest"]
        )
        accepted_policy["acceptance"]["accepted_disposition_artifact_sha256"] = (
            grade_refresh.digest_file(artifact_path)
        )
        accepted_policy["acceptance"]["accepted_disposition_path"] = artifact_path.name
        disposition_path = tmp_path / "accepted-dispositions.json"
        disposition_path.write_text(json.dumps(accepted_policy), encoding="utf-8")
    return build_publication_review_decision(
        candidate=tmp_path / "first",
        repeat_candidate=tmp_path / "second",
        preflight=preflight,
        repeatability=repeatability,
        triage=triage,
        seed_path=SEED,
        masked_path=MASKED,
        policy_path=POLICY,
        repo_root=ROOT,
        disposition_path=disposition_path,
        accepted_review_path=accepted_review_path,
        projection_builder=lambda _path: projection,
    )


def test_publication_review_is_deterministic_and_fail_closed(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    first = _build(monkeypatch, tmp_path)
    second = _build(monkeypatch, tmp_path)

    assert first == second
    assert first["decision"] == "NO_GO"
    assert first["publication_allowed"] is False
    assert first["deployment_allowed"] is False
    assert first["scheduler_change_allowed"] is False
    assert first["review_state"] == "ACCEPTED_FOR_SOURCE_REVIEW"
    assert first["disposition_counts"] == {
        "total": 8,
        "pending_human_acceptance": 0,
        "accepted_human": 8,
        "retain_masked": 8,
    }
    assert first["historical_baseline"]["state"] == "UNKNOWN"
    assert first["forward_baseline"]["state"] == (
        "OPERATOR_ACCEPTED_EXACT_V38_LOCAL_REVIEW_ONLY"
    )
    assert first["forward_baseline"]["tool_versions"]["python_executable"] == (
        "python3.11"
    )
    assert all(
        entry["acceptance_state"] == "HUMAN_ACCEPTED_V38"
        for entry in first["entry_dispositions"]
    )
    assert first["scheduler_disposition"]["observed_state"] == "DISABLED_UNLOADED"
    assert "masked_disposition_acceptance_required" not in first["blocking_gates"]
    assert "forward_baseline_acceptance_required" not in first["blocking_gates"]
    assert "sanitized_review_acceptance_required" not in first["blocking_gates"]
    assert "exact_source_review_and_landing_required" not in first["blocking_gates"]
    assert "explicit_publication_authority_required" in first["blocking_gates"]
    assert "dormant_scheduler_definition_drift_before_activation" in first[
        "quarantined_gates"
    ]
    rendered = json.dumps(first, sort_keys=True)
    assert '"fresh_grade"' not in rendered
    assert '"risk"' not in rendered
    assert '"findings"' not in rendered
    state = build_publication_review_state_card(first)
    assert state["publication_state"] == "NO_GO"
    assert state["production_freshness"] == "UNKNOWN"
    assert state["candidate_counts"] == {"fresh": 23, "masked": 8, "total": 31}
    assert state["severity_findings"] == {
        "Critical": 0,
        "High": 8,
        "Medium": 10,
        "Low": 0,
    }
    assert "masked-disposition-accepted-v38-current-source" in state[
        "completed_controls"
    ]
    assert "v37-forward-baseline-accepted-v38" in state["completed_controls"]
    assert state["next_action"].startswith("Build and verify")


def test_v131_boundary_review_accepts_exact_post_policy_lineage(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    inventory = _v131_inventory()
    monkeypatch.setattr(
        grade_refresh, "catalog_inventory", lambda **_kwargs: _v131_inventory()
    )
    blocked = sorted(
        row["slug"]
        for row in inventory["entries"]
        if row["execution_disposition"] == "do-not-execute"
    )
    scannable = sorted(
        row["slug"]
        for row in inventory["entries"]
        if row["execution_disposition"] == "pinned-network-off-sandbox-only"
    )
    assert len(blocked) == 11
    assert len(scannable) == 20
    preflight, repeatability, _, _ = _inputs()
    findings = [
        {"severity": "Critical", "code": "result_blocked-policy", "slug": slug}
        for slug in blocked
    ]
    findings.extend(
        {"severity": "Medium", "code": "baseline_or_drift_unknown", "slug": slug}
        for slug in scannable
    )
    findings.append(
        {
            "severity": "Medium",
            "code": "baseline_policy_digest_unknown",
            "slug": "catalog",
        }
    )
    triage = {
        "counts": {"Critical": 11, "High": 0, "Medium": 21, "Low": 0},
        "findings": findings,
        "candidate_manifest_digest": "sha256:" + "6" * 64,
        "repeat_candidate_manifest_digest": "sha256:" + "7" * 64,
        "receipt_digest": "sha256:" + "8" * 64,
    }
    projections = {
        slug: {
            "server_slug": slug,
            "state": "blocked-policy",
            "fresh_grade": None,
            "execution_disposition": "do-not-execute",
            "reason": "sandbox_image_qualification_unknown",
            "error_type": None,
        }
        for slug in blocked
    }
    projections.update(
        {
            slug: {"server_slug": slug, "state": "fresh"}
            for slug in scannable
        }
    )
    monkeypatch.setattr(grade_refresh, "triage_candidate", lambda **_kwargs: triage)
    historical = json.loads(DISPOSITIONS.read_text(encoding="utf-8"))
    proposed_policy = {
        **historical,
        "schema": "McpTrustGradeRefreshDispositionPolicyV4",
        "review_state": "PROPOSED",
        "forward_baseline": {
            "state": "PROPOSED",
            "disposition": "adopt-exact-candidate-bindings-after-operator-acceptance",
        },
        "entries": [
            {
                "slug": slug,
                "disposition": "KEEP_BLOCKED_POLICY",
                "rationale_code": "execution-prohibited-by-reviewed-policy",
                "next_review_condition": (
                    "separate-policy-change-and-fresh-controlled-evidence"
                ),
            }
            for slug in blocked
        ],
    }
    proposed_policy.pop("acceptance")
    proposed_policy_path = tmp_path / "v131-boundary-proposed.json"
    proposed_policy_path.write_text(json.dumps(proposed_policy), encoding="utf-8")
    build_kwargs = {
        "candidate": tmp_path / "first",
        "repeat_candidate": tmp_path / "second",
        "preflight": preflight,
        "repeatability": repeatability,
        "triage": triage,
        "seed_path": SEED,
        "masked_path": MASKED,
        "policy_path": POLICY,
        "repo_root": ROOT,
        "projection_builder": lambda _path: projections,
    }
    proposed = build_publication_review_decision(
        **build_kwargs, disposition_path=proposed_policy_path
    )
    assert proposed["candidate_counts"] == {
        "fresh": 20,
        "masked": 0,
        "blocked": 11,
        "total": 31,
    }
    assert proposed["disposition_counts"]["retain_blocked"] == 11
    assert proposed["review_state"] == "READY_FOR_HUMAN_DISPOSITION"

    proposed_review_path = tmp_path / "publication-review-v131-proposed.json"
    proposed_review_path.write_bytes(canonical_bytes(proposed))
    accepted_artifact = {
        "schema": "McpTrustAcceptedDispositionArtifactV3",
        "decision": "OPERATOR_ACCEPTED_EXACT_V131_BOUNDARY",
        "acceptance": {
            "state": "ACCEPTED_EXACT_V131_BOUNDARY",
            "source": "direct-current-chat-token",
            "scope": "all-eleven-current-policy-blocks-and-exact-v131-forward-baseline",
            "proposal_artifact_sha256": grade_refresh.digest_file(proposed_review_path),
            "proposal_receipt_digest": proposed["receipt_digest"],
            "proposal_policy_sha256": proposed["disposition_policy"]["sha256"],
        },
        "forward_baseline": {
            **proposed["forward_baseline"],
            "state": "OPERATOR_ACCEPTED_EXACT_V131_BOUNDARY_LOCAL_REVIEW_ONLY",
        },
        "historical_baseline": proposed["historical_baseline"],
        "blocked_dispositions": {
            "count": 11,
            "acceptance_state": "ACCEPTED_EXACT_V131_RETAIN_BLOCKED",
            "projection_repeatability": "PASS",
            "entries": [
                {
                    "slug": entry["slug"],
                    "disposition": entry["disposition"],
                    "rationale_code": entry["rationale_code"],
                    "next_review_condition": entry["next_review_condition"],
                    "projection_digest": entry["controlled_evidence"]["projection_digest"],
                }
                for entry in proposed["entry_dispositions"]
            ],
        },
        "privacy": {
            "host_specific_path_matches": 0,
            "credential_values_present": False,
            "blocked_grade_risk_finding_or_receipt_fields_present": False,
            "raw_candidate_transfer_allowed": False,
        },
        "prior_acceptance_lineage": {"transfer_from_v130": False},
        "separate_public_state": {
            "production_freshness": "UNKNOWN",
            "production_source_binding": "UNKNOWN",
            "production_deployment_revision": "UNKNOWN",
            "relationship_to_v131": "NOT_PUBLISHED_AND_NOT_DEPLOYED",
        },
    }
    accepted_artifact["receipt_digest"] = grade_refresh.digest_bytes(
        canonical_bytes(accepted_artifact)
    )
    accepted_artifact_path = tmp_path / "accepted-disposition-v131.json"
    accepted_artifact_path.write_bytes(canonical_bytes(accepted_artifact))
    accepted_policy = {
        **proposed_policy,
        "review_state": "ACCEPTED_CURRENT_BOUNDARY_REVIEW",
        "forward_baseline": {
            "state": "OPERATOR_ACCEPTED_EXACT_V131_BOUNDARY_LOCAL_REVIEW_ONLY",
            "disposition": "retain-exact-v131-policy-boundary-as-forward-baseline",
        },
        "acceptance": {
            "authority": "operator",
            "scope": "all-eleven-current-policy-blocks-and-exact-v131-forward-baseline",
            "acceptance_state": "ACCEPTED_EXACT_V131_BOUNDARY",
            "accepted_review_path": proposed_review_path.name,
            "accepted_review_receipt_digest": proposed["receipt_digest"],
            "accepted_review_artifact_sha256": grade_refresh.digest_file(
                proposed_review_path
            ),
            "accepted_review_policy_sha256": proposed["disposition_policy"]["sha256"],
            "accepted_disposition_path": accepted_artifact_path.name,
            "accepted_disposition_receipt_digest": accepted_artifact["receipt_digest"],
            "accepted_disposition_artifact_sha256": grade_refresh.digest_file(
                accepted_artifact_path
            ),
        },
    }
    accepted_policy_path = tmp_path / "v131-boundary-accepted.json"
    accepted_policy_path.write_text(json.dumps(accepted_policy), encoding="utf-8")
    accepted = build_publication_review_decision(
        **build_kwargs,
        disposition_path=accepted_policy_path,
        accepted_review_path=proposed_review_path,
    )
    assert accepted["review_state"] == "ACCEPTED_FOR_BOUNDARY_REVIEW"
    assert accepted["disposition_counts"]["accepted_human"] == 11
    assert "blocked_policy_change_and_fresh_controlled_evidence_required" in accepted[
        "blocking_gates"
    ]
    state = build_publication_review_state_card(accepted)
    assert state["severity_findings"] == {
        "Critical": 11,
        "High": 0,
        "Medium": 22,
        "Low": 0,
    }
    assert state["next_action"].startswith("A separate policy change")


def test_publication_review_state_card_rejects_tampered_decision(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    decision = _build(monkeypatch, tmp_path)
    decision["publication_allowed"] = True

    with pytest.raises(GradeRefreshError, match="receipt integrity is invalid"):
        build_publication_review_state_card(decision)


def test_publication_review_state_card_rejects_false_accepted_counts(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    decision = _build(monkeypatch, tmp_path)
    decision["disposition_counts"]["accepted_human"] = 7
    unsigned = dict(decision)
    unsigned.pop("receipt_digest")
    decision["receipt_digest"] = grade_refresh.digest_bytes(canonical_bytes(unsigned))

    with pytest.raises(GradeRefreshError, match="accepted disposition counts"):
        build_publication_review_state_card(decision)


def test_publication_review_state_card_requires_current_acceptance_binding(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    decision = _build(monkeypatch, tmp_path)
    decision.pop("acceptance")
    unsigned = dict(decision)
    unsigned.pop("receipt_digest")
    decision["receipt_digest"] = grade_refresh.digest_bytes(canonical_bytes(unsigned))

    with pytest.raises(GradeRefreshError, match="acceptance binding is invalid"):
        build_publication_review_state_card(decision)


def test_bundled_v38_acceptance_is_receipt_bound_and_privacy_hardened() -> None:
    policy = json.loads(DISPOSITIONS.read_text(encoding="utf-8"))
    review = json.loads(BUNDLED_ACCEPTED_REVIEW.read_text(encoding="utf-8"))
    artifact = json.loads(BUNDLED_ACCEPTED_DISPOSITION.read_text(encoding="utf-8"))

    assert policy["review_state"] == "ACCEPTED_CURRENT_SOURCE_REVIEW"
    assert policy["acceptance"]["accepted_review_path"] == (
        BUNDLED_ACCEPTED_REVIEW.name
    )
    assert policy["acceptance"]["accepted_review_artifact_sha256"] == (
        grade_refresh.digest_file(BUNDLED_ACCEPTED_REVIEW)
    )
    assert policy["acceptance"]["accepted_review_receipt_digest"] == review[
        "receipt_digest"
    ]
    assert policy["acceptance"]["accepted_disposition_artifact_sha256"] == (
        grade_refresh.digest_file(BUNDLED_ACCEPTED_DISPOSITION)
    )
    assert policy["acceptance"]["accepted_disposition_receipt_digest"] == artifact[
        "receipt_digest"
    ]
    assert artifact["prior_acceptance_lineage"]["transfer_to_v38"] is False
    assert artifact["historical_baseline"]["state"] == "UNKNOWN"
    combined = BUNDLED_ACCEPTED_REVIEW.read_text() + BUNDLED_ACCEPTED_DISPOSITION.read_text()
    assert "/Users/" not in combined
    assert artifact["privacy"] == {
        "host_specific_path_matches": 0,
        "credential_values_present": False,
        "masked_grade_risk_finding_or_receipt_fields_present": False,
        "raw_candidate_transfer_allowed": False,
    }


def test_current_acceptance_rejects_v20_state_transfer(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    policy = json.loads(DISPOSITIONS.read_text(encoding="utf-8"))
    policy["review_state"] = "ACCEPTED"
    policy["forward_baseline"] = {
        "state": "ACCEPTED",
        "disposition": "adopt-exact-v20-candidate-bindings-as-forward-baseline",
    }
    policy_path = tmp_path / "v20-transfer.json"
    policy_path.write_text(json.dumps(policy), encoding="utf-8")

    with pytest.raises(GradeRefreshError, match="acceptance binding is invalid"):
        _build(
            monkeypatch,
            tmp_path,
            disposition_path=policy_path,
            accepted_review_path=BUNDLED_ACCEPTED_REVIEW,
        )


def test_current_acceptance_rejects_absolute_interpreter_path(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    review = json.loads(BUNDLED_ACCEPTED_REVIEW.read_text(encoding="utf-8"))
    review["forward_baseline"]["tool_versions"]["python_executable"] = (
        "/private/host/python3.11"
    )
    review_path = tmp_path / "accepted_publication_review_v38.json"
    review_path.write_bytes(canonical_bytes(review))

    with pytest.raises(GradeRefreshError, match="artifact digest does not match"):
        _build(
            monkeypatch,
            tmp_path,
            accepted_review_path=review_path,
        )


def test_publication_review_rejects_missing_masked_disposition(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    payload = json.loads(DISPOSITIONS.read_text(encoding="utf-8"))
    payload["entries"].pop()
    dispositions = tmp_path / "dispositions.json"
    dispositions.write_text(json.dumps(payload), encoding="utf-8")

    with pytest.raises(GradeRefreshError, match="every masked catalog entry"):
        _build(monkeypatch, tmp_path, disposition_path=dispositions)


def test_publication_review_preserves_historical_baseline_unknown(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    payload = json.loads(DISPOSITIONS.read_text(encoding="utf-8"))
    payload["historical_baseline"]["state"] = "KNOWN"
    dispositions = tmp_path / "dispositions.json"
    dispositions.write_text(json.dumps(payload), encoding="utf-8")

    with pytest.raises(GradeRefreshError, match="historical baseline must remain UNKNOWN"):
        _build(monkeypatch, tmp_path, disposition_path=dispositions)


def test_publication_review_rejects_false_green_masked_proof(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    _, _, _, projections = _inputs()
    tampered = copy.deepcopy(projections)
    first_slug = sorted(tampered)[0]
    tampered[first_slug]["sandbox"]["MCP_TRUST_SANDBOX_NETWORK"] = "bridge"

    with pytest.raises(GradeRefreshError, match="masked controlled evidence is invalid"):
        _build(monkeypatch, tmp_path, projections=tampered)


def test_publication_review_rejects_unqualified_masked_image(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    _, _, _, projections = _inputs()
    tampered = copy.deepcopy(projections)
    first_slug = sorted(tampered)[0]
    tampered[first_slug]["sandbox"]["MCP_TRUST_SANDBOX_IMAGE"] = "sha256:" + "9" * 64

    with pytest.raises(GradeRefreshError, match="qualified image binding"):
        _build(monkeypatch, tmp_path, projections=tampered)


def test_publication_review_rejects_inventory_inconsistent_disposition(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    payload = json.loads(DISPOSITIONS.read_text(encoding="utf-8"))
    discourse = next(
        entry
        for entry in payload["entries"]
        if entry["slug"] == "io-github-discourse-mcp-0-2-9"
    )
    discourse["rationale_code"] = "backing-service-not-exercised"
    dispositions = tmp_path / "dispositions.json"
    dispositions.write_text(json.dumps(payload), encoding="utf-8")

    with pytest.raises(GradeRefreshError, match="inconsistent with inventory"):
        _build(monkeypatch, tmp_path, disposition_path=dispositions)


def test_accepted_policy_requires_exact_review_artifact(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    preflight, repeatability, triage, projections = _inputs()
    monkeypatch.setattr(grade_refresh, "triage_candidate", lambda **_kwargs: triage)
    monkeypatch.setattr(
        grade_refresh, "catalog_inventory", lambda **_kwargs: _legacy_v38_inventory()
    )

    with pytest.raises(GradeRefreshError, match="requires a review artifact"):
        build_publication_review_decision(
            candidate=tmp_path / "first",
            repeat_candidate=tmp_path / "second",
            preflight=preflight,
            repeatability=repeatability,
            triage=triage,
            seed_path=SEED,
            masked_path=MASKED,
            policy_path=POLICY,
            disposition_path=DISPOSITIONS,
            projection_builder=lambda _path: projections,
        )


def test_accepted_policy_rejects_wrong_review_artifact(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    wrong_review = tmp_path / "wrong-review.json"
    wrong_review.write_text("{}", encoding="utf-8")

    with pytest.raises(GradeRefreshError, match="artifact digest does not match"):
        _build(monkeypatch, tmp_path, accepted_review_path=wrong_review)


def test_publication_review_rejects_preflight_inventory_denominator_mismatch(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    preflight, repeatability, triage, projections = _inputs()
    preflight["catalog"]["denominator"] = 0
    monkeypatch.setattr(grade_refresh, "triage_candidate", lambda **_kwargs: triage)
    monkeypatch.setattr(
        grade_refresh, "catalog_inventory", lambda **_kwargs: _legacy_v38_inventory()
    )
    proposed_policy = json.loads(DISPOSITIONS.read_text(encoding="utf-8"))
    proposed_policy["review_state"] = "PROPOSED"
    proposed_policy["forward_baseline"] = {
        "state": "PROPOSED",
        "disposition": "adopt-exact-candidate-bindings-after-operator-acceptance",
    }
    proposed_policy.pop("acceptance")
    proposed_policy_path = tmp_path / "proposed-dispositions.json"
    proposed_policy_path.write_text(json.dumps(proposed_policy), encoding="utf-8")

    with pytest.raises(GradeRefreshError, match="preflight is stale or unbound"):
        build_publication_review_decision(
            candidate=tmp_path / "first",
            repeat_candidate=tmp_path / "second",
            preflight=preflight,
            repeatability=repeatability,
            triage=triage,
            seed_path=SEED,
            masked_path=MASKED,
            policy_path=POLICY,
            disposition_path=proposed_policy_path,
            projection_builder=lambda _path: projections,
        )
