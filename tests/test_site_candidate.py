from __future__ import annotations

import hashlib
import json
from datetime import UTC, datetime
from pathlib import Path

import pytest

from mcp_trust.core.models import Server, ServerSource, SourceKind
from mcp_trust.grade_refresh import digest_file
from mcp_trust.site.candidate import (
    ACCEPTED_REVIEW_STATE,
    DEPLOYABLE_STATE,
    PENDING_STATE,
    SiteCandidateError,
    build_site_candidate,
    canonical_bytes,
    site_candidate_readback_manifest,
    verify_site_candidate,
)
from mcp_trust.store.db import connect, init_schema
from mcp_trust.store.repository import ServerRepository


def _fixture(tmp_path: Path) -> dict[str, object]:
    candidate = tmp_path / "candidate"
    candidate.mkdir()
    connection = connect(candidate / "registry.db")
    init_schema(connection)
    ServerRepository(connection).upsert(
        Server(
            slug="masked-server",
            name="Masked Server",
            description="grade-must-remain-withheld",
            source=ServerSource(kind=SourceKind.NPM, reference="masked-server"),
            added_at=datetime(2026, 8, 23, tzinfo=UTC),
        )
    )
    connection.close()
    (candidate / "MANIFEST.json").write_text(
        json.dumps(
            {
                "created_at": "2026-08-23T17:36:33+00:00",
                "masking": {"slugs": ["masked-server"]},
            }
        ),
        encoding="utf-8",
    )
    seed = tmp_path / "seed.json"
    seed.write_text("[]\n", encoding="utf-8")
    masked = tmp_path / "masked.json"
    masked.write_text('["masked-server"]\n', encoding="utf-8")
    policy = tmp_path / "policy.json"
    policy.write_text('{"schema":"test-policy"}\n', encoding="utf-8")
    corrections = tmp_path / "corrections.json"
    corrections.write_text("[]\n", encoding="utf-8")

    manifest_hex = "a" * 64
    review: dict[str, object] = {
        "schema": "McpTrustPublicationReviewDecisionV1",
        "review_state": "READY_FOR_HUMAN_DISPOSITION",
        "decision": "NO_GO",
        "publication_allowed": False,
        "deployment_allowed": False,
        "scheduler_change_allowed": False,
        "grade_semantics": "technical-danger-not-endorsement",
        "claim_ceiling": "Local review only; not publication or deployment.",
        "disposition_policy": {
            "path": "refresh_disposition_policy.json",
            "review_state": "PROPOSED",
            "sha256": "sha256:" + "1" * 64,
        },
        "entry_dispositions": [
            {
                "slug": "masked-server",
                "disposition": "KEEP_MASKED_REVIEW_REQUIRED",
                "rationale_code": "operator-masking-continuity",
                "next_review_condition": "explicit-human-disposition",
                "acceptance_state": "PENDING_HUMAN_ACCEPTANCE",
                "classification": {
                    "unsupported_upstream": False,
                    "credential_dependent": False,
                    "backing_service_dependent": False,
                    "unsafe_to_execute_unsandboxed": True,
                },
                "controlled_evidence": {
                    "outcome": "scan_succeeded",
                    "evidence_state": "present",
                    "sandbox_image_id": "sha256:" + "d" * 64,
                    "projection_digest": "sha256:" + "e" * 64,
                },
                "claim_ceiling": "No unmasked grade or safety claim.",
            }
        ],
        "disposition_counts": {
            "total": 1,
            "pending_human_acceptance": 1,
            "retain_masked": 1,
        },
        "candidate_counts": {"fresh": 0, "masked": 1, "total": 1},
        "historical_baseline": {
            "state": "UNKNOWN",
            "disposition": "preserve-unknown-no-retroactive-comparison",
        },
        "forward_baseline": {
            "state": "PROPOSED",
            "candidate_manifest_digest": "sha256:" + manifest_hex,
            "repeat_candidate_manifest_digest": "sha256:" + "f" * 64,
            "seed_digest": digest_file(seed),
            "masking_digest": digest_file(masked),
            "policy_digest": digest_file(policy),
            "preflight_receipt_digest": "sha256:" + "2" * 64,
            "repeatability_receipt_digest": "sha256:" + "3" * 64,
            "triage_receipt_digest": "sha256:" + "4" * 64,
            "catalog_denominator": 1,
            "source_revision": "b" * 40,
            "source_tree_digest": "sha256:" + "c" * 64,
            "qualified_images": {"fixture": "sha256:" + "d" * 64},
            "tool_versions": {"python": "3.11.15", "python_executable": "python3.11"},
        },
        "scheduler_disposition": {
            "activation_authorized": False,
            "mutation_performed": False,
            "observed_state": "DISABLED_UNLOADED",
            "loaded_domains": [],
        },
        "blocking_gates": [
            "masked_disposition_acceptance_required",
            "forward_baseline_acceptance_required",
            "exact_source_review_and_landing_required",
            "immutable_site_artifact_and_rollback_binding_required",
            "explicit_publication_authority_required",
            "production_source_and_deployment_binding_unknown",
        ],
        "quarantined_gates": ["dormant_scheduler_definition_drift_before_activation"],
        "false_green_guards": [
            "candidate-readiness-is-not-publication-authority",
            "masked-scan-success-is-not-an-unmasked-grade-or-safety-claim",
            "local-candidate-freshness-does-not-prove-production-freshness",
        ],
    }
    review["receipt_digest"] = "sha256:" + hashlib.sha256(canonical_bytes(review)).hexdigest()
    review_path = tmp_path / "sanitized-review.json"
    review_path.write_bytes(canonical_bytes(review))
    disposition = {
        "schema": "McpTrustGradeRefreshDispositionPolicyV1",
        "review_state": "SANITIZED_REACCEPTANCE_REQUIRED",
        "acceptance": {
            "sanitized_acceptance_state": "PENDING_OPERATOR_REACCEPTANCE",
            "sanitized_review_path": review_path.name,
            "sanitized_review_artifact_sha256": digest_file(review_path),
            "sanitized_review_receipt_digest": review["receipt_digest"],
        },
    }
    disposition_path = tmp_path / "disposition.json"
    disposition_path.write_text(json.dumps(disposition), encoding="utf-8")

    def verifier(*_args, **_kwargs) -> dict[str, object]:
        return {
            "publication_ready": True,
            "manifest_sha256": manifest_hex,
            "scan_counts": {"fresh": 0, "masked": 1, "total": 1, "failed": 0},
            "errors": [],
        }

    return {
        "candidate_path": candidate,
        "review_path": review_path,
        "disposition_path": disposition_path,
        "seed_path": seed,
        "masked_path": masked,
        "policy_path": policy,
        "corrections_path": corrections,
        "base_url": "https://mcp-trust.example",
        "implementation_binding": {
            "state": "CLEAN_COMMITTED",
            "revision": "9" * 40,
            "source_tree_digest": "sha256:" + "8" * 64,
        },
        "candidate_verifier": verifier,
    }


def _tree(root: Path) -> dict[str, bytes]:
    return {
        path.relative_to(root).as_posix(): path.read_bytes()
        for path in root.rglob("*")
        if path.is_file()
    }


def _accepted_fixture(tmp_path: Path) -> dict[str, object]:
    inputs = _fixture(tmp_path)
    review_path = inputs["review_path"]
    disposition_path = inputs["disposition_path"]
    assert isinstance(review_path, Path)
    assert isinstance(disposition_path, Path)
    review = json.loads(review_path.read_text())
    artifact: dict[str, object] = {
        "schema": "McpTrustAcceptedDispositionArtifactV1",
        "decision": "OPERATOR_ACCEPTED_EXACT_V38",
        "acceptance": {
            "state": "ACCEPTED_EXACT_V38",
            "scope": (
                "all-eight-current-masked-dispositions-and-exact-v37-forward-baseline"
            ),
            "proposal_policy_sha256": review["disposition_policy"]["sha256"],
        },
        "forward_baseline": {
            **review["forward_baseline"],
            "state": "OPERATOR_ACCEPTED_EXACT_V38_LOCAL_REVIEW_ONLY",
        },
        "historical_baseline": review["historical_baseline"],
        "masked_dispositions": {
            "count": 1,
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
                for entry in review["entry_dispositions"]
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
        },
    }
    artifact["receipt_digest"] = "sha256:" + hashlib.sha256(
        canonical_bytes(artifact)
    ).hexdigest()
    artifact_path = tmp_path / "accepted_disposition_artifact_v38.json"
    artifact_path.write_bytes(canonical_bytes(artifact))
    disposition = {
        "schema": "McpTrustGradeRefreshDispositionPolicyV2",
        "review_state": "ACCEPTED_CURRENT_SOURCE_REVIEW",
        "grade_semantics": "technical-danger-not-endorsement",
        "historical_baseline": review["historical_baseline"],
        "forward_baseline": {
            "state": "OPERATOR_ACCEPTED_EXACT_V38_LOCAL_REVIEW_ONLY",
            "disposition": (
                "adopt-exact-v37-candidate-bindings-as-current-forward-baseline"
            ),
        },
        "acceptance": {
            "authority": "operator",
            "scope": (
                "all-eight-current-masked-dispositions-and-exact-v37-forward-baseline"
            ),
            "acceptance_state": "ACCEPTED_EXACT_V38",
            "accepted_review_path": review_path.name,
            "accepted_review_artifact_sha256": digest_file(review_path),
            "accepted_review_receipt_digest": review["receipt_digest"],
            "accepted_review_policy_sha256": review["disposition_policy"]["sha256"],
            "accepted_disposition_path": artifact_path.name,
            "accepted_disposition_artifact_sha256": digest_file(artifact_path),
            "accepted_disposition_receipt_digest": artifact["receipt_digest"],
        },
    }
    disposition_path.write_text(json.dumps(disposition), encoding="utf-8")
    return inputs


def test_pending_site_candidate_is_deterministic_and_non_publishable(tmp_path: Path) -> None:
    inputs = _fixture(tmp_path)
    first = build_site_candidate(output_path=tmp_path / "first", **inputs)
    second = build_site_candidate(output_path=tmp_path / "second", **inputs)

    assert _tree(first) == _tree(second)
    verified = verify_site_candidate(first)
    assert verified == {
        "structural_valid": True,
        "state": PENDING_STATE,
        "publication_allowed": False,
        "deployment_allowed": False,
        "rollback_state": "UNKNOWN",
        "content_digest": verified["content_digest"],
        "receipt_digest": verified["receipt_digest"],
        "file_count": 7,
        "readback_manifest_bound": True,
        "readback_manifest_digest": verified["readback_manifest_digest"],
    }
    badge = json.loads((first / "servers/masked-server/badge.json").read_text())
    assert badge["message"] == "under review"
    assert '"message": "A"' not in (first / "servers/masked-server/badge.json").read_text()
    manifest = json.loads((first / "SITE_CANDIDATE.json").read_text())
    assert manifest["implementation_binding"] == inputs["implementation_binding"]
    readback = site_candidate_readback_manifest(first)
    assert readback == manifest["public_readback"]
    assert len(readback["routes"]) == 7
    assert readback["routes"][0]["route"] == "/__mcp_trust_candidate_missing__"
    assert readback["routes"][0]["expected_status"] == 404
    assert readback["routes"][-1]["route"] == "/ui/servers/masked-server"
    assert all("body_sha256" in route for route in readback["routes"])


def test_accepted_current_site_candidate_is_deterministic_and_non_publishable(
    tmp_path: Path,
) -> None:
    inputs = _accepted_fixture(tmp_path)
    first = build_site_candidate(output_path=tmp_path / "first", **inputs)
    second = build_site_candidate(output_path=tmp_path / "second", **inputs)

    assert _tree(first) == _tree(second)
    verified = verify_site_candidate(first)
    assert verified["state"] == ACCEPTED_REVIEW_STATE
    assert verified["publication_allowed"] is False
    assert verified["deployment_allowed"] is False
    assert verified["rollback_state"] == "UNKNOWN"
    manifest = json.loads((first / "SITE_CANDIDATE.json").read_text())
    assert "sanitized_review_acceptance_required" not in manifest["blocking_gates"]
    assert "explicit_publication_authority_required" in manifest["blocking_gates"]
    assert "production_source_and_deployment_binding_unknown" in manifest[
        "blocking_gates"
    ]
    assert "rollback_artifact_binding_unknown" in manifest["blocking_gates"]


def test_accepted_current_site_candidate_rejects_acceptance_artifact_tamper(
    tmp_path: Path,
) -> None:
    inputs = _accepted_fixture(tmp_path)
    disposition_path = inputs["disposition_path"]
    assert isinstance(disposition_path, Path)
    disposition = json.loads(disposition_path.read_text())
    artifact = disposition_path.parent / disposition["acceptance"][
        "accepted_disposition_path"
    ]
    artifact.write_text("{}\n", encoding="utf-8")

    with pytest.raises(SiteCandidateError, match="artifact integrity"):
        build_site_candidate(output_path=tmp_path / "output", **inputs)


def test_receipt_bound_public_readback_manifest_cannot_drift(tmp_path: Path) -> None:
    inputs = _fixture(tmp_path)
    output = build_site_candidate(output_path=tmp_path / "output", **inputs)
    manifest_path = output / "SITE_CANDIDATE.json"
    manifest = json.loads(manifest_path.read_text())
    manifest.pop("receipt_digest")
    manifest["public_readback"]["routes"][0]["body_sha256"] = "0" * 64
    manifest["receipt_digest"] = "sha256:" + hashlib.sha256(canonical_bytes(manifest)).hexdigest()
    manifest_path.write_bytes(canonical_bytes(manifest))

    with pytest.raises(SiteCandidateError, match="public readback manifest changed"):
        verify_site_candidate(output)


def test_legacy_pending_candidate_remains_valid_but_cannot_emit_exact_readback(
    tmp_path: Path,
) -> None:
    inputs = _fixture(tmp_path)
    output = build_site_candidate(output_path=tmp_path / "output", **inputs)
    manifest_path = output / "SITE_CANDIDATE.json"
    manifest = json.loads(manifest_path.read_text())
    manifest.pop("receipt_digest")
    manifest.pop("public_readback")
    manifest["receipt_digest"] = "sha256:" + hashlib.sha256(canonical_bytes(manifest)).hexdigest()
    manifest_path.write_bytes(canonical_bytes(manifest))

    verification = verify_site_candidate(output)
    assert verification["readback_manifest_bound"] is False
    assert verification["readback_manifest_digest"] is None
    with pytest.raises(SiteCandidateError, match="no receipt-bound public readback"):
        site_candidate_readback_manifest(output)


def test_deployable_candidate_cannot_omit_exact_public_readback(tmp_path: Path) -> None:
    inputs = _fixture(tmp_path)
    output = build_site_candidate(output_path=tmp_path / "output", **inputs)
    manifest_path = output / "SITE_CANDIDATE.json"
    manifest = json.loads(manifest_path.read_text())
    manifest.pop("receipt_digest")
    manifest.pop("public_readback")
    manifest["state"] = DEPLOYABLE_STATE
    manifest["publication_allowed"] = True
    manifest["deployment_allowed"] = True
    manifest["blocking_gates"] = []
    manifest["bindings"]["state"] = DEPLOYABLE_STATE
    manifest["bindings"]["publication_allowed"] = True
    manifest["bindings"]["deployment_allowed"] = True
    manifest["bindings"]["rollback_state"] = "BOUND"
    manifest["rollback"] = {
        "state": "BOUND",
        "site_receipt_digest": "sha256:" + "1" * 64,
        "content_digest": "sha256:" + "2" * 64,
    }
    manifest["receipt_digest"] = "sha256:" + hashlib.sha256(canonical_bytes(manifest)).hexdigest()
    manifest_path.write_bytes(canonical_bytes(manifest))

    with pytest.raises(SiteCandidateError, match="lacks exact public readback"):
        verify_site_candidate(output)


def test_pending_prior_artifact_cannot_become_bound_rollback(tmp_path: Path) -> None:
    inputs = _fixture(tmp_path)
    prior = build_site_candidate(output_path=tmp_path / "prior", **inputs)
    current = tmp_path / "current"

    with pytest.raises(SiteCandidateError, match="not a retained deployment-qualified"):
        build_site_candidate(output_path=current, rollback_candidate=prior, **inputs)
    assert not current.exists()


def test_tampered_review_fails_without_final_output(tmp_path: Path) -> None:
    inputs = _fixture(tmp_path)
    review = inputs["review_path"]
    assert isinstance(review, Path)
    payload = json.loads(review.read_text())
    payload["candidate_counts"]["total"] = 2
    review.write_text(json.dumps(payload), encoding="utf-8")
    output = tmp_path / "output"

    with pytest.raises(SiteCandidateError, match="lineage|integrity"):
        build_site_candidate(output_path=output, **inputs)
    assert not output.exists()
    assert not list(tmp_path.glob(".output.tmp-*"))


def test_site_candidate_tamper_and_extra_file_fail_verification(tmp_path: Path) -> None:
    inputs = _fixture(tmp_path)
    output = build_site_candidate(output_path=tmp_path / "output", **inputs)
    badge = output / "servers/masked-server/badge.json"
    badge.write_text('{"message":"A"}\n', encoding="utf-8")
    with pytest.raises(SiteCandidateError, match="file manifest changed"):
        verify_site_candidate(output)

    badge.unlink()
    (output / "unexpected.txt").write_text("extra\n", encoding="utf-8")
    with pytest.raises(SiteCandidateError, match="file manifest changed"):
        verify_site_candidate(output)


def test_pending_manifest_cannot_self_assert_publication_authority(tmp_path: Path) -> None:
    inputs = _fixture(tmp_path)
    output = build_site_candidate(output_path=tmp_path / "output", **inputs)
    manifest_path = output / "SITE_CANDIDATE.json"
    manifest = json.loads(manifest_path.read_text())
    manifest.pop("receipt_digest")
    manifest["publication_allowed"] = True
    manifest["deployment_allowed"] = True
    manifest["receipt_digest"] = "sha256:" + hashlib.sha256(canonical_bytes(manifest)).hexdigest()
    manifest_path.write_bytes(canonical_bytes(manifest))

    with pytest.raises(SiteCandidateError, match="exceeds its authority"):
        verify_site_candidate(output)


def test_input_drift_during_rendering_fails_without_output(tmp_path: Path) -> None:
    inputs = _fixture(tmp_path)
    stable = inputs["candidate_verifier"]
    assert callable(stable)
    calls = 0

    def drifting(*args, **kwargs) -> dict[str, object]:
        nonlocal calls
        calls += 1
        result = dict(stable(*args, **kwargs))
        if calls > 1:
            result["manifest_sha256"] = "e" * 64
        return result

    inputs["candidate_verifier"] = drifting
    output = tmp_path / "output"
    with pytest.raises(SiteCandidateError, match="candidate_manifest_digest"):
        build_site_candidate(output_path=output, **inputs)
    assert not output.exists()


def test_symlinked_review_input_is_rejected(tmp_path: Path) -> None:
    inputs = _fixture(tmp_path)
    review = inputs["review_path"]
    assert isinstance(review, Path)
    link = tmp_path / "review-link.json"
    link.symlink_to(review)
    inputs["review_path"] = link

    with pytest.raises(SiteCandidateError, match="must not be symlinked"):
        build_site_candidate(output_path=tmp_path / "output", **inputs)


def test_site_candidate_refuses_existing_target_and_symlink(tmp_path: Path) -> None:
    inputs = _fixture(tmp_path)
    output = tmp_path / "output"
    output.mkdir()
    with pytest.raises(SiteCandidateError, match="already exists"):
        build_site_candidate(output_path=output, **inputs)

    output.rmdir()
    output.symlink_to(tmp_path / "missing")
    with pytest.raises(SiteCandidateError, match="already exists"):
        build_site_candidate(output_path=output, **inputs)
