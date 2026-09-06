"""V47 local-only publication admission and deterministic package contract."""

from __future__ import annotations

import json
from collections.abc import Callable
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

import pytest

from mcp_trust.site import candidate as candidate_module
from mcp_trust.site.candidate import (
    ACCEPTED_REVIEW_STATE,
    PROVIDER_NATIVE_ROLLBACK_SCHEMA,
    PROVIDER_NATIVE_ROLLBACK_STATE,
    canonical_bytes,
)
from mcp_trust.site.publication import (
    PROVIDER_PREPUBLICATION_SCHEMA,
    PublicationAdmissionError,
    _binding_digest,
    _candidate_projection,
    _sha256_bytes,
    build_publication_package,
    verify_publication_approval,
    verify_publication_package,
)

NOW = datetime(2026, 8, 25, 12, 10, tzinfo=UTC)
ISSUED = datetime(2026, 8, 25, 12, 5, tzinfo=UTC)
DIGESTS = {letter: _sha256_bytes(letter.encode()) for letter in "abcdefghijklmno"}


def _write_receipted(path: Path, payload: dict[str, Any]) -> None:
    payload.pop("receipt_digest", None)
    payload["receipt_digest"] = _sha256_bytes(canonical_bytes(payload))
    path.write_bytes(canonical_bytes(payload))


def _provider_rollback() -> dict[str, Any]:
    payload: dict[str, Any] = {
        "schema": PROVIDER_NATIVE_ROLLBACK_SCHEMA,
        "state": PROVIDER_NATIVE_ROLLBACK_STATE,
        "provider": "vercel",
        "observed_at": "2026-08-25T11:55:00+00:00",
        "freshness_seconds": 3600,
        "production_target": {
            "alias": "mcp-trust.example",
            "deployment_id": "dpl_previous",
            "immutable_deployment_url": "previous.vercel.app",
            "project_id": "prj_project",
            "team_id": "team_team",
            "target": "production",
            "deployment_state": "READY_PROMOTED",
            "source_revision": "1" * 40,
            "source_tree": "2" * 40,
            "public_tree_digest": DIGESTS["a"],
        },
        "provenance": {
            "provider_metadata_receipt": DIGESTS["b"],
            "provider_binding_decision_receipt": DIGESTS["c"],
        },
        "conditions": {
            "first_following_same_project_publication": True,
            "no_intervening_production_deployment": True,
            "target_must_remain_retained": True,
            "prepublication_provider_readback_required": True,
            "immediate_previous_rollback_only": True,
        },
        "authority": {
            "publication_allowed": False,
            "deployment_allowed": False,
            "rollback_execution_allowed": False,
            "scheduler_activation_allowed": False,
        },
        "unknown": [
            "provider_artifact_digest",
            "exercised_rollback_routing",
            "future_prepublication_binding",
        ],
        "claim_ceiling": (
            "Review-only target binding; not publication authority, not deployment "
            "authority, and not exercised rollback proof."
        ),
    }
    payload["receipt_digest"] = _sha256_bytes(canonical_bytes(payload))
    return payload


def _site_candidate(tmp_path: Path) -> Path:
    root = tmp_path / "site-candidate"
    root.mkdir()
    (root / "index.html").write_text("historical catalog\n", encoding="utf-8")
    (root / "404.html").write_text("not found\n", encoding="utf-8")
    files = candidate_module._capture_content(root)
    content_digest = candidate_module._content_digest(files)
    rollback = _provider_rollback()
    manifest: dict[str, Any] = {
        "schema": "McpTrustSiteCandidateV2",
        "state": ACCEPTED_REVIEW_STATE,
        "created_at": "2026-08-25T12:00:00+00:00",
        "base_url": "https://mcp-trust.example",
        "implementation_binding": {
            "state": "CLEAN_COMMITTED",
            "revision": "9" * 40,
            "source_tree_digest": DIGESTS["d"],
        },
        "publication_allowed": False,
        "deployment_allowed": False,
        "claim_ceiling": "Review-only historical artifact; not publication or deployment.",
        "bindings": {
            "state": ACCEPTED_REVIEW_STATE,
            "publication_allowed": False,
            "deployment_allowed": False,
            "rollback_state": PROVIDER_NATIVE_ROLLBACK_STATE,
            "candidate_manifest_digest": DIGESTS["e"],
            "review_artifact_sha256": DIGESTS["f"],
            "review_receipt_digest": DIGESTS["g"],
            "disposition_policy_sha256": DIGESTS["h"],
            "seed_digest": DIGESTS["i"],
            "masking_digest": DIGESTS["j"],
            "policy_digest": DIGESTS["k"],
            "source_revision": "8" * 40,
            "source_tree_digest": DIGESTS["l"],
        },
        "corrections_digest": DIGESTS["m"],
        "site_counts": {
            "servers": 1,
            "scanned": 1,
            "masked": 1,
            "stale": 0,
            "demo": 0,
        },
        "freshness": {
            "mode": "STATIC_HISTORICAL_ONLY",
            "horizon_days": 90,
            "evaluated_at": "2026-08-25T12:00:00+00:00",
            "earliest_stale_after": "2026-11-23T12:00:00+00:00",
            "publication_not_after": "2026-08-26T12:00:00+00:00",
            "state_counts": {
                "FRESH": 0,
                "STALE": 0,
                "UNKNOWN": 0,
                "NOT_APPLICABLE": 1,
            },
        },
        "projection_digests": {
            "refresh_scan_results": DIGESTS["a"],
            "refresh_static_snapshot": DIGESTS["b"],
            "masking": DIGESTS["c"],
            "site_content": content_digest,
        },
        "content": {"digest": content_digest, "files": files},
        "public_readback": candidate_module._public_readback_manifest(files),
        "rollback": rollback,
        "blocking_gates": [
            "explicit_publication_authority_required",
            "provider_native_rollback_revalidation_and_publication_approval_required",
        ],
    }
    manifest["receipt_digest"] = _sha256_bytes(canonical_bytes(manifest))
    (root / "SITE_CANDIDATE.json").write_bytes(canonical_bytes(manifest))
    candidate_module.verify_site_candidate(root)
    return root


def _approval_payload(candidate: Path) -> dict[str, Any]:
    candidate_projection, site = _candidate_projection(candidate)
    bindings = site["bindings"]
    provider: dict[str, Any] = {
        "schema": PROVIDER_PREPUBLICATION_SCHEMA,
        "metadata_receipt_digest": DIGESTS["a"],
        "binding_decision_receipt_digest": DIGESTS["b"],
        "observed_at": "2026-08-25T12:00:00+00:00",
        "freshness_seconds": 3600,
        "alias": "mcp-trust.example",
        "deployment_id": "dpl_previous",
        "immutable_deployment_url": "previous.vercel.app",
        "project_id": "prj_project",
        "team_id": "team_team",
        "target": "production",
        "deployment_state": "READY_PROMOTED",
        "source_revision": "1" * 40,
        "source_tree": "2" * 40,
        "public_tree_digest": DIGESTS["c"],
        "alias_matches": True,
        "same_project_team": True,
        "no_intervening_deployment": True,
        "target_retained": True,
        "matches_candidate_rollback_target": True,
    }
    provider["receipt_digest"] = _sha256_bytes(canonical_bytes(provider))
    approval: dict[str, Any] = {
        "schema": "McpTrustPublicationApprovalV1",
        "state": "PUBLICATION_CONTENT_APPROVED_LOCAL_ONLY",
        "approval_id": "approval-001",
        "issued_at": ISSUED.isoformat(),
        "expires_at": (ISSUED + timedelta(minutes=40)).isoformat(),
        "freshness_seconds": 3600,
        "candidate": candidate_projection,
        "refresh_lineage": {
            "candidate_manifest_digest": bindings["candidate_manifest_digest"],
            "repeat_candidate_manifest_digest": DIGESTS["d"],
            "candidate_relative_tree_digest": DIGESTS["e"],
            "repeat_candidate_relative_tree_digest": DIGESTS["e"],
            "preflight_receipt_digest": DIGESTS["f"],
            "repeatability_receipt_digest": DIGESTS["g"],
            "triage_receipt_digest": DIGESTS["h"],
            "sandbox_qualification_receipt_digest": DIGESTS["i"],
            "source_revision": bindings["source_revision"],
            "source_tree_digest": bindings["source_tree_digest"],
            "seed_digest": bindings["seed_digest"],
            "masking_digest": bindings["masking_digest"],
            "policy_digest": bindings["policy_digest"],
            "tool_versions_digest": DIGESTS["j"],
            "qualified_images_digest": DIGESTS["k"],
        },
        "review_lineage": {
            "publication_review_artifact_sha256": bindings["review_artifact_sha256"],
            "publication_review_receipt_digest": bindings["review_receipt_digest"],
            "disposition_policy_sha256": bindings["disposition_policy_sha256"],
            "accepted_disposition_artifact_sha256": DIGESTS["l"],
            "accepted_disposition_receipt_digest": DIGESTS["m"],
            "accepted_review_policy_sha256": DIGESTS["n"],
            "acceptance_state": "ACCEPTED_EXACT_V38",
            "acceptance_scope": (
                "all-eight-current-masked-dispositions-and-exact-v37-forward-baseline"
            ),
        },
        "triage_resolution": {
            "triage_receipt_digest": DIGESTS["h"],
            "findings_projection_digest": DIGESTS["i"],
            "resolution_receipt_digest": DIGESTS["j"],
            "reviewed_finding_count": 2,
            "unresolved_finding_count": 0,
            "accepted_finding_codes": ["large-change", "policy-change"],
            "accepted_masked_slugs": ["masked-server"],
            "policy_change_reviewed": True,
        },
        "policy_and_semantics": {
            "danger_grade_axis": "technical-danger-only",
            "transparency_axis": "separate-from-danger",
            "evidence_quality_axis": "separate-from-danger-and-transparency",
            "endorsement": False,
            "masked_results_withheld": True,
            "unknown_is_not_safe": True,
        },
        "provider_prepublication": provider,
        "rollback": {
            "mode": "provider-native-first-publication",
            "embedded_candidate_rollback_receipt": site["rollback"]["receipt_digest"],
            "prepublication_revalidation_receipt": provider["receipt_digest"],
            "immediate_previous_deployment_id": "dpl_previous",
            "target_retained": True,
            "same_project_team": True,
            "rollback_execution_allowed": False,
            "provider_artifact_digest": "UNKNOWN",
            "exercised_rollback_routing": "UNKNOWN",
        },
        "operator_acceptance": {
            "authority": "operator",
            "decision": "OPERATOR_ACCEPTED_EXACT_PUBLICATION_CONTENT",
            "locator": "chat-approval-v47",
            "accepted_at": "2026-08-25T12:04:00+00:00",
            "statement_sha256": DIGESTS["o"],
            "accepted_binding_digest": "pending",
        },
        "authority": {
            "publication_content_approved": True,
            "publication_package_build_allowed": True,
            "public_mutation_allowed": False,
            "deployment_allowed": False,
            "rollback_execution_allowed": False,
            "scheduler_activation_allowed": False,
            "outreach_allowed": False,
        },
        "unknown": [
            "provider_artifact_digest",
            "exercised_rollback_routing",
            "future_provider_deployment_identity",
            "post_deploy_public_readback",
            "production_grade_freshness",
        ],
        "claim_ceiling": (
            "Content approval only; not deployment authority; not rollback execution "
            "authority; not scheduler authority; not endorsement; production freshness unknown."
        ),
    }
    approval["operator_acceptance"]["accepted_binding_digest"] = _binding_digest(approval)
    approval["receipt_digest"] = _sha256_bytes(canonical_bytes(approval))
    return approval


def _approval_fixture(tmp_path: Path) -> tuple[Path, Path, dict[str, Any]]:
    candidate = _site_candidate(tmp_path)
    approval = _approval_payload(candidate)
    approval_path = tmp_path / "approval.json"
    approval_path.write_bytes(canonical_bytes(approval))
    return candidate, approval_path, approval


def _resign(approval: dict[str, Any], path: Path) -> None:
    approval.pop("receipt_digest", None)
    approval["operator_acceptance"]["accepted_binding_digest"] = _binding_digest(approval)
    approval["receipt_digest"] = _sha256_bytes(canonical_bytes(approval))
    path.write_bytes(canonical_bytes(approval))


def test_pa_001_exact_inputs_produce_local_only_approval(tmp_path: Path) -> None:
    candidate, approval_path, _ = _approval_fixture(tmp_path)

    verified = verify_publication_approval(
        approval_path,
        candidate_path=candidate,
        now=NOW,
    )

    assert verified["state"] == "PUBLICATION_CONTENT_APPROVED_LOCAL_ONLY"
    assert verified["public_mutation_allowed"] is False
    assert verified["deployment_allowed"] is False


def test_pa_002_two_frozen_package_builds_are_byte_identical(tmp_path: Path) -> None:
    candidate, approval_path, _ = _approval_fixture(tmp_path)
    first = build_publication_package(
        candidate_path=candidate,
        approval_path=approval_path,
        output_path=tmp_path / "package-a",
        now=NOW,
    )
    second = build_publication_package(
        candidate_path=candidate,
        approval_path=approval_path,
        output_path=tmp_path / "package-b",
        now=NOW,
    )

    tree = lambda root: {  # noqa: E731 - concise deterministic tree projection
        path.relative_to(root).as_posix(): path.read_bytes()
        for path in root.rglob("*")
        if path.is_file()
    }
    assert tree(first) == tree(second)
    assert (
        verify_publication_package(first, approval_path=approval_path, now=NOW)[
            "deployment_allowed"
        ]
        is False
    )


Mutation = Callable[[Path, Path, dict[str, Any]], None]


def _mutate_approval(
    field: str,
    value: Any,
    *,
    nested: str | None = None,
    resign: bool = True,
) -> Mutation:
    def mutate(_candidate: Path, approval_path: Path, approval: dict[str, Any]) -> None:
        target = approval[nested] if nested is not None else approval
        target[field] = value
        if resign:
            _resign(approval, approval_path)
        else:
            approval_path.write_bytes(canonical_bytes(approval))

    return mutate


def _duplicate_approval(_candidate: Path, approval_path: Path, _approval: dict[str, Any]) -> None:
    text = approval_path.read_text(encoding="utf-8").rstrip()
    approval_path.write_text(text[:-1] + ',"state":"duplicate"}\n', encoding="utf-8")


def _missing_approval(_candidate: Path, approval_path: Path, _approval: dict[str, Any]) -> None:
    approval_path.rename(approval_path.with_suffix(".missing"))


def _legacy_candidate(candidate: Path, _path: Path, _approval: dict[str, Any]) -> None:
    manifest_path = candidate / "SITE_CANDIDATE.json"
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    manifest["schema"] = "McpTrustSiteCandidateV1"
    manifest["state"] = "PUBLICATION_APPROVED_ROLLBACK_BOUND"
    manifest["publication_allowed"] = True
    manifest["deployment_allowed"] = True
    manifest["blocking_gates"] = []
    manifest["receipt_digest"] = _sha256_bytes(
        canonical_bytes({key: value for key, value in manifest.items() if key != "receipt_digest"})
    )
    manifest_path.write_bytes(canonical_bytes(manifest))


def _provider_mutation(field: str, value: Any) -> Mutation:
    def mutate(_candidate: Path, path: Path, approval: dict[str, Any]) -> None:
        provider = approval["provider_prepublication"]
        provider[field] = value
        provider.pop("receipt_digest", None)
        provider["receipt_digest"] = _sha256_bytes(canonical_bytes(provider))
        approval["rollback"]["prepublication_revalidation_receipt"] = provider["receipt_digest"]
        _resign(approval, path)

    return mutate


def _candidate_symlink(candidate: Path, _path: Path, _approval: dict[str, Any]) -> None:
    target = candidate.parent / "real-candidate"
    candidate.rename(target)
    candidate.symlink_to(target, target_is_directory=True)


@pytest.mark.parametrize(
    ("case_id", "mutation"),
    [
        ("PA-003", _missing_approval),
        ("PA-004", _legacy_candidate),
        ("PA-005", _mutate_approval("approval_id", "tampered", resign=False)),
        (
            "PA-006",
            _mutate_approval("triage_receipt_digest", DIGESTS["o"], nested="triage_resolution"),
        ),
        ("PA-007", _duplicate_approval),
        ("PA-008", _mutate_approval("unexpected", True)),
        ("PA-009", _mutate_approval("source_revision", "7" * 40, nested="refresh_lineage")),
        ("PA-010", _mutate_approval("source_tree_digest", DIGESTS["o"], nested="refresh_lineage")),
        ("PA-011", _mutate_approval("base_url", "https://replay.example", nested="candidate")),
        (
            "PA-012",
            _mutate_approval(
                "repeat_candidate_relative_tree_digest", DIGESTS["o"], nested="refresh_lineage"
            ),
        ),
        (
            "PA-013",
            _mutate_approval(
                "accepted_finding_codes", ["policy-change"], nested="triage_resolution"
            ),
        ),
        ("PA-014", _mutate_approval("accepted_masked_slugs", [], nested="triage_resolution")),
        ("PA-015", _mutate_approval("tool_versions_digest", "UNKNOWN", nested="refresh_lineage")),
        ("PA-016", _mutate_approval("policy_change_reviewed", False, nested="triage_resolution")),
        ("PA-017", _provider_mutation("observed_at", "2026-08-25T10:00:00+00:00")),
        ("PA-018", _provider_mutation("observed_at", "2026-08-25T12:12:00+00:00")),
        ("PA-019", _provider_mutation("alias_matches", False)),
        ("PA-020", _provider_mutation("no_intervening_deployment", False)),
        ("PA-021", _provider_mutation("target_retained", False)),
        ("PA-022", _provider_mutation("project_id", "prj_other")),
        ("PA-023", _mutate_approval("expires_at", "2026-08-25T12:06:00+00:00")),
        (
            "PA-024",
            _mutate_approval("locator", "/Users/operator/raw-chat", nested="operator_acceptance"),
        ),
        ("PA-025", _candidate_symlink),
    ],
    ids=lambda value: value if isinstance(value, str) and value.startswith("PA-") else None,
)
def test_pa_negative_contracts(
    tmp_path: Path,
    case_id: str,
    mutation: Mutation,
) -> None:
    candidate, approval_path, approval = _approval_fixture(tmp_path)
    mutation(candidate, approval_path, approval)

    with pytest.raises((OSError, PublicationAdmissionError, candidate_module.SiteCandidateError)):
        verify_publication_approval(approval_path, candidate_path=candidate, now=NOW)
    assert case_id.startswith("PA-")


@pytest.mark.parametrize("state", ["STALE"], ids=["P03"])
def test_p03_stale_unmasked_entry_rejected(tmp_path: Path, state: str) -> None:
    candidate, approval_path, _ = _approval_fixture(tmp_path)
    _set_candidate_freshness(candidate, state)
    with pytest.raises(PublicationAdmissionError, match="stale or UNKNOWN"):
        verify_publication_approval(approval_path, candidate_path=candidate, now=NOW)


@pytest.mark.parametrize("state", ["UNKNOWN"], ids=["P04"])
def test_p04_unknown_unmasked_entry_rejected(tmp_path: Path, state: str) -> None:
    candidate, approval_path, _ = _approval_fixture(tmp_path)
    _set_candidate_freshness(candidate, state)
    with pytest.raises(PublicationAdmissionError, match="stale or UNKNOWN"):
        verify_publication_approval(approval_path, candidate_path=candidate, now=NOW)


def _set_candidate_freshness(candidate: Path, state: str) -> None:
    manifest_path = candidate / "SITE_CANDIDATE.json"
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    manifest["freshness"]["state_counts"]["NOT_APPLICABLE"] = 0
    manifest["freshness"]["state_counts"][state] = 1
    unsigned = {key: value for key, value in manifest.items() if key != "receipt_digest"}
    manifest["receipt_digest"] = _sha256_bytes(canonical_bytes(unsigned))
    manifest_path.write_bytes(canonical_bytes(manifest))


def test_p05_approval_expiry_is_minimum_bound(tmp_path: Path) -> None:
    candidate, approval_path, approval = _approval_fixture(tmp_path)
    approval["expires_at"] = "2026-08-25T13:01:00+00:00"
    approval["freshness_seconds"] = 3600
    _resign(approval, approval_path)

    with pytest.raises(PublicationAdmissionError):
        verify_publication_approval(approval_path, candidate_path=candidate, now=NOW)


def test_v132_boundary_acceptance_is_not_publication_authority(tmp_path: Path) -> None:
    candidate, approval_path, approval = _approval_fixture(tmp_path)
    approval["review_lineage"].update(
        {
            "acceptance_state": "ACCEPTED_EXACT_V132_BOUNDARY",
            "acceptance_scope": (
                "all-nine-current-policy-blocks-and-exact-v132-forward-baseline"
            ),
        }
    )
    _resign(approval, approval_path)

    with pytest.raises(PublicationAdmissionError, match="not accepted exact V38"):
        verify_publication_approval(approval_path, candidate_path=candidate, now=NOW)


def test_p06_package_second_read_rejects_expiry(tmp_path: Path) -> None:
    candidate, approval_path, _ = _approval_fixture(tmp_path)
    package = build_publication_package(
        candidate_path=candidate,
        approval_path=approval_path,
        output_path=tmp_path / "package",
        now=NOW,
    )

    with pytest.raises(PublicationAdmissionError, match="not current"):
        verify_publication_package(
            package,
            approval_path=approval_path,
            now=ISSUED + timedelta(minutes=41),
        )
