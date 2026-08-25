"""Immutable, receipt-bound static-site candidates for operator review.

This module deliberately stops before publication.  It turns one verified
refresh candidate plus one integrity-checked publication-review packet into a
deterministic local artifact, and independently verifies that artifact later.
"""

from __future__ import annotations

import hashlib
import json
import os
import re
import sqlite3
import stat
import tempfile
from collections.abc import Callable
from datetime import UTC, datetime
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

from mcp_trust.grade_refresh import (
    DISPOSITION_POLICY_SCHEMA,
    DISPOSITION_POLICY_SCHEMA_V1,
    PUBLICATION_REVIEW_SCHEMA,
)
from mcp_trust.refresh import verify_refresh_candidate
from mcp_trust.site.generator import SiteBuild, generate_site
from mcp_trust.store.repository import ScanRepository, ServerRepository

SITE_CANDIDATE_SCHEMA_V1 = "McpTrustSiteCandidateV1"
SITE_CANDIDATE_SCHEMA = "McpTrustSiteCandidateV2"
SITE_CANDIDATE_MANIFEST = "SITE_CANDIDATE.json"
PENDING_STATE = "REVIEW_ONLY_PENDING_SANITIZED_REACCEPTANCE"
ACCEPTED_REVIEW_STATE = "REVIEW_ONLY_ACCEPTED_FOR_SOURCE_REVIEW"
DEPLOYABLE_STATE = "PUBLICATION_APPROVED_ROLLBACK_BOUND"
PROVIDER_NATIVE_ROLLBACK_SCHEMA = "McpTrustProviderNativeRollbackBindingV1"
PROVIDER_NATIVE_ROLLBACK_STATE = "PROVIDER_NATIVE_FIRST_PUBLICATION_REVIEW_BOUND"
_PROVIDER_NATIVE_MAX_FRESHNESS_SECONDS = 3600
_SHA256 = re.compile(r"^sha256:[0-9a-f]{64}$")
_DEPLOYMENT_ENVELOPE_FILES = frozenset({".vercel/project.json"})
_READBACK_MANIFEST_SCHEMA = "WebReleaseSentinelManifestV1"
_READBACK_CONTRACT_VERSION = "1.0.0"
_READBACK_MISSING_ROUTE = "/__mcp_trust_candidate_missing__"
_READBACK_MAX_ROUTES = 128
_READBACK_MAX_BODY_BYTES = 16 * 1024 * 1024
_READBACK_NON_PUBLIC_FILES = frozenset({"vercel.json"})
_REVIEW_KEYS = frozenset(
    {
        "schema",
        "decision",
        "review_state",
        "publication_allowed",
        "deployment_allowed",
        "scheduler_change_allowed",
        "grade_semantics",
        "claim_ceiling",
        "disposition_policy",
        "entry_dispositions",
        "disposition_counts",
        "candidate_counts",
        "historical_baseline",
        "forward_baseline",
        "scheduler_disposition",
        "blocking_gates",
        "quarantined_gates",
        "false_green_guards",
        "receipt_digest",
    }
)


class SiteCandidateError(RuntimeError):
    """A site-candidate input, build, or verification contract failed."""


def _aware_datetime(value: object, label: str) -> datetime:
    try:
        parsed = datetime.fromisoformat(str(value).replace("Z", "+00:00"))
    except ValueError as exc:
        raise SiteCandidateError(f"{label} is invalid") from exc
    if parsed.tzinfo is None:
        raise SiteCandidateError(f"{label} lacks a timezone")
    return parsed.astimezone(UTC)


def canonical_bytes(value: object) -> bytes:
    """Return deterministic JSON bytes for receipt computation."""
    return (
        json.dumps(
            value,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=True,
        ).encode("utf-8")
        + b"\n"
    )


def _sha256_bytes(value: bytes) -> str:
    return "sha256:" + hashlib.sha256(value).hexdigest()


def _stable_file_bytes(path: Path, label: str) -> bytes:
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(path, flags)
    except OSError as exc:
        raise SiteCandidateError(f"{label} cannot be opened safely") from exc
    try:
        before = os.fstat(descriptor)
        if not stat.S_ISREG(before.st_mode):
            raise SiteCandidateError(f"{label} must be a regular file")
        with os.fdopen(descriptor, "rb", closefd=False) as handle:
            content = handle.read()
        after = os.fstat(descriptor)
        current = os.stat(path, follow_symlinks=False)
    finally:
        os.close(descriptor)

    def identity(value: os.stat_result) -> tuple[int, int, int, int, int]:
        return (
            value.st_dev,
            value.st_ino,
            value.st_mode,
            value.st_size,
            value.st_mtime_ns,
        )

    if identity(before) != identity(after) or identity(after) != identity(current):
        raise SiteCandidateError(f"{label} changed while it was read")
    return content


def _sha256_file(path: Path) -> str:
    return _sha256_bytes(_stable_file_bytes(path, path.name))


def _reject_duplicate_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    payload: dict[str, Any] = {}
    for key, value in pairs:
        if key in payload:
            raise SiteCandidateError(f"duplicate JSON key is forbidden: {key}")
        payload[key] = value
    return payload


def _receipt_valid(payload: object) -> bool:
    if not isinstance(payload, dict):
        return False
    unsigned = dict(payload)
    claimed = unsigned.pop("receipt_digest", None)
    return isinstance(claimed, str) and claimed == _sha256_bytes(canonical_bytes(unsigned))


def _stable_json(path: Path, label: str) -> Any:
    current = path
    symlinked = False
    while current != current.parent:
        if current.is_symlink():
            symlinked = True
            break
        current = current.parent
    if symlinked:
        raise SiteCandidateError(f"{label} must not be symlinked")
    try:
        payload = json.loads(
            _stable_file_bytes(path, label), object_pairs_hook=_reject_duplicate_keys
        )
    except (UnicodeError, json.JSONDecodeError) as exc:
        raise SiteCandidateError(f"{label} is invalid JSON") from exc
    return payload


def _regular_json(path: Path, label: str) -> dict[str, Any]:
    payload = _stable_json(path, label)
    if not isinstance(payload, dict):
        raise SiteCandidateError(f"{label} must be a JSON object")
    return payload


def _validate_provider_native_rollback_payload(
    payload: dict[str, Any],
    *,
    expected_base_url: str,
    now: datetime | None,
) -> dict[str, Any]:
    expected_keys = {
        "schema",
        "state",
        "provider",
        "observed_at",
        "freshness_seconds",
        "production_target",
        "provenance",
        "conditions",
        "authority",
        "unknown",
        "claim_ceiling",
        "receipt_digest",
    }
    if set(payload) != expected_keys:
        raise SiteCandidateError("provider-native rollback binding fields are invalid")
    if (
        payload.get("schema") != PROVIDER_NATIVE_ROLLBACK_SCHEMA
        or payload.get("state") != PROVIDER_NATIVE_ROLLBACK_STATE
        or payload.get("provider") != "vercel"
        or not _receipt_valid(payload)
    ):
        raise SiteCandidateError("provider-native rollback binding receipt is invalid")

    freshness = payload.get("freshness_seconds")
    if type(freshness) is not int or not 1 <= freshness <= _PROVIDER_NATIVE_MAX_FRESHNESS_SECONDS:
        raise SiteCandidateError("provider-native rollback freshness policy is invalid")
    observed_at = _aware_datetime(payload.get("observed_at"), "provider observation time")
    if now is not None:
        if now.tzinfo is None:
            raise SiteCandidateError("provider rollback verification time lacks a timezone")
        age_seconds = (now.astimezone(UTC) - observed_at).total_seconds()
        if age_seconds < -60 or age_seconds > freshness:
            raise SiteCandidateError("provider-native rollback binding is stale or from the future")

    parsed_base = urlsplit(expected_base_url.rstrip("/"))
    try:
        port = parsed_base.port
    except ValueError as exc:
        raise SiteCandidateError("site candidate base URL is not an exact HTTPS origin") from exc
    if (
        parsed_base.scheme != "https"
        or not parsed_base.hostname
        or parsed_base.username is not None
        or parsed_base.password is not None
        or port is not None
        or parsed_base.path not in {"", "/"}
        or parsed_base.query
        or parsed_base.fragment
    ):
        raise SiteCandidateError("site candidate base URL is not an exact HTTPS origin")

    target = payload.get("production_target")
    target_keys = {
        "alias",
        "deployment_id",
        "immutable_deployment_url",
        "project_id",
        "team_id",
        "target",
        "deployment_state",
        "source_revision",
        "source_tree",
        "public_tree_digest",
    }
    if not isinstance(target, dict) or set(target) != target_keys:
        raise SiteCandidateError("provider-native rollback target fields are invalid")
    if (
        target.get("alias") != parsed_base.hostname
        or re.fullmatch(r"dpl_[A-Za-z0-9]+", str(target.get("deployment_id", ""))) is None
        or re.fullmatch(
            r"[a-z0-9](?:[a-z0-9-]*[a-z0-9])?\.vercel\.app",
            str(target.get("immutable_deployment_url", "")),
        )
        is None
        or target.get("immutable_deployment_url") == target.get("alias")
        or re.fullmatch(r"prj_[A-Za-z0-9]+", str(target.get("project_id", ""))) is None
        or re.fullmatch(r"team_[A-Za-z0-9]+", str(target.get("team_id", ""))) is None
        or target.get("target") != "production"
        or target.get("deployment_state") != "READY_PROMOTED"
        or re.fullmatch(r"[0-9a-f]{40}", str(target.get("source_revision", ""))) is None
        or re.fullmatch(r"[0-9a-f]{40}", str(target.get("source_tree", ""))) is None
        or _SHA256.fullmatch(str(target.get("public_tree_digest", ""))) is None
    ):
        raise SiteCandidateError("provider-native rollback target identity is invalid")

    provenance = payload.get("provenance")
    if (
        not isinstance(provenance, dict)
        or set(provenance) != {"provider_metadata_receipt", "provider_binding_decision_receipt"}
        or any(_SHA256.fullmatch(str(value)) is None for value in provenance.values())
    ):
        raise SiteCandidateError("provider-native rollback provenance is incomplete")
    if payload.get("conditions") != {
        "first_following_same_project_publication": True,
        "no_intervening_production_deployment": True,
        "target_must_remain_retained": True,
        "prepublication_provider_readback_required": True,
        "immediate_previous_rollback_only": True,
    }:
        raise SiteCandidateError("provider-native rollback validity conditions changed")
    if payload.get("authority") != {
        "publication_allowed": False,
        "deployment_allowed": False,
        "rollback_execution_allowed": False,
        "scheduler_activation_allowed": False,
    }:
        raise SiteCandidateError("provider-native rollback binding exceeds review authority")
    if payload.get("unknown") != [
        "provider_artifact_digest",
        "exercised_rollback_routing",
        "future_prepublication_binding",
    ]:
        raise SiteCandidateError("provider-native rollback UNKNOWN semantics changed")
    claim_ceiling = payload.get("claim_ceiling")
    required_claims = {
        "review-only",
        "not publication authority",
        "not deployment authority",
        "not exercised rollback proof",
    }
    if not isinstance(claim_ceiling, str) or not all(
        claim in claim_ceiling.lower() for claim in required_claims
    ):
        raise SiteCandidateError("provider-native rollback claim ceiling is incomplete")
    return payload


def verify_provider_native_rollback_binding(
    *,
    binding_path: Path,
    expected_base_url: str,
    expected_receipt_digest: str,
    now: datetime | None = None,
) -> dict[str, Any]:
    """Verify a sanitized provider target for one local review artifact.

    This does not authenticate a provider receipt, re-read Vercel, authorize a
    publication, or prove that rollback routing has been exercised.
    """
    payload = _regular_json(binding_path, "provider-native rollback binding")
    if (
        _SHA256.fullmatch(expected_receipt_digest) is None
        or payload.get("receipt_digest") != expected_receipt_digest
    ):
        raise SiteCandidateError("provider-native rollback receipt does not match approval")
    verification_time = now or datetime.now(UTC)
    return _validate_provider_native_rollback_payload(
        payload,
        expected_base_url=expected_base_url,
        now=verification_time,
    )


def provider_native_rollback_binding_from_evidence(
    *,
    provider_metadata_path: Path,
    provider_decision_path: Path,
    expected_base_url: str,
    now: datetime,
    freshness_seconds: int = _PROVIDER_NATIVE_MAX_FRESHNESS_SECONDS,
) -> dict[str, Any]:
    """Project sanitized provider evidence into the strict review-only contract."""
    metadata = _regular_json(provider_metadata_path, "provider metadata evidence")
    decision = _regular_json(provider_decision_path, "provider rollback decision")
    if metadata.get(
        "schema"
    ) != "McpTrustAuthenticatedProviderMetadataEvidenceV1" or not _receipt_valid(metadata):
        raise SiteCandidateError("provider metadata evidence receipt is invalid")
    if decision.get("schema") != "McpTrustProviderRollbackBindingDecisionV1" or not _receipt_valid(
        decision
    ):
        raise SiteCandidateError("provider rollback decision receipt is invalid")
    metadata_receipt = metadata.get("receipt_digest")
    decision_receipt = decision.get("receipt_digest")
    deployment = metadata.get("deployment")
    provider_source = metadata.get("provider_source")
    project = metadata.get("project_binding")
    reconciliation = metadata.get("reconciliation")
    provider_binding = decision.get("provider_binding")
    rollback_target = decision.get("provider_native_rollback_target")
    authentication = metadata.get("authentication")
    if (
        not isinstance(deployment, dict)
        or not isinstance(provider_source, dict)
        or not isinstance(project, dict)
        or not isinstance(reconciliation, dict)
        or not isinstance(provider_binding, dict)
        or not isinstance(rollback_target, dict)
        or not isinstance(authentication, dict)
    ):
        raise SiteCandidateError("provider rollback evidence structure is incomplete")
    if (
        decision.get("provider_metadata_receipt") != metadata_receipt
        or decision.get("decision") != "NO_GO"
        or decision.get("state") != "PROVIDER_NATIVE_TARGET_BOUND_SOURCE_GUARD_NOT_BOOTSTRAPPED"
        or rollback_target.get("state") != "CONDITIONALLY_QUALIFIED"
        or decision.get("publication_allowed") is not False
        or decision.get("deployment_allowed") is not False
        or decision.get("rollback_execution_allowed") is not False
        or decision.get("scheduler_activation_allowed") is not False
        or authentication.get("credential_values_read_or_recorded") is not False
        or metadata.get("external_effects") != []
    ):
        raise SiteCandidateError("provider rollback evidence claim ceiling is invalid")
    target_projection = {
        "alias": deployment.get("alias"),
        "deployment_id": deployment.get("deployment_id"),
        "immutable_deployment_url": deployment.get("immutable_deployment_url"),
        "project_id": project.get("project_id"),
        "team_id": project.get("team_id"),
        "target": deployment.get("target"),
        "deployment_state": (f"{deployment.get('ready_state')}_{deployment.get('ready_substate')}"),
        "source_revision": provider_source.get("git_commit_sha"),
        "source_tree": provider_source.get("local_git_tree"),
        "public_tree_digest": reconciliation.get("current_public_tree_digest"),
    }
    decision_projection = {
        "alias": provider_binding.get("alias"),
        "deployment_id": provider_binding.get("deployment_id"),
        "immutable_deployment_url": provider_binding.get("immutable_deployment_url"),
        "project_id": provider_binding.get("project_id"),
        "team_id": provider_binding.get("team_id"),
        "target": provider_binding.get("target"),
        "deployment_state": provider_binding.get("deployment_state"),
        "source_revision": provider_binding.get("source_revision"),
    }
    if (
        any(target_projection[key] != decision_projection[key] for key in decision_projection)
        or deployment.get("status") != "READY"
        or deployment.get("alias_assigned") is not True
        or project.get("provider_deployment_project_matches_local_link") is not True
        or project.get("provider_deployment_team_matches_local_link") is not True
        or reconciliation.get("provider_source_matches_public_source_witness") is not True
        or reconciliation.get("provider_source_revision") != target_projection["source_revision"]
        or reconciliation.get("public_source_witness_revision")
        != target_projection["source_revision"]
        or reconciliation.get("public_source_witness_tree") != target_projection["source_tree"]
        or type(reconciliation.get("current_public_route_matches")) is not int
        or reconciliation.get("current_public_route_matches")
        != reconciliation.get("current_public_route_total")
        or reconciliation.get("current_public_route_total", 0) <= 0
    ):
        raise SiteCandidateError("provider rollback evidence identity does not reconcile")

    payload: dict[str, Any] = {
        "schema": PROVIDER_NATIVE_ROLLBACK_SCHEMA,
        "state": PROVIDER_NATIVE_ROLLBACK_STATE,
        "provider": "vercel",
        "observed_at": metadata.get("as_of"),
        "freshness_seconds": freshness_seconds,
        "production_target": target_projection,
        "provenance": {
            "provider_metadata_receipt": metadata_receipt,
            "provider_binding_decision_receipt": decision_receipt,
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
            "Review-only provider target binding for the exact sanitized evidence; "
            "not publication authority, not deployment authority, and not exercised "
            "rollback proof."
        ),
    }
    payload["receipt_digest"] = _sha256_bytes(canonical_bytes(payload))
    return _validate_provider_native_rollback_payload(
        payload,
        expected_base_url=expected_base_url,
        now=now,
    )


def _validate_review_semantics(review: dict[str, Any]) -> None:
    """Validate the complete proposal surface, including privacy false greens."""
    if set(review) != _REVIEW_KEYS:
        raise SiteCandidateError("review fields are invalid")
    if review.get("historical_baseline") != {
        "state": "UNKNOWN",
        "disposition": "preserve-unknown-no-retroactive-comparison",
    }:
        raise SiteCandidateError("review historical baseline is not UNKNOWN")
    disposition = review.get("disposition_policy")
    if (
        not isinstance(disposition, dict)
        or not isinstance(disposition.get("path"), str)
        or Path(disposition["path"]).name != disposition["path"]
        or disposition.get("review_state") != "PROPOSED"
        or not isinstance(disposition.get("sha256"), str)
        or _SHA256.fullmatch(disposition["sha256"]) is None
    ):
        raise SiteCandidateError("review disposition projection is invalid")
    entries = review.get("entry_dispositions")
    counts = review.get("disposition_counts")
    candidates = review.get("candidate_counts")
    if (
        not isinstance(entries, list)
        or not isinstance(counts, dict)
        or not isinstance(candidates, dict)
        or set(candidates) != {"fresh", "masked", "total"}
        or any(type(candidates[key]) is not int for key in candidates)
        or candidates["fresh"] + candidates["masked"] != candidates["total"]
        or counts
        not in (
            {
                "total": len(entries),
                "pending_human_acceptance": len(entries),
                "retain_masked": len(entries),
            },
            {
                "total": len(entries),
                "pending_human_acceptance": len(entries),
                "accepted_human": 0,
                "retain_masked": len(entries),
            },
        )
        or candidates["masked"] != len(entries)
    ):
        raise SiteCandidateError("review disposition or candidate counts are invalid")
    slugs: list[str] = []
    for entry in entries:
        classification = entry.get("classification") if isinstance(entry, dict) else None
        evidence = entry.get("controlled_evidence") if isinstance(entry, dict) else None
        if (
            not isinstance(entry, dict)
            or not isinstance(entry.get("slug"), str)
            or entry.get("acceptance_state") != "PENDING_HUMAN_ACCEPTANCE"
            or entry.get("disposition")
            not in {"KEEP_MASKED_REVIEW_REQUIRED", "KEEP_MASKED_ARCHIVED_UNSUPPORTED"}
            or not isinstance(classification, dict)
            or set(classification)
            != {
                "unsupported_upstream",
                "credential_dependent",
                "backing_service_dependent",
                "unsafe_to_execute_unsandboxed",
            }
            or any(type(value) is not bool for value in classification.values())
            or classification.get("unsafe_to_execute_unsandboxed") is not True
            or not isinstance(evidence, dict)
            or set(evidence)
            != {"outcome", "evidence_state", "sandbox_image_id", "projection_digest"}
            or evidence.get("outcome") != "scan_succeeded"
            or evidence.get("evidence_state") != "present"
            or _SHA256.fullmatch(str(evidence.get("sandbox_image_id", ""))) is None
            or _SHA256.fullmatch(str(evidence.get("projection_digest", ""))) is None
        ):
            raise SiteCandidateError("review masked disposition evidence is invalid")
        slugs.append(entry["slug"])
    if len(slugs) != len(set(slugs)):
        raise SiteCandidateError("review contains duplicate dispositions")

    forward = review.get("forward_baseline")
    if not isinstance(forward, dict) or forward.get("state") != "PROPOSED":
        raise SiteCandidateError("review forward baseline state is invalid")
    required_forward = {
        "candidate_manifest_digest",
        "repeat_candidate_manifest_digest",
        "seed_digest",
        "masking_digest",
        "policy_digest",
        "preflight_receipt_digest",
        "repeatability_receipt_digest",
        "triage_receipt_digest",
        "source_revision",
        "source_tree_digest",
    }
    if (
        any(
            not isinstance(forward.get(field), str) or _SHA256.fullmatch(forward[field]) is None
            for field in required_forward - {"source_revision"}
        )
        or re.fullmatch(r"[0-9a-f]{40}", str(forward.get("source_revision", ""))) is None
    ):
        raise SiteCandidateError("review provenance digests are invalid")
    tool_versions = forward.get("tool_versions")
    images = forward.get("qualified_images")
    if (
        not isinstance(tool_versions, dict)
        or not isinstance(tool_versions.get("python_executable"), str)
        or "/" in tool_versions["python_executable"]
        or not isinstance(images, dict)
        or not images
        or any(
            not isinstance(reference, str)
            or not isinstance(image_id, str)
            or _SHA256.fullmatch(image_id) is None
            for reference, image_id in images.items()
        )
    ):
        raise SiteCandidateError("review tool or image provenance is invalid")
    blockers = review.get("blocking_gates")
    false_green = review.get("false_green_guards")
    scheduler = review.get("scheduler_disposition")
    required_blockers = {
        "masked_disposition_acceptance_required",
        "forward_baseline_acceptance_required",
        "exact_source_review_and_landing_required",
        "immutable_site_artifact_and_rollback_binding_required",
        "explicit_publication_authority_required",
        "production_source_and_deployment_binding_unknown",
    }
    required_false_green = {
        "candidate-readiness-is-not-publication-authority",
        "masked-scan-success-is-not-an-unmasked-grade-or-safety-claim",
        "local-candidate-freshness-does-not-prove-production-freshness",
    }
    if (
        not isinstance(blockers, list)
        or not required_blockers <= set(blockers)
        or not isinstance(false_green, list)
        or not required_false_green <= set(false_green)
        or not isinstance(scheduler, dict)
        or scheduler.get("activation_authorized") is not False
        or scheduler.get("mutation_performed") is not False
        or scheduler.get("observed_state") != "DISABLED_UNLOADED"
        or scheduler.get("loaded_domains") != []
    ):
        raise SiteCandidateError("review fail-closed gates are invalid")


def verify_site_candidate_review(
    *,
    review_path: Path,
    disposition_path: Path,
    candidate_path: Path,
    seed_path: Path,
    masked_path: Path,
    policy_path: Path,
    candidate_verifier: Callable[..., dict[str, object]] = verify_refresh_candidate,
    now: datetime | None = None,
) -> dict[str, Any]:
    """Verify an exact review-only acceptance or pending sanitized review.

    A successful return is an admission to build a local review artifact only.
    It is never publication or deployment authority.
    """
    verification = candidate_verifier(
        candidate_path,
        expected_seed_path=seed_path,
        expected_masked_path=masked_path,
        now=now,
    )
    if verification.get("publication_ready") is not True:
        errors = verification.get("errors", [])
        raise SiteCandidateError(f"refresh candidate is not current and complete: {errors}")
    if (
        verification.get("schema") != "RefreshCandidateV2"
        or verification.get("publication_eligible_schema") is not True
    ):
        raise SiteCandidateError("site candidate requires a publication-eligible V2 refresh")
    manifest_digest = verification.get("manifest_sha256")
    if (
        not isinstance(manifest_digest, str)
        or re.fullmatch(r"[0-9a-f]{64}", manifest_digest) is None
    ):
        raise SiteCandidateError("refresh candidate verifier omitted its manifest digest")

    disposition = _regular_json(disposition_path, "disposition policy")
    review = _regular_json(review_path, "sanitized review")
    if disposition.get("schema") not in {
        DISPOSITION_POLICY_SCHEMA,
        DISPOSITION_POLICY_SCHEMA_V1,
    }:
        raise SiteCandidateError("disposition policy schema is unsupported")
    disposition_state = disposition.get("review_state")
    if disposition_state not in {
        "SANITIZED_REACCEPTANCE_REQUIRED",
        "ACCEPTED_CURRENT_SOURCE_REVIEW",
    }:
        raise SiteCandidateError("disposition policy is not review-only admissible")
    accepted_current = disposition_state == "ACCEPTED_CURRENT_SOURCE_REVIEW"
    acceptance = disposition.get("acceptance")
    if not isinstance(acceptance, dict):
        raise SiteCandidateError("disposition policy lacks acceptance lineage")
    if accepted_current:
        review_policy = review.get("disposition_policy")
        artifact_name = acceptance.get("accepted_disposition_path")
        if (
            disposition.get("schema") != DISPOSITION_POLICY_SCHEMA
            or disposition.get("grade_semantics") != "technical-danger-not-endorsement"
            or disposition.get("historical_baseline")
            != {
                "state": "UNKNOWN",
                "disposition": "preserve-unknown-no-retroactive-comparison",
            }
            or disposition.get("forward_baseline")
            != {
                "state": "OPERATOR_ACCEPTED_EXACT_V38_LOCAL_REVIEW_ONLY",
                "disposition": ("adopt-exact-v37-candidate-bindings-as-current-forward-baseline"),
            }
            or acceptance.get("acceptance_state") != "ACCEPTED_EXACT_V38"
            or acceptance.get("scope")
            != "all-eight-current-masked-dispositions-and-exact-v37-forward-baseline"
            or acceptance.get("accepted_review_path") != review_path.name
            or acceptance.get("accepted_review_artifact_sha256") != _sha256_file(review_path)
            or acceptance.get("accepted_review_receipt_digest") != review.get("receipt_digest")
            or not isinstance(review_policy, dict)
            or review_policy.get("sha256") != acceptance.get("accepted_review_policy_sha256")
            or not isinstance(artifact_name, str)
            or Path(artifact_name).name != artifact_name
        ):
            raise SiteCandidateError("accepted review does not match current-source lineage")
        artifact_path = disposition_path.parent / artifact_name
        artifact = _regular_json(artifact_path, "accepted disposition artifact")
        artifact_acceptance = artifact.get("acceptance")
        artifact_forward = artifact.get("forward_baseline")
        artifact_masked = artifact.get("masked_dispositions")
        artifact_privacy = artifact.get("privacy")
        artifact_public = artifact.get("separate_public_state")
        if (
            _sha256_file(artifact_path) != acceptance.get("accepted_disposition_artifact_sha256")
            or artifact.get("schema") != "McpTrustAcceptedDispositionArtifactV1"
            or artifact.get("decision") != "OPERATOR_ACCEPTED_EXACT_V38"
            or not _receipt_valid(artifact)
            or artifact.get("receipt_digest")
            != acceptance.get("accepted_disposition_receipt_digest")
            or not isinstance(artifact_acceptance, dict)
            or artifact_acceptance.get("state") != "ACCEPTED_EXACT_V38"
            or artifact_acceptance.get("scope") != acceptance.get("scope")
            or artifact_acceptance.get("proposal_policy_sha256")
            != acceptance.get("accepted_review_policy_sha256")
            or not isinstance(artifact_forward, dict)
            or artifact_forward.get("state") != "OPERATOR_ACCEPTED_EXACT_V38_LOCAL_REVIEW_ONLY"
            or artifact.get("historical_baseline") != review.get("historical_baseline")
            or not isinstance(artifact_masked, dict)
            or artifact_masked.get("count") != len(review.get("entry_dispositions", []))
            or artifact_masked.get("acceptance_state") != "ACCEPTED_EXACT_V38_RETAIN_MASKED"
            or artifact_masked.get("projection_repeatability") != "PASS"
            or artifact_privacy
            != {
                "host_specific_path_matches": 0,
                "credential_values_present": False,
                "masked_grade_risk_finding_or_receipt_fields_present": False,
                "raw_candidate_transfer_allowed": False,
            }
            or not isinstance(artifact_public, dict)
            or artifact_public.get("production_freshness") != "UNKNOWN"
            or artifact_public.get("production_source_binding") != "UNKNOWN"
            or artifact_public.get("production_deployment_revision") != "UNKNOWN"
        ):
            raise SiteCandidateError("accepted disposition artifact integrity is invalid")
        review_forward = review.get("forward_baseline")
        artifact_entries = artifact_masked.get("entries")
        review_entries = review.get("entry_dispositions")
        shared_forward_fields = {
            "source_revision",
            "source_tree_digest",
            "policy_digest",
            "seed_digest",
            "masking_digest",
            "catalog_denominator",
            "preflight_receipt_digest",
            "repeatability_receipt_digest",
            "triage_receipt_digest",
            "candidate_manifest_digest",
            "repeat_candidate_manifest_digest",
        }
        if (
            not isinstance(review_forward, dict)
            or any(
                artifact_forward.get(field) != review_forward.get(field)
                for field in shared_forward_fields
            )
            or not isinstance(artifact_entries, list)
            or not isinstance(review_entries, list)
        ):
            raise SiteCandidateError("accepted disposition artifact semantics changed")
        artifact_projection = {
            entry.get("slug"): {
                "disposition": entry.get("disposition"),
                "rationale_code": entry.get("rationale_code"),
                "next_review_condition": entry.get("next_review_condition"),
                "projection_digest": entry.get("projection_digest"),
            }
            for entry in artifact_entries
            if isinstance(entry, dict)
        }
        review_projection = {
            entry.get("slug"): {
                "disposition": entry.get("disposition"),
                "rationale_code": entry.get("rationale_code"),
                "next_review_condition": entry.get("next_review_condition"),
                "projection_digest": (
                    entry.get("controlled_evidence", {}).get("projection_digest")
                    if isinstance(entry.get("controlled_evidence"), dict)
                    else None
                ),
            }
            for entry in review_entries
            if isinstance(entry, dict)
        }
        if artifact_projection != review_projection:
            raise SiteCandidateError("accepted disposition artifact semantics changed")
    elif (
        acceptance.get("sanitized_acceptance_state") != "PENDING_OPERATOR_REACCEPTANCE"
        or acceptance.get("sanitized_review_path") != review_path.name
        or acceptance.get("sanitized_review_artifact_sha256") != _sha256_file(review_path)
        or acceptance.get("sanitized_review_receipt_digest") != review.get("receipt_digest")
    ):
        raise SiteCandidateError("sanitized review does not match disposition-policy lineage")
    if review.get("schema") != PUBLICATION_REVIEW_SCHEMA or not _receipt_valid(review):
        raise SiteCandidateError("review receipt integrity is invalid")
    _validate_review_semantics(review)
    if (
        review.get("review_state") != "READY_FOR_HUMAN_DISPOSITION"
        or review.get("decision") != "NO_GO"
        or review.get("publication_allowed") is not False
        or review.get("deployment_allowed") is not False
        or review.get("scheduler_change_allowed") is not False
        or review.get("grade_semantics") != "technical-danger-not-endorsement"
    ):
        raise SiteCandidateError("review claim ceiling is invalid")

    forward = review.get("forward_baseline")
    counts = review.get("candidate_counts")
    scan_counts = verification.get("scan_counts")
    if not isinstance(forward, dict) or not isinstance(counts, dict):
        raise SiteCandidateError("review forward bindings are missing")
    expected = {
        "candidate_manifest_digest": "sha256:" + manifest_digest,
        "seed_digest": _sha256_file(seed_path),
        "masking_digest": _sha256_file(masked_path),
        "policy_digest": _sha256_file(policy_path),
    }
    for field, value in expected.items():
        if forward.get(field) != value:
            raise SiteCandidateError(f"review {field} does not match current input")
    verified_counts = (
        {key: scan_counts.get(key) for key in ("fresh", "masked", "total")}
        if isinstance(scan_counts, dict)
        else None
    )
    if counts != verified_counts or counts.get("total") != forward.get("catalog_denominator"):
        raise SiteCandidateError("review candidate denominator changed")
    if not isinstance(forward.get("source_revision"), str) or not isinstance(
        forward.get("qualified_images"), dict
    ):
        raise SiteCandidateError("review provenance bindings are incomplete")

    return {
        "state": ACCEPTED_REVIEW_STATE if accepted_current else PENDING_STATE,
        "publication_allowed": False,
        "deployment_allowed": False,
        "rollback_state": "UNKNOWN",
        "candidate_manifest_digest": "sha256:" + manifest_digest,
        "review_artifact_sha256": _sha256_file(review_path),
        "review_receipt_digest": review["receipt_digest"],
        "disposition_policy_sha256": _sha256_file(disposition_path),
        "disposition_review_state": disposition_state,
        "seed_digest": forward["seed_digest"],
        "masking_digest": forward["masking_digest"],
        "policy_digest": forward["policy_digest"],
        "source_revision": forward["source_revision"],
        "source_tree_digest": forward.get("source_tree_digest", "UNKNOWN"),
        "tool_versions": forward.get("tool_versions", {}),
        "qualified_images": forward["qualified_images"],
        "candidate_counts": counts,
    }


def _capture_content(
    root: Path, *, allow_deployment_envelope: bool = False
) -> list[dict[str, Any]]:
    files: list[dict[str, Any]] = []
    allowed_extra = _DEPLOYMENT_ENVELOPE_FILES if allow_deployment_envelope else frozenset()
    for path in sorted(root.rglob("*"), key=lambda item: item.relative_to(root).as_posix()):
        relative = path.relative_to(root).as_posix()
        if path.is_symlink():
            raise SiteCandidateError(f"site candidate contains a symlink: {relative}")
        if path.is_dir():
            continue
        if not path.is_file():
            raise SiteCandidateError(f"site candidate contains a special file: {relative}")
        if relative == SITE_CANDIDATE_MANIFEST or relative in allowed_extra:
            continue
        content = _stable_file_bytes(path, f"site candidate file {relative}")
        files.append(
            {
                "path": relative,
                "bytes": len(content),
                "sha256": _sha256_bytes(content),
            }
        )
    if not files:
        raise SiteCandidateError("site candidate contains no generated files")
    return files


def _content_digest(files: list[dict[str, Any]]) -> str:
    return _sha256_bytes(canonical_bytes(files))


def _public_route(relative: str) -> tuple[str, int]:
    if relative == "index.html":
        route, expected_status = "/", 200
    elif relative == "404.html":
        route, expected_status = _READBACK_MISSING_ROUTE, 404
    elif relative.startswith("ui/") and relative.endswith("/index.html"):
        route, expected_status = "/" + relative[: -len("/index.html")], 200
    elif relative.startswith("servers/") and relative.endswith("/badge.json"):
        route, expected_status = "/" + relative, 200
    else:
        raise SiteCandidateError(f"site candidate file has no public route mapping: {relative}")
    if (
        not route.startswith("/")
        or route.startswith("//")
        or "#" in route
        or any(character.isspace() for character in route)
    ):
        raise SiteCandidateError(f"site candidate file maps to an invalid public route: {relative}")
    return route, expected_status


def _public_readback_manifest(files: list[dict[str, Any]]) -> dict[str, Any]:
    public_files = [item for item in files if item["path"] not in _READBACK_NON_PUBLIC_FILES]
    if not 1 <= len(public_files) <= _READBACK_MAX_ROUTES:
        raise SiteCandidateError(
            f"site candidate exact readback requires between 1 and {_READBACK_MAX_ROUTES} routes"
        )
    routes: list[dict[str, Any]] = []
    largest_body = 1
    for index, item in enumerate(public_files):
        relative = item["path"]
        route, expected_status = _public_route(relative)
        largest_body = max(largest_body, item["bytes"])
        routes.append(
            {
                "id": f"route-{index:03d}",
                "method": "GET",
                "route": route,
                "expected_status": expected_status,
                "body_sha256": item["sha256"].removeprefix("sha256:"),
            }
        )
    if largest_body > _READBACK_MAX_BODY_BYTES:
        raise SiteCandidateError("site candidate file exceeds exact readback body limit")
    return {
        "schema": _READBACK_MANIFEST_SCHEMA,
        "contract_version": _READBACK_CONTRACT_VERSION,
        "name": "mcp-trust-site-candidate-exact",
        "defaults": {
            "timeout_seconds": 10,
            "max_body_bytes": largest_body,
            "follow_same_origin_redirects": False,
        },
        "denied_methods": ["POST", "PUT", "PATCH", "DELETE", "CONNECT", "TRACE"],
        "routes": routes,
    }


def verify_site_candidate(root: Path, *, allow_deployment_envelope: bool = False) -> dict[str, Any]:
    """Independently verify one finalized site-candidate directory."""
    if root.is_symlink() or not root.is_dir():
        raise SiteCandidateError("site candidate root must be a real directory")
    manifest = _regular_json(root / SITE_CANDIDATE_MANIFEST, "site candidate manifest")
    schema = manifest.get("schema")
    if schema not in {SITE_CANDIDATE_SCHEMA_V1, SITE_CANDIDATE_SCHEMA} or not _receipt_valid(
        manifest
    ):
        raise SiteCandidateError("site candidate manifest receipt integrity is invalid")
    implementation = manifest.get("implementation_binding")
    if (
        not isinstance(implementation, dict)
        or implementation.get("state") != "CLEAN_COMMITTED"
        or re.fullmatch(r"[0-9a-f]{40}", str(implementation.get("revision", ""))) is None
        or _SHA256.fullmatch(str(implementation.get("source_tree_digest", ""))) is None
    ):
        raise SiteCandidateError("site candidate implementation binding is invalid")
    state_value = manifest.get("state")
    if state_value in {PENDING_STATE, ACCEPTED_REVIEW_STATE}:
        if (
            manifest.get("publication_allowed") is not False
            or manifest.get("deployment_allowed") is not False
        ):
            raise SiteCandidateError("review-only site candidate exceeds its authority")
    elif state_value == DEPLOYABLE_STATE:
        if schema == SITE_CANDIDATE_SCHEMA_V1:
            raise SiteCandidateError("legacy site candidate cannot self-assert deploy authority")
        if (
            manifest.get("publication_allowed") is not True
            or manifest.get("deployment_allowed") is not True
            or manifest.get("blocking_gates", []) != []
        ):
            raise SiteCandidateError("approved site candidate authority is incomplete")
        bindings = manifest.get("bindings")
        if (
            not isinstance(bindings, dict)
            or bindings.get("state") != DEPLOYABLE_STATE
            or bindings.get("publication_allowed") is not True
            or bindings.get("deployment_allowed") is not True
            or bindings.get("rollback_state") != "BOUND"
        ):
            raise SiteCandidateError("approved site candidate review binding is incomplete")
    else:
        raise SiteCandidateError("site candidate state is unsupported")
    rollback = manifest.get("rollback")
    if not isinstance(rollback, dict) or rollback.get("state") not in {
        "BOUND",
        "UNKNOWN",
        PROVIDER_NATIVE_ROLLBACK_STATE,
    }:
        raise SiteCandidateError("site candidate rollback lineage is invalid")
    if rollback.get("state") == "BOUND" and (
        not isinstance(rollback.get("site_receipt_digest"), str)
        or _SHA256.fullmatch(rollback["site_receipt_digest"]) is None
        or not isinstance(rollback.get("content_digest"), str)
        or _SHA256.fullmatch(rollback["content_digest"]) is None
    ):
        raise SiteCandidateError("bound rollback lineage is incomplete")
    blocking_gates = manifest.get("blocking_gates", [])
    if rollback.get("state") == "UNKNOWN" and (
        state_value not in {PENDING_STATE, ACCEPTED_REVIEW_STATE}
        or "rollback_artifact_binding_unknown" not in blocking_gates
    ):
        raise SiteCandidateError("UNKNOWN rollback is not fail-closed")
    if rollback.get("state") == PROVIDER_NATIVE_ROLLBACK_STATE:
        bindings = manifest.get("bindings")
        if (
            state_value not in {PENDING_STATE, ACCEPTED_REVIEW_STATE}
            or not isinstance(manifest.get("base_url"), str)
            or not isinstance(bindings, dict)
            or bindings.get("rollback_state") != PROVIDER_NATIVE_ROLLBACK_STATE
            or "provider_native_rollback_revalidation_and_publication_approval_required"
            not in blocking_gates
        ):
            raise SiteCandidateError("provider-native rollback binding is not fail-closed")
        _validate_provider_native_rollback_payload(
            rollback,
            expected_base_url=manifest["base_url"],
            now=None,
        )
    files = _capture_content(root, allow_deployment_envelope=allow_deployment_envelope)
    content = manifest.get("content")
    if not isinstance(content, dict) or content.get("files") != files:
        raise SiteCandidateError("site candidate file manifest changed")
    if content.get("digest") != _content_digest(files):
        raise SiteCandidateError("site candidate content digest changed")
    if schema == SITE_CANDIDATE_SCHEMA:
        freshness = manifest.get("freshness")
        projection_digests = manifest.get("projection_digests")
        if (
            not isinstance(freshness, dict)
            or freshness.get("mode") != "STATIC_HISTORICAL_ONLY"
            or freshness.get("horizon_days") != 90
            or freshness.get("evaluated_at") != manifest.get("created_at")
            or not isinstance(freshness.get("publication_not_after"), str)
            or not isinstance(projection_digests, dict)
            or set(projection_digests)
            != {"refresh_scan_results", "refresh_static_snapshot", "masking", "site_content"}
            or projection_digests.get("site_content") != content.get("digest")
            or any(
                not isinstance(value, str) or _SHA256.fullmatch(value) is None
                for value in projection_digests.values()
            )
        ):
            raise SiteCandidateError("site candidate V2 freshness binding is invalid")
    expected_readback = _public_readback_manifest(files)
    public_readback = manifest.get("public_readback")
    readback_manifest_bound = public_readback is not None
    if readback_manifest_bound and public_readback != expected_readback:
        raise SiteCandidateError("site candidate public readback manifest changed")
    if state_value == DEPLOYABLE_STATE and not readback_manifest_bound:
        raise SiteCandidateError("deployable site candidate lacks exact public readback binding")
    return {
        "structural_valid": True,
        "schema": schema,
        "publication_eligible_schema": schema == SITE_CANDIDATE_SCHEMA,
        "state": state_value,
        "publication_allowed": manifest["publication_allowed"],
        "deployment_allowed": manifest["deployment_allowed"],
        "rollback_state": rollback["state"],
        "content_digest": content["digest"],
        "receipt_digest": manifest["receipt_digest"],
        "file_count": len(files),
        "readback_manifest_bound": readback_manifest_bound,
        "readback_manifest_digest": (
            _sha256_bytes(canonical_bytes(expected_readback)) if readback_manifest_bound else None
        ),
    }


def site_candidate_readback_manifest(root: Path) -> dict[str, Any]:
    """Return the receipt-bound exact public readback manifest for one candidate."""
    verification = verify_site_candidate(root)
    if not verification["readback_manifest_bound"]:
        raise SiteCandidateError("site candidate has no receipt-bound public readback manifest")
    manifest = _regular_json(root / SITE_CANDIDATE_MANIFEST, "site candidate manifest")
    public_readback = manifest["public_readback"]
    if not isinstance(public_readback, dict):
        raise SiteCandidateError("site candidate public readback manifest is invalid")
    return public_readback


def _connect_read_only(path: Path) -> sqlite3.Connection:
    connection = sqlite3.connect(
        f"{path.resolve(strict=True).as_uri()}?mode=ro&immutable=1",
        uri=True,
        check_same_thread=False,
    )
    connection.row_factory = sqlite3.Row
    connection.execute("PRAGMA foreign_keys = ON")
    return connection


def build_site_candidate(
    *,
    candidate_path: Path,
    review_path: Path,
    disposition_path: Path,
    seed_path: Path,
    masked_path: Path,
    policy_path: Path,
    corrections_path: Path,
    output_path: Path,
    base_url: str,
    rollback_candidate: Path | None = None,
    provider_rollback_binding: Path | None = None,
    provider_rollback_binding_receipt: str | None = None,
    implementation_binding: dict[str, str],
    candidate_verifier: Callable[..., dict[str, object]] = verify_refresh_candidate,
    now: datetime | None = None,
) -> Path:
    """Build a deterministic site in a sibling temp directory, then atomically finalize it."""
    if output_path.exists() or output_path.is_symlink():
        raise SiteCandidateError("site candidate output already exists")
    if (
        set(implementation_binding) != {"state", "revision", "source_tree_digest"}
        or implementation_binding.get("state") != "CLEAN_COMMITTED"
        or re.fullmatch(r"[0-9a-f]{40}", implementation_binding.get("revision", "")) is None
        or _SHA256.fullmatch(implementation_binding.get("source_tree_digest", "")) is None
    ):
        raise SiteCandidateError("site candidate requires a clean committed implementation")
    output_path.parent.mkdir(parents=True, exist_ok=True)
    binding = verify_site_candidate_review(
        review_path=review_path,
        disposition_path=disposition_path,
        candidate_path=candidate_path,
        seed_path=seed_path,
        masked_path=masked_path,
        policy_path=policy_path,
        candidate_verifier=candidate_verifier,
        now=now,
    )
    candidate_manifest = _regular_json(candidate_path / "MANIFEST.json", "refresh manifest")
    try:
        as_of = datetime.fromisoformat(str(candidate_manifest["created_at"]).replace("Z", "+00:00"))
    except (KeyError, TypeError, ValueError) as exc:
        raise SiteCandidateError("refresh candidate creation time is invalid") from exc
    if as_of.tzinfo is None:
        raise SiteCandidateError("refresh candidate creation time lacks a timezone")

    masked_raw = _stable_json(masked_path, "masked-grades input")
    if (
        not isinstance(masked_raw, list)
        or not all(isinstance(item, str) and item for item in masked_raw)
        or len(masked_raw) != len(set(masked_raw))
    ):
        raise SiteCandidateError("masked-grades input is invalid")
    masked_slugs = set(masked_raw)
    verified_masked = set(candidate_manifest.get("masking", {}).get("slugs", []))
    if verified_masked != masked_slugs:
        raise SiteCandidateError("refresh candidate masked proof coverage changed")
    corrections = (
        _stable_json(corrections_path, "corrections input") if corrections_path.exists() else []
    )
    if not isinstance(corrections, list):
        raise SiteCandidateError("corrections input must be a JSON list")

    if rollback_candidate is not None and provider_rollback_binding is not None:
        raise SiteCandidateError(
            "retained-site and provider-native rollback bindings are mutually exclusive"
        )
    if (provider_rollback_binding is None) != (provider_rollback_binding_receipt is None):
        raise SiteCandidateError(
            "provider-native rollback path and approved receipt must be supplied together"
        )
    rollback: dict[str, Any]
    provider_rollback_snapshot: dict[str, Any] | None = None
    if provider_rollback_binding is not None:
        if provider_rollback_binding_receipt is None:
            raise SiteCandidateError("provider-native rollback approved receipt is missing")
        provider_rollback_snapshot = verify_provider_native_rollback_binding(
            binding_path=provider_rollback_binding,
            expected_base_url=base_url,
            expected_receipt_digest=provider_rollback_binding_receipt,
            now=now or datetime.now(UTC),
        )
        rollback = provider_rollback_snapshot
    elif rollback_candidate is None:
        rollback = {
            "state": "UNKNOWN",
            "reason": "no-prior-immutable-site-candidate-bound",
        }
    else:
        prior = verify_site_candidate(rollback_candidate)
        if (
            prior["state"] != DEPLOYABLE_STATE
            or prior["publication_allowed"] is not True
            or prior["deployment_allowed"] is not True
            or prior["rollback_state"] != "BOUND"
        ):
            raise SiteCandidateError(
                "rollback candidate is not a retained deployment-qualified artifact"
            )
        rollback = {
            "state": "BOUND",
            "site_receipt_digest": prior["receipt_digest"],
            "content_digest": prior["content_digest"],
        }

    temporary = Path(tempfile.mkdtemp(prefix=f".{output_path.name}.tmp-", dir=output_path.parent))
    try:
        connection = _connect_read_only(candidate_path / "registry.db")
        try:
            build: SiteBuild = generate_site(
                connection,
                temporary,
                base_url=base_url,
                now=as_of,
                corrections=corrections,
                masked_slugs=masked_slugs,
                masked_scan_succeeded_slugs=verified_masked,
            )
            servers = ServerRepository(connection).list()
            scanned = set(ScanRepository(connection).latest_all())
        finally:
            connection.close()
        if build.server_count != binding["candidate_counts"]["total"]:
            raise SiteCandidateError("rendered catalog denominator changed")
        if build.masked_count != binding["candidate_counts"]["masked"]:
            raise SiteCandidateError("rendered masked denominator changed")
        if {server.slug for server in servers} != scanned | masked_slugs:
            raise SiteCandidateError("rendered site scan coverage changed")

        final_binding = verify_site_candidate_review(
            review_path=review_path,
            disposition_path=disposition_path,
            candidate_path=candidate_path,
            seed_path=seed_path,
            masked_path=masked_path,
            policy_path=policy_path,
            candidate_verifier=candidate_verifier,
            now=now,
        )
        if final_binding != binding:
            raise SiteCandidateError("site candidate inputs changed during rendering")
        if provider_rollback_binding is not None:
            final_provider_rollback = verify_provider_native_rollback_binding(
                binding_path=provider_rollback_binding,
                expected_base_url=base_url,
                expected_receipt_digest=provider_rollback_binding_receipt,
                now=now or datetime.now(UTC),
            )
            if final_provider_rollback != provider_rollback_snapshot:
                raise SiteCandidateError(
                    "provider-native rollback binding changed during rendering"
                )

        files = _capture_content(temporary)
        accepted_current = binding["state"] == ACCEPTED_REVIEW_STATE
        site_binding = {**binding, "rollback_state": rollback["state"]}
        blocking_gates = [
            *([] if accepted_current else ["sanitized_review_acceptance_required"]),
            "explicit_publication_authority_required",
            "production_source_and_deployment_binding_unknown",
        ]
        if rollback["state"] == "UNKNOWN":
            blocking_gates.append("rollback_artifact_binding_unknown")
        elif rollback["state"] == PROVIDER_NATIVE_ROLLBACK_STATE:
            blocking_gates.append(
                "provider_native_rollback_revalidation_and_publication_approval_required"
            )
        refresh_freshness = candidate_manifest.get("freshness")
        refresh_semantic = candidate_manifest.get("semantic_digests")
        if (
            candidate_manifest.get("schema") != "RefreshCandidateV2"
            or not isinstance(refresh_freshness, dict)
            or not isinstance(refresh_semantic, dict)
            or set(refresh_semantic) != {"scan_results", "static_snapshot", "masking"}
            or any(
                not isinstance(value, str) or re.fullmatch(r"[0-9a-f]{64}", value) is None
                for value in refresh_semantic.values()
            )
        ):
            raise SiteCandidateError("refresh candidate V2 projection binding is invalid")
        content_digest = _content_digest(files)
        manifest: dict[str, Any] = {
            "schema": SITE_CANDIDATE_SCHEMA,
            "state": binding["state"],
            "created_at": as_of.isoformat(),
            "base_url": base_url.rstrip("/"),
            "implementation_binding": dict(implementation_binding),
            "publication_allowed": False,
            "deployment_allowed": False,
            "claim_ceiling": (
                "Deterministic local review artifact for the exact V38 accepted source "
                "contract only; not publication, deployment, production freshness, "
                "safety, backing-service functionality, credentialed functionality, "
                "or endorsement."
                if accepted_current
                else "Deterministic local review artifact only; not sanitized acceptance, "
                "publication, deployment, production freshness, safety, or endorsement."
            ),
            "bindings": site_binding,
            "corrections_digest": (
                _sha256_file(corrections_path)
                if corrections_path.exists()
                else _sha256_bytes(canonical_bytes([]))
            ),
            "site_counts": {
                "servers": build.server_count,
                "scanned": build.scanned_count,
                "masked": build.masked_count,
                "stale": build.stale_count,
                "demo": build.demo_count,
            },
            "freshness": dict(refresh_freshness),
            "projection_digests": {
                "refresh_scan_results": "sha256:" + refresh_semantic["scan_results"],
                "refresh_static_snapshot": "sha256:" + refresh_semantic["static_snapshot"],
                "masking": "sha256:" + refresh_semantic["masking"],
                "site_content": content_digest,
            },
            "content": {"digest": content_digest, "files": files},
            "public_readback": _public_readback_manifest(files),
            "rollback": rollback,
            "blocking_gates": blocking_gates,
        }
        manifest["receipt_digest"] = _sha256_bytes(canonical_bytes(manifest))
        (temporary / SITE_CANDIDATE_MANIFEST).write_bytes(canonical_bytes(manifest))
        verify_site_candidate(temporary)
        os.replace(temporary, output_path)
        verify_site_candidate(output_path)
    except Exception:
        if temporary.exists():
            import shutil

            shutil.rmtree(temporary)
        raise
    return output_path
