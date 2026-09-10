"""Strict, provider-free publication approval and package admission.

This module can only create local files. It has no network, deployment,
rollback, scheduler, credential, or provider capability.
"""

from __future__ import annotations

import hashlib
import json
import os
import re
import shutil
import stat
import tempfile
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any
from urllib.parse import urljoin, urlsplit

from mcp_trust.site.candidate import (
    ACCEPTED_REVIEW_STATE,
    PROVIDER_NATIVE_ROLLBACK_STATE,
    SITE_CANDIDATE_MANIFEST,
    canonical_bytes,
    verify_site_candidate,
)

PUBLICATION_APPROVAL_SCHEMA = "McpTrustPublicationApprovalV1"
PUBLICATION_APPROVAL_STATE = "PUBLICATION_CONTENT_APPROVED_LOCAL_ONLY"
PUBLICATION_PACKAGE_SCHEMA = "McpTrustPublicationPackageV1"
PUBLICATION_PACKAGE_STATE = "PUBLICATION_PACKAGE_READY_FOR_DEPLOY_REVIEW"
PUBLICATION_PACKAGE_MANIFEST = "PUBLICATION_PACKAGE.json"
PROVIDER_PREPUBLICATION_SCHEMA = "McpTrustProviderPrepublicationRevalidationV1"
PRODUCTION_PUBLICATION_RECEIPT_SCHEMA = "McpTrustProductionPublicationReceiptV1"
MAX_APPROVAL_FRESHNESS_SECONDS = 3600

_SHA256 = re.compile(r"^sha256:[0-9a-f]{64}$")
_HEX_SHA256 = re.compile(r"^[0-9a-f]{64}$")
_REVISION = re.compile(r"^[0-9a-f]{40}$")

_APPROVAL_KEYS = frozenset(
    {
        "schema",
        "state",
        "approval_id",
        "issued_at",
        "expires_at",
        "freshness_seconds",
        "candidate",
        "refresh_lineage",
        "review_lineage",
        "triage_resolution",
        "policy_and_semantics",
        "provider_prepublication",
        "rollback",
        "operator_acceptance",
        "authority",
        "unknown",
        "claim_ceiling",
        "receipt_digest",
    }
)
_CANDIDATE_KEYS = frozenset(
    {
        "schema",
        "state",
        "manifest_sha256",
        "manifest_receipt_digest",
        "content_digest",
        "public_readback_manifest_digest",
        "base_url",
        "implementation_revision",
        "implementation_tree_digest",
        "server_count",
        "masked_count",
    }
)
_REFRESH_KEYS = frozenset(
    {
        "candidate_manifest_digest",
        "repeat_candidate_manifest_digest",
        "candidate_relative_tree_digest",
        "repeat_candidate_relative_tree_digest",
        "preflight_receipt_digest",
        "repeatability_receipt_digest",
        "triage_receipt_digest",
        "sandbox_qualification_receipt_digest",
        "source_revision",
        "source_tree_digest",
        "seed_digest",
        "masking_digest",
        "policy_digest",
        "tool_versions_digest",
        "qualified_images_digest",
    }
)
_REVIEW_KEYS = frozenset(
    {
        "publication_review_artifact_sha256",
        "publication_review_receipt_digest",
        "disposition_policy_sha256",
        "accepted_disposition_artifact_sha256",
        "accepted_disposition_receipt_digest",
        "accepted_review_policy_sha256",
        "acceptance_state",
        "acceptance_scope",
    }
)
_TRIAGE_KEYS = frozenset(
    {
        "triage_receipt_digest",
        "findings_projection_digest",
        "resolution_receipt_digest",
        "reviewed_finding_count",
        "unresolved_finding_count",
        "accepted_finding_codes",
        "accepted_masked_slugs",
        "policy_change_reviewed",
    }
)
_PROVIDER_KEYS = frozenset(
    {
        "schema",
        "receipt_digest",
        "metadata_receipt_digest",
        "binding_decision_receipt_digest",
        "observed_at",
        "freshness_seconds",
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
        "alias_matches",
        "same_project_team",
        "no_intervening_deployment",
        "target_retained",
        "matches_candidate_rollback_target",
    }
)
_ROLLBACK_KEYS = frozenset(
    {
        "mode",
        "embedded_candidate_rollback_receipt",
        "prepublication_revalidation_receipt",
        "immediate_previous_deployment_id",
        "target_retained",
        "same_project_team",
        "rollback_execution_allowed",
        "provider_artifact_digest",
        "exercised_rollback_routing",
    }
)
_OPERATOR_KEYS = frozenset(
    {
        "authority",
        "decision",
        "locator",
        "accepted_at",
        "statement_sha256",
        "accepted_binding_digest",
    }
)
_PACKAGE_KEYS = frozenset(
    {
        "schema",
        "state",
        "created_at",
        "candidate_path_name",
        "candidate_manifest_sha256",
        "candidate_receipt_digest",
        "candidate_content_digest",
        "publication_approval_sha256",
        "publication_approval_receipt_digest",
        "provider_revalidation_receipt_digest",
        "content_files",
        "content_digest",
        "authority",
        "claim_ceiling",
        "receipt_digest",
    }
)
_PRODUCTION_RECEIPT_KEYS = frozenset(
    {
        "schema",
        "state",
        "observed_at",
        "publication_package_receipt_digest",
        "publication_approval_receipt_digest",
        "deployment_authorization_receipt_digest",
        "provider_deployment_id",
        "immutable_deployment_url",
        "alias",
        "project_id",
        "team_id",
        "provider_source_revision",
        "provider_source_tree",
        "provider_artifact_digest",
        "exact_public_readback_receipt_digest",
        "route_matches",
        "route_total",
        "production_freshness",
        "rollback_target_deployment_id",
        "external_effects",
        "claim_ceiling",
        "receipt_digest",
    }
)
_DEPLOYMENT_AUTHORIZATION_KEYS = frozenset(
    {
        "schema",
        "receipt_id",
        "repository",
        "branch",
        "commit",
        "target_url",
        "vercel_project_id",
        "vercel_org_id",
        "vercel_invocation_path",
        "vercel_bin",
        "vercel_sha256",
        "node_invocation_path",
        "node_bin",
        "node_sha256",
        "python_invocation_path",
        "python_bin",
        "python_sha256",
        "publication_verifier_path",
        "publication_verifier_sha256",
        "approval_path",
        "output_path",
        "output_sha256",
        "issued_at",
        "expires_at",
        "publication_package_path",
        "publication_package_manifest_sha256",
        "publication_package_receipt_digest",
        "publication_approval_path",
        "publication_approval_sha256",
        "publication_approval_receipt_digest",
        "provider_prepublication_receipt_digest",
        "operator_acceptance_statement_sha256",
        "site_candidate_receipt_digest",
        "site_candidate_content_digest",
        "implementation_revision",
        "implementation_source_tree_digest",
        "rollback_artifact_path",
        "rollback_site_candidate_receipt_digest",
        "rollback_site_candidate_content_digest",
        "approval_receipt_digest",
    }
)
_READBACK_RECEIPT_KEYS = frozenset(
    {
        "schema",
        "contract_version",
        "target_url",
        "manifest",
        "checked_at",
        "verifier",
        "state",
        "summary",
        "routes",
    }
)
_READBACK_VERIFIER = {
    "name": "web-release-readback",
    "version": "1.0.0",
    "network_methods": ["GET", "HEAD"],
    "denied_methods": ["POST", "PUT", "PATCH", "DELETE", "CONNECT", "TRACE"],
    "credentials_supported": False,
    "proxy_environment_used": False,
    "same_origin_redirects_only": True,
    "mutation_capabilities": [],
}
_READBACK_ROUTE_KEYS = frozenset(
    {
        "id",
        "method",
        "route",
        "requested_url",
        "final_url",
        "expected_status",
        "actual_status",
        "body_bytes",
        "body_sha256",
        "required_sentinels",
        "forbidden_sentinels",
        "state",
        "reason_codes",
    }
)

_POLICY_AND_SEMANTICS = {
    "danger_grade_axis": "technical-danger-only",
    "transparency_axis": "separate-from-danger",
    "evidence_quality_axis": "separate-from-danger-and-transparency",
    "endorsement": False,
    "masked_results_withheld": True,
    "unknown_is_not_safe": True,
}
_APPROVAL_AUTHORITY = {
    "publication_content_approved": True,
    "publication_package_build_allowed": True,
    "public_mutation_allowed": False,
    "deployment_allowed": False,
    "rollback_execution_allowed": False,
    "scheduler_activation_allowed": False,
    "outreach_allowed": False,
}
_PACKAGE_AUTHORITY = {
    "public_mutation_allowed": False,
    "deployment_allowed": False,
    "rollback_execution_allowed": False,
    "scheduler_activation_allowed": False,
}
_REQUIRED_UNKNOWN = frozenset(
    {
        "provider_artifact_digest",
        "exercised_rollback_routing",
        "future_provider_deployment_identity",
        "post_deploy_public_readback",
        "production_grade_freshness",
    }
)
_CLAIM_PHRASES = (
    "content approval only",
    "not deployment authority",
    "not rollback execution authority",
    "not scheduler authority",
    "not endorsement",
    "production freshness unknown",
)
_FORBIDDEN_PRIVACY_KEYS = frozenset(
    {
        "credential",
        "credential_value",
        "token",
        "secret",
        "raw_chat",
        "masked_grade",
        "masked_risk",
        "masked_findings",
        "report_ref",
    }
)


class PublicationAdmissionError(RuntimeError):
    """One local publication-admission contract failed closed."""


def _sha256_bytes(value: bytes) -> str:
    return "sha256:" + hashlib.sha256(value).hexdigest()


def _stable_bytes(path: Path, label: str) -> bytes:
    if path.is_symlink():
        raise PublicationAdmissionError(f"{label} must not be a symlink")
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(path, flags)
    except OSError as exc:
        raise PublicationAdmissionError(f"{label} cannot be opened safely") from exc
    try:
        before = os.fstat(descriptor)
        if not stat.S_ISREG(before.st_mode):
            raise PublicationAdmissionError(f"{label} must be a regular file")
        with os.fdopen(descriptor, "rb", closefd=False) as handle:
            content = handle.read()
        after = os.fstat(descriptor)
        current = os.stat(path, follow_symlinks=False)
    finally:
        os.close(descriptor)
    identity = lambda value: (  # noqa: E731 - compact immutable identity projection
        value.st_dev,
        value.st_ino,
        value.st_mode,
        value.st_size,
        value.st_mtime_ns,
    )
    if identity(before) != identity(after) or identity(after) != identity(current):
        raise PublicationAdmissionError(f"{label} changed while it was read")
    return content


def _reject_duplicate_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    payload: dict[str, Any] = {}
    for key, value in pairs:
        if key in payload:
            raise PublicationAdmissionError(f"duplicate JSON key is forbidden: {key}")
        payload[key] = value
    return payload


def _stable_json(path: Path, label: str) -> dict[str, Any]:
    try:
        payload = json.loads(_stable_bytes(path, label), object_pairs_hook=_reject_duplicate_keys)
    except (UnicodeError, json.JSONDecodeError) as exc:
        raise PublicationAdmissionError(f"{label} is invalid JSON") from exc
    if not isinstance(payload, dict):
        raise PublicationAdmissionError(f"{label} must be a JSON object")
    return payload


def _aware(value: object, label: str) -> datetime:
    try:
        parsed = datetime.fromisoformat(str(value).replace("Z", "+00:00"))
    except ValueError as exc:
        raise PublicationAdmissionError(f"{label} is invalid") from exc
    if parsed.tzinfo is None:
        raise PublicationAdmissionError(f"{label} lacks a timezone")
    return parsed.astimezone(UTC)


def _require_exact(payload: object, keys: frozenset[str], label: str) -> dict[str, Any]:
    if not isinstance(payload, dict) or set(payload) != keys:
        raise PublicationAdmissionError(f"{label} fields are invalid")
    return payload


def _receipt_valid(payload: dict[str, Any]) -> bool:
    unsigned = dict(payload)
    claimed = unsigned.pop("receipt_digest", None)
    return isinstance(claimed, str) and claimed == _sha256_bytes(canonical_bytes(unsigned))


def _require_digest(value: object, label: str, *, prefixed: bool = True) -> str:
    pattern = _SHA256 if prefixed else _HEX_SHA256
    if not isinstance(value, str) or pattern.fullmatch(value) is None:
        raise PublicationAdmissionError(f"{label} is not a canonical SHA-256 digest")
    return value


def _privacy_walk(value: object, *, key: str = "") -> None:
    if key.lower() in _FORBIDDEN_PRIVACY_KEYS:
        raise PublicationAdmissionError(f"privacy-forbidden field: {key}")
    if isinstance(value, dict):
        for child_key, child in value.items():
            _privacy_walk(child, key=str(child_key))
    elif isinstance(value, list):
        for child in value:
            _privacy_walk(child, key=key)
    elif isinstance(value, str):
        if value.startswith("/Users/") or value.startswith("/home/"):
            raise PublicationAdmissionError("host-specific absolute path is forbidden")
        if re.search(r"(?i)(?:token|secret|password|credential)\s*[:=]", value):
            raise PublicationAdmissionError("credential-like value is forbidden")


def _candidate_projection(root: Path) -> tuple[dict[str, Any], dict[str, Any]]:
    verified = verify_site_candidate(root)
    manifest_path = root / SITE_CANDIDATE_MANIFEST
    manifest = _stable_json(manifest_path, "site candidate manifest")
    if (
        verified.get("schema") != "McpTrustSiteCandidateV2"
        or verified.get("publication_eligible_schema") is not True
        or verified.get("state") != ACCEPTED_REVIEW_STATE
        or verified.get("publication_allowed") is not False
        or verified.get("deployment_allowed") is not False
    ):
        raise PublicationAdmissionError("site candidate is not an accepted V2 review artifact")
    counts = manifest.get("site_counts")
    freshness = manifest.get("freshness")
    if not isinstance(counts, dict) or not isinstance(freshness, dict):
        raise PublicationAdmissionError("site candidate counts or freshness are invalid")
    state_counts = freshness.get("state_counts")
    if (
        not isinstance(state_counts, dict)
        or type(counts.get("masked")) is not int
        or state_counts.get("STALE") != 0
        or state_counts.get("UNKNOWN") != 0
        or state_counts.get("NOT_APPLICABLE", 0) > counts.get("masked", -1)
    ):
        raise PublicationAdmissionError("site candidate contains stale or UNKNOWN public evidence")
    projection = {
        "schema": manifest["schema"],
        "state": manifest["state"],
        "manifest_sha256": _sha256_bytes(_stable_bytes(manifest_path, "site candidate manifest")),
        "manifest_receipt_digest": manifest["receipt_digest"],
        "content_digest": verified["content_digest"],
        "public_readback_manifest_digest": verified["readback_manifest_digest"],
        "base_url": manifest["base_url"],
        "implementation_revision": manifest["implementation_binding"]["revision"],
        "implementation_tree_digest": manifest["implementation_binding"]["source_tree_digest"],
        "server_count": counts["servers"],
        "masked_count": counts["masked"],
    }
    return projection, manifest


def _binding_digest(approval: dict[str, Any]) -> str:
    return _sha256_bytes(
        canonical_bytes(
            {
                key: approval[key]
                for key in (
                    "candidate",
                    "refresh_lineage",
                    "review_lineage",
                    "triage_resolution",
                    "policy_and_semantics",
                    "provider_prepublication",
                    "rollback",
                )
            }
        )
    )


def verify_publication_approval(
    approval_path: Path,
    *,
    candidate_path: Path,
    now: datetime | None = None,
) -> dict[str, Any]:
    """Verify one exact, local-only content approval against a site candidate."""
    approval = _stable_json(approval_path, "publication approval")
    _require_exact(approval, _APPROVAL_KEYS, "publication approval")
    if not _receipt_valid(approval):
        raise PublicationAdmissionError("publication approval receipt integrity is invalid")
    if (
        approval["schema"] != PUBLICATION_APPROVAL_SCHEMA
        or approval["state"] != PUBLICATION_APPROVAL_STATE
        or approval["authority"] != _APPROVAL_AUTHORITY
        or approval["policy_and_semantics"] != _POLICY_AND_SEMANTICS
        or not isinstance(approval["unknown"], list)
        or len(approval["unknown"]) != len(_REQUIRED_UNKNOWN)
        or set(approval["unknown"]) != _REQUIRED_UNKNOWN
    ):
        raise PublicationAdmissionError("publication approval semantics or authority are invalid")
    claim = str(approval["claim_ceiling"]).lower()
    if any(phrase not in claim for phrase in _CLAIM_PHRASES):
        raise PublicationAdmissionError("publication approval claim ceiling is incomplete")
    if not isinstance(approval["approval_id"], str) or not approval["approval_id"]:
        raise PublicationAdmissionError("publication approval ID is invalid")
    issued_at = _aware(approval["issued_at"], "approval issued_at")
    expires_at = _aware(approval["expires_at"], "approval expires_at")
    freshness_seconds = approval["freshness_seconds"]
    if (
        type(freshness_seconds) is not int
        or freshness_seconds <= 0
        or freshness_seconds > MAX_APPROVAL_FRESHNESS_SECONDS
        or expires_at <= issued_at
        or expires_at > issued_at + timedelta(seconds=freshness_seconds)
    ):
        raise PublicationAdmissionError("publication approval lifetime is invalid")
    evaluated_at = (now or datetime.now(UTC)).astimezone(UTC)
    if issued_at > evaluated_at + timedelta(seconds=60) or evaluated_at > expires_at:
        raise PublicationAdmissionError("publication approval is not current")

    candidate = _require_exact(approval["candidate"], _CANDIDATE_KEYS, "candidate")
    expected_candidate, site_manifest = _candidate_projection(candidate_path)
    if candidate != expected_candidate:
        raise PublicationAdmissionError("publication approval candidate binding changed")
    freshness = site_manifest["freshness"]
    publication_not_after = _aware(
        freshness["publication_not_after"], "candidate publication_not_after"
    )
    if expires_at > publication_not_after:
        raise PublicationAdmissionError("approval outlives candidate freshness")

    refresh = _require_exact(approval["refresh_lineage"], _REFRESH_KEYS, "refresh lineage")
    review = _require_exact(approval["review_lineage"], _REVIEW_KEYS, "review lineage")
    triage = _require_exact(approval["triage_resolution"], _TRIAGE_KEYS, "triage resolution")
    bindings = site_manifest.get("bindings")
    if not isinstance(bindings, dict):
        raise PublicationAdmissionError("site candidate bindings are invalid")
    if (
        refresh["candidate_manifest_digest"] != bindings.get("candidate_manifest_digest")
        or refresh["source_revision"] != bindings.get("source_revision")
        or refresh["source_tree_digest"] != bindings.get("source_tree_digest")
        or refresh["seed_digest"] != bindings.get("seed_digest")
        or refresh["masking_digest"] != bindings.get("masking_digest")
        or refresh["policy_digest"] != bindings.get("policy_digest")
        or refresh["triage_receipt_digest"] != triage["triage_receipt_digest"]
        or refresh["candidate_relative_tree_digest"]
        != refresh["repeat_candidate_relative_tree_digest"]
    ):
        raise PublicationAdmissionError("refresh or triage lineage does not match candidate")
    for label, value in {**refresh, **review}.items():
        if label == "source_revision":
            if not isinstance(value, str) or _REVISION.fullmatch(value) is None:
                raise PublicationAdmissionError("source revision is invalid")
        elif label == "acceptance_state" or label == "acceptance_scope":
            continue
        else:
            _require_digest(value, label)
    if (
        review["publication_review_artifact_sha256"] != bindings.get("review_artifact_sha256")
        or review["publication_review_receipt_digest"] != bindings.get("review_receipt_digest")
        or review["disposition_policy_sha256"] != bindings.get("disposition_policy_sha256")
        or review["acceptance_state"] != "ACCEPTED_EXACT_V38"
        or review["acceptance_scope"]
        != "all-eight-current-masked-dispositions-and-exact-v37-forward-baseline"
    ):
        raise PublicationAdmissionError("review lineage is not accepted exact V38")
    if (
        type(triage["reviewed_finding_count"]) is not int
        or triage["reviewed_finding_count"] < 0
        or triage["unresolved_finding_count"] != 0
        or not isinstance(triage["accepted_finding_codes"], list)
        or triage["reviewed_finding_count"] != len(set(triage["accepted_finding_codes"]))
        or not isinstance(triage["accepted_masked_slugs"], list)
        or triage["accepted_masked_slugs"] != sorted(set(triage["accepted_masked_slugs"]))
        or len(triage["accepted_masked_slugs"]) != candidate["masked_count"]
        or triage["policy_change_reviewed"] is not True
    ):
        raise PublicationAdmissionError("triage findings are unresolved or unbound")
    for key in ("triage_receipt_digest", "findings_projection_digest", "resolution_receipt_digest"):
        _require_digest(triage[key], key)

    provider = _require_exact(
        approval["provider_prepublication"], _PROVIDER_KEYS, "provider prepublication"
    )
    if not _receipt_valid(provider):
        raise PublicationAdmissionError("provider prepublication receipt integrity is invalid")
    provider_observed = _aware(provider["observed_at"], "provider observed_at")
    provider_freshness = provider["freshness_seconds"]
    if (
        type(provider_freshness) is not int
        or provider_freshness <= 0
        or provider_freshness > MAX_APPROVAL_FRESHNESS_SECONDS
        or provider_observed > evaluated_at + timedelta(seconds=60)
        or evaluated_at > provider_observed + timedelta(seconds=provider_freshness)
        or expires_at > provider_observed + timedelta(seconds=provider_freshness)
        or provider["schema"] != PROVIDER_PREPUBLICATION_SCHEMA
        or provider["target"] != "production"
        or provider["deployment_state"] != "READY_PROMOTED"
        or any(
            not isinstance(provider[field], str) or not provider[field]
            for field in (
                "alias",
                "deployment_id",
                "immutable_deployment_url",
                "project_id",
                "team_id",
            )
        )
        or not isinstance(provider["source_revision"], str)
        or _REVISION.fullmatch(provider["source_revision"]) is None
        or not isinstance(provider["source_tree"], str)
        or _REVISION.fullmatch(provider["source_tree"]) is None
        or any(
            provider[field] is not True
            for field in (
                "alias_matches",
                "same_project_team",
                "no_intervening_deployment",
                "target_retained",
                "matches_candidate_rollback_target",
            )
        )
    ):
        raise PublicationAdmissionError("provider prepublication binding is stale or unsafe")
    for key in (
        "receipt_digest",
        "metadata_receipt_digest",
        "binding_decision_receipt_digest",
        "public_tree_digest",
    ):
        _require_digest(provider[key], f"provider {key}")

    rollback = _require_exact(approval["rollback"], _ROLLBACK_KEYS, "rollback")
    candidate_rollback = site_manifest.get("rollback")
    candidate_target = (
        candidate_rollback.get("production_target")
        if isinstance(candidate_rollback, dict)
        else None
    )
    rollback_observed = (
        _aware(candidate_rollback.get("observed_at"), "candidate rollback observed_at")
        if isinstance(candidate_rollback, dict)
        else issued_at
    )
    rollback_freshness = (
        candidate_rollback.get("freshness_seconds")
        if isinstance(candidate_rollback, dict)
        else None
    )
    if (
        not isinstance(candidate_rollback, dict)
        or candidate_rollback.get("state") != PROVIDER_NATIVE_ROLLBACK_STATE
        or not isinstance(candidate_target, dict)
        or type(rollback_freshness) is not int
        or rollback_freshness <= 0
        or expires_at > rollback_observed + timedelta(seconds=rollback_freshness)
        or any(
            candidate_target.get(field) != provider[field]
            for field in ("alias", "deployment_id", "project_id", "team_id")
        )
        or rollback
        != {
            "mode": "provider-native-first-publication",
            "embedded_candidate_rollback_receipt": candidate_rollback.get("receipt_digest"),
            "prepublication_revalidation_receipt": provider["receipt_digest"],
            "immediate_previous_deployment_id": provider["deployment_id"],
            "target_retained": True,
            "same_project_team": True,
            "rollback_execution_allowed": False,
            "provider_artifact_digest": "UNKNOWN",
            "exercised_rollback_routing": "UNKNOWN",
        }
    ):
        raise PublicationAdmissionError("rollback binding is invalid")

    operator = _require_exact(
        approval["operator_acceptance"], _OPERATOR_KEYS, "operator acceptance"
    )
    if (
        operator["authority"] != "operator"
        or operator["decision"] != "OPERATOR_ACCEPTED_EXACT_PUBLICATION_CONTENT"
        or not isinstance(operator["locator"], str)
        or not operator["locator"]
        or _aware(operator["accepted_at"], "operator accepted_at") > issued_at
        or operator["accepted_binding_digest"] != _binding_digest(approval)
    ):
        raise PublicationAdmissionError("operator acceptance binding is invalid")
    _require_digest(operator["statement_sha256"], "operator statement")
    _privacy_walk(approval)
    return {
        "schema": approval["schema"],
        "state": approval["state"],
        "approval_id": approval["approval_id"],
        "issued_at": approval["issued_at"],
        "expires_at": approval["expires_at"],
        "receipt_digest": approval["receipt_digest"],
        "candidate_receipt_digest": candidate["manifest_receipt_digest"],
        "candidate_content_digest": candidate["content_digest"],
        "provider_revalidation_receipt_digest": provider["receipt_digest"],
        "public_mutation_allowed": False,
        "deployment_allowed": False,
    }


def _candidate_files(root: Path) -> list[dict[str, Any]]:
    files: list[dict[str, Any]] = []
    for path in sorted(root.rglob("*"), key=lambda item: item.relative_to(root).as_posix()):
        relative = path.relative_to(root).as_posix()
        if path.is_symlink():
            raise PublicationAdmissionError(f"candidate contains a symlink: {relative}")
        if path.is_dir():
            continue
        content = _stable_bytes(path, f"candidate file {relative}")
        files.append(
            {
                "path": relative,
                "bytes": len(content),
                "sha256": _sha256_bytes(content),
            }
        )
    if not files:
        raise PublicationAdmissionError("candidate contains no files")
    return files


def _files_digest(files: list[dict[str, Any]]) -> str:
    return _sha256_bytes(canonical_bytes(files))


def build_publication_package(
    *,
    candidate_path: Path,
    approval_path: Path,
    output_path: Path,
    now: datetime | None = None,
) -> Path:
    """Copy one approved candidate into a deterministic, non-publishing package."""
    approval = verify_publication_approval(
        approval_path,
        candidate_path=candidate_path,
        now=now,
    )
    if output_path.exists() or output_path.is_symlink():
        raise PublicationAdmissionError("publication package output must not already exist")
    candidate_resolved = candidate_path.resolve(strict=True)
    output_parent = output_path.parent.resolve(strict=True)
    if candidate_resolved == output_parent or candidate_resolved in output_parent.parents:
        raise PublicationAdmissionError("publication package overlaps the candidate root")
    source_files = _candidate_files(candidate_path)
    approval_payload = _stable_json(approval_path, "publication approval")
    temporary = Path(tempfile.mkdtemp(prefix=f".{output_path.name}.tmp-", dir=output_path.parent))
    try:
        candidate_destination = temporary / candidate_path.name
        for item in source_files:
            source = candidate_path / item["path"]
            destination = candidate_destination / item["path"]
            destination.parent.mkdir(parents=True, exist_ok=True)
            destination.write_bytes(_stable_bytes(source, f"candidate file {item['path']}"))
        if _candidate_files(candidate_destination) != source_files:
            raise PublicationAdmissionError("candidate changed during package copy")
        package: dict[str, Any] = {
            "schema": PUBLICATION_PACKAGE_SCHEMA,
            "state": PUBLICATION_PACKAGE_STATE,
            "created_at": approval["issued_at"],
            "candidate_path_name": candidate_path.name,
            "candidate_manifest_sha256": approval_payload["candidate"]["manifest_sha256"],
            "candidate_receipt_digest": approval["candidate_receipt_digest"],
            "candidate_content_digest": approval["candidate_content_digest"],
            "publication_approval_sha256": _sha256_bytes(
                _stable_bytes(approval_path, "publication approval")
            ),
            "publication_approval_receipt_digest": approval["receipt_digest"],
            "provider_revalidation_receipt_digest": approval[
                "provider_revalidation_receipt_digest"
            ],
            "content_files": source_files,
            "content_digest": _files_digest(source_files),
            "authority": dict(_PACKAGE_AUTHORITY),
            "claim_ceiling": (
                "Local copy-only publication package; not deployment authority, not public "
                "mutation, not rollback execution authority, and not scheduler authority."
            ),
        }
        package["receipt_digest"] = _sha256_bytes(canonical_bytes(package))
        (temporary / PUBLICATION_PACKAGE_MANIFEST).write_bytes(canonical_bytes(package))
        verify_publication_package(temporary, approval_path=approval_path, now=now)
        for path in sorted(temporary.rglob("*"), reverse=True):
            path.chmod(0o500 if path.is_dir() else 0o400)
        temporary.chmod(0o500)
        os.replace(temporary, output_path)
        verify_publication_package(output_path, approval_path=approval_path, now=now)
    except Exception:
        if temporary.exists():
            shutil.rmtree(temporary)
        raise
    return output_path


def verify_publication_package(
    root: Path,
    *,
    approval_path: Path,
    now: datetime | None = None,
) -> dict[str, Any]:
    """Re-read and verify an immutable-copy publication package."""
    if root.is_symlink() or not root.is_dir():
        raise PublicationAdmissionError("publication package root must be a real directory")
    package = _stable_json(root / PUBLICATION_PACKAGE_MANIFEST, "publication package")
    _require_exact(package, _PACKAGE_KEYS, "publication package")
    if (
        package["schema"] != PUBLICATION_PACKAGE_SCHEMA
        or package["state"] != PUBLICATION_PACKAGE_STATE
        or package["authority"] != _PACKAGE_AUTHORITY
        or not _receipt_valid(package)
    ):
        raise PublicationAdmissionError("publication package receipt or authority is invalid")
    candidate_path_name = package.get("candidate_path_name")
    if (
        not isinstance(candidate_path_name, str)
        or not candidate_path_name
        or Path(candidate_path_name).name != candidate_path_name
    ):
        raise PublicationAdmissionError("publication package candidate name is invalid")
    candidate_root = root / candidate_path_name
    approval = verify_publication_approval(
        approval_path,
        candidate_path=candidate_root,
        now=now,
    )
    approval_payload = _stable_json(approval_path, "publication approval")
    files = _candidate_files(candidate_root)
    if package["content_files"] != files or package["content_digest"] != _files_digest(files):
        raise PublicationAdmissionError("publication package content changed")
    if (
        package["created_at"] != approval["issued_at"]
        or package["candidate_manifest_sha256"] != approval_payload["candidate"]["manifest_sha256"]
        or package["candidate_receipt_digest"] != approval["candidate_receipt_digest"]
        or package["candidate_content_digest"] != approval["candidate_content_digest"]
        or package["publication_approval_sha256"]
        != _sha256_bytes(_stable_bytes(approval_path, "publication approval"))
        or package["publication_approval_receipt_digest"] != approval["receipt_digest"]
        or package["provider_revalidation_receipt_digest"]
        != approval["provider_revalidation_receipt_digest"]
    ):
        raise PublicationAdmissionError("publication package lineage changed")
    _privacy_walk(package)
    return {
        "schema": package["schema"],
        "state": package["state"],
        "receipt_digest": package["receipt_digest"],
        "content_digest": package["content_digest"],
        "file_count": len(files),
        "public_mutation_allowed": False,
        "deployment_allowed": False,
    }


def verify_production_publication_receipt(
    receipt_path: Path,
    *,
    package_path: Path,
    approval_path: Path,
    deployment_authorization_path: Path,
    readback_receipt_path: Path,
    now: datetime | None = None,
) -> dict[str, Any]:
    """Verify provider identity plus exact all-route readback after a deployment.

    A provider exit code, route equality alone, or a missing artifact digest can
    never produce a fresh result.
    """
    deployment = _stable_json(deployment_authorization_path, "deployment authorization")
    _require_exact(
        deployment, _DEPLOYMENT_AUTHORIZATION_KEYS, "deployment authorization"
    )
    if deployment.get("schema") != "McpTrustProductionDeployAuthorizationV4":
        raise PublicationAdmissionError("deployment authorization V4 is required")
    deployment_unsigned = dict(deployment)
    deployment_receipt = deployment_unsigned.pop("approval_receipt_digest", None)
    if deployment_receipt != _sha256_bytes(canonical_bytes(deployment_unsigned)):
        raise PublicationAdmissionError("deployment authorization receipt integrity is invalid")
    deployment_issued_at = _aware(deployment.get("issued_at"), "deployment issued_at")
    deployment_expires_at = _aware(deployment.get("expires_at"), "deployment expires_at")
    if not (
        deployment_issued_at < deployment_expires_at
        <= deployment_issued_at + timedelta(minutes=15)
    ):
        raise PublicationAdmissionError("deployment authorization validity is invalid")
    package = verify_publication_package(
        package_path,
        approval_path=approval_path,
        now=deployment_issued_at,
    )
    package_manifest_for_path = _stable_json(
        package_path / PUBLICATION_PACKAGE_MANIFEST, "publication package"
    )
    approval = verify_publication_approval(
        approval_path,
        candidate_path=package_path / package_manifest_for_path["candidate_path_name"],
        now=deployment_issued_at,
    )
    approval_payload = _stable_json(approval_path, "publication approval")
    package_manifest_sha256 = _sha256_bytes(
        _stable_bytes(
            package_path / PUBLICATION_PACKAGE_MANIFEST, "publication package manifest"
        )
    )
    approval_sha256 = _sha256_bytes(_stable_bytes(approval_path, "publication approval"))
    candidate_manifest_for_binding = _stable_json(
        package_path
        / package_manifest_for_path["candidate_path_name"]
        / SITE_CANDIDATE_MANIFEST,
        "packaged site candidate",
    )
    if (
        deployment.get("approval_path") != str(deployment_authorization_path.resolve())
        or deployment.get("publication_package_path") != str(package_path.resolve())
        or deployment.get("publication_approval_path") != str(approval_path.resolve())
        or deployment.get("publication_package_manifest_sha256")
        != package_manifest_sha256
        or deployment.get("publication_package_receipt_digest")
        != package["receipt_digest"]
        or deployment.get("publication_approval_sha256") != approval_sha256
        or deployment.get("publication_approval_receipt_digest")
        != approval["receipt_digest"]
        or deployment.get("provider_prepublication_receipt_digest")
        != approval["provider_revalidation_receipt_digest"]
        or deployment.get("operator_acceptance_statement_sha256")
        != approval_payload.get("operator_acceptance", {}).get("statement_sha256")
        or deployment.get("site_candidate_receipt_digest")
        != candidate_manifest_for_binding.get("receipt_digest")
        or deployment.get("site_candidate_content_digest")
        != candidate_manifest_for_binding.get("content", {}).get("digest")
        or deployment.get("implementation_revision")
        != candidate_manifest_for_binding.get("implementation_binding", {}).get("revision")
        or deployment.get("implementation_source_tree_digest")
        != candidate_manifest_for_binding.get("implementation_binding", {}).get(
            "source_tree_digest"
        )
    ):
        raise PublicationAdmissionError("deployment authorization lineage is invalid")

    receipt = _stable_json(receipt_path, "production publication receipt")
    _require_exact(receipt, _PRODUCTION_RECEIPT_KEYS, "production publication receipt")
    if not _receipt_valid(receipt):
        raise PublicationAdmissionError("production publication receipt integrity is invalid")
    if (
        receipt["schema"] != PRODUCTION_PUBLICATION_RECEIPT_SCHEMA
        or receipt["publication_package_receipt_digest"] != package["receipt_digest"]
        or receipt["publication_approval_receipt_digest"] != approval["receipt_digest"]
        or receipt["deployment_authorization_receipt_digest"] != deployment_receipt
        or receipt["external_effects"] != ["provider_deployment_attempted"]
        or "scheduler" in str(receipt["external_effects"]).lower()
    ):
        raise PublicationAdmissionError("production publication receipt lineage is invalid")
    observed_at = _aware(receipt["observed_at"], "publication observed_at")
    if now is not None and observed_at > now.astimezone(UTC) + timedelta(seconds=60):
        raise PublicationAdmissionError("production publication observation is in the future")
    package_manifest = _stable_json(
        package_path / PUBLICATION_PACKAGE_MANIFEST, "publication package"
    )
    candidate_manifest = _stable_json(
        package_path / package_manifest["candidate_path_name"] / SITE_CANDIDATE_MANIFEST,
        "packaged site candidate",
    )
    readback_bytes = _stable_bytes(readback_receipt_path, "exact public readback receipt")
    readback = _stable_json(readback_receipt_path, "exact public readback receipt")
    _require_exact(readback, _READBACK_RECEIPT_KEYS, "exact public readback receipt")
    public_readback = candidate_manifest.get("public_readback")
    expected_routes = public_readback.get("routes") if isinstance(public_readback, dict) else None
    actual_routes = readback.get("routes") if isinstance(readback, dict) else None
    summary = readback.get("summary") if isinstance(readback, dict) else None
    content = candidate_manifest.get("content")
    content_files = content.get("files") if isinstance(content, dict) else None
    public_files = (
        [item for item in content_files if item.get("path") != "vercel.json"]
        if isinstance(content_files, list)
        else None
    )
    expected_manifest_digest = _sha256_bytes(
        (json.dumps(public_readback, indent=2, sort_keys=True) + "\n").encode()
    ).removeprefix("sha256:")
    checked_at = _aware(readback.get("checked_at"), "readback checked_at")
    readback_exact = (
        isinstance(expected_routes, list)
        and isinstance(actual_routes, list)
        and isinstance(public_files, list)
        and len(expected_routes) > 0
        and len(actual_routes) == len(expected_routes)
        and len(public_files) == len(expected_routes)
        and readback.get("schema") == "WebReleaseReadbackV1"
        and readback.get("contract_version") == "1.0.0"
        and readback.get("target_url") == candidate_manifest.get("base_url")
        and readback.get("manifest")
        == {"name": public_readback.get("name"), "sha256": expected_manifest_digest}
        and readback.get("verifier") == _READBACK_VERIFIER
        and readback.get("state") == "passed"
        and checked_at <= observed_at
        and summary
        == {"total": len(expected_routes), "passed": len(expected_routes), "failed": 0}
        and all(
            isinstance(actual, dict)
            and set(actual) == _READBACK_ROUTE_KEYS
            and actual.get("id") == expected.get("id")
            and actual.get("method") == expected.get("method")
            and actual.get("route") == expected.get("route")
            and actual.get("requested_url")
            == urljoin(
                f"{candidate_manifest.get('base_url')}/",
                str(expected.get("route", "")).lstrip("/"),
            )
            and actual.get("final_url") == actual.get("requested_url")
            and actual.get("expected_status") == expected.get("expected_status")
            and actual.get("actual_status") == expected.get("expected_status")
            and actual.get("body_bytes") == expected_file.get("bytes")
            and actual.get("body_sha256")
            == str(expected.get("body_sha256", "")).removeprefix("sha256:")
            and actual.get("required_sentinels") == {"expected": [], "missing": []}
            and actual.get("forbidden_sentinels")
            == {"expected_absent": [], "present": []}
            and actual.get("state") == "passed"
            and actual.get("reason_codes") == ["matched"]
            for expected, expected_file, actual in zip(
                expected_routes, public_files, actual_routes, strict=True
            )
        )
    )
    if not readback_exact:
        raise PublicationAdmissionError("exact all-route public readback is invalid")
    actual_readback_digest = _sha256_bytes(readback_bytes)
    if receipt["exact_public_readback_receipt_digest"] != actual_readback_digest:
        raise PublicationAdmissionError("exact public readback receipt digest changed")
    if receipt["route_matches"] != len(actual_routes) or receipt["route_total"] != len(
        expected_routes
    ):
        raise PublicationAdmissionError("production route totals do not match exact readback")
    expected_alias = urlsplit(str(deployment.get("target_url"))).hostname
    immutable_deployment_url = receipt["immutable_deployment_url"]
    provider_bound = (
        isinstance(receipt["provider_deployment_id"], str)
        and re.fullmatch(r"dpl_[A-Za-z0-9]+", receipt["provider_deployment_id"])
        is not None
        and isinstance(immutable_deployment_url, str)
        and re.fullmatch(
            r"[a-z0-9](?:[a-z0-9-]*[a-z0-9])?(?:\.[a-z0-9-]+)*\.vercel\.app",
            immutable_deployment_url,
        )
        is not None
        and receipt["alias"] == expected_alias
        and receipt["project_id"] == deployment.get("vercel_project_id")
        and receipt["team_id"] == deployment.get("vercel_org_id")
        and receipt["provider_source_revision"] == deployment.get("commit")
        and receipt["provider_source_tree"]
        == deployment.get("implementation_source_tree_digest")
    )
    artifact_bound = (
        isinstance(receipt["provider_artifact_digest"], str)
        and _SHA256.fullmatch(receipt["provider_artifact_digest"]) is not None
    )
    readback_bound = readback_exact
    routes_exact = True
    freshness = candidate_manifest.get("freshness")
    state_counts = freshness.get("state_counts") if isinstance(freshness, dict) else None
    earliest = (
        _aware(freshness.get("earliest_stale_after"), "earliest stale_after")
        if isinstance(freshness, dict) and freshness.get("earliest_stale_after") is not None
        else None
    )
    expected_freshness = "UNKNOWN"
    if (
        routes_exact
        and provider_bound
        and artifact_bound
        and readback_bound
        and isinstance(state_counts, dict)
        and state_counts.get("FRESH", 0) > 0
    ):
        expected_freshness = "STALE" if earliest is not None and observed_at > earliest else "FRESH"
    expected_state = (
        "PUBLICATION_OBSERVED_EXACT"
        if routes_exact and provider_bound and readback_bound
        else "PUBLICATION_OBSERVATION_UNKNOWN"
    )
    if receipt["state"] != expected_state or receipt["production_freshness"] != expected_freshness:
        raise PublicationAdmissionError("production freshness or adoption claim is invalid")
    rollback = approval_payload.get("rollback")
    if (
        not isinstance(rollback, dict)
        or receipt["rollback_target_deployment_id"]
        != rollback.get("immediate_previous_deployment_id")
    ):
        raise PublicationAdmissionError("publication rollback target changed")
    claim = str(receipt["claim_ceiling"]).lower()
    if "not endorsement" not in claim or "scheduler" not in claim or "static" not in claim:
        raise PublicationAdmissionError("production publication claim ceiling is incomplete")
    return {
        "state": expected_state,
        "production_freshness": expected_freshness,
        "routes_exact": routes_exact,
        "provider_identity_bound": provider_bound,
        "provider_artifact_bound": artifact_bound,
        "scheduler_change_allowed": False,
        "receipt_digest": receipt["receipt_digest"],
    }
