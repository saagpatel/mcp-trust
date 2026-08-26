"""V47 deployment admission and post-publication false-green cases."""

from __future__ import annotations

import hashlib
import importlib.util
import json
import sys
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import pytest

from mcp_trust.site.candidate import canonical_bytes, verify_site_candidate
from mcp_trust.site.publication import (
    PublicationAdmissionError,
    _sha256_bytes,
    build_publication_package,
    verify_production_publication_receipt,
    verify_publication_approval,
)

ROOT = Path(__file__).resolve().parents[1]


def _load_test_helpers(name: str, path: Path) -> Any:
    spec = importlib.util.spec_from_file_location(name, path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


PUBLICATION = _load_test_helpers(
    "v47_publication_helpers", ROOT / "tests/test_publication_admission.py"
)
DEPLOYMENT = _load_test_helpers(
    "v47_deployment_helpers", ROOT / "tests/test_deployment_authority.py"
)
OBSERVED = datetime(2026, 8, 25, 12, 20, tzinfo=UTC)


def _sign(payload: dict[str, Any], field: str = "receipt_digest") -> None:
    payload.pop(field, None)
    payload[field] = _sha256_bytes(canonical_bytes(payload))


def _chmod_fixture(root: Path) -> None:
    for item in root.rglob("*"):
        item.chmod(0o700 if item.is_dir() else 0o600)
    root.chmod(0o700)


def _publication_fixture(
    tmp_path: Path, *, fresh_until: str | None = None
) -> tuple[Path, Path, Path, Path, Path, dict[str, Any], dict[str, Any]]:
    candidate = PUBLICATION._site_candidate(tmp_path)
    if fresh_until is not None:
        manifest_path = candidate / "SITE_CANDIDATE.json"
        manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
        manifest["freshness"]["earliest_stale_after"] = fresh_until
        manifest["freshness"]["state_counts"] = {
            "FRESH": 1,
            "STALE": 0,
            "UNKNOWN": 0,
            "NOT_APPLICABLE": 0,
        }
        _sign(manifest)
        manifest_path.write_bytes(canonical_bytes(manifest))
        verify_site_candidate(candidate)

    approval_payload = PUBLICATION._approval_payload(candidate)
    approval_path = tmp_path / "publication-approval.json"
    approval_path.write_bytes(canonical_bytes(approval_payload))
    package_path = tmp_path / "publication-package"
    build_publication_package(
        candidate_path=candidate,
        approval_path=approval_path,
        output_path=package_path,
        now=PUBLICATION.NOW,
    )
    _chmod_fixture(package_path)
    package_manifest_path = package_path / "PUBLICATION_PACKAGE.json"
    package = json.loads(package_manifest_path.read_text())
    manifest = json.loads((candidate / "SITE_CANDIDATE.json").read_text())
    deployment_path = tmp_path / "deployment-authorization.json"

    deployment: dict[str, Any] = {
        "schema": "McpTrustProductionDeployAuthorizationV4",
        "receipt_id": "deploy-v47-test",
        "repository": str(ROOT),
        "branch": "main",
        "issued_at": PUBLICATION.NOW.isoformat(),
        "expires_at": "2026-08-25T12:20:00+00:00",
        "target_url": "https://mcp-trust.example",
        "vercel_project_id": "prj_project",
        "vercel_org_id": "team_team",
        "vercel_invocation_path": "/test/vercel",
        "vercel_bin": "/test/vercel",
        "vercel_sha256": "a" * 64,
        "node_invocation_path": "/test/node",
        "node_bin": "/test/node",
        "node_sha256": "b" * 64,
        "python_invocation_path": "/test/python",
        "python_bin": "/test/python",
        "python_sha256": "c" * 64,
        "publication_verifier_path": "/test/build_publication_package.py",
        "publication_verifier_sha256": "d" * 64,
        "approval_path": str(deployment_path.resolve()),
        "output_path": "/test/site",
        "output_sha256": "e" * 64,
        "commit": "9" * 40,
        "publication_package_path": str(package_path.resolve()),
        "publication_package_manifest_sha256": _sha256_bytes(
            package_manifest_path.read_bytes()
        ),
        "implementation_source_tree_digest": PUBLICATION.DIGESTS["d"],
        "publication_package_receipt_digest": package["receipt_digest"],
        "publication_approval_path": str(approval_path.resolve()),
        "publication_approval_sha256": _sha256_bytes(approval_path.read_bytes()),
        "publication_approval_receipt_digest": approval_payload["receipt_digest"],
        "provider_prepublication_receipt_digest": approval_payload[
            "provider_prepublication"
        ]["receipt_digest"],
        "operator_acceptance_statement_sha256": approval_payload[
            "operator_acceptance"
        ]["statement_sha256"],
        "site_candidate_receipt_digest": manifest["receipt_digest"],
        "site_candidate_content_digest": manifest["content"]["digest"],
        "implementation_revision": manifest["implementation_binding"]["revision"],
        "rollback_artifact_path": "/test/prior-site",
        "rollback_site_candidate_receipt_digest": PUBLICATION.DIGESTS["m"],
        "rollback_site_candidate_content_digest": PUBLICATION.DIGESTS["n"],
    }
    _sign(deployment, "approval_receipt_digest")
    deployment_path.write_bytes(canonical_bytes(deployment))

    expected_readback = manifest["public_readback"]
    public_files = [
        item for item in manifest["content"]["files"] if item["path"] != "vercel.json"
    ]
    routes = []
    for expected, expected_file in zip(
        expected_readback["routes"], public_files, strict=True
    ):
        routes.append(
            {
                "id": expected["id"],
                "method": expected["method"],
                "route": expected["route"],
                "requested_url": "https://mcp-trust.example" + expected["route"],
                "final_url": "https://mcp-trust.example" + expected["route"],
                "expected_status": expected["expected_status"],
                "actual_status": expected["expected_status"],
                "body_bytes": expected_file["bytes"],
                "body_sha256": expected["body_sha256"].removeprefix("sha256:"),
                "required_sentinels": {"expected": [], "missing": []},
                "forbidden_sentinels": {"expected_absent": [], "present": []},
                "state": "passed",
                "reason_codes": ["matched"],
            }
        )
    readback: dict[str, Any] = {
        "schema": "WebReleaseReadbackV1",
        "contract_version": "1.0.0",
        "target_url": manifest["base_url"],
        "manifest": {
            "name": expected_readback["name"],
            "sha256": _sha256_bytes(
                (json.dumps(expected_readback, indent=2, sort_keys=True) + "\n").encode()
            ).removeprefix("sha256:"),
        },
        "checked_at": OBSERVED.isoformat(),
        "verifier": {
            "name": "web-release-readback",
            "version": "1.0.0",
            "network_methods": ["GET", "HEAD"],
            "denied_methods": ["POST", "PUT", "PATCH", "DELETE", "CONNECT", "TRACE"],
            "credentials_supported": False,
            "proxy_environment_used": False,
            "same_origin_redirects_only": True,
            "mutation_capabilities": [],
        },
        "state": "passed",
        "summary": {"total": len(routes), "passed": len(routes), "failed": 0},
        "routes": routes,
    }
    readback_path = tmp_path / "readback.json"
    readback_path.write_bytes(canonical_bytes(readback))
    return (
        candidate,
        approval_path,
        package_path,
        deployment_path,
        readback_path,
        deployment,
        approval_payload,
    )


def _production_receipt(
    tmp_path: Path,
    *,
    package_path: Path,
    approval_path: Path,
    deployment: dict[str, Any],
    readback_path: Path,
    state: str = "PUBLICATION_OBSERVED_EXACT",
    freshness: str = "UNKNOWN",
    artifact_digest: str = "UNKNOWN",
    provider_source_revision: str | None = None,
) -> Path:
    package = json.loads((package_path / "PUBLICATION_PACKAGE.json").read_text())
    approval = json.loads(approval_path.read_text())
    readback = json.loads(readback_path.read_text())
    payload: dict[str, Any] = {
        "schema": "McpTrustProductionPublicationReceiptV1",
        "state": state,
        "observed_at": OBSERVED.isoformat(),
        "publication_package_receipt_digest": package["receipt_digest"],
        "publication_approval_receipt_digest": approval["receipt_digest"],
        "deployment_authorization_receipt_digest": deployment["approval_receipt_digest"],
        "provider_deployment_id": "dpl_new",
        "immutable_deployment_url": "new.vercel.app",
        "alias": "mcp-trust.example",
        "project_id": "prj_project",
        "team_id": "team_team",
        "provider_source_revision": provider_source_revision
        if provider_source_revision is not None
        else deployment["commit"],
        "provider_source_tree": deployment["implementation_source_tree_digest"],
        "provider_artifact_digest": artifact_digest,
        "exact_public_readback_receipt_digest": _sha256_bytes(readback_path.read_bytes()),
        "route_matches": readback["summary"]["passed"],
        "route_total": readback["summary"]["total"],
        "production_freshness": freshness,
        "rollback_target_deployment_id": "dpl_previous",
        "external_effects": ["provider_deployment_attempted"],
        "claim_ceiling": (
            "Static historical catalog; not endorsement; scheduler unchanged; "
            "only the bound routes and provider observation are claimed."
        ),
    }
    _sign(payload)
    path = tmp_path / "production-publication-receipt.json"
    path.write_bytes(canonical_bytes(payload))
    return path


def _verify_post(
    receipt: Path, package: Path, approval: Path, deployment: Path, readback: Path
) -> dict[str, Any]:
    return verify_production_publication_receipt(
        receipt,
        package_path=package,
        approval_path=approval,
        deployment_authorization_path=deployment,
        readback_receipt_path=readback,
        now=datetime(2026, 8, 25, 12, 30, tzinfo=UTC),
    )


def test_pa026_v3_deployment_authorization_is_rejected_before_provider(tmp_path: Path) -> None:
    repo, provider, record = DEPLOYMENT._make_deploy_repo(tmp_path)
    commit = DEPLOYMENT._git(repo, "rev-parse", "HEAD")
    approval = tmp_path / "approval.json"
    DEPLOYMENT._write_approval(approval, repo=repo, commit=commit, vercel_bin=provider)
    payload = json.loads(approval.read_text())
    payload["schema"] = "McpTrustProductionDeployAuthorizationV3"
    _sign(payload, "approval_receipt_digest")
    approval.write_bytes(canonical_bytes(payload))
    result = DEPLOYMENT._run(
        DEPLOYMENT._deploy_command(repo, approval, provider),
        cwd=repo,
        env=DEPLOYMENT._deploy_env(tmp_path, record),
        check=False,
    )
    assert result.returncode != 0
    assert not record.exists()


def test_pa027_v4_missing_package_binding_is_rejected_before_provider(tmp_path: Path) -> None:
    repo, provider, record = DEPLOYMENT._make_deploy_repo(tmp_path)
    commit = DEPLOYMENT._git(repo, "rev-parse", "HEAD")
    approval = tmp_path / "approval.json"
    DEPLOYMENT._write_approval(approval, repo=repo, commit=commit, vercel_bin=provider)
    payload = json.loads(approval.read_text())
    payload.pop("publication_package_receipt_digest")
    _sign(payload, "approval_receipt_digest")
    approval.write_bytes(canonical_bytes(payload))
    result = DEPLOYMENT._run(
        DEPLOYMENT._deploy_command(repo, approval, provider),
        cwd=repo,
        env=DEPLOYMENT._deploy_env(tmp_path, record),
        check=False,
    )
    assert result.returncode != 0
    assert not record.exists()


def test_pa028_post_confirmation_package_drift_is_rejected(tmp_path: Path) -> None:
    repo, provider, record = DEPLOYMENT._make_deploy_repo(tmp_path)
    commit = DEPLOYMENT._git(repo, "rev-parse", "HEAD")
    approval = tmp_path / "approval.json"
    DEPLOYMENT._write_approval(approval, repo=repo, commit=commit, vercel_bin=provider)

    def mutate() -> None:
        package = tmp_path / "approval-package/approval-candidate/index.html"
        package.write_text("changed after confirmation\n", encoding="utf-8")

    result = DEPLOYMENT._run_with_tty(
        DEPLOYMENT._deploy_command(repo, approval, provider),
        cwd=repo,
        env=DEPLOYMENT._deploy_env(tmp_path, record),
        confirmation="DEPLOY_MCP_TRUST_PRODUCTION",
        before_confirmation=mutate,
    )
    assert result.returncode != 0
    assert "package changed after confirmation" in result.stdout
    assert not record.exists()


def test_pa029_provider_exit_zero_does_not_claim_freshness(tmp_path: Path) -> None:
    repo, provider, record = DEPLOYMENT._make_deploy_repo(tmp_path)
    commit = DEPLOYMENT._git(repo, "rev-parse", "HEAD")
    approval = tmp_path / "approval.json"
    DEPLOYMENT._write_approval(approval, repo=repo, commit=commit, vercel_bin=provider)
    result = DEPLOYMENT._run_with_tty(
        DEPLOYMENT._deploy_command(repo, approval, provider),
        cwd=repo,
        env=DEPLOYMENT._deploy_env(tmp_path, record),
        confirmation="DEPLOY_MCP_TRUST_PRODUCTION",
    )
    assert result.returncode == 0
    assert "production freshness remain UNKNOWN" in result.stdout


def test_pa030_sentinel_only_route_count_mismatch_is_rejected(tmp_path: Path) -> None:
    _, approval, package, deployment_path, readback, deployment, _ = _publication_fixture(
        tmp_path
    )
    exact_readback_payload = json.loads(readback.read_text())
    readback_payload = json.loads(json.dumps(exact_readback_payload))
    readback_payload["summary"]["total"] -= 1
    readback.write_bytes(canonical_bytes(readback_payload))
    receipt = _production_receipt(
        tmp_path,
        package_path=package,
        approval_path=approval,
        deployment=deployment,
        readback_path=readback,
    )
    with pytest.raises(PublicationAdmissionError, match="exact all-route"):
        _verify_post(receipt, package, approval, deployment_path, readback)

    readback_payload = json.loads(json.dumps(exact_readback_payload))
    readback_payload["verifier"] = {}
    readback.write_bytes(canonical_bytes(readback_payload))
    receipt = _production_receipt(
        tmp_path,
        package_path=package,
        approval_path=approval,
        deployment=deployment,
        readback_path=readback,
    )
    with pytest.raises(PublicationAdmissionError, match="exact all-route"):
        _verify_post(receipt, package, approval, deployment_path, readback)

    readback_payload = json.loads(json.dumps(exact_readback_payload))
    readback_payload["routes"][0]["required_sentinels"]["missing"] = ["spoofed"]
    readback.write_bytes(canonical_bytes(readback_payload))
    receipt = _production_receipt(
        tmp_path,
        package_path=package,
        approval_path=approval,
        deployment=deployment,
        readback_path=readback,
    )
    with pytest.raises(PublicationAdmissionError, match="exact all-route"):
        _verify_post(receipt, package, approval, deployment_path, readback)


def test_pa031_collapsed_grade_and_evidence_axes_are_rejected(tmp_path: Path) -> None:
    candidate = PUBLICATION._site_candidate(tmp_path)
    approval = PUBLICATION._approval_payload(candidate)
    approval["policy_and_semantics"]["evidence_quality_axis"] = "technical-danger-only"
    path = tmp_path / "approval.json"
    PUBLICATION._resign(approval, path)
    with pytest.raises(PublicationAdmissionError, match="semantics or authority"):
        verify_publication_approval(path, candidate_path=candidate, now=PUBLICATION.NOW)


def test_pa032_unknown_provider_artifact_cannot_become_fresh(tmp_path: Path) -> None:
    _, approval, package, deployment_path, readback, deployment, _ = _publication_fixture(
        tmp_path, fresh_until="2026-08-25T12:25:00+00:00"
    )
    receipt = _production_receipt(
        tmp_path,
        package_path=package,
        approval_path=approval,
        deployment=deployment,
        readback_path=readback,
        artifact_digest="UNKNOWN",
        freshness="UNKNOWN",
    )
    result = _verify_post(receipt, package, approval, deployment_path, readback)
    assert result["production_freshness"] == "UNKNOWN"


def test_pa033_scheduler_authority_is_rejected(tmp_path: Path) -> None:
    candidate = PUBLICATION._site_candidate(tmp_path)
    approval = PUBLICATION._approval_payload(candidate)
    approval["authority"]["scheduler_activation_allowed"] = True
    path = tmp_path / "approval.json"
    PUBLICATION._resign(approval, path)
    with pytest.raises(PublicationAdmissionError, match="authority"):
        verify_publication_approval(path, candidate_path=candidate, now=PUBLICATION.NOW)


def test_pa034_vm_bundle_rejects_static_vercel_approval(tmp_path: Path) -> None:
    approval = tmp_path / "approval.json"
    approval.write_text('{"schema":"McpTrustPublicationApprovalV1"}\n', encoding="utf-8")
    result = DEPLOYMENT._run(
        [
            sys.executable,
            str(ROOT / "scripts/build_deploy_bundle.py"),
            "--candidate",
            str(tmp_path / "candidate"),
            "--review",
            str(tmp_path / "review.json"),
            "--publication-approval",
            str(approval),
        ],
        cwd=ROOT,
        check=False,
    )
    assert result.returncode != 0
    assert "cannot authorize a VM deploy bundle" in result.stderr


def test_pa035_provider_failure_leaves_adoption_and_freshness_unknown(tmp_path: Path) -> None:
    repo, provider, record = DEPLOYMENT._make_deploy_repo(tmp_path)
    provider.write_text("#!/bin/sh\nexit 23\n", encoding="utf-8")
    provider.chmod(0o700)
    commit = DEPLOYMENT._git(repo, "rev-parse", "HEAD")
    approval = tmp_path / "approval.json"
    DEPLOYMENT._write_approval(approval, repo=repo, commit=commit, vercel_bin=provider)
    result = DEPLOYMENT._run_with_tty(
        DEPLOYMENT._deploy_command(repo, approval, provider),
        cwd=repo,
        env=DEPLOYMENT._deploy_env(tmp_path, record),
        confirmation="DEPLOY_MCP_TRUST_PRODUCTION",
    )
    assert result.returncode != 0
    assert "freshness remain UNKNOWN" in result.stdout
    assert "scheduler" not in result.stdout.lower()


def test_p07_route_equality_without_provider_identity_remains_unknown(tmp_path: Path) -> None:
    _, approval, package, deployment_path, readback, deployment, _ = _publication_fixture(
        tmp_path
    )
    receipt = _production_receipt(
        tmp_path,
        package_path=package,
        approval_path=approval,
        deployment=deployment,
        readback_path=readback,
        state="PUBLICATION_OBSERVATION_UNKNOWN",
        provider_source_revision="",
    )
    payload = json.loads(receipt.read_text())
    payload["immutable_deployment_url"] = "javascript:unbound"
    _sign(payload)
    receipt.write_bytes(canonical_bytes(payload))
    result = _verify_post(receipt, package, approval, deployment_path, readback)
    assert result["state"] == "PUBLICATION_OBSERVATION_UNKNOWN"
    assert result["provider_identity_bound"] is False


def test_p08_exact_provider_readback_after_stale_boundary_is_stale(tmp_path: Path) -> None:
    _, approval, package, deployment_path, readback, deployment, _ = _publication_fixture(
        tmp_path, fresh_until="2026-08-25T12:15:00+00:00"
    )
    receipt = _production_receipt(
        tmp_path,
        package_path=package,
        approval_path=approval,
        deployment=deployment,
        readback_path=readback,
        artifact_digest="sha256:" + hashlib.sha256(b"provider artifact").hexdigest(),
        freshness="STALE",
    )
    result = _verify_post(receipt, package, approval, deployment_path, readback)
    assert result["state"] == "PUBLICATION_OBSERVED_EXACT"
    assert result["production_freshness"] == "STALE"
