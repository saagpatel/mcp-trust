from __future__ import annotations

import json
import subprocess
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
        "scannable": 31,
        "blocked": 0,
        "intentionally_masked": 8,
        "unsupported_upstream": 8,
        "credential_dependent": 7,
        "backing_service_dependent": 10,
        "unsafe_to_execute_unsandboxed": 31,
    }
    assert all(row["live_credentials_allowed"] is False for row in inventory["entries"])
    assert all(row["broad_egress_allowed"] is False for row in inventory["entries"])


def test_policy_masking_must_match_operator_masking(tmp_path: Path) -> None:
    masked = tmp_path / "masked.json"
    masked.write_text("[]\n", encoding="utf-8")

    with pytest.raises(GradeRefreshError, match="masking does not match"):
        catalog_inventory(seed_path=SEED, masked_path=masked, policy_path=POLICY)


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

    assert receipt["status"] == "READY"
    assert receipt["safe_to_execute_catalog"] is True
    assert not receipt["reasons"]
    assert all(
        row["image_id"] == image_id and row["sandbox_controls"]["all_required_controls"]
        for row in receipt["sandbox"]["image_bindings"]
    )


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


def test_triage_flags_upgrades_masks_and_unknown_policy_baseline(tmp_path: Path) -> None:
    candidate = tmp_path / "candidate"
    candidate.mkdir()
    (candidate / "MANIFEST.json").write_text(
        json.dumps({"candidate_state": "complete"}), encoding="utf-8"
    )
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
                        },
                    },
                    {"server_slug": "masked", "state": "masked", "drift": None},
                ]
            }
        ),
        encoding="utf-8",
    )
    preflight = {
        "status": "READY",
        "receipt_digest": "sha256:" + "1" * 64,
        "source_binding": {"worktree_state": "clean"},
        "catalog": {"policy_digest": "sha256:" + "2" * 64},
    }
    repeatability = {"status": "PASS", "receipt_digest": "sha256:" + "3" * 64}

    triage = triage_candidate(
        candidate=candidate, preflight=preflight, repeatability=repeatability
    )

    codes = {finding["code"] for finding in triage["findings"]}
    assert triage["review_required"] is True
    assert triage["publication_allowed"] is False
    assert {"suspicious_upgrade", "large_grade_change", "missing_comparable_provenance"} <= codes
    assert "masked_result_requires_review" in codes
    assert "baseline_policy_digest_unknown" in codes


def test_state_card_and_resume_capsule_keep_publication_waiting() -> None:
    preflight = {
        "safe_to_execute_catalog": False,
        "reasons": ["catalog_image_missing:x"],
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
        "High": 1,
        "Medium": 2,
        "Low": 0,
    }
    assert [finding["severity"] for finding in state["findings"]] == [
        "Critical",
        "High",
        "Medium",
        "Medium",
    ]
    assert state["scheduler_state"]["state"] == "DISABLED_UNLOADED"
    assert capsule["schema"] == "HumanGateResumeCapsuleV1"
    assert capsule["capsule"]["target"] == capsule["capsule"]["authorized_next_read"]["target"]
    assert capsule["observation"]["readback_status"] == "not_run"
    assert capsule["capsule"]["authority"]["boundary"].startswith("Read this Codex task")
