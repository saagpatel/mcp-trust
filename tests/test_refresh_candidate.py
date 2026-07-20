"""Approval-gated refresh-candidate workflow and honesty boundaries."""

from __future__ import annotations

import hashlib
import json
import os
import sqlite3
import subprocess
import sys
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest

from mcp_trust import refresh as refresh_module
from mcp_trust.core.models import (
    RiskSummary,
    ScanEvidence,
    ScanRecord,
    Server,
    ServerSource,
    SourceKind,
    ToolEvidence,
    TrustGrade,
)
from mcp_trust.engine.base import EngineResult
from mcp_trust.engine.stub import StubEngine
from mcp_trust.refresh import (
    RefreshCandidateError,
    _real_scan_mode,
    approve_refresh_candidate,
    create_refresh_candidate,
    preflight_real_refresh,
    publish_refresh_candidate,
    verified_masked_scan_slugs,
    verify_refresh_candidate,
)
from mcp_trust.store.db import connect, init_schema
from mcp_trust.store.repository import ScanRepository, ServerRepository
from scripts import refresh_candidate as refresh_cli

FIXED_NOW = datetime(2026, 7, 18, 8, 0, tzinfo=UTC)
ROOT = Path(__file__).resolve().parents[1]


def _server(slug: str) -> Server:
    return Server(
        slug=slug,
        name=slug,
        source=ServerSource(
            kind=SourceKind.NPM,
            reference=f"@example/{slug}",
            command=f"/opt/{slug}",
        ),
        added_at=FIXED_NOW,
    )


def _inputs(
    tmp_path: Path,
    *,
    slugs: tuple[str, ...] = ("alpha",),
    masked: tuple[str, ...] = (),
) -> tuple[Path, Path, Path]:
    db_path = tmp_path / "registry.db"
    conn = connect(db_path)
    init_schema(conn)
    servers = ServerRepository(conn)
    for slug in slugs:
        servers.upsert(_server(slug))
    conn.close()
    seed_path = tmp_path / "seed.json"
    seed_path.write_text(
        json.dumps(
            [
                {
                    "slug": slug,
                    "name": slug,
                    "source": {
                        "kind": "npm",
                        "reference": f"@example/{slug}",
                        "command": f"/opt/{slug}",
                    },
                }
                for slug in slugs
            ]
        ),
        encoding="utf-8",
    )
    masked_path = tmp_path / "masked.json"
    masked_path.write_text(json.dumps(list(masked)), encoding="utf-8")
    return db_path, seed_path, masked_path


def _stub_scanner(server: Server) -> EngineResult:
    return (
        StubEngine()
        .scan(server.source)
        .model_copy(
            update={
                "evidence": ScanEvidence(tools=[ToolEvidence(name="fixture-tool")]),
            }
        )
    )


def _candidate(
    tmp_path: Path,
    *,
    slugs: tuple[str, ...] = ("alpha",),
    masked: tuple[str, ...] = (),
    scanner=_stub_scanner,
    receipt_writer=None,
    now: datetime = FIXED_NOW,
) -> Path:
    db_path, seed_path, masked_path = _inputs(
        tmp_path,
        slugs=slugs,
        masked=masked,
    )
    return create_refresh_candidate(
        source_db=db_path,
        seed_path=seed_path,
        masked_path=masked_path,
        output_parent=tmp_path / "candidates",
        default_image="fixture:image",
        scanner=scanner,
        receipt_writer=receipt_writer,
        now=now,
        candidate_name="candidate",
    )


def _complete_remote_candidate(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    *,
    masked: tuple[str, ...] = (),
    slug: str = "alpha",
) -> tuple[Path, Path, Path]:
    db_path = tmp_path / "registry.db"
    remote = _server(slug).model_copy(
        update={
            "source": ServerSource(
                kind=SourceKind.REMOTE,
                reference="https://example.test/mcp",
            )
        }
    )
    conn = connect(db_path)
    init_schema(conn)
    ServerRepository(conn).upsert(remote)
    conn.close()
    seed_path = tmp_path / "seed.json"
    seed_path.write_text(
        json.dumps([remote.model_dump(mode="json", exclude={"added_at"})]),
        encoding="utf-8",
    )
    masked_path = tmp_path / "masked.json"
    masked_path.write_text(json.dumps(list(masked)), encoding="utf-8")

    class RemoteMCPAuditEngine:
        def __init__(self, timeout: float) -> None:
            assert timeout == 90.0

        def scan(self, source: ServerSource) -> EngineResult:
            assert source == remote.source
            return _stub_scanner(remote).model_copy(
                update={
                    "engine_name": "mcpaudit",
                    "engine_version": "2.4.0",
                    "sandbox_image": None,
                }
            )

    monkeypatch.setattr(
        "mcp_trust.refresh.preflight_real_refresh",
        lambda servers, *, default_image: {
            "docker_daemon": "not_required",
            "profiles": [],
            "remote_transport_count": len(servers),
        },
    )
    monkeypatch.setattr("mcp_trust.refresh.MCPAuditEngine", RemoteMCPAuditEngine)
    candidate = create_refresh_candidate(
        source_db=db_path,
        seed_path=seed_path,
        masked_path=masked_path,
        output_parent=tmp_path / "candidates",
        default_image="not-needed:image",
        now=FIXED_NOW,
        candidate_name="candidate",
    )
    return candidate, seed_path, masked_path


def _results(candidate: Path) -> list[dict[str, object]]:
    return json.loads((candidate / "scan_results.json").read_text())["results"]


def test_verified_masked_scan_slugs_exposes_only_success_claim(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    candidate, seed_path, masked_path = _complete_remote_candidate(
        tmp_path,
        monkeypatch,
        masked=("alpha",),
    )

    assert verified_masked_scan_slugs(
        candidate,
        seed_path=seed_path,
        masked_path=masked_path,
        now=FIXED_NOW,
    ) == frozenset({"alpha"})


def test_verified_masked_scan_slugs_rejects_stale_candidate(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    candidate, seed_path, masked_path = _complete_remote_candidate(
        tmp_path,
        monkeypatch,
        masked=("alpha",),
    )

    with pytest.raises(RefreshCandidateError, match="complete, current, publishable"):
        verified_masked_scan_slugs(
            candidate,
            seed_path=seed_path,
            masked_path=masked_path,
            now=FIXED_NOW + timedelta(hours=25),
        )


def test_verified_masked_scan_slugs_uses_the_verified_candidate_snapshot(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    first_root = tmp_path / "first"
    second_root = tmp_path / "second"
    first_root.mkdir()
    second_root.mkdir()
    candidate, seed_path, masked_path = _complete_remote_candidate(
        first_root,
        monkeypatch,
        masked=("alpha",),
        slug="alpha",
    )
    replacement, _replacement_seed, _replacement_mask = _complete_remote_candidate(
        second_root,
        monkeypatch,
        masked=("beta",),
        slug="beta",
    )
    real_verify = verify_refresh_candidate

    def verify_then_swap(*args, **kwargs):
        verification = real_verify(*args, **kwargs)
        parked = tmp_path / "parked-candidate"
        candidate.parent.chmod(0o700)
        replacement.parent.chmod(0o700)
        candidate.chmod(0o700)
        replacement.chmod(0o700)
        candidate.rename(parked)
        replacement.rename(candidate)
        parked.rename(replacement)
        return verification

    monkeypatch.setattr(
        "mcp_trust.refresh.verify_refresh_candidate",
        verify_then_swap,
    )

    assert verified_masked_scan_slugs(
        candidate,
        seed_path=seed_path,
        masked_path=masked_path,
        now=FIXED_NOW,
    ) == frozenset({"alpha"})


def test_candidate_replacement_during_verification_fails_closed(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    first_root = tmp_path / "first"
    second_root = tmp_path / "second"
    first_root.mkdir()
    second_root.mkdir()
    candidate = _candidate(first_root)
    replacement = _candidate(second_root)
    real_captured_json = refresh_module._captured_json
    swapped = False

    def capture_then_swap(snapshot, relative):
        nonlocal swapped
        payload = real_captured_json(snapshot, relative)
        if not swapped:
            swapped = True
            parked = tmp_path / "parked-candidate"
            candidate.parent.chmod(0o700)
            replacement.parent.chmod(0o700)
            candidate.chmod(0o700)
            replacement.chmod(0o700)
            candidate.rename(parked)
            replacement.rename(candidate)
            parked.rename(replacement)
        return payload

    monkeypatch.setattr(refresh_module, "_captured_json", capture_then_swap)

    verification = verify_refresh_candidate(candidate, now=FIXED_NOW)

    assert verification["structural_valid"] is False
    assert verification["publication_ready"] is False
    assert "candidate_changed_during_verification" in verification["errors"]


def _rebind_manifest_time(candidate: Path, created_at: datetime) -> None:
    manifest_path = candidate / "MANIFEST.json"
    digest_path = candidate / "MANIFEST.sha256"
    candidate.chmod(0o700)
    manifest_path.chmod(0o600)
    digest_path.chmod(0o600)
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    manifest["created_at"] = created_at.isoformat()
    manifest["expires_at"] = (created_at + timedelta(hours=24)).isoformat()
    manifest_path.write_text(json.dumps(manifest), encoding="utf-8")
    digest_path.write_text(
        hashlib.sha256(manifest_path.read_bytes()).hexdigest() + "\n",
        encoding="utf-8",
    )
    manifest_path.chmod(0o400)
    digest_path.chmod(0o400)
    candidate.chmod(0o500)


def _rebind_candidate_artifacts(candidate: Path, *artifact_names: str) -> None:
    manifest_path = candidate / "MANIFEST.json"
    digest_path = candidate / "MANIFEST.sha256"
    candidate.chmod(0o700)
    manifest_path.chmod(0o600)
    digest_path.chmod(0o600)
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    selected = set(artifact_names)
    for artifact in manifest["artifacts"]:
        if artifact["path"] not in selected:
            continue
        artifact_path = candidate / artifact["path"]
        artifact["bytes"] = artifact_path.stat().st_size
        artifact["sha256"] = hashlib.sha256(artifact_path.read_bytes()).hexdigest()
        artifact_path.chmod(0o400)
    manifest_path.write_text(json.dumps(manifest), encoding="utf-8")
    digest_path.write_text(
        hashlib.sha256(manifest_path.read_bytes()).hexdigest() + "\n",
        encoding="utf-8",
    )
    manifest_path.chmod(0o400)
    digest_path.chmod(0o400)
    candidate.chmod(0o500)


def _rebind_manifest(candidate: Path, **updates: object) -> None:
    manifest_path = candidate / "MANIFEST.json"
    digest_path = candidate / "MANIFEST.sha256"
    candidate.chmod(0o700)
    manifest_path.chmod(0o600)
    digest_path.chmod(0o600)
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    manifest.update(updates)
    manifest_path.write_text(json.dumps(manifest), encoding="utf-8")
    digest_path.write_text(
        hashlib.sha256(manifest_path.read_bytes()).hexdigest() + "\n",
        encoding="utf-8",
    )
    manifest_path.chmod(0o400)
    digest_path.chmod(0o400)
    candidate.chmod(0o500)


def test_deterministic_fixture_candidate_is_immutable_and_reviewable(
    tmp_path: Path,
) -> None:
    candidate = _candidate(tmp_path)

    verification = verify_refresh_candidate(candidate, now=FIXED_NOW)
    manifest = json.loads((candidate / "MANIFEST.json").read_text())

    assert verification["structural_valid"] is True
    assert verification["state"] == "fixture"
    assert verification["publication_ready"] is False
    assert manifest["scan_mode"] == "deterministic-fixture"
    assert manifest["authority"] == {
        "candidate_creation": True,
        "publication": False,
        "deployment": False,
        "schedule_change": False,
    }
    assert _results(candidate)[0]["state"] == "fresh"
    assert (candidate / "MANIFEST.json").stat().st_mode & 0o222 == 0
    assert candidate.stat().st_mode & 0o222 == 0


def test_empty_reviewed_catalog_is_refused_before_candidate_creation(
    tmp_path: Path,
) -> None:
    db_path, seed_path, masked_path = _inputs(tmp_path, slugs=())

    with pytest.raises(RefreshCandidateError, match="at least one server"):
        create_refresh_candidate(
            source_db=db_path,
            seed_path=seed_path,
            masked_path=masked_path,
            output_parent=tmp_path / "candidates",
            default_image="fixture:image",
            scanner=_stub_scanner,
            now=FIXED_NOW,
            candidate_name="candidate",
        )


def test_legacy_empty_candidate_is_rejected_by_verifier(tmp_path: Path) -> None:
    candidate = _candidate(tmp_path)
    results_path = candidate / "scan_results.json"
    catalog_path = candidate / "catalog_identity.json"
    snapshot_path = candidate / "static_snapshot.json"
    candidate.chmod(0o700)
    for path in (results_path, catalog_path, snapshot_path):
        path.chmod(0o600)
    results = json.loads(results_path.read_text(encoding="utf-8"))
    results["results"] = []
    results_path.write_text(json.dumps(results), encoding="utf-8")
    catalog = json.loads(catalog_path.read_text(encoding="utf-8"))
    catalog["server_count"] = 0
    catalog["servers"] = []
    catalog_path.write_text(json.dumps(catalog), encoding="utf-8")
    snapshot = json.loads(snapshot_path.read_text(encoding="utf-8"))
    snapshot["server_count"] = 0
    snapshot["servers"] = []
    snapshot["generated_from_scan_at"] = ""
    snapshot_path.write_text(json.dumps(snapshot), encoding="utf-8")
    _rebind_candidate_artifacts(
        candidate,
        "scan_results.json",
        "catalog_identity.json",
        "static_snapshot.json",
    )
    _rebind_manifest(
        candidate,
        catalog={
            "seed_sha256": catalog["seed_sha256"],
            "server_count": 0,
        },
        scan_counts={"total": 0, "fresh": 0, "masked": 0, "failed": 0},
    )

    verification = verify_refresh_candidate(candidate, now=FIXED_NOW)

    assert verification["structural_valid"] is False
    assert verification["publication_ready"] is False
    assert "empty_candidate" in verification["errors"]


def test_real_scan_mode_describes_local_remote_and_mixed_transports() -> None:
    assert _real_scan_mode(local_count=2, total_count=2) == "mcpaudit-local-network-off"
    assert _real_scan_mode(local_count=0, total_count=2) == "mcpaudit-remote-live-network"
    assert _real_scan_mode(local_count=1, total_count=2) == "mcpaudit-mixed-transport"


def test_legacy_refresh_entrypoint_only_creates_a_candidate() -> None:
    script = (ROOT / "scripts/refresh_and_publish.sh").read_text(encoding="utf-8")

    assert "refresh_candidate.py create" in script
    assert "uv run --frozen --extra engine" in script
    assert "mcp-trust scan" not in script
    assert "build_site.py" not in script
    assert "deploy_production" not in script
    assert "vercel deploy" not in script


def test_create_cli_returns_failure_for_partial_candidate(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    candidate = tmp_path / "partial"
    monkeypatch.setattr(
        refresh_cli,
        "create_refresh_candidate",
        lambda **_kwargs: candidate,
    )
    monkeypatch.setattr(
        refresh_cli,
        "verify_refresh_candidate",
        lambda *_args, **_kwargs: {
            "structural_valid": True,
            "candidate_state": "partial",
            "publication_ready": False,
            "errors": [],
        },
    )

    result = refresh_cli.main(["create"])
    output = json.loads(capsys.readouterr().out)

    assert result == 1
    assert output["candidate_state"] == "partial"
    assert output["publication_ready"] is False
    assert output["deployment_performed"] is False


def test_verify_cli_returns_failure_when_candidate_is_not_publication_ready(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    monkeypatch.setattr(
        refresh_cli,
        "verify_refresh_candidate",
        lambda *_args, **_kwargs: {
            "structural_valid": True,
            "state": "stale",
            "candidate_state": "complete",
            "publication_ready": False,
            "manifest_sha256": "a" * 64,
            "age_hours": 24.0,
            "scan_counts": {"total": 1, "fresh": 1, "masked": 0, "failed": 0},
            "reviewed_inputs_bound": True,
            "errors": [],
        },
    )

    result = refresh_cli.main(["verify", str(tmp_path / "candidate")])
    output = json.loads(capsys.readouterr().out)

    assert result == 1
    assert output["structural_valid"] is True
    assert output["state"] == "stale"
    assert output["publication_ready"] is False


def test_unknown_masked_slug_refuses_before_scanning(tmp_path: Path) -> None:
    db_path, seed_path, masked_path = _inputs(
        tmp_path,
        masked=("alpah",),
    )
    scanned: list[str] = []

    def scanner(server: Server) -> EngineResult:
        scanned.append(server.slug)
        return _stub_scanner(server)

    with pytest.raises(
        RefreshCandidateError,
        match="masked grade list contains unknown catalog slug.*alpah",
    ):
        create_refresh_candidate(
            source_db=db_path,
            seed_path=seed_path,
            masked_path=masked_path,
            output_parent=tmp_path / "candidates",
            default_image="fixture:image",
            scanner=scanner,
            now=FIXED_NOW,
            candidate_name="candidate",
        )

    assert scanned == []


@pytest.mark.parametrize(
    ("field", "value"),
    (
        ("command", "/opt/reviewed-alpha"),
        ("reference", "@example/reviewed-alpha"),
        ("env_keys", ["REVIEWED_TOKEN"]),
        ("sandbox_image", "reviewed:image"),
    ),
)
def test_seed_source_metadata_mismatch_refuses_before_scanning(
    tmp_path: Path,
    field: str,
    value: object,
) -> None:
    db_path, seed_path, masked_path = _inputs(tmp_path)
    seed = json.loads(seed_path.read_text(encoding="utf-8"))
    seed[0]["source"][field] = value
    seed_path.write_text(json.dumps(seed), encoding="utf-8")
    scanned: list[str] = []

    def scanner(server: Server) -> EngineResult:
        scanned.append(server.slug)
        return _stub_scanner(server)

    with pytest.raises(
        RefreshCandidateError,
        match="registry DB server metadata differs from reviewed catalog: alpha",
    ):
        create_refresh_candidate(
            source_db=db_path,
            seed_path=seed_path,
            masked_path=masked_path,
            output_parent=tmp_path / "candidates",
            default_image="fixture:image",
            scanner=scanner,
            now=FIXED_NOW,
            candidate_name="candidate",
        )

    assert scanned == []


def test_candidate_supports_sqlite_uri_characters_in_source_path(
    tmp_path: Path,
) -> None:
    db_path, seed_path, masked_path = _inputs(tmp_path)
    special_db = tmp_path / "registry#operator?.db"
    db_path.rename(special_db)

    candidate = create_refresh_candidate(
        source_db=special_db,
        seed_path=seed_path,
        masked_path=masked_path,
        output_parent=tmp_path / "candidates",
        default_image="fixture:image",
        scanner=_stub_scanner,
        now=FIXED_NOW,
        candidate_name="candidate",
    )

    assert verify_refresh_candidate(candidate, now=FIXED_NOW)["structural_valid"] is True


def test_manifest_tampering_fails_content_verification(tmp_path: Path) -> None:
    candidate = _candidate(tmp_path)
    manifest = candidate / "MANIFEST.json"
    os.chmod(candidate, 0o700)
    os.chmod(manifest, 0o600)
    payload = json.loads(manifest.read_text())
    payload["publication_allowed"] = True
    manifest.write_text(json.dumps(payload), encoding="utf-8")
    os.chmod(manifest, 0o400)
    os.chmod(candidate, 0o500)

    verification = verify_refresh_candidate(
        candidate,
        now=FIXED_NOW,
        expected_seed_path=tmp_path / "seed.json",
        expected_masked_path=tmp_path / "masked.json",
    )

    assert verification["structural_valid"] is False
    assert "manifest_digest_mismatch" in verification["errors"]


def test_duplicate_json_keys_are_rejected_as_ambiguous(tmp_path: Path) -> None:
    candidate = _candidate(tmp_path)
    manifest_path = candidate / "MANIFEST.json"
    digest_path = candidate / "MANIFEST.sha256"
    candidate.chmod(0o700)
    manifest_path.chmod(0o600)
    digest_path.chmod(0o600)
    manifest_text = manifest_path.read_text(encoding="utf-8").strip()
    ambiguous = manifest_text[:-1] + ',"candidate_state":"complete"}'
    manifest_path.write_text(ambiguous, encoding="utf-8")
    digest_path.write_text(
        hashlib.sha256(manifest_path.read_bytes()).hexdigest() + "\n",
        encoding="utf-8",
    )
    manifest_path.chmod(0o400)
    digest_path.chmod(0o400)
    candidate.chmod(0o500)

    verification = verify_refresh_candidate(candidate, now=FIXED_NOW)

    assert verification["structural_valid"] is False
    assert verification["publication_ready"] is False
    assert "manifest_unreadable" in verification["errors"]


def test_unreadable_manifest_returns_structured_invalid_result(
    tmp_path: Path,
) -> None:
    candidate = _candidate(tmp_path)
    manifest_path = candidate / "MANIFEST.json"
    manifest_path.chmod(0o000)

    verification = verify_refresh_candidate(
        candidate,
        now=FIXED_NOW,
        expected_seed_path=tmp_path / "seed.json",
        expected_masked_path=tmp_path / "masked.json",
    )

    assert verification["structural_valid"] is False
    assert verification["publication_ready"] is False
    assert "manifest_unreadable" in verification["errors"]
    assert "manifest_digest_mismatch" in verification["errors"]


def test_invalid_masking_manifest_fails_closed_with_reviewed_inputs(
    tmp_path: Path,
) -> None:
    candidate = _candidate(tmp_path)
    manifest_path = candidate / "MANIFEST.json"
    digest_path = candidate / "MANIFEST.sha256"
    candidate.chmod(0o700)
    manifest_path.chmod(0o600)
    digest_path.chmod(0o600)
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    manifest["masking"] = []
    manifest_path.write_text(json.dumps(manifest), encoding="utf-8")
    digest_path.write_text(
        hashlib.sha256(manifest_path.read_bytes()).hexdigest() + "\n",
        encoding="utf-8",
    )
    manifest_path.chmod(0o400)
    digest_path.chmod(0o400)
    candidate.chmod(0o500)

    verification = verify_refresh_candidate(
        candidate,
        now=FIXED_NOW,
        expected_seed_path=tmp_path / "seed.json",
        expected_masked_path=tmp_path / "masked.json",
    )

    assert verification["structural_valid"] is False
    assert verification["publication_ready"] is False
    assert "masking_manifest_invalid" in verification["errors"]
    assert "reviewed_inputs_mismatch" in verification["errors"]


def test_rebound_manifest_cannot_relabel_fixture_as_publishable(
    tmp_path: Path,
) -> None:
    candidate = _candidate(tmp_path)
    manifest_path = candidate / "MANIFEST.json"
    digest_path = candidate / "MANIFEST.sha256"
    os.chmod(candidate, 0o700)
    os.chmod(manifest_path, 0o600)
    os.chmod(digest_path, 0o600)
    manifest = json.loads(manifest_path.read_text())
    manifest["candidate_state"] = "complete"
    manifest["scan_mode"] = "mcpaudit-local-network-off"
    manifest["publication_allowed"] = True
    manifest_path.write_text(json.dumps(manifest), encoding="utf-8")
    digest_path.write_text(
        hashlib.sha256(manifest_path.read_bytes()).hexdigest() + "\n",
        encoding="utf-8",
    )
    os.chmod(manifest_path, 0o400)
    os.chmod(digest_path, 0o400)
    os.chmod(candidate, 0o500)

    verification = verify_refresh_candidate(candidate, now=FIXED_NOW)

    assert verification["structural_valid"] is False
    assert verification["publication_ready"] is False
    assert any("publishable_scan_provenance_invalid" in error for error in verification["errors"])


def test_candidate_state_is_closed_to_known_values(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    candidate, seed_path, masked_path = _complete_remote_candidate(tmp_path, monkeypatch)
    _rebind_manifest(
        candidate,
        candidate_state="approved",
        publication_allowed=False,
    )

    verification = verify_refresh_candidate(
        candidate,
        now=FIXED_NOW,
        expected_seed_path=seed_path,
        expected_masked_path=masked_path,
    )

    assert verification["structural_valid"] is False
    assert verification["publication_ready"] is False
    assert verification["state"] == "invalid"
    assert "candidate_state_invalid" in verification["errors"]


def test_bidi_control_in_candidate_json_is_rejected_without_echo(
    tmp_path: Path,
) -> None:
    candidate = _candidate(tmp_path)
    _rebind_manifest(candidate, scan_mode="fixture\u202eapproved")

    verification = verify_refresh_candidate(candidate, now=FIXED_NOW)
    rendered = json.dumps(verification, ensure_ascii=False)

    assert verification["structural_valid"] is False
    assert verification["publication_ready"] is False
    assert "manifest_unreadable" in verification["errors"]
    assert "\u202e" not in rendered


def test_stale_candidate_is_not_publication_ready(tmp_path: Path) -> None:
    candidate = _candidate(tmp_path)

    verification = verify_refresh_candidate(
        candidate,
        now=FIXED_NOW + timedelta(hours=25),
    )

    assert verification["structural_valid"] is True
    assert verification["state"] == "stale"
    assert verification["publication_ready"] is False


def test_exact_expiry_boundary_is_stale(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    candidate, seed_path, masked_path = _complete_remote_candidate(tmp_path, monkeypatch)

    verification = verify_refresh_candidate(
        candidate,
        now=FIXED_NOW + timedelta(hours=24),
        expected_seed_path=seed_path,
        expected_masked_path=masked_path,
    )

    assert verification["structural_valid"] is True
    assert verification["state"] == "stale"
    assert verification["publication_ready"] is False


@pytest.mark.parametrize(
    ("expires_at", "expected_error"),
    [
        ("not-a-timestamp", "candidate_expiry_invalid"),
        (
            (FIXED_NOW + timedelta(hours=1)).isoformat(),
            "candidate_expiry_mismatch",
        ),
    ],
)
def test_invalid_or_mismatched_expiry_fails_closed(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    expires_at: str,
    expected_error: str,
) -> None:
    candidate, seed_path, masked_path = _complete_remote_candidate(tmp_path, monkeypatch)
    _rebind_manifest(candidate, expires_at=expires_at)

    verification = verify_refresh_candidate(
        candidate,
        now=FIXED_NOW,
        expected_seed_path=seed_path,
        expected_masked_path=masked_path,
    )

    assert verification["structural_valid"] is False
    assert verification["publication_ready"] is False
    assert expected_error in verification["errors"]


def test_timestamp_near_datetime_limit_returns_structured_expiry_failure(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    candidate, seed_path, masked_path = _complete_remote_candidate(tmp_path, monkeypatch)
    _rebind_manifest(
        candidate,
        created_at="9999-12-31T23:00:00+00:00",
        expires_at="9999-12-31T23:59:59+00:00",
    )

    verification = verify_refresh_candidate(
        candidate,
        now=FIXED_NOW,
        expected_seed_path=seed_path,
        expected_masked_path=masked_path,
    )

    assert verification["structural_valid"] is False
    assert verification["publication_ready"] is False
    assert "candidate_expiry_invalid" in verification["errors"]


@pytest.mark.parametrize(
    ("field", "expected_error"),
    [
        ("created_at", "candidate_timestamp_invalid"),
        ("expires_at", "candidate_expiry_invalid"),
    ],
)
def test_extreme_timezone_offset_returns_structured_timestamp_failure(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    field: str,
    expected_error: str,
) -> None:
    candidate, seed_path, masked_path = _complete_remote_candidate(tmp_path, monkeypatch)
    _rebind_manifest(candidate, **{field: "0001-01-01T00:00:00+23:59"})

    verification = verify_refresh_candidate(
        candidate,
        now=FIXED_NOW,
        expected_seed_path=seed_path,
        expected_masked_path=masked_path,
    )

    assert verification["structural_valid"] is False
    assert verification["publication_ready"] is False
    assert expected_error in verification["errors"]


def test_future_dated_complete_candidate_is_not_publication_ready(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    candidate, seed_path, masked_path = _complete_remote_candidate(
        tmp_path,
        monkeypatch,
    )
    _rebind_manifest_time(candidate, FIXED_NOW + timedelta(hours=1))

    verification = verify_refresh_candidate(
        candidate,
        now=FIXED_NOW,
        expected_seed_path=seed_path,
        expected_masked_path=masked_path,
    )

    assert verification["structural_valid"] is False
    assert verification["publication_ready"] is False
    assert "candidate_timestamp_in_future" in verification["errors"]


def test_fresh_manifest_cannot_replay_stale_complete_scans(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    candidate, seed_path, masked_path = _complete_remote_candidate(
        tmp_path,
        monkeypatch,
    )
    rebound_now = FIXED_NOW + timedelta(hours=48)
    _rebind_manifest_time(candidate, rebound_now)

    verification = verify_refresh_candidate(
        candidate,
        now=rebound_now,
        expected_seed_path=seed_path,
        expected_masked_path=masked_path,
    )

    assert verification["age_hours"] == 0.0
    assert verification["structural_valid"] is False
    assert verification["publication_ready"] is False
    assert "scan_timestamp_stale:alpha" in verification["errors"]
    assert "scan_age_mismatch:alpha" in verification["errors"]


def test_partial_scan_failure_never_retains_old_grade_as_fresh(tmp_path: Path) -> None:
    def scanner(server: Server) -> EngineResult:
        if server.slug == "beta":
            raise RuntimeError("fixture failure")
        return _stub_scanner(server)

    candidate = _candidate(tmp_path, slugs=("alpha", "beta"), scanner=scanner)
    by_slug = {row["server_slug"]: row for row in _results(candidate)}

    assert by_slug["alpha"]["state"] == "fresh"
    assert by_slug["beta"]["state"] == "scan-failed"
    assert by_slug["beta"]["fresh_grade"] is None
    assert by_slug["beta"]["error_type"] == "RuntimeError"
    assert "fixture failure" not in json.dumps(by_slug["beta"])


def test_masked_real_scan_failure_is_a_valid_nonpublishable_partial_candidate(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    db_path, seed_path, masked_path = _inputs(tmp_path, masked=("alpha",))

    class FailingMCPAuditEngine:
        def __init__(self, timeout: float) -> None:
            assert timeout == 90.0

        def scan(self, source: ServerSource) -> EngineResult:
            raise RuntimeError(f"controlled failure for {source.reference}")

    monkeypatch.setattr(
        "mcp_trust.refresh.preflight_real_refresh",
        lambda servers, *, default_image: {
            "docker_daemon": "available",
            "profiles": [refresh_module._sandbox_profile(default_image)],
            "remote_transport_count": 0,
        },
    )
    monkeypatch.setattr("mcp_trust.refresh.MCPAuditEngine", FailingMCPAuditEngine)

    candidate = create_refresh_candidate(
        source_db=db_path,
        seed_path=seed_path,
        masked_path=masked_path,
        output_parent=tmp_path / "candidates",
        default_image="required:image",
        now=FIXED_NOW,
        candidate_name="candidate",
    )
    verification = verify_refresh_candidate(
        candidate,
        now=FIXED_NOW,
        expected_seed_path=seed_path,
        expected_masked_path=masked_path,
    )

    assert _results(candidate)[0]["state"] == "scan-failed"
    assert verification["structural_valid"] is True
    assert verification["state"] == "partial"
    assert verification["publication_ready"] is False
    assert verification["errors"] == []


def test_failed_rescan_excludes_the_previous_grade_from_static_snapshot(
    tmp_path: Path,
) -> None:
    db_path, seed_path, masked_path = _inputs(tmp_path, slugs=("alpha", "beta"))
    conn = connect(db_path)
    ScanRepository(conn).record(
        ScanRecord(
            id="old-beta",
            server_slug="beta",
            engine_name="mcpaudit",
            engine_version="2.3.0",
            grade=TrustGrade.D,
            risk=RiskSummary(composite=6.0),
            evidence=ScanEvidence(tools=[ToolEvidence(name="fixture-tool")]),
            scanned_at=FIXED_NOW - timedelta(days=30),
        )
    )
    conn.close()

    def scanner(server: Server) -> EngineResult:
        if server.slug == "beta":
            raise RuntimeError("fixture failure")
        return _stub_scanner(server)

    candidate = create_refresh_candidate(
        source_db=db_path,
        seed_path=seed_path,
        masked_path=masked_path,
        output_parent=tmp_path / "candidates",
        default_image="fixture:image",
        scanner=scanner,
        now=FIXED_NOW,
        candidate_name="candidate",
    )
    snapshot = json.loads((candidate / "static_snapshot.json").read_text())

    assert "beta" not in {server["slug"] for server in snapshot["servers"]}
    beta = next(row for row in _results(candidate) if row["server_slug"] == "beta")
    assert beta["fresh_grade"] is None
    assert beta["previous_grade"] == "D"
    assert beta["previous_scan_age_days"] == 30.0


def test_candidate_reuses_grade_drift_attribution(tmp_path: Path) -> None:
    db_path, seed_path, masked_path = _inputs(tmp_path)
    conn = connect(db_path)
    ScanRepository(conn).record(
        ScanRecord(
            id="old-alpha",
            server_slug="alpha",
            engine_name="mcpaudit",
            engine_version="2.3.0",
            grade=TrustGrade.D,
            risk=RiskSummary(composite=6.0),
            evidence=ScanEvidence(tools=[ToolEvidence(name="fixture-tool")]),
            scanned_at=FIXED_NOW - timedelta(days=7),
        )
    )
    conn.close()

    candidate = create_refresh_candidate(
        source_db=db_path,
        seed_path=seed_path,
        masked_path=masked_path,
        output_parent=tmp_path / "candidates",
        default_image="fixture:image",
        scanner=_stub_scanner,
        now=FIXED_NOW,
        candidate_name="candidate",
    )
    result = _results(candidate)[0]

    assert result["drift"]["cause"] == "engine-changed"
    assert result["drift"]["surface_comparison"] == "unchanged"
    assert "engine change" in result["drift"]["summary"]


def test_rebound_manifest_cannot_invent_drift(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    candidate, seed_path, masked_path = _complete_remote_candidate(tmp_path, monkeypatch)
    results_path = candidate / "scan_results.json"
    candidate.chmod(0o700)
    results_path.chmod(0o600)
    payload = json.loads(results_path.read_text(encoding="utf-8"))
    payload["results"][0]["drift"] = {
        "cause": "surface-changed",
        "surface_comparison": "changed",
        "summary": "attacker-authored decision evidence",
        "previous_grade": "A",
        "current_grade": "F",
    }
    results_path.write_text(json.dumps(payload), encoding="utf-8")
    _rebind_candidate_artifacts(candidate, "scan_results.json")

    verification = verify_refresh_candidate(
        candidate,
        now=FIXED_NOW,
        expected_seed_path=seed_path,
        expected_masked_path=masked_path,
    )

    assert verification["structural_valid"] is False
    assert verification["publication_ready"] is False
    assert any(
        error.startswith("fresh_scan_drift_mismatch:")
        for error in verification["errors"]
    )


def test_rebound_receipt_cannot_add_authoritative_claims(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    candidate, seed_path, masked_path = _complete_remote_candidate(tmp_path, monkeypatch)
    result = _results(candidate)[0]
    receipt_path = candidate / "receipts" / str(result["receipt"])
    candidate.chmod(0o700)
    receipt_path.chmod(0o600)
    receipt = json.loads(receipt_path.read_text(encoding="utf-8"))
    receipt["publication_ready"] = True
    receipt["approval"] = {"approval_ref": "attacker-authored"}
    receipt_path.write_text(json.dumps(receipt), encoding="utf-8")
    _rebind_candidate_artifacts(candidate, f"receipts/{receipt_path.name}")

    verification = verify_refresh_candidate(
        candidate,
        now=FIXED_NOW,
        expected_seed_path=seed_path,
        expected_masked_path=masked_path,
    )

    assert verification["structural_valid"] is False
    assert verification["publication_ready"] is False
    assert any(
        error.startswith("successful_scan_receipt_schema_invalid:")
        for error in verification["errors"]
    )


def test_receipt_cannot_assert_unverified_scanner_revision(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    candidate, seed_path, masked_path = _complete_remote_candidate(tmp_path, monkeypatch)
    result = _results(candidate)[0]
    receipt_path = candidate / "receipts" / str(result["receipt"])
    candidate.chmod(0o700)
    receipt_path.chmod(0o600)
    receipt = json.loads(receipt_path.read_text(encoding="utf-8"))
    receipt["scanner"]["scanner_git_ref"] = "attacker-claimed-revision"
    receipt_path.write_text(json.dumps(receipt), encoding="utf-8")
    _rebind_candidate_artifacts(candidate, f"receipts/{receipt_path.name}")

    verification = verify_refresh_candidate(
        candidate,
        now=FIXED_NOW,
        expected_seed_path=seed_path,
        expected_masked_path=masked_path,
    )

    assert verification["structural_valid"] is False
    assert verification["publication_ready"] is False
    assert any(
        error.startswith("successful_scan_receipt_schema_invalid:")
        for error in verification["errors"]
    )


def test_successful_result_cannot_add_authority_fields(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    candidate, seed_path, masked_path = _complete_remote_candidate(tmp_path, monkeypatch)
    results_path = candidate / "scan_results.json"
    candidate.chmod(0o700)
    results_path.chmod(0o600)
    payload = json.loads(results_path.read_text(encoding="utf-8"))
    payload["results"][0]["publication_ready"] = True
    results_path.write_text(json.dumps(payload), encoding="utf-8")
    _rebind_candidate_artifacts(candidate, "scan_results.json")

    verification = verify_refresh_candidate(
        candidate,
        now=FIXED_NOW,
        expected_seed_path=seed_path,
        expected_masked_path=masked_path,
    )

    assert verification["structural_valid"] is False
    assert verification["publication_ready"] is False
    assert "successful_scan_schema_invalid:alpha" in verification["errors"]


def test_fresh_result_cannot_relabel_evidence_visibility(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    candidate, seed_path, masked_path = _complete_remote_candidate(tmp_path, monkeypatch)
    results_path = candidate / "scan_results.json"
    candidate.chmod(0o700)
    results_path.chmod(0o600)
    payload = json.loads(results_path.read_text(encoding="utf-8"))
    payload["results"][0]["receipt_visibility"] = "approved"
    results_path.write_text(json.dumps(payload), encoding="utf-8")
    _rebind_candidate_artifacts(candidate, "scan_results.json")

    verification = verify_refresh_candidate(
        candidate,
        now=FIXED_NOW,
        expected_seed_path=seed_path,
        expected_masked_path=masked_path,
    )

    assert verification["structural_valid"] is False
    assert verification["publication_ready"] is False
    assert "fresh_scan_semantics_invalid:alpha" in verification["errors"]


def test_receipt_caveats_cannot_claim_publication_authority(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    candidate, seed_path, masked_path = _complete_remote_candidate(tmp_path, monkeypatch)
    result = _results(candidate)[0]
    receipt_path = candidate / "receipts" / str(result["receipt"])
    candidate.chmod(0o700)
    receipt_path.chmod(0o600)
    receipt = json.loads(receipt_path.read_text(encoding="utf-8"))
    receipt["caveats"].append("Publication approved.")
    receipt_path.write_text(json.dumps(receipt), encoding="utf-8")
    _rebind_candidate_artifacts(candidate, f"receipts/{receipt_path.name}")

    verification = verify_refresh_candidate(
        candidate,
        now=FIXED_NOW,
        expected_seed_path=seed_path,
        expected_masked_path=masked_path,
    )

    assert verification["structural_valid"] is False
    assert verification["publication_ready"] is False
    assert any(
        error.startswith("fresh_scan_binding_mismatch:")
        for error in verification["errors"]
    )


def test_missing_receipt_is_explicit_and_not_fresh(tmp_path: Path) -> None:
    candidate = _candidate(
        tmp_path,
        receipt_writer=lambda _server, _scan, _directory: None,
    )

    result = _results(candidate)[0]
    assert result["state"] == "missing-receipt"
    assert result["fresh_grade"] is None


def test_unknown_evidence_is_explicit_and_not_fresh(tmp_path: Path) -> None:
    def scanner(_server: Server) -> EngineResult:
        return EngineResult(
            engine_name="stub",
            engine_version="fixture",
            risk=RiskSummary(composite=1.0),
            evidence=None,
        )

    candidate = _candidate(tmp_path, scanner=scanner)

    result = _results(candidate)[0]
    assert result["state"] == "unknown-evidence"
    assert result["fresh_grade"] is None


def test_masked_grade_is_withheld_from_results_and_snapshot(tmp_path: Path) -> None:
    db_path, seed_path, masked_path = _inputs(tmp_path, masked=("alpha",))
    masked_sentinel = "masked-secret-sentinel-8fd3c764"
    conn = connect(db_path)
    ScanRepository(conn).record(
        ScanRecord(
            id="old-alpha",
            server_slug="alpha",
            engine_name="mcpaudit",
            engine_version="2.3.0",
            grade=TrustGrade.D,
            risk=RiskSummary(composite=6.0),
            evidence=ScanEvidence(tools=[ToolEvidence(name=masked_sentinel)]),
            scanned_at=FIXED_NOW - timedelta(days=30),
        )
    )
    conn.close()
    candidate = create_refresh_candidate(
        source_db=db_path,
        seed_path=seed_path,
        masked_path=masked_path,
        output_parent=tmp_path / "candidates",
        default_image="fixture:image",
        scanner=_stub_scanner,
        now=FIXED_NOW,
        candidate_name="candidate",
    )

    result = _results(candidate)[0]
    snapshot = json.loads((candidate / "static_snapshot.json").read_text())
    candidate_conn = connect(candidate / "registry.db")
    masked_scan_count = candidate_conn.execute(
        "SELECT COUNT(*) FROM scans WHERE server_slug = 'alpha'"
    ).fetchone()[0]
    freelist_count = candidate_conn.execute("PRAGMA freelist_count").fetchone()[0]
    candidate_conn.close()
    assert result["state"] == "masked"
    assert result["fresh_grade"] is None
    assert result["grade_visibility"] == "withheld"
    assert result["receipt_visibility"] == "withheld"
    assert result["receipt"] is None
    assert result["scan_id"] is None
    assert result["drift"] is None
    assert list((candidate / "receipts").iterdir()) == []
    proof_ref = result["scan_proof"]
    assert isinstance(proof_ref, str)
    proof = json.loads((candidate / "masked-proofs" / proof_ref).read_text())
    assert proof["outcome"] == "scan_succeeded"
    assert proof["evidence_present"] is True
    assert "scan" not in proof
    assert "evidence" not in proof
    assert "danger_score" not in proof
    assert masked_sentinel not in json.dumps(proof)
    assert masked_scan_count == 0
    assert freelist_count == 0
    assert masked_sentinel.encode() not in (candidate / "registry.db").read_bytes()
    assert snapshot["servers"] == []


def test_rebound_masked_result_without_scan_proof_is_rejected(tmp_path: Path) -> None:
    candidate = _candidate(tmp_path, masked=("alpha",))
    results_path = candidate / "scan_results.json"
    manifest_path = candidate / "MANIFEST.json"
    digest_path = candidate / "MANIFEST.sha256"
    candidate.chmod(0o700)
    results_path.chmod(0o600)
    manifest_path.chmod(0o600)
    digest_path.chmod(0o600)
    results_payload = json.loads(results_path.read_text())
    results_payload["results"][0]["scan_proof"] = None
    results_path.write_text(json.dumps(results_payload), encoding="utf-8")
    manifest = json.loads(manifest_path.read_text())
    for artifact in manifest["artifacts"]:
        if artifact["path"] == "scan_results.json":
            artifact["bytes"] = results_path.stat().st_size
            artifact["sha256"] = hashlib.sha256(results_path.read_bytes()).hexdigest()
    manifest_path.write_text(json.dumps(manifest), encoding="utf-8")
    digest_path.write_text(
        hashlib.sha256(manifest_path.read_bytes()).hexdigest() + "\n",
        encoding="utf-8",
    )
    for path in (results_path, manifest_path, digest_path):
        path.chmod(0o400)
    candidate.chmod(0o500)

    verification = verify_refresh_candidate(candidate, now=FIXED_NOW)

    assert verification["structural_valid"] is False
    assert verification["publication_ready"] is False
    assert "masked_scan_proof_ref_invalid" in verification["errors"]


def test_rebound_manifest_cannot_omit_catalog_result(tmp_path: Path) -> None:
    candidate = _candidate(tmp_path, slugs=("alpha", "beta"))
    results_path = candidate / "scan_results.json"
    manifest_path = candidate / "MANIFEST.json"
    digest_path = candidate / "MANIFEST.sha256"
    os.chmod(candidate, 0o700)
    os.chmod(results_path, 0o600)
    os.chmod(manifest_path, 0o600)
    os.chmod(digest_path, 0o600)
    results_payload = json.loads(results_path.read_text())
    results_payload["results"] = results_payload["results"][:1]
    results_path.write_text(json.dumps(results_payload), encoding="utf-8")
    manifest = json.loads(manifest_path.read_text())
    for artifact in manifest["artifacts"]:
        if artifact["path"] == "scan_results.json":
            artifact["bytes"] = results_path.stat().st_size
            artifact["sha256"] = hashlib.sha256(results_path.read_bytes()).hexdigest()
    manifest["scan_counts"] = {
        "total": 1,
        "fresh": 1,
        "masked": 0,
        "failed": 0,
    }
    manifest_path.write_text(json.dumps(manifest), encoding="utf-8")
    digest_path.write_text(
        hashlib.sha256(manifest_path.read_bytes()).hexdigest() + "\n",
        encoding="utf-8",
    )
    for path in (results_path, manifest_path, digest_path):
        os.chmod(path, 0o400)
    os.chmod(candidate, 0o500)

    verification = verify_refresh_candidate(candidate, now=FIXED_NOW)

    assert verification["structural_valid"] is False
    assert verification["publication_ready"] is False
    assert "catalog_scan_coverage_mismatch" in verification["errors"]


def test_rebound_manifest_cannot_change_snapshot_grade(tmp_path: Path) -> None:
    candidate = _candidate(tmp_path)
    snapshot_path = candidate / "static_snapshot.json"
    manifest_path = candidate / "MANIFEST.json"
    digest_path = candidate / "MANIFEST.sha256"
    os.chmod(candidate, 0o700)
    os.chmod(snapshot_path, 0o600)
    os.chmod(manifest_path, 0o600)
    os.chmod(digest_path, 0o600)
    snapshot = json.loads(snapshot_path.read_text())
    snapshot["servers"] = [
        {
            "slug": "alpha",
            "grade": "A",
            "scan_age_days": 0.0,
        }
    ]
    snapshot["server_count"] = 1
    snapshot_path.write_text(json.dumps(snapshot), encoding="utf-8")
    manifest = json.loads(manifest_path.read_text())
    for artifact in manifest["artifacts"]:
        if artifact["path"] == "static_snapshot.json":
            artifact["bytes"] = snapshot_path.stat().st_size
            artifact["sha256"] = hashlib.sha256(snapshot_path.read_bytes()).hexdigest()
    manifest_path.write_text(json.dumps(manifest), encoding="utf-8")
    digest_path.write_text(
        hashlib.sha256(manifest_path.read_bytes()).hexdigest() + "\n",
        encoding="utf-8",
    )
    for path in (snapshot_path, manifest_path, digest_path):
        os.chmod(path, 0o400)
    os.chmod(candidate, 0o500)

    verification = verify_refresh_candidate(candidate, now=FIXED_NOW)

    assert verification["structural_valid"] is False
    assert verification["publication_ready"] is False
    assert "static_snapshot_scan_binding_mismatch" in verification["errors"]


def test_rebound_manifest_cannot_change_fresh_result_grade(tmp_path: Path) -> None:
    candidate = _candidate(tmp_path)
    results_path = candidate / "scan_results.json"
    manifest_path = candidate / "MANIFEST.json"
    digest_path = candidate / "MANIFEST.sha256"
    os.chmod(candidate, 0o700)
    os.chmod(results_path, 0o600)
    os.chmod(manifest_path, 0o600)
    os.chmod(digest_path, 0o600)
    results_payload = json.loads(results_path.read_text())
    results_payload["results"][0]["fresh_grade"] = "A"
    results_path.write_text(json.dumps(results_payload), encoding="utf-8")
    manifest = json.loads(manifest_path.read_text())
    for artifact in manifest["artifacts"]:
        if artifact["path"] == "scan_results.json":
            artifact["bytes"] = results_path.stat().st_size
            artifact["sha256"] = hashlib.sha256(results_path.read_bytes()).hexdigest()
    manifest_path.write_text(json.dumps(manifest), encoding="utf-8")
    digest_path.write_text(
        hashlib.sha256(manifest_path.read_bytes()).hexdigest() + "\n",
        encoding="utf-8",
    )
    for path in (results_path, manifest_path, digest_path):
        os.chmod(path, 0o400)
    os.chmod(candidate, 0o500)

    verification = verify_refresh_candidate(candidate, now=FIXED_NOW)

    assert verification["structural_valid"] is False
    assert any(error.startswith("fresh_scan_binding_mismatch:") for error in verification["errors"])


def test_rebound_manifest_rejects_unreferenced_artifact(tmp_path: Path) -> None:
    candidate = _candidate(tmp_path)
    extra = candidate / "receipts" / "masked-leak.json"
    manifest_path = candidate / "MANIFEST.json"
    digest_path = candidate / "MANIFEST.sha256"
    os.chmod(candidate, 0o700)
    os.chmod(extra.parent, 0o700)
    os.chmod(manifest_path, 0o600)
    os.chmod(digest_path, 0o600)
    extra.write_text('{"grade":"A"}\n', encoding="utf-8")
    manifest = json.loads(manifest_path.read_text())
    manifest["artifacts"].append(
        {
            "path": "receipts/masked-leak.json",
            "bytes": extra.stat().st_size,
            "sha256": hashlib.sha256(extra.read_bytes()).hexdigest(),
        }
    )
    manifest_path.write_text(json.dumps(manifest), encoding="utf-8")
    digest_path.write_text(
        hashlib.sha256(manifest_path.read_bytes()).hexdigest() + "\n",
        encoding="utf-8",
    )
    for path in (extra, manifest_path, digest_path):
        os.chmod(path, 0o400)
    os.chmod(extra.parent, 0o500)
    os.chmod(candidate, 0o500)

    verification = verify_refresh_candidate(candidate, now=FIXED_NOW)

    assert verification["structural_valid"] is False
    assert "unreferenced_candidate_artifact" in verification["errors"]


def test_nested_manifest_named_file_is_not_excluded_from_artifact_set(
    tmp_path: Path,
) -> None:
    candidate = _candidate(tmp_path)
    nested = candidate / "receipts" / "MANIFEST.json"
    os.chmod(candidate, 0o700)
    os.chmod(nested.parent, 0o700)
    nested.write_text('{"masked":"receipt"}\n', encoding="utf-8")
    nested.chmod(0o400)
    nested.parent.chmod(0o500)
    candidate.chmod(0o500)

    verification = verify_refresh_candidate(candidate, now=FIXED_NOW)

    assert verification["structural_valid"] is False
    assert "artifact_set_mismatch" in verification["errors"]
    assert "unreferenced_candidate_artifact" in verification["errors"]


def test_duplicate_artifact_manifest_entry_is_rejected(tmp_path: Path) -> None:
    candidate = _candidate(tmp_path)
    manifest = json.loads((candidate / "MANIFEST.json").read_text(encoding="utf-8"))
    manifest["artifacts"].append(dict(manifest["artifacts"][0]))
    _rebind_manifest(candidate, artifacts=manifest["artifacts"])

    verification = verify_refresh_candidate(candidate, now=FIXED_NOW)

    assert verification["structural_valid"] is False
    assert "artifact_manifest_invalid" in verification["errors"]


def test_boolean_scan_count_cannot_alias_integer_count(tmp_path: Path) -> None:
    candidate = _candidate(tmp_path)
    _rebind_manifest(
        candidate,
        scan_counts={
            "total": True,
            "fresh": True,
            "masked": False,
            "failed": False,
        },
    )

    verification = verify_refresh_candidate(candidate, now=FIXED_NOW)

    assert verification["structural_valid"] is False
    assert verification["scan_counts"] is None
    assert "scan_counts_invalid" in verification["errors"]


def test_hardlinked_candidate_artifact_is_rejected(tmp_path: Path) -> None:
    candidate = _candidate(tmp_path)
    results_path = candidate / "scan_results.json"
    external = tmp_path / "external-results.json"
    external.write_bytes(results_path.read_bytes())
    external.chmod(0o400)
    candidate.chmod(0o700)
    results_path.unlink()
    os.link(external, results_path)
    candidate.chmod(0o500)

    verification = verify_refresh_candidate(candidate, now=FIXED_NOW)

    assert verification["structural_valid"] is False
    assert verification["publication_ready"] is False
    assert "hardlinked_artifact:scan_results.json" in verification["errors"]


def test_oversized_candidate_json_returns_bounded_invalid_result(tmp_path: Path) -> None:
    candidate = _candidate(tmp_path)
    results_path = candidate / "scan_results.json"
    candidate.chmod(0o700)
    results_path.chmod(0o600)
    payload = json.loads(results_path.read_text(encoding="utf-8"))
    payload["padding"] = "x" * (17 * 1024 * 1024)
    results_path.write_text(json.dumps(payload), encoding="utf-8")
    _rebind_candidate_artifacts(candidate, "scan_results.json")

    verification = verify_refresh_candidate(candidate, now=FIXED_NOW)

    assert verification["structural_valid"] is False
    assert verification["publication_ready"] is False
    assert "artifact_too_large:scan_results.json" in verification["errors"]


def test_deeply_nested_json_returns_structured_invalid_result(tmp_path: Path) -> None:
    candidate = _candidate(tmp_path)
    results_path = candidate / "scan_results.json"
    candidate.chmod(0o700)
    results_path.chmod(0o600)
    results_path.write_text("[" * 10000 + "0" + "]" * 10000, encoding="utf-8")
    _rebind_candidate_artifacts(candidate, "scan_results.json")

    verification = verify_refresh_candidate(candidate, now=FIXED_NOW)

    assert verification["structural_valid"] is False
    assert verification["publication_ready"] is False
    assert "candidate_projection_unreadable" in verification["errors"]


def test_extreme_json_integer_returns_structured_invalid_result(tmp_path: Path) -> None:
    candidate = _candidate(tmp_path)
    results_path = candidate / "scan_results.json"
    candidate.chmod(0o700)
    results_path.chmod(0o600)
    results_path.write_text(
        '{"schema":"RefreshScanResultsV1","generated_at":"'
        + FIXED_NOW.isoformat()
        + '","results":[],"extreme":'
        + "9" * 5000
        + "}",
        encoding="utf-8",
    )
    _rebind_candidate_artifacts(candidate, "scan_results.json")

    previous_limit = sys.get_int_max_str_digits()
    sys.set_int_max_str_digits(0)
    try:
        verification = verify_refresh_candidate(candidate, now=FIXED_NOW)
    finally:
        sys.set_int_max_str_digits(previous_limit)

    assert verification["structural_valid"] is False
    assert verification["publication_ready"] is False
    assert "candidate_projection_unreadable" in verification["errors"]


def test_deeply_nested_database_json_returns_structured_invalid_result(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    candidate, seed_path, masked_path = _complete_remote_candidate(tmp_path, monkeypatch)
    database_path = candidate / "registry.db"
    candidate.chmod(0o700)
    database_path.chmod(0o600)
    conn = sqlite3.connect(database_path)
    conn.execute(
        "UPDATE scans SET risk_json = ?",
        ("[" * 10000 + "0" + "]" * 10000,),
    )
    conn.commit()
    conn.close()
    _rebind_candidate_artifacts(candidate, "registry.db")

    verification = verify_refresh_candidate(
        candidate,
        now=FIXED_NOW,
        expected_seed_path=seed_path,
        expected_masked_path=masked_path,
    )

    assert verification["structural_valid"] is False
    assert verification["publication_ready"] is False
    assert any(
        error.startswith("fresh_scan_")
        or error == "static_snapshot_scan_binding_unavailable"
        for error in verification["errors"]
    )


def test_unsafe_artifact_name_cannot_create_deceptive_output(tmp_path: Path) -> None:
    candidate = _candidate(tmp_path)
    unsafe_name = "evidence-\u202ejson"
    candidate.chmod(0o700)
    unsafe_path = candidate / unsafe_name
    unsafe_path.write_text("attacker-authored", encoding="utf-8")
    unsafe_path.chmod(0o400)
    candidate.chmod(0o500)

    verification = verify_refresh_candidate(candidate, now=FIXED_NOW)
    rendered = json.dumps(verification, ensure_ascii=False)

    assert verification["structural_valid"] is False
    assert verification["publication_ready"] is False
    assert "unsafe_artifact_name" in verification["errors"]
    assert "\u202e" not in rendered
    assert unsafe_name not in rendered


def test_real_preflight_refuses_when_required_sandbox_is_unavailable(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr("mcp_trust.refresh.shutil.which", lambda _name: None)

    with pytest.raises(RefreshCandidateError, match="Docker executable"):
        preflight_real_refresh([_server("alpha")], default_image="required:image")


def test_real_preflight_refuses_missing_pinned_image(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    host = "unix:///Users/operator/.colima/default/docker.sock"
    monkeypatch.setenv("DOCKER_HOST", host)
    monkeypatch.setattr("mcp_trust.refresh.shutil.which", lambda _name: "/usr/bin/docker")

    def runner(command: list[str], **_kwargs) -> subprocess.CompletedProcess[str]:
        return subprocess.CompletedProcess(
            command,
            0 if command == ["docker", "--host", host, "info"] else 1,
            "",
            "",
        )

    with pytest.raises(RefreshCandidateError, match="required local sandbox image"):
        preflight_real_refresh(
            [_server("alpha")],
            default_image="required:image",
            runner=runner,
        )


def test_real_preflight_refuses_missing_mcpaudit_engine(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv(
        "DOCKER_HOST",
        "unix:///Users/operator/.colima/default/docker.sock",
    )
    monkeypatch.setattr("mcp_trust.refresh.shutil.which", lambda _name: "/usr/bin/docker")
    monkeypatch.setattr("mcp_trust.refresh.importlib.util.find_spec", lambda _name: None)

    def runner(command: list[str], **_kwargs) -> subprocess.CompletedProcess[str]:
        return subprocess.CompletedProcess(command, 0, "", "")

    with pytest.raises(RefreshCandidateError, match="MCPAudit engine"):
        preflight_real_refresh(
            [_server("alpha")],
            default_image="required:image",
            runner=runner,
        )


def test_real_preflight_binds_one_explicit_local_docker_endpoint(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    host = "unix:///Users/operator/.colima/default/docker.sock"
    commands: list[list[str]] = []
    monkeypatch.setenv("DOCKER_HOST", host)
    monkeypatch.setattr("mcp_trust.refresh.shutil.which", lambda _name: "/usr/bin/docker")
    monkeypatch.setattr(
        "mcp_trust.refresh.importlib.util.find_spec",
        lambda _name: object(),
    )

    def runner(command: list[str], **_kwargs) -> subprocess.CompletedProcess[str]:
        commands.append(command)
        return subprocess.CompletedProcess(command, 0, "", "")

    evidence = preflight_real_refresh(
        [_server("alpha")],
        default_image="required:image",
        runner=runner,
    )

    assert commands == [
        ["docker", "--host", host, "info"],
        ["docker", "--host", host, "image", "inspect", "required:image"],
    ]
    assert evidence["_execution_docker_host"] == host


def test_real_preflight_resolves_and_binds_the_current_local_docker_context(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    host = "unix:///Users/operator/.colima/default/docker.sock"
    commands: list[list[str]] = []
    monkeypatch.delenv("DOCKER_HOST", raising=False)
    monkeypatch.setattr("mcp_trust.refresh.shutil.which", lambda _name: "/usr/bin/docker")
    monkeypatch.setattr(
        "mcp_trust.refresh.importlib.util.find_spec",
        lambda _name: object(),
    )

    def runner(command: list[str], **_kwargs) -> subprocess.CompletedProcess[str]:
        commands.append(command)
        stdout = json.dumps(host) if command[1:3] == ["context", "inspect"] else ""
        return subprocess.CompletedProcess(command, 0, stdout, "")

    evidence = preflight_real_refresh(
        [_server("alpha")],
        default_image="required:image",
        runner=runner,
    )

    assert commands == [
        [
            "docker",
            "context",
            "inspect",
            "--format",
            "{{json .Endpoints.docker.Host}}",
        ],
        ["docker", "--host", host, "info"],
        ["docker", "--host", host, "image", "inspect", "required:image"],
    ]
    assert evidence["_execution_docker_host"] == host


def test_real_preflight_rejects_remote_docker_daemon_authority(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("DOCKER_HOST", "tcp://example.test:2375")
    monkeypatch.setattr("mcp_trust.refresh.shutil.which", lambda _name: "/usr/bin/docker")
    monkeypatch.setattr(
        "mcp_trust.refresh.importlib.util.find_spec",
        lambda _name: object(),
    )

    with pytest.raises(RefreshCandidateError, match="local Unix socket"):
        preflight_real_refresh(
            [_server("alpha")],
            default_image="required:image",
        )


def test_remote_only_preflight_does_not_require_docker(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    remote = _server("alpha").model_copy(
        update={
            "source": ServerSource(
                kind=SourceKind.REMOTE,
                reference="https://example.test/mcp",
            )
        }
    )
    monkeypatch.setattr("mcp_trust.refresh.shutil.which", lambda _name: None)
    monkeypatch.setattr(
        "mcp_trust.refresh.importlib.util.find_spec",
        lambda _name: object(),
    )

    evidence = preflight_real_refresh(
        [remote],
        default_image="not-needed:image",
    )

    assert evidence == {
        "docker_daemon": "not_required",
        "profiles": [],
        "remote_transport_count": 1,
    }


def test_remote_only_real_candidate_records_sandbox_not_applicable(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    db_path = tmp_path / "registry.db"
    remote = _server("alpha").model_copy(
        update={
            "source": ServerSource(
                kind=SourceKind.REMOTE,
                reference="https://example.test/mcp",
            )
        }
    )
    conn = connect(db_path)
    init_schema(conn)
    ServerRepository(conn).upsert(remote)
    conn.close()
    seed_path = tmp_path / "seed.json"
    seed_path.write_text(
        json.dumps([remote.model_dump(mode="json", exclude={"added_at"})]),
        encoding="utf-8",
    )
    masked_path = tmp_path / "masked.json"
    masked_path.write_text("[]", encoding="utf-8")

    class RemoteMCPAuditEngine:
        def __init__(self, timeout: float) -> None:
            assert timeout == 90.0

        def scan(self, source: ServerSource) -> EngineResult:
            assert source == remote.source
            assert "MCP_TRUST_SANDBOX" not in os.environ
            assert "MCP_TRUST_SANDBOX_NETWORK" not in os.environ
            assert "MCP_TRUST_SANDBOX_IMAGE" not in os.environ
            assert "MCP_TRUST_SCAN_CREDENTIALS" not in os.environ
            return _stub_scanner(remote).model_copy(
                update={
                    "engine_name": "mcpaudit",
                    "engine_version": "2.4.0",
                    "sandbox_image": None,
                }
            )

    monkeypatch.setattr(
        "mcp_trust.refresh.preflight_real_refresh",
        lambda servers, *, default_image: {
            "docker_daemon": "not_required",
            "profiles": [],
            "remote_transport_count": len(servers),
        },
    )
    monkeypatch.setattr("mcp_trust.refresh.MCPAuditEngine", RemoteMCPAuditEngine)

    candidate = create_refresh_candidate(
        source_db=db_path,
        seed_path=seed_path,
        masked_path=masked_path,
        output_parent=tmp_path / "candidates",
        default_image="not-needed:image",
        now=FIXED_NOW,
        candidate_name="candidate",
    )
    result = _results(candidate)[0]
    receipt = json.loads(
        (candidate / "receipts" / str(result["receipt"])).read_text(encoding="utf-8")
    )
    manifest = json.loads((candidate / "MANIFEST.json").read_text(encoding="utf-8"))
    snapshot = json.loads((candidate / "static_snapshot.json").read_text(encoding="utf-8"))
    verification = verify_refresh_candidate(
        candidate,
        now=FIXED_NOW,
        expected_seed_path=seed_path,
        expected_masked_path=masked_path,
    )

    assert manifest["scan_mode"] == "mcpaudit-remote-live-network"
    assert snapshot["servers"][0]["scan_mode"] == "mcpaudit-remote-live-network"
    assert snapshot["servers"][0]["sandbox"] == {
        "mode": "not_applicable",
        "reason": "remote_endpoint_no_local_process",
    }
    assert receipt["sandbox"] == {
        "mode": "not_applicable",
        "reason": "remote_endpoint_no_local_process",
    }
    assert not any(
        caveat.startswith("Network-off sandboxing") or "dummy credentials" in caveat
        for caveat in receipt["caveats"]
    )
    assert any("live network" in caveat for caveat in receipt["caveats"])
    assert verification["structural_valid"] is True
    assert verification["publication_ready"] is True


def test_complete_candidate_requires_reviewed_inputs_for_publication(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    candidate, seed_path, masked_path = _complete_remote_candidate(
        tmp_path,
        monkeypatch,
    )

    unbound = verify_refresh_candidate(candidate, now=FIXED_NOW)
    bound = verify_refresh_candidate(
        candidate,
        now=FIXED_NOW,
        expected_seed_path=seed_path,
        expected_masked_path=masked_path,
    )

    assert unbound["structural_valid"] is True
    assert unbound["reviewed_inputs_bound"] is False
    assert unbound["publication_ready"] is False
    assert bound["structural_valid"] is True
    assert bound["reviewed_inputs_bound"] is True
    assert bound["publication_ready"] is True


def test_reviewed_input_symlinks_are_not_source_binding(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    candidate, seed_path, masked_path = _complete_remote_candidate(tmp_path, monkeypatch)
    reviewed_seed = tmp_path / "reviewed-seed-link.json"
    reviewed_masked = tmp_path / "reviewed-masked-link.json"
    reviewed_seed.symlink_to(seed_path)
    reviewed_masked.symlink_to(masked_path)

    verification = verify_refresh_candidate(
        candidate,
        now=FIXED_NOW,
        expected_seed_path=reviewed_seed,
        expected_masked_path=reviewed_masked,
    )

    assert verification["structural_valid"] is False
    assert verification["reviewed_inputs_bound"] is False
    assert verification["publication_ready"] is False
    assert "reviewed_inputs_unavailable" in verification["errors"]


def test_reviewed_input_replacement_during_read_is_not_source_binding(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    candidate, seed_path, masked_path = _complete_remote_candidate(tmp_path, monkeypatch)
    replacement_seed = tmp_path / "replacement-seed.json"
    replacement_seed.write_bytes(seed_path.read_bytes())
    real_open = os.open
    replaced = False

    def replace_then_open(path, flags, mode=0o777, *, dir_fd=None):
        nonlocal replaced
        if (
            not replaced
            and isinstance(path, (str, os.PathLike))
            and Path(path) == seed_path
        ):
            replaced = True
            os.replace(replacement_seed, seed_path)
        if dir_fd is None:
            return real_open(path, flags, mode)
        return real_open(path, flags, mode, dir_fd=dir_fd)

    monkeypatch.setattr(os, "open", replace_then_open)

    verification = verify_refresh_candidate(
        candidate,
        now=FIXED_NOW,
        expected_seed_path=seed_path,
        expected_masked_path=masked_path,
    )

    assert verification["structural_valid"] is False
    assert verification["reviewed_inputs_bound"] is False
    assert verification["publication_ready"] is False
    assert "reviewed_inputs_unavailable" in verification["errors"]


def test_extreme_reviewed_input_integer_returns_structured_unavailable(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    candidate, seed_path, masked_path = _complete_remote_candidate(tmp_path, monkeypatch)
    seed_path.write_text("[" + "9" * 5000 + "]", encoding="utf-8")

    verification = verify_refresh_candidate(
        candidate,
        now=FIXED_NOW,
        expected_seed_path=seed_path,
        expected_masked_path=masked_path,
    )

    assert verification["structural_valid"] is False
    assert verification["reviewed_inputs_bound"] is False
    assert verification["publication_ready"] is False
    assert "reviewed_inputs_unavailable" in verification["errors"]


def test_repeated_verification_output_is_deterministic(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    candidate, seed_path, masked_path = _complete_remote_candidate(tmp_path, monkeypatch)

    first = verify_refresh_candidate(
        candidate,
        now=FIXED_NOW,
        expected_seed_path=seed_path,
        expected_masked_path=masked_path,
    )
    second = verify_refresh_candidate(
        candidate,
        now=FIXED_NOW,
        expected_seed_path=seed_path,
        expected_masked_path=masked_path,
    )

    assert first == second
    assert json.dumps(first, sort_keys=True) == json.dumps(second, sort_keys=True)


def test_complete_candidate_rejects_external_seed_catalog_mismatch(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    candidate, seed_path, masked_path = _complete_remote_candidate(
        tmp_path,
        monkeypatch,
    )
    reviewed_seed = tmp_path / "reviewed-seed.json"
    reviewed_rows = json.loads(seed_path.read_text(encoding="utf-8"))
    reviewed_rows.append(
        {
            "slug": "beta",
            "name": "beta",
            "source": {
                "kind": "npm",
                "reference": "@example/beta",
                "command": "/opt/beta",
            },
        }
    )
    reviewed_seed.write_text(json.dumps(reviewed_rows), encoding="utf-8")

    verification = verify_refresh_candidate(
        candidate,
        now=FIXED_NOW,
        expected_seed_path=reviewed_seed,
        expected_masked_path=masked_path,
    )

    assert verification["structural_valid"] is False
    assert verification["reviewed_inputs_bound"] is False
    assert "reviewed_inputs_mismatch" in verification["errors"]


def test_complete_candidate_rejects_external_mask_authorization_mismatch(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    candidate, seed_path, _masked_path = _complete_remote_candidate(
        tmp_path,
        monkeypatch,
        masked=("alpha",),
    )
    reviewed_mask = tmp_path / "reviewed-mask.json"
    reviewed_mask.write_text("[]", encoding="utf-8")

    verification = verify_refresh_candidate(
        candidate,
        now=FIXED_NOW,
        expected_seed_path=seed_path,
        expected_masked_path=reviewed_mask,
    )

    assert verification["structural_valid"] is False
    assert verification["reviewed_inputs_bound"] is False
    assert "reviewed_inputs_mismatch" in verification["errors"]


def test_complete_candidate_rejects_rebound_transport_count(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    candidate, seed_path, masked_path = _complete_remote_candidate(tmp_path, monkeypatch)
    manifest = json.loads((candidate / "MANIFEST.json").read_text(encoding="utf-8"))
    sandbox = dict(manifest["sandbox"])
    sandbox["remote_transport_count"] = 0
    _rebind_manifest(candidate, sandbox=sandbox)

    verification = verify_refresh_candidate(
        candidate,
        now=FIXED_NOW,
        expected_seed_path=seed_path,
        expected_masked_path=masked_path,
    )

    assert verification["structural_valid"] is False
    assert verification["publication_ready"] is False
    assert "sandbox_manifest_invalid" in verification["errors"]


def test_complete_candidate_rejects_rebound_unreviewed_sandbox_image(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    db_path, seed_path, masked_path = _inputs(tmp_path)

    class LocalMCPAuditEngine:
        def __init__(self, timeout: float) -> None:
            assert timeout == 90.0

        def scan(self, source: ServerSource) -> EngineResult:
            return (
                StubEngine()
                .scan(source)
                .model_copy(
                    update={
                        "engine_name": "mcpaudit",
                        "engine_version": "2.4.0",
                        "evidence": ScanEvidence(tools=[ToolEvidence(name="fixture-tool")]),
                        "sandbox_image": "required:image",
                    }
                )
            )

    monkeypatch.setattr(
        "mcp_trust.refresh.preflight_real_refresh",
        lambda servers, *, default_image: {
            "docker_daemon": "available",
            "profiles": [
                {
                    "kind": "docker",
                    "image": default_image,
                    "network": "none",
                    "read_only_root": True,
                    "capabilities": "dropped-all",
                    "no_new_privileges": True,
                    "memory": "512m",
                    "pids_limit": 128,
                    "cpus": "1.0",
                    "user": "65532:65532",
                    "tmpfs": "/work:rw,noexec,nosuid,size=64m",
                }
            ],
            "remote_transport_count": 0,
        },
    )
    monkeypatch.setattr("mcp_trust.refresh.MCPAuditEngine", LocalMCPAuditEngine)
    candidate = create_refresh_candidate(
        source_db=db_path,
        seed_path=seed_path,
        masked_path=masked_path,
        output_parent=tmp_path / "candidates",
        default_image="required:image",
        now=FIXED_NOW,
        candidate_name="candidate",
    )
    manifest = json.loads((candidate / "MANIFEST.json").read_text(encoding="utf-8"))
    assert manifest["scan_mode"] == "mcpaudit-local-network-off"
    assert (
        verify_refresh_candidate(
            candidate,
            now=FIXED_NOW,
            expected_seed_path=seed_path,
            expected_masked_path=masked_path,
        )["publication_ready"]
        is True
    )

    result = _results(candidate)[0]
    receipt_path = candidate / "receipts" / str(result["receipt"])
    registry_path = candidate / "registry.db"
    manifest_path = candidate / "MANIFEST.json"
    digest_path = candidate / "MANIFEST.sha256"
    candidate.chmod(0o700)
    for path in (receipt_path, registry_path, manifest_path, digest_path):
        path.chmod(0o600)
    conn = connect(registry_path)
    conn.execute(
        "UPDATE scans SET sandbox_image = ? WHERE id = ?",
        ("unreviewed:image", result["scan_id"]),
    )
    conn.commit()
    conn.close()
    receipt = json.loads(receipt_path.read_text(encoding="utf-8"))
    receipt["scan"]["sandbox_image"] = "unreviewed:image"
    receipt["sandbox"]["MCP_TRUST_SANDBOX_IMAGE"] = "unreviewed:image"
    receipt_path.write_text(json.dumps(receipt), encoding="utf-8")
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    for artifact in manifest["artifacts"]:
        artifact_path = candidate / artifact["path"]
        artifact["bytes"] = artifact_path.stat().st_size
        artifact["sha256"] = hashlib.sha256(artifact_path.read_bytes()).hexdigest()
    manifest_path.write_text(json.dumps(manifest), encoding="utf-8")
    digest_path.write_text(
        hashlib.sha256(manifest_path.read_bytes()).hexdigest() + "\n",
        encoding="utf-8",
    )
    for path in (receipt_path, registry_path, manifest_path, digest_path):
        path.chmod(0o400)
    candidate.chmod(0o500)

    verification = verify_refresh_candidate(candidate, now=FIXED_NOW)

    assert verification["structural_valid"] is False
    assert verification["publication_ready"] is False
    assert any(
        error.startswith("publishable_scan_provenance_invalid:") for error in verification["errors"]
    )


def test_candidate_registry_and_snapshot_exclude_non_catalog_server(
    tmp_path: Path,
) -> None:
    db_path, seed_path, masked_path = _inputs(tmp_path)
    conn = connect(db_path)
    extra = _server("extra")
    ServerRepository(conn).upsert(extra)
    ScanRepository(conn).record(
        ScanRecord(
            id="extra-real-scan",
            server_slug=extra.slug,
            engine_name="mcpaudit",
            engine_version="2.4.0",
            grade=TrustGrade.A,
            risk=RiskSummary(composite=0.0),
            evidence=ScanEvidence(tools=[ToolEvidence(name="extra-tool")]),
            scanned_at=FIXED_NOW,
        )
    )
    conn.close()

    candidate = create_refresh_candidate(
        source_db=db_path,
        seed_path=seed_path,
        masked_path=masked_path,
        output_parent=tmp_path / "candidates",
        default_image="fixture:image",
        scanner=_stub_scanner,
        now=FIXED_NOW,
        candidate_name="candidate",
    )
    snapshot = json.loads((candidate / "static_snapshot.json").read_text(encoding="utf-8"))
    candidate_conn = connect(candidate / "registry.db")
    candidate_servers = ServerRepository(candidate_conn).list()
    candidate_conn.close()

    assert [server.slug for server in candidate_servers] == ["alpha"]
    assert "extra" not in {server["slug"] for server in snapshot["servers"]}
    assert verify_refresh_candidate(candidate, now=FIXED_NOW)["structural_valid"] is True


def test_candidate_name_cannot_escape_output_directory(tmp_path: Path) -> None:
    db_path, seed_path, masked_path = _inputs(tmp_path)

    with pytest.raises(RefreshCandidateError, match="safe single path component"):
        create_refresh_candidate(
            source_db=db_path,
            seed_path=seed_path,
            masked_path=masked_path,
            output_parent=tmp_path / "candidates",
            default_image="fixture:image",
            scanner=_stub_scanner,
            now=FIXED_NOW,
            candidate_name="../escaped",
        )

    assert not (tmp_path / "escaped").exists()


def test_publication_without_distinct_approval_is_refused(tmp_path: Path) -> None:
    candidate = _candidate(tmp_path)

    with pytest.raises(RefreshCandidateError, match="approval is required"):
        publish_refresh_candidate(
            candidate=candidate,
            approval_path=None,
            destination_parent=tmp_path / "published",
            seed_path=tmp_path / "seed.json",
            masked_path=tmp_path / "masked.json",
            now=FIXED_NOW,
        )


def test_local_publication_binds_the_reviewed_seed_and_mask_inputs(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    candidate, seed_path, masked_path = _complete_remote_candidate(
        tmp_path,
        monkeypatch,
    )
    verification = verify_refresh_candidate(
        candidate,
        now=FIXED_NOW,
        expected_seed_path=seed_path,
        expected_masked_path=masked_path,
    )
    approval_path = tmp_path / "approval.json"
    destination = tmp_path / "published"

    approve_refresh_candidate(
        candidate=candidate,
        approval_path=approval_path,
        actor="operator",
        reason="reviewed inputs match the candidate",
        publication_target=destination,
        confirmation_digest=str(verification["manifest_sha256"]),
        seed_path=seed_path,
        masked_path=masked_path,
        now=FIXED_NOW,
    )
    published = publish_refresh_candidate(
        candidate=candidate,
        approval_path=approval_path,
        destination_parent=destination,
        seed_path=seed_path,
        masked_path=masked_path,
        now=FIXED_NOW,
    )
    approval = json.loads(approval_path.read_text(encoding="utf-8"))
    publication = json.loads((published / "PUBLICATION.json").read_text(encoding="utf-8"))

    assert approval["reviewed_seed_sha256"] == hashlib.sha256(seed_path.read_bytes()).hexdigest()
    assert approval_path.stat().st_mode & 0o777 == 0o400
    assert (
        approval["reviewed_masked_sha256"] == hashlib.sha256(masked_path.read_bytes()).hexdigest()
    )
    assert publication["deployment_performed"] is False
    assert (
        verify_refresh_candidate(
            published / "candidate",
            now=FIXED_NOW,
            expected_seed_path=seed_path,
            expected_masked_path=masked_path,
        )["publication_ready"]
        is True
    )


def test_publication_rejects_writable_approval_receipt(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    candidate, seed_path, masked_path = _complete_remote_candidate(
        tmp_path,
        monkeypatch,
    )
    verification = verify_refresh_candidate(
        candidate,
        now=FIXED_NOW,
        expected_seed_path=seed_path,
        expected_masked_path=masked_path,
    )
    approval_path = tmp_path / "approval.json"
    approve_refresh_candidate(
        candidate=candidate,
        approval_path=approval_path,
        actor="operator",
        reason="reviewed candidate",
        publication_target=tmp_path / "published",
        confirmation_digest=str(verification["manifest_sha256"]),
        seed_path=seed_path,
        masked_path=masked_path,
        now=FIXED_NOW,
    )
    approval_path.chmod(0o600)

    with pytest.raises(RefreshCandidateError, match="unsafe ownership or permissions"):
        publish_refresh_candidate(
            candidate=candidate,
            approval_path=approval_path,
            destination_parent=tmp_path / "published",
            seed_path=seed_path,
            masked_path=masked_path,
            now=FIXED_NOW,
        )


def test_publication_uses_verified_snapshot_if_source_candidate_is_replaced(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    first_root = tmp_path / "first"
    second_root = tmp_path / "second"
    first_root.mkdir()
    second_root.mkdir()
    candidate, seed_path, masked_path = _complete_remote_candidate(
        first_root,
        monkeypatch,
        slug="alpha",
    )
    replacement, _replacement_seed, _replacement_mask = _complete_remote_candidate(
        second_root,
        monkeypatch,
        slug="beta",
    )
    verification = verify_refresh_candidate(
        candidate,
        now=FIXED_NOW,
        expected_seed_path=seed_path,
        expected_masked_path=masked_path,
    )
    expected_digest = str(verification["manifest_sha256"])
    approval_path = tmp_path / "approval.json"
    destination = tmp_path / "published"
    approve_refresh_candidate(
        candidate=candidate,
        approval_path=approval_path,
        actor="operator",
        reason="reviewed candidate",
        publication_target=destination,
        confirmation_digest=expected_digest,
        seed_path=seed_path,
        masked_path=masked_path,
        now=FIXED_NOW,
    )
    real_load_approval = refresh_module._load_read_only_json_with_digest
    swapped = False

    def load_then_swap(path):
        nonlocal swapped
        loaded = real_load_approval(path)
        if not swapped:
            swapped = True
            parked = tmp_path / "parked-candidate"
            candidate.parent.chmod(0o700)
            replacement.parent.chmod(0o700)
            candidate.chmod(0o700)
            replacement.chmod(0o700)
            candidate.rename(parked)
            replacement.rename(candidate)
            parked.rename(replacement)
        return loaded

    monkeypatch.setattr(
        refresh_module,
        "_load_read_only_json_with_digest",
        load_then_swap,
    )

    published = publish_refresh_candidate(
        candidate=candidate,
        approval_path=approval_path,
        destination_parent=destination,
        seed_path=seed_path,
        masked_path=masked_path,
        now=FIXED_NOW,
    )
    published_verification = verify_refresh_candidate(
        published / "candidate",
        now=FIXED_NOW,
        expected_seed_path=seed_path,
        expected_masked_path=masked_path,
    )

    assert published_verification["publication_ready"] is True
    assert published_verification["manifest_sha256"] == expected_digest


def test_publication_rejects_extra_approval_authority_fields(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    candidate, seed_path, masked_path = _complete_remote_candidate(tmp_path, monkeypatch)
    verification = verify_refresh_candidate(
        candidate,
        now=FIXED_NOW,
        expected_seed_path=seed_path,
        expected_masked_path=masked_path,
    )
    approval_path = tmp_path / "approval.json"
    destination = tmp_path / "published"
    approve_refresh_candidate(
        candidate=candidate,
        approval_path=approval_path,
        actor="operator",
        reason="reviewed candidate",
        publication_target=destination,
        confirmation_digest=str(verification["manifest_sha256"]),
        seed_path=seed_path,
        masked_path=masked_path,
        now=FIXED_NOW,
    )
    approval_path.chmod(0o600)
    approval = json.loads(approval_path.read_text(encoding="utf-8"))
    approval["publication_ready"] = True
    approval_path.write_text(json.dumps(approval), encoding="utf-8")
    approval_path.chmod(0o400)

    with pytest.raises(RefreshCandidateError, match="approval is invalid"):
        publish_refresh_candidate(
            candidate=candidate,
            approval_path=approval_path,
            destination_parent=destination,
            seed_path=seed_path,
            masked_path=masked_path,
            now=FIXED_NOW,
        )


def test_publication_rejects_extreme_approval_integer(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    candidate, seed_path, masked_path = _complete_remote_candidate(tmp_path, monkeypatch)
    verification = verify_refresh_candidate(
        candidate,
        now=FIXED_NOW,
        expected_seed_path=seed_path,
        expected_masked_path=masked_path,
    )
    approval_path = tmp_path / "approval.json"
    destination = tmp_path / "published"
    approve_refresh_candidate(
        candidate=candidate,
        approval_path=approval_path,
        actor="operator",
        reason="reviewed candidate",
        publication_target=destination,
        confirmation_digest=str(verification["manifest_sha256"]),
        seed_path=seed_path,
        masked_path=masked_path,
        now=FIXED_NOW,
    )
    approval_path.chmod(0o600)
    approval_path.write_text(
        '{"schema":"RefreshPublicationApprovalV1","extreme":'
        + "9" * 5000
        + "}",
        encoding="utf-8",
    )
    approval_path.chmod(0o400)

    with pytest.raises(
        RefreshCandidateError,
        match="unreadable immutable JSON artifact",
    ):
        publish_refresh_candidate(
            candidate=candidate,
            approval_path=approval_path,
            destination_parent=destination,
            seed_path=seed_path,
            masked_path=masked_path,
            now=FIXED_NOW,
        )

    assert not destination.exists()


def test_renamed_deceptive_candidate_is_not_verifiable_or_publishable(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    candidate, seed_path, masked_path = _complete_remote_candidate(tmp_path, monkeypatch)
    initial = verify_refresh_candidate(
        candidate,
        now=FIXED_NOW,
        expected_seed_path=seed_path,
        expected_masked_path=masked_path,
    )
    approval_path = tmp_path / "approval.json"
    destination = tmp_path / "published"
    approve_refresh_candidate(
        candidate=candidate,
        approval_path=approval_path,
        actor="operator",
        reason="reviewed candidate",
        publication_target=destination,
        confirmation_digest=str(initial["manifest_sha256"]),
        seed_path=seed_path,
        masked_path=masked_path,
        now=FIXED_NOW,
    )
    candidate.parent.chmod(0o700)
    renamed = candidate.rename(candidate.parent / "candidate-\u202ejson")

    verification = verify_refresh_candidate(
        renamed,
        now=FIXED_NOW,
        expected_seed_path=seed_path,
        expected_masked_path=masked_path,
    )

    assert verification["structural_valid"] is False
    assert verification["publication_ready"] is False
    assert "candidate_name_invalid" in verification["errors"]
    assert "\u202e" not in json.dumps(verification, ensure_ascii=False)
    with pytest.raises(RefreshCandidateError, match="failed immediate"):
        publish_refresh_candidate(
            candidate=renamed,
            approval_path=approval_path,
            destination_parent=destination,
            seed_path=seed_path,
            masked_path=masked_path,
            now=FIXED_NOW,
        )
    assert not destination.exists()


def test_fixture_candidate_cannot_receive_publication_approval(tmp_path: Path) -> None:
    candidate = _candidate(tmp_path)
    verification = verify_refresh_candidate(candidate, now=FIXED_NOW)

    with pytest.raises(RefreshCandidateError, match="not complete"):
        approve_refresh_candidate(
            candidate=candidate,
            approval_path=tmp_path / "approval.json",
            actor="operator",
            reason="fixture must remain fixture",
            publication_target=tmp_path / "published",
            confirmation_digest=str(verification["manifest_sha256"]),
            seed_path=tmp_path / "seed.json",
            masked_path=tmp_path / "masked.json",
            now=FIXED_NOW,
        )


def test_snapshot_projection_surfaces_scan_age_and_excludes_masked(
    tmp_path: Path,
) -> None:
    from mcp_trust.catalog.snapshot import build_snapshot

    db_path, _seed, _masked = _inputs(tmp_path, slugs=("alpha", "beta"))
    conn = connect(db_path)
    scans = ScanRepository(conn)
    for slug in ("alpha", "beta"):
        scans.record(
            ScanRecord(
                id=slug,
                server_slug=slug,
                engine_name="mcpaudit",
                engine_version="2.4.0",
                grade=TrustGrade.B,
                risk=RiskSummary(composite=2.0),
                evidence=ScanEvidence(tools=[ToolEvidence(name="ping")]),
                scanned_at=FIXED_NOW - timedelta(days=2),
            )
        )
    conn.close()

    snapshot = build_snapshot(
        str(db_path),
        masked_slugs=frozenset({"beta"}),
        now=FIXED_NOW,
    )

    assert snapshot["schema_version"] == 2
    assert snapshot["server_count"] == 1
    assert snapshot["servers"][0]["slug"] == "alpha"
    assert snapshot["servers"][0]["scan_age_days"] == 2.0
