"""Approval-gated refresh-candidate workflow and honesty boundaries."""

from __future__ import annotations

import hashlib
import json
import os
import subprocess
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest

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
    approve_refresh_candidate,
    create_refresh_candidate,
    preflight_real_refresh,
    publish_refresh_candidate,
    verify_refresh_candidate,
)
from mcp_trust.store.db import connect, init_schema
from mcp_trust.store.repository import ScanRepository, ServerRepository

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
    return StubEngine().scan(server.source).model_copy(
        update={
            "evidence": ScanEvidence(tools=[ToolEvidence(name="fixture-tool")]),
        }
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


def _results(candidate: Path) -> list[dict[str, object]]:
    return json.loads((candidate / "scan_results.json").read_text())["results"]


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


def test_legacy_refresh_entrypoint_only_creates_a_candidate() -> None:
    script = (ROOT / "scripts/refresh_and_publish.sh").read_text(encoding="utf-8")

    assert "refresh_candidate.py create" in script
    assert "uv run --frozen" in script
    assert "mcp-trust scan" not in script
    assert "build_site.py" not in script
    assert "deploy_production" not in script
    assert "vercel deploy" not in script


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

    verification = verify_refresh_candidate(candidate, now=FIXED_NOW)

    assert verification["structural_valid"] is False
    assert "manifest_digest_mismatch" in verification["errors"]


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
    manifest["scan_mode"] = "mcpaudit-network-off"
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
    assert any(
        "publishable_scan_provenance_invalid" in error
        for error in verification["errors"]
    )


def test_stale_candidate_is_not_publication_ready(tmp_path: Path) -> None:
    candidate = _candidate(tmp_path)

    verification = verify_refresh_candidate(
        candidate,
        now=FIXED_NOW + timedelta(hours=25),
    )

    assert verification["structural_valid"] is True
    assert verification["state"] == "stale"
    assert verification["publication_ready"] is False


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
    candidate_conn.close()
    assert result["state"] == "masked"
    assert result["fresh_grade"] is None
    assert result["grade_visibility"] == "withheld"
    assert result["receipt_visibility"] == "withheld"
    assert result["receipt"] is None
    assert result["scan_id"] is None
    assert result["drift"] is None
    assert list((candidate / "receipts").iterdir()) == []
    assert masked_scan_count == 0
    assert snapshot["servers"] == []


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
            artifact["sha256"] = hashlib.sha256(
                snapshot_path.read_bytes()
            ).hexdigest()
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
    assert any(
        error.startswith("fresh_scan_binding_mismatch:")
        for error in verification["errors"]
    )


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
    monkeypatch.setattr("mcp_trust.refresh.shutil.which", lambda _name: "/usr/bin/docker")

    def runner(command: list[str], **_kwargs) -> subprocess.CompletedProcess[str]:
        return subprocess.CompletedProcess(
            command,
            0 if command == ["docker", "info"] else 1,
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
    verification = verify_refresh_candidate(candidate, now=FIXED_NOW)

    assert receipt["sandbox"] == {
        "mode": "not_applicable",
        "reason": "remote_endpoint_no_local_process",
    }
    assert verification["structural_valid"] is True
    assert verification["publication_ready"] is True


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
            now=FIXED_NOW,
        )


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
