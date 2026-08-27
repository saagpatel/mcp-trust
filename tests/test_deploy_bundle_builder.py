from __future__ import annotations

import hashlib
import importlib.util
import json
import sqlite3
import sys
import tarfile
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
SCRIPTS = ROOT / "scripts"


def _load_module(name: str, path: Path):
    spec = importlib.util.spec_from_file_location(name, path)
    assert spec is not None
    assert spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


def _write_seed(path: Path, slugs: list[str]) -> None:
    payload = [
        {"slug": slug, "name": slug, "source": {"kind": "npm", "reference": slug}} for slug in slugs
    ]
    path.write_text(json.dumps(payload), encoding="utf-8")


def _init_db(path: Path) -> sqlite3.Connection:
    conn = sqlite3.connect(path)
    conn.execute(
        """
        CREATE TABLE scans (
            id TEXT PRIMARY KEY,
            server_slug TEXT NOT NULL,
            engine_name TEXT NOT NULL,
            engine_version TEXT NOT NULL,
            grade TEXT NOT NULL,
            transparency TEXT NOT NULL,
            risk_json TEXT NOT NULL,
            findings_json TEXT NOT NULL,
            scanned_at TEXT NOT NULL,
            report_ref TEXT
        )
        """
    )
    return conn


def _insert_scan(
    conn: sqlite3.Connection,
    *,
    slug: str,
    scan_id: str,
    report_ref: str,
    scanned_at: datetime,
) -> None:
    conn.execute(
        """
        INSERT INTO scans
            (id, server_slug, engine_name, engine_version, grade, transparency,
             risk_json, findings_json, scanned_at, report_ref)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (
            scan_id,
            slug,
            "mcpaudit",
            "2.1.0",
            "A",
            "high",
            '{"composite": 1.0}',
            "[]",
            scanned_at.isoformat(),
            report_ref,
        ),
    )
    conn.commit()


def _write_receipt(receipts_dir: Path, *, filename: str, slug: str, scan_id: str) -> None:
    receipts_dir.mkdir(exist_ok=True)
    (receipts_dir / filename).write_text(
        json.dumps(
            {
                "server_slug": slug,
                "scan_id": scan_id,
                "scanner": {"engine_name": "mcpaudit", "engine_version": "2.1.0"},
            }
        ),
        encoding="utf-8",
    )


def _artifact_manifest(candidate: Path) -> list[dict[str, object]]:
    return [
        {
            "path": path.relative_to(candidate).as_posix(),
            "bytes": path.stat().st_size,
            "sha256": hashlib.sha256(path.read_bytes()).hexdigest(),
        }
        for path in sorted(candidate.rglob("*"))
        if path.is_file()
    ]


def _admitted_candidate_verifier(candidate: Path, **_kwargs) -> dict[str, object]:
    assert _kwargs["repo_root"] == ROOT
    return {
        "structural_valid": True,
        "publication_ready": True,
        "manifest_sha256": "a" * 64,
        "_artifact_manifest": _artifact_manifest(candidate),
        "errors": [],
    }


def _admitted_review_verifier(**kwargs) -> dict[str, object]:
    assert kwargs["repo_root"] == ROOT
    masked_path = kwargs["masked_path"]
    return {
        "state": "PUBLICATION_APPROVED_ROLLBACK_BOUND",
        "publication_allowed": True,
        "deployment_allowed": True,
        "rollback_state": "BOUND",
        "candidate_manifest_digest": "sha256:" + "a" * 64,
        "masking_digest": "sha256:" + hashlib.sha256(masked_path.read_bytes()).hexdigest(),
        "review_receipt_digest": "sha256:" + "b" * 64,
    }


def _review_args(tmp_path: Path) -> dict[str, object]:
    return {
        "repo_root": ROOT,
        "policy_path": tmp_path / "policy.json",
        "review_path": tmp_path / "review.json",
        "disposition_path": tmp_path / "disposition.json",
        "review_verifier": _admitted_review_verifier,
        "implementation_binding_provider": lambda: {
            "state": "CLEAN_COMMITTED",
            "revision": "c" * 40,
            "source_tree_digest": "sha256:" + "d" * 64,
        },
    }


@pytest.mark.parametrize(
    "review_state",
    [
        "REVIEW_ONLY_PENDING_SANITIZED_REACCEPTANCE",
        "REVIEW_ONLY_ACCEPTED_FOR_SOURCE_REVIEW",
    ],
)
def test_build_deploy_bundle_rejects_review_only_state(
    tmp_path: Path, review_state: str
) -> None:
    _load_module("validate_launch_state", SCRIPTS / "validate_launch_state.py")
    builder = _load_module("build_deploy_bundle", SCRIPTS / "build_deploy_bundle.py")
    candidate = tmp_path / "candidate"
    candidate.mkdir()
    seed = tmp_path / "seed.json"
    masked = tmp_path / "masked.json"
    _write_seed(seed, ["alpha"])
    masked.write_text("[]\n", encoding="utf-8")

    with pytest.raises(ValueError, match="does not authorize a deployment-shaped bundle"):
        builder.build_deploy_bundle(
            candidate_path=candidate,
            seed_path=seed,
            masked_path=masked,
            policy_path=tmp_path / "policy.json",
            review_path=tmp_path / "review.json",
            disposition_path=tmp_path / "disposition.json",
            out_dir=tmp_path / "dist",
            candidate_verifier=_admitted_candidate_verifier,
            implementation_binding_provider=lambda: {
                "state": "CLEAN_COMMITTED",
                "revision": "c" * 40,
                "source_tree_digest": "sha256:" + "d" * 64,
            },
            review_verifier=lambda **_kwargs: {
                "state": review_state,
                "publication_allowed": False,
                "deployment_allowed": False,
                "rollback_state": "UNKNOWN",
            },
        )
    assert not (tmp_path / "dist").exists()


def test_build_deploy_bundle_rejects_unverified_candidate(tmp_path) -> None:
    _load_module("validate_launch_state", SCRIPTS / "validate_launch_state.py")
    builder = _load_module("build_deploy_bundle", SCRIPTS / "build_deploy_bundle.py")
    candidate = tmp_path / "candidate"
    candidate.mkdir()
    seed_path = tmp_path / "seed.json"
    masked_path = tmp_path / "masked.json"
    _write_seed(seed_path, ["alpha"])
    masked_path.write_text("[]\n", encoding="utf-8")

    with pytest.raises(ValueError, match="not complete, current, and publication-ready"):
        builder.build_deploy_bundle(
            candidate_path=candidate,
            seed_path=seed_path,
            masked_path=masked_path,
            out_dir=tmp_path / "dist",
            **_review_args(tmp_path),
        )


def test_build_deploy_bundle_sanitizes_historical_scan_rows(tmp_path) -> None:
    _load_module("validate_launch_state", SCRIPTS / "validate_launch_state.py")
    builder = _load_module("build_deploy_bundle", SCRIPTS / "build_deploy_bundle.py")
    candidate_path = tmp_path / "candidate"
    candidate_path.mkdir()
    db_path = candidate_path / "registry.db"
    receipts_dir = candidate_path / "receipts"
    seed_path = tmp_path / "seed.json"
    masked_path = tmp_path / "masked.json"
    out_dir = tmp_path / "dist"
    _write_seed(seed_path, ["alpha"])
    masked_path.write_text("[]\n", encoding="utf-8")

    conn = _init_db(db_path)
    now = datetime.now(tz=UTC)
    _insert_scan(
        conn,
        slug="alpha",
        scan_id="old-scan",
        report_ref="~/Projects/mcp-trust/receipts/old-alpha.json",
        scanned_at=now - timedelta(hours=1),
    )
    _insert_scan(
        conn,
        slug="alpha",
        scan_id="new-scan",
        report_ref="new-alpha.json",
        scanned_at=now,
    )
    _write_receipt(receipts_dir, filename="new-alpha.json", slug="alpha", scan_id="new-scan")

    bundle_path = builder.build_deploy_bundle(
        candidate_path=candidate_path,
        seed_path=seed_path,
        masked_path=masked_path,
        out_dir=out_dir,
        bundle_name="bundle",
        candidate_verifier=_admitted_candidate_verifier,
        **_review_args(tmp_path),
    )

    assert bundle_path.exists()
    extract_dir = tmp_path / "extract"
    with tarfile.open(bundle_path, "r:gz") as tar:
        tar.extractall(extract_dir, filter="data")

    bundle_root = extract_dir / "bundle"
    manifest = json.loads((bundle_root / "MANIFEST.json").read_text())
    assert manifest["bundle"]["scan_rows"] == 1
    assert manifest["schema"] == "McpTrustVmDeployBundleV2"
    assert manifest["format_version"] == 2
    assert manifest["source"]["candidate_manifest_sha256"] == "a" * 64
    assert "candidate" not in manifest["source"]
    assert manifest["implementation_binding"] == {
        "state": "CLEAN_COMMITTED",
        "revision": "c" * 40,
        "source_tree_digest": "sha256:" + "d" * 64,
    }
    assert manifest["source"]["db_sha256"] == hashlib.sha256(db_path.read_bytes()).hexdigest()
    assert manifest["source"]["receipts"] == [
        {
            "bytes": (receipts_dir / "new-alpha.json").stat().st_size,
            "receipt": "new-alpha.json",
            "sha256": hashlib.sha256((receipts_dir / "new-alpha.json").read_bytes()).hexdigest(),
        }
    ]
    unsigned = dict(manifest)
    claimed_receipt = unsigned.pop("receipt_digest")
    assert (
        claimed_receipt
        == "sha256:" + hashlib.sha256(builder._canonical_bytes(unsigned)).hexdigest()
    )
    assert str(tmp_path) not in json.dumps(manifest)
    assert manifest["bundle"]["receipts"][0]["receipt"] == "new-alpha.json"
    assert (bundle_root / "receipts/new-alpha.json").exists()
    assert json.loads((bundle_root / "masked-grades.json").read_text()) == []

    bundle_conn = sqlite3.connect(bundle_root / "registry.db")
    bundle_conn.row_factory = sqlite3.Row
    rows = bundle_conn.execute("select id, report_ref from scans").fetchall()
    assert [(row["id"], row["report_ref"]) for row in rows] == [("new-scan", "new-alpha.json")]


def test_build_deploy_bundle_accepts_candidate_with_masked_rows_absent(tmp_path) -> None:
    _load_module("validate_launch_state", SCRIPTS / "validate_launch_state.py")
    builder = _load_module("build_deploy_bundle", SCRIPTS / "build_deploy_bundle.py")
    candidate_path = tmp_path / "candidate"
    candidate_path.mkdir()
    db_path = candidate_path / "registry.db"
    receipts_dir = candidate_path / "receipts"
    seed_path = tmp_path / "seed.json"
    masked_path = tmp_path / "masked.json"
    out_dir = tmp_path / "dist"
    _write_seed(seed_path, ["alpha", "masked"])
    masked_path.write_text(json.dumps(["masked"]), encoding="utf-8")
    conn = _init_db(db_path)
    now = datetime.now(tz=UTC)
    _insert_scan(
        conn,
        slug="alpha",
        scan_id="alpha-scan",
        report_ref="alpha.json",
        scanned_at=now,
    )
    _write_receipt(
        receipts_dir,
        filename="alpha.json",
        slug="alpha",
        scan_id="alpha-scan",
    )

    bundle_path = builder.build_deploy_bundle(
        candidate_path=candidate_path,
        seed_path=seed_path,
        masked_path=masked_path,
        out_dir=out_dir,
        bundle_name="bundle-masked",
        candidate_verifier=_admitted_candidate_verifier,
        **_review_args(tmp_path),
    )
    extract_dir = tmp_path / "extract"
    with tarfile.open(bundle_path, "r:gz") as tar:
        tar.extractall(extract_dir, filter="data")
    root = extract_dir / "bundle-masked"
    bundle_conn = sqlite3.connect(root / "registry.db")
    assert bundle_conn.execute("select server_slug from scans").fetchall() == [("alpha",)]
    assert (root / "receipts/alpha.json").is_file()
    assert not (root / "receipts/masked.json").exists()
    assert json.loads((root / "masked-grades.json").read_text()) == ["masked"]


def test_build_deploy_bundle_rejects_candidate_that_contains_masked_scan(
    tmp_path,
) -> None:
    _load_module("validate_launch_state", SCRIPTS / "validate_launch_state.py")
    builder = _load_module("build_deploy_bundle", SCRIPTS / "build_deploy_bundle.py")
    candidate = tmp_path / "candidate"
    candidate.mkdir()
    db_path = candidate / "registry.db"
    receipts_dir = candidate / "receipts"
    seed_path = tmp_path / "seed.json"
    masked_path = tmp_path / "masked.json"
    _write_seed(seed_path, ["alpha"])
    masked_path.write_text(json.dumps(["alpha"]), encoding="utf-8")
    conn = _init_db(db_path)
    _insert_scan(
        conn,
        slug="alpha",
        scan_id="masked-scan",
        report_ref="masked.json",
        scanned_at=datetime.now(tz=UTC),
    )
    _write_receipt(
        receipts_dir,
        filename="masked.json",
        slug="alpha",
        scan_id="masked-scan",
    )

    with pytest.raises(ValueError, match="masked latest scans exposed"):
        builder.build_deploy_bundle(
            candidate_path=candidate,
            seed_path=seed_path,
            masked_path=masked_path,
            out_dir=tmp_path / "dist",
            candidate_verifier=_admitted_candidate_verifier,
            **_review_args(tmp_path),
        )


def _buildable_inputs(tmp_path: Path) -> tuple[Path, Path, Path]:
    candidate = tmp_path / "candidate"
    candidate.mkdir()
    seed = tmp_path / "seed.json"
    masked = tmp_path / "masked.json"
    _write_seed(seed, ["alpha"])
    masked.write_text("[]\n", encoding="utf-8")
    conn = _init_db(candidate / "registry.db")
    _insert_scan(
        conn,
        slug="alpha",
        scan_id="alpha-scan",
        report_ref="alpha.json",
        scanned_at=datetime(2026, 8, 23, 12, 0, tzinfo=UTC),
    )
    _write_receipt(
        candidate / "receipts",
        filename="alpha.json",
        slug="alpha",
        scan_id="alpha-scan",
    )
    return candidate, seed, masked


def test_deploy_bundle_is_byte_deterministic_and_privacy_safe(tmp_path: Path) -> None:
    _load_module("validate_launch_state", SCRIPTS / "validate_launch_state.py")
    builder = _load_module("build_deploy_bundle", SCRIPTS / "build_deploy_bundle.py")
    candidate, seed, masked = _buildable_inputs(tmp_path)
    first = builder.build_deploy_bundle(
        candidate_path=candidate,
        seed_path=seed,
        masked_path=masked,
        out_dir=tmp_path / "first",
        bundle_name="deterministic",
        candidate_verifier=_admitted_candidate_verifier,
        **_review_args(tmp_path),
    )
    second = builder.build_deploy_bundle(
        candidate_path=candidate,
        seed_path=seed,
        masked_path=masked,
        out_dir=tmp_path / "second",
        bundle_name="deterministic",
        candidate_verifier=_admitted_candidate_verifier,
        **_review_args(tmp_path),
    )
    assert first.read_bytes() == second.read_bytes()
    assert str(tmp_path).encode() not in first.read_bytes()


def test_deploy_bundle_archive_failure_leaves_no_final_or_partial_output(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _load_module("validate_launch_state", SCRIPTS / "validate_launch_state.py")
    builder = _load_module("build_deploy_bundle", SCRIPTS / "build_deploy_bundle.py")
    candidate, seed, masked = _buildable_inputs(tmp_path)
    out_dir = tmp_path / "dist"

    def interrupt(*_args, **_kwargs) -> None:
        raise RuntimeError("simulated archive interruption")

    monkeypatch.setattr(builder, "_write_deterministic_archive", interrupt)
    with pytest.raises(RuntimeError, match="simulated archive interruption"):
        builder.build_deploy_bundle(
            candidate_path=candidate,
            seed_path=seed,
            masked_path=masked,
            out_dir=out_dir,
            bundle_name="interrupted",
            candidate_verifier=_admitted_candidate_verifier,
            **_review_args(tmp_path),
        )
    assert list(out_dir.iterdir()) == []


def test_directory_sync_failure_removes_only_newly_published_archive(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _load_module("validate_launch_state", SCRIPTS / "validate_launch_state.py")
    builder = _load_module("build_deploy_bundle", SCRIPTS / "build_deploy_bundle.py")
    candidate, seed, masked = _buildable_inputs(tmp_path)
    out_dir = tmp_path / "dist"

    def fail_directory_sync(_path: Path) -> None:
        raise OSError("simulated directory sync failure")

    monkeypatch.setattr(builder, "_fsync_directory", fail_directory_sync)
    with pytest.raises(OSError, match="final archive was removed"):
        builder.build_deploy_bundle(
            candidate_path=candidate,
            seed_path=seed,
            masked_path=masked,
            out_dir=out_dir,
            bundle_name="sync-failed",
            candidate_verifier=_admitted_candidate_verifier,
            **_review_args(tmp_path),
        )
    assert list(out_dir.iterdir()) == []


def test_deploy_bundle_rejects_copy_not_bound_to_candidate_manifest(tmp_path: Path) -> None:
    _load_module("validate_launch_state", SCRIPTS / "validate_launch_state.py")
    builder = _load_module("build_deploy_bundle", SCRIPTS / "build_deploy_bundle.py")
    candidate, seed, masked = _buildable_inputs(tmp_path)

    def stale_verifier(path: Path, **kwargs) -> dict[str, object]:
        result = _admitted_candidate_verifier(path, **kwargs)
        artifacts = list(result["_artifact_manifest"])
        artifacts = [
            {**item, "sha256": "f" * 64} if item["path"] == "registry.db" else item
            for item in artifacts
        ]
        result["_artifact_manifest"] = artifacts
        return result

    with pytest.raises(ValueError, match="copied candidate artifact does not match manifest"):
        builder.build_deploy_bundle(
            candidate_path=candidate,
            seed_path=seed,
            masked_path=masked,
            out_dir=tmp_path / "dist",
            bundle_name="stale-copy",
            candidate_verifier=stale_verifier,
            **_review_args(tmp_path),
        )


def test_deploy_bundle_rejects_candidate_drift_before_archive(tmp_path: Path) -> None:
    _load_module("validate_launch_state", SCRIPTS / "validate_launch_state.py")
    builder = _load_module("build_deploy_bundle", SCRIPTS / "build_deploy_bundle.py")
    candidate, seed, masked = _buildable_inputs(tmp_path)
    calls = 0

    def drifting_verifier(path: Path, **kwargs) -> dict[str, object]:
        nonlocal calls
        calls += 1
        result = _admitted_candidate_verifier(path, **kwargs)
        if calls == 2:
            result["manifest_sha256"] = "c" * 64
        return result

    with pytest.raises(ValueError, match="refresh candidate inputs changed"):
        builder.build_deploy_bundle(
            candidate_path=candidate,
            seed_path=seed,
            masked_path=masked,
            out_dir=tmp_path / "dist",
            bundle_name="drifted",
            candidate_verifier=drifting_verifier,
            **_review_args(tmp_path),
        )


def test_stable_copy_never_removes_preexisting_destination(tmp_path: Path) -> None:
    _load_module("validate_launch_state", SCRIPTS / "validate_launch_state.py")
    builder = _load_module("build_deploy_bundle", SCRIPTS / "build_deploy_bundle.py")
    source = tmp_path / "source"
    destination = tmp_path / "destination"
    source.write_bytes(b"verified source")
    destination.write_bytes(b"foreign destination")

    with pytest.raises(FileExistsError):
        builder._stable_copy_file(source, destination, "test source")
    assert destination.read_bytes() == b"foreign destination"


def test_deploy_bundle_never_overwrites_preexisting_archive(tmp_path: Path) -> None:
    _load_module("validate_launch_state", SCRIPTS / "validate_launch_state.py")
    builder = _load_module("build_deploy_bundle", SCRIPTS / "build_deploy_bundle.py")
    candidate, seed, masked = _buildable_inputs(tmp_path)
    out_dir = tmp_path / "dist"
    out_dir.mkdir()
    existing = out_dir / "protected.tar.gz"
    existing.write_bytes(b"foreign archive")

    with pytest.raises(ValueError, match="output already exists"):
        builder.build_deploy_bundle(
            candidate_path=candidate,
            seed_path=seed,
            masked_path=masked,
            out_dir=out_dir,
            bundle_name="protected",
            candidate_verifier=_admitted_candidate_verifier,
            **_review_args(tmp_path),
        )
    assert existing.read_bytes() == b"foreign archive"


def test_deploy_bundle_rejects_invalid_implementation_binding(tmp_path: Path) -> None:
    _load_module("validate_launch_state", SCRIPTS / "validate_launch_state.py")
    builder = _load_module("build_deploy_bundle", SCRIPTS / "build_deploy_bundle.py")
    candidate, seed, masked = _buildable_inputs(tmp_path)
    args = _review_args(tmp_path)
    args["implementation_binding_provider"] = lambda: {
        "state": "DIRTY",
        "revision": "not-a-revision",
        "source_tree_digest": "UNKNOWN",
    }

    with pytest.raises(ValueError, match="implementation binding is invalid"):
        builder.build_deploy_bundle(
            candidate_path=candidate,
            seed_path=seed,
            masked_path=masked,
            out_dir=tmp_path / "dist",
            bundle_name="invalid-binding",
            candidate_verifier=_admitted_candidate_verifier,
            **args,
        )


@pytest.mark.parametrize("name", ["../escape", "/absolute", "nested/name", ".."])
def test_deploy_bundle_rejects_unsafe_archive_name(tmp_path: Path, name: str) -> None:
    _load_module("validate_launch_state", SCRIPTS / "validate_launch_state.py")
    builder = _load_module("build_deploy_bundle", SCRIPTS / "build_deploy_bundle.py")
    candidate, seed, masked = _buildable_inputs(tmp_path)

    with pytest.raises(ValueError, match="bundle name is unsafe"):
        builder.build_deploy_bundle(
            candidate_path=candidate,
            seed_path=seed,
            masked_path=masked,
            out_dir=tmp_path / "dist",
            bundle_name=name,
            candidate_verifier=_admitted_candidate_verifier,
            **_review_args(tmp_path),
        )
    assert not (tmp_path / "escape.tar.gz").exists()
