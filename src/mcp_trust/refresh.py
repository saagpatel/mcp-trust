"""Manual, approval-gated refresh candidates with no deployment authority."""

from __future__ import annotations

import hashlib
import importlib.util
import json
import os
import re
import shutil
import sqlite3
import subprocess
import tempfile
import uuid
from collections.abc import Callable, Iterator
from contextlib import contextmanager
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

from pydantic import ValidationError

from mcp_trust.core import grading
from mcp_trust.core.drift import diff_latest
from mcp_trust.core.models import ScanRecord, Server, SourceKind
from mcp_trust.engine.base import EngineResult
from mcp_trust.engine.mcpaudit import MCPAuditEngine
from mcp_trust.engine.sandbox import DockerSandbox
from mcp_trust.receipts import build_scan_receipt
from mcp_trust.store.db import connect, init_schema
from mcp_trust.store.repository import ScanRepository, ServerRepository

CANDIDATE_SCHEMA = "RefreshCandidateV1"
APPROVAL_SCHEMA = "RefreshCandidateApprovalV1"
PUBLICATION_SCHEMA = "RefreshCandidatePublicationV1"
MANIFEST_NAME = "MANIFEST.json"
MANIFEST_DIGEST_NAME = "MANIFEST.sha256"
DEFAULT_MAX_AGE_HOURS = 24
_DEPLOYMENT_ENV = ("VERCEL_TOKEN", "VERCEL_ORG_ID", "VERCEL_PROJECT_ID", "VERCEL_SCOPE")
_SANDBOX_FLAGS = (
    "--network",
    "none",
    "--read-only",
    "--cap-drop",
    "ALL",
    "--security-opt",
    "no-new-privileges",
    "--memory",
    "--pids-limit",
    "--cpus",
)
_SAFE_CANDIDATE_NAME = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]*$")


class RefreshCandidateError(RuntimeError):
    """A fail-closed refresh-candidate contract violation."""


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _json_bytes(payload: object) -> bytes:
    return (
        json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=True) + "\n"
    ).encode("utf-8")


def _write_private(path: Path, payload: object) -> None:
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    if hasattr(os, "O_CLOEXEC"):
        flags |= os.O_CLOEXEC
    fd = os.open(path, flags, 0o600)
    try:
        view = memoryview(_json_bytes(payload))
        while view:
            written = os.write(fd, view)
            if written <= 0:
                raise OSError("short refresh-candidate write")
            view = view[written:]
        os.fsync(fd)
    finally:
        os.close(fd)


def _write_private_text(path: Path, text: str) -> None:
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    fd = os.open(path, flags, 0o600)
    try:
        encoded = text.encode("utf-8")
        view = memoryview(encoded)
        while view:
            written = os.write(fd, view)
            if written <= 0:
                raise OSError("short refresh-candidate text write")
            view = view[written:]
        os.fsync(fd)
    finally:
        os.close(fd)


def _sqlite_online_copy(source: Path, destination: Path) -> None:
    if not source.is_file():
        raise RefreshCandidateError(f"registry database is missing: {source}")
    source_db = sqlite3.connect(f"file:{source}?mode=ro", uri=True)
    destination_db = sqlite3.connect(destination)
    try:
        source_db.backup(destination_db)
    finally:
        destination_db.close()
        source_db.close()
    os.chmod(destination, 0o600)


def _load_json(path: Path) -> Any:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError, UnicodeError) as exc:
        raise RefreshCandidateError(f"unreadable JSON artifact: {path.name}") from exc


def _load_string_list(path: Path) -> frozenset[str]:
    loaded = _load_json(path)
    if not isinstance(loaded, list) or not all(isinstance(item, str) for item in loaded):
        raise RefreshCandidateError(f"{path.name} must be a JSON string list")
    return frozenset(loaded)


def _catalog_slugs(seed_path: Path) -> tuple[frozenset[str], list[dict[str, Any]]]:
    loaded = _load_json(seed_path)
    if not isinstance(loaded, list):
        raise RefreshCandidateError("catalog identity must be a JSON list")
    rows: list[dict[str, Any]] = []
    slugs: set[str] = set()
    for item in loaded:
        if not isinstance(item, dict) or not isinstance(item.get("slug"), str):
            raise RefreshCandidateError("catalog identity contains an invalid row")
        slug = item["slug"]
        if slug in slugs:
            raise RefreshCandidateError(f"catalog identity contains duplicate slug {slug}")
        slugs.add(slug)
        rows.append(item)
    return frozenset(slugs), rows


def _reviewed_server_from_seed(row: dict[str, Any], *, added_at: datetime) -> Server:
    try:
        return Server.model_validate({**row, "added_at": added_at})
    except ValidationError as exc:
        slug = row.get("slug")
        raise RefreshCandidateError(
            f"catalog identity contains invalid server metadata: {slug!r}"
        ) from exc


def _server_identity(server: Server) -> dict[str, Any]:
    return server.model_dump(mode="json", exclude={"added_at"})


def _sandbox_profile(image: str) -> dict[str, object]:
    sandbox = DockerSandbox(image=image, network="none")
    command, args = sandbox.wrap("server-command", ["--probe"])
    joined = [command, *args]
    for required in _SANDBOX_FLAGS:
        if required not in joined:
            raise RefreshCandidateError(f"sandbox profile missing required control: {required}")
    if any(token in joined for token in ("--volume", "-v", "--mount")):
        raise RefreshCandidateError("sandbox profile unexpectedly exposes a host mount")
    return {
        "kind": "docker",
        "image": image,
        "network": "none",
        "read_only_root": True,
        "capabilities": "dropped-all",
        "no_new_privileges": True,
        "memory": sandbox.memory,
        "pids_limit": sandbox.pids_limit,
        "cpus": sandbox.cpus,
        "user": sandbox.user,
        "tmpfs": sandbox.workdir,
    }


def _requires_local_sandbox(server: Server) -> bool:
    return not (server.source.kind == SourceKind.REMOTE and server.source.command is None)


def _real_scan_mode(*, local_count: int, total_count: int) -> str:
    if local_count == total_count:
        return "mcpaudit-local-network-off"
    if local_count == 0:
        return "mcpaudit-remote-live-network"
    return "mcpaudit-mixed-transport"


def preflight_real_refresh(
    servers: list[Server],
    *,
    default_image: str,
    runner: Callable[..., subprocess.CompletedProcess[str]] = subprocess.run,
) -> dict[str, object]:
    """Prove the network-off Docker controls and every pinned image locally."""
    local_servers = [server for server in servers if _requires_local_sandbox(server)]
    images = sorted(
        {server.source.sandbox_image or default_image for server in local_servers}
        | ({default_image} if local_servers else set())
    )
    profiles: list[dict[str, object]] = []
    if local_servers:
        if shutil.which("docker") is None:
            raise RefreshCandidateError("required Docker executable is unavailable")
        info = runner(
            ["docker", "info"],
            text=True,
            capture_output=True,
            check=False,
        )
        if info.returncode != 0:
            raise RefreshCandidateError("required Docker daemon is unavailable")
        for image in images:
            inspected = runner(
                ["docker", "image", "inspect", image],
                text=True,
                capture_output=True,
                check=False,
            )
            if inspected.returncode != 0:
                raise RefreshCandidateError(f"required local sandbox image is unavailable: {image}")
            profiles.append(_sandbox_profile(image))
    if importlib.util.find_spec("mcp_audit") is None:
        raise RefreshCandidateError("required MCPAudit engine package is unavailable")
    return {
        "docker_daemon": "available" if local_servers else "not_required",
        "profiles": profiles,
        "remote_transport_count": len(servers) - len(local_servers),
    }


@contextmanager
def _scan_environment(default_image: str) -> Iterator[None]:
    keys = {
        "MCP_TRUST_ENGINE",
        "MCP_TRUST_SANDBOX",
        "MCP_TRUST_SANDBOX_NETWORK",
        "MCP_TRUST_SANDBOX_IMAGE",
        "MCP_TRUST_SCAN_CREDENTIALS",
        *_DEPLOYMENT_ENV,
    }
    previous = {key: os.environ.get(key) for key in keys}
    try:
        os.environ["MCP_TRUST_ENGINE"] = "mcpaudit"
        os.environ["MCP_TRUST_SANDBOX"] = "docker"
        os.environ["MCP_TRUST_SANDBOX_NETWORK"] = "none"
        os.environ["MCP_TRUST_SANDBOX_IMAGE"] = default_image
        os.environ["MCP_TRUST_SCAN_CREDENTIALS"] = "dummy"
        for key in _DEPLOYMENT_ENV:
            os.environ.pop(key, None)
        yield
    finally:
        for key, value in previous.items():
            if value is None:
                os.environ.pop(key, None)
            else:
                os.environ[key] = value


@contextmanager
def _remote_transport_environment() -> Iterator[None]:
    """Prevent remote endpoints from inheriting local-process sandbox claims."""
    keys = {
        "MCP_TRUST_SANDBOX",
        "MCP_TRUST_SANDBOX_NETWORK",
        "MCP_TRUST_SANDBOX_IMAGE",
        "MCP_TRUST_SCAN_CREDENTIALS",
    }
    previous = {key: os.environ.get(key) for key in keys}
    try:
        for key in keys:
            os.environ.pop(key, None)
        yield
    finally:
        for key, value in previous.items():
            if value is None:
                os.environ.pop(key, None)
            else:
                os.environ[key] = value


def _write_receipt(server: Server, scan: ScanRecord, receipts_dir: Path) -> str:
    name = f"{scan.server_slug}-{scan.id}.json"
    if not _requires_local_sandbox(server):
        with _remote_transport_environment():
            payload = build_scan_receipt(server, scan)
        payload["sandbox"] = {
            "mode": "not_applicable",
            "reason": "remote_endpoint_no_local_process",
        }
        caveats = payload.get("caveats")
        if isinstance(caveats, list):
            payload["caveats"] = [
                caveat
                for caveat in caveats
                if isinstance(caveat, str) and not caveat.startswith("Network-off sandboxing")
            ] + ["Remote transport used the live network; no local process sandbox was applicable."]
    else:
        payload = build_scan_receipt(server, scan)
    _write_private(receipts_dir / name, payload)
    return name


def _validate_receipt(
    path: Path,
    *,
    server: Server,
    scan: ScanRecord,
    expected_image: str | None,
) -> bool:
    try:
        receipt = _load_json(path)
    except RefreshCandidateError:
        return False
    if not isinstance(receipt, dict):
        return False
    scanner = receipt.get("scanner")
    sandbox = receipt.get("sandbox")
    base_valid = bool(
        receipt.get("server_slug") == server.slug
        and receipt.get("scan_id") == scan.id
        and isinstance(scanner, dict)
        and scanner.get("engine_name") == scan.engine_name
        and scanner.get("engine_version") == scan.engine_version
        and isinstance(sandbox, dict)
    )
    if not base_valid:
        return False
    if not _requires_local_sandbox(server):
        return bool(
            sandbox.get("mode") == "not_applicable"
            and sandbox.get("reason") == "remote_endpoint_no_local_process"
            and "MCP_TRUST_SANDBOX_IMAGE" not in sandbox
        )
    return bool(
        sandbox.get("MCP_TRUST_SANDBOX") == "docker"
        and sandbox.get("MCP_TRUST_SANDBOX_NETWORK") == "none"
        and sandbox.get("MCP_TRUST_SANDBOX_IMAGE") == expected_image
    )


def _fresh_result_matches_persisted_scan(
    candidate: Path,
    *,
    result: dict[str, object],
    receipt: dict[str, Any],
) -> bool:
    slug = result.get("server_slug")
    if not isinstance(slug, str):
        return False
    try:
        db_uri = f"{(candidate / 'registry.db').resolve().as_uri()}?mode=ro"
        with sqlite3.connect(db_uri, uri=True) as conn:
            conn.row_factory = sqlite3.Row
            server = ServerRepository(conn).get(slug)
            scan = ScanRepository(conn).latest(slug)
    except (OSError, sqlite3.Error, TypeError, ValueError):
        return False
    if server is None or scan is None:
        return False
    expected_evidence = scan.evidence.model_dump(mode="json") if scan.evidence is not None else None
    return bool(
        result.get("scan_id") == scan.id
        and result.get("fresh_grade") == str(scan.grade)
        and result.get("transparency") == str(scan.transparency)
        and result.get("scanned_at") == scan.scanned_at.isoformat()
        and result.get("engine_name") == scan.engine_name
        and result.get("engine_version") == scan.engine_version
        and result.get("receipt") == scan.report_ref
        and receipt.get("server") == server.model_dump(mode="json")
        and receipt.get("scan") == scan.model_dump(mode="json")
        and receipt.get("evidence") == expected_evidence
        and receipt.get("danger_score") == grading.danger_score(scan.risk)
    )


def _scan_age_days(scanned_at: datetime, now: datetime) -> float:
    if scanned_at.tzinfo is None:
        scanned_at = scanned_at.replace(tzinfo=UTC)
    return round(
        max(0.0, (now.astimezone(UTC) - scanned_at.astimezone(UTC)).total_seconds() / 86400),
        6,
    )


def _artifact_inventory(root: Path) -> list[dict[str, object]]:
    artifacts: list[dict[str, object]] = []
    for path in sorted(candidate for candidate in root.rglob("*") if candidate.is_file()):
        relative = path.relative_to(root).as_posix()
        if relative in {MANIFEST_NAME, MANIFEST_DIGEST_NAME}:
            continue
        artifacts.append(
            {
                "path": relative,
                "bytes": path.stat().st_size,
                "sha256": _sha256(path),
            }
        )
    return artifacts


def _make_read_only(root: Path) -> None:
    for path in sorted(root.rglob("*"), reverse=True):
        if path.is_file():
            os.chmod(path, 0o400)
        elif path.is_dir():
            os.chmod(path, 0o500)
    os.chmod(root, 0o500)


def _make_files_read_only(root: Path) -> None:
    for path in root.rglob("*"):
        if path.is_file():
            os.chmod(path, 0o400)


def create_refresh_candidate(
    *,
    source_db: Path,
    seed_path: Path,
    masked_path: Path,
    output_parent: Path,
    default_image: str,
    scanner: Callable[[Server], EngineResult] | None = None,
    receipt_writer: Callable[[Server, ScanRecord, Path], str | None] | None = None,
    now: datetime | None = None,
    candidate_name: str | None = None,
) -> Path:
    """Create one immutable candidate; never mutate canonical/public outputs."""
    fixed_now = now or datetime.now(tz=UTC)
    if fixed_now.tzinfo is None:
        fixed_now = fixed_now.replace(tzinfo=UTC)
    fixture_mode = scanner is not None
    if not source_db.is_file():
        raise RefreshCandidateError(f"registry database is missing: {source_db}")
    catalog_slugs, catalog_rows = _catalog_slugs(seed_path)
    masked_slugs = _load_string_list(masked_path)
    unknown_masked_slugs = sorted(masked_slugs - catalog_slugs)
    if unknown_masked_slugs:
        raise RefreshCandidateError(
            "masked grade list contains unknown catalog slug(s): " + ",".join(unknown_masked_slugs)
        )
    catalog_by_slug = {row["slug"]: row for row in catalog_rows}

    source_conn = sqlite3.connect(f"file:{source_db}?mode=ro", uri=True)
    source_conn.row_factory = sqlite3.Row
    try:
        source_servers = ServerRepository(source_conn)
        servers: list[Server] = []
        for slug in sorted(catalog_slugs):
            server = source_servers.get(slug)
            if server is None:
                raise RefreshCandidateError(f"catalog server missing from registry DB: {slug}")
            reviewed_server = _reviewed_server_from_seed(
                catalog_by_slug[slug],
                added_at=server.added_at,
            )
            if _server_identity(server) != _server_identity(reviewed_server):
                raise RefreshCandidateError(
                    f"registry DB server metadata differs from reviewed catalog: {slug}"
                )
            servers.append(server)
    finally:
        source_conn.close()

    sandbox_evidence: dict[str, object]
    if fixture_mode:
        sandbox_evidence = {
            "mode": "deterministic-fixture",
            "profiles": [_sandbox_profile(default_image)],
        }
    else:
        sandbox_evidence = preflight_real_refresh(servers, default_image=default_image)
        scanner_engine = MCPAuditEngine(timeout=90.0)

        def scan_server(server: Server) -> EngineResult:
            if not _requires_local_sandbox(server):
                with _remote_transport_environment():
                    return scanner_engine.scan(server.source)
            return scanner_engine.scan(server.source)

        scanner = scan_server

    assert scanner is not None
    output_parent.mkdir(parents=True, exist_ok=True)
    name = candidate_name or f"refresh-candidate-{fixed_now.strftime('%Y%m%dT%H%M%SZ')}"
    if not _SAFE_CANDIDATE_NAME.fullmatch(name):
        raise RefreshCandidateError("candidate name must be a safe single path component")
    final = output_parent / name
    if final.exists():
        raise RefreshCandidateError(f"candidate already exists: {final}")
    temporary = Path(tempfile.mkdtemp(prefix=f".{name}.tmp-", dir=output_parent))
    published = False
    try:
        receipts_dir = temporary / "receipts"
        receipts_dir.mkdir(mode=0o700)
        candidate_db = temporary / "registry.db"
        _sqlite_online_copy(source_db, candidate_db)
        conn = connect(str(candidate_db))
        init_schema(conn)
        scan_repo = ScanRepository(conn)
        conn.execute("PRAGMA secure_delete = ON")
        placeholders = ",".join("?" for _ in catalog_slugs)
        if placeholders:
            catalog_parameters = tuple(sorted(catalog_slugs))
            conn.execute(
                f"DELETE FROM scans WHERE server_slug NOT IN ({placeholders})",  # noqa: S608
                catalog_parameters,
            )
            conn.execute(
                f"DELETE FROM servers WHERE slug NOT IN ({placeholders})",  # noqa: S608
                catalog_parameters,
            )
        else:
            conn.execute("DELETE FROM scans")
            conn.execute("DELETE FROM servers")
        if masked_slugs:
            conn.executemany(
                "DELETE FROM scans WHERE server_slug = ?",
                ((slug,) for slug in sorted(masked_slugs)),
            )
        conn.commit()
        conn.execute("VACUUM")

        results: list[dict[str, object]] = []
        excluded: set[str] = set()
        writer = receipt_writer or _write_receipt
        with _scan_environment(default_image):
            for server in servers:
                previous = scan_repo.latest(server.slug)
                try:
                    engine_result = scanner(server)
                    if not fixture_mode and engine_result.engine_name != "mcpaudit":
                        raise RefreshCandidateError("real refresh returned a non-mcpaudit result")
                    if engine_result.evidence is None:
                        results.append(
                            {
                                "server_slug": server.slug,
                                "state": "unknown-evidence",
                                "fresh_grade": None,
                                "previous_grade": str(previous.grade) if previous else None,
                                "previous_scanned_at": (
                                    previous.scanned_at.isoformat() if previous else None
                                ),
                            }
                        )
                        excluded.add(server.slug)
                        continue
                    expected_image = (
                        server.source.sandbox_image or default_image
                        if _requires_local_sandbox(server)
                        else None
                    )
                    if (
                        not fixture_mode
                        and _requires_local_sandbox(server)
                        and engine_result.sandbox_image != expected_image
                    ):
                        results.append(
                            {
                                "server_slug": server.slug,
                                "state": "unknown-sandbox-evidence",
                                "fresh_grade": None,
                                "expected_sandbox_image": expected_image,
                            }
                        )
                        excluded.add(server.slug)
                        continue
                    scan = ScanRecord(
                        id=uuid.uuid4().hex,
                        server_slug=server.slug,
                        engine_name=engine_result.engine_name,
                        engine_version=engine_result.engine_version,
                        grade=grading.grade(engine_result.risk),
                        transparency=grading.transparency(engine_result.risk),
                        risk=engine_result.risk,
                        findings=engine_result.findings,
                        evidence=engine_result.evidence,
                        scanned_at=fixed_now,
                        sandbox_image=engine_result.sandbox_image,
                    )
                    masked = server.slug in masked_slugs
                    if masked:
                        receipt_ref = None
                    elif receipt_writer is None:
                        receipt_ref = f"{scan.server_slug}-{scan.id}.json"
                        scan = scan.model_copy(update={"report_ref": receipt_ref})
                        _write_receipt(server, scan, receipts_dir)
                    else:
                        receipt_ref = writer(server, scan, receipts_dir)
                    receipt_portable = bool(
                        receipt_ref
                        and "/" not in receipt_ref
                        and "\\" not in receipt_ref
                        and receipt_ref not in {".", ".."}
                    )
                    receipt_path = receipts_dir / receipt_ref if receipt_portable else None
                    receipt_valid = masked or bool(
                        receipt_path is not None
                        and receipt_path.is_file()
                        and (
                            fixture_mode
                            or _validate_receipt(
                                receipt_path,
                                server=server,
                                scan=scan,
                                expected_image=expected_image,
                            )
                        )
                    )
                    if not masked and (not receipt_ref or not receipt_valid):
                        results.append(
                            {
                                "server_slug": server.slug,
                                "state": "missing-receipt",
                                "fresh_grade": None,
                                "previous_grade": str(previous.grade) if previous else None,
                            }
                        )
                        excluded.add(server.slug)
                        continue
                    if masked:
                        drift = None
                    else:
                        if scan.report_ref != receipt_ref:
                            scan = scan.model_copy(update={"report_ref": receipt_ref})
                        scan_repo.record(scan)
                        drift = diff_latest(scan_repo.history(server.slug, limit=2))
                    results.append(
                        {
                            "server_slug": server.slug,
                            "state": "masked" if masked else "fresh",
                            "fresh_grade": None if masked else str(scan.grade),
                            "grade_visibility": "withheld" if masked else "reviewable",
                            "transparency": (None if masked else str(scan.transparency)),
                            "scanned_at": scan.scanned_at.isoformat(),
                            "scan_age_days": _scan_age_days(scan.scanned_at, fixed_now),
                            "scan_id": None if masked else scan.id,
                            "engine_name": scan.engine_name,
                            "engine_version": scan.engine_version,
                            "receipt": None if masked else receipt_ref,
                            "receipt_visibility": ("withheld" if masked else "reviewable"),
                            "drift": (
                                {
                                    "cause": str(drift.cause),
                                    "surface_comparison": str(drift.surface_comparison),
                                    "summary": drift.summary,
                                    "previous_grade": str(drift.previous_grade),
                                    "current_grade": (None if masked else str(drift.current_grade)),
                                }
                                if drift is not None
                                else None
                            ),
                        }
                    )
                except Exception as exc:  # noqa: BLE001 - one row must become explicit partial
                    results.append(
                        {
                            "server_slug": server.slug,
                            "state": "scan-failed",
                            "fresh_grade": None,
                            "error_type": type(exc).__name__,
                            "previous_grade": str(previous.grade) if previous else None,
                            "previous_scanned_at": (
                                previous.scanned_at.isoformat() if previous else None
                            ),
                            "previous_scan_age_days": (
                                _scan_age_days(previous.scanned_at, fixed_now) if previous else None
                            ),
                        }
                    )
                    excluded.add(server.slug)
        conn.close()

        from mcp_trust.catalog.snapshot import build_snapshot

        snapshot = build_snapshot(
            str(candidate_db),
            excluded_slugs=frozenset(excluded),
            masked_slugs=masked_slugs,
            verified_local_network=None if fixture_mode else "none",
            now=fixed_now,
        )
        _write_private(
            temporary / "catalog_identity.json",
            {
                "schema": "RefreshCatalogIdentityV1",
                "seed_sha256": _sha256(seed_path),
                "server_count": len(catalog_rows),
                "servers": catalog_rows,
            },
        )
        _write_private(
            temporary / "scan_results.json",
            {
                "schema": "RefreshScanResultsV1",
                "generated_at": fixed_now.isoformat(),
                "results": results,
            },
        )
        _write_private(temporary / "static_snapshot.json", snapshot)

        complete = all(result["state"] in {"fresh", "masked"} for result in results)
        candidate_state = "fixture" if fixture_mode else "complete" if complete else "partial"
        manifest = {
            "schema": CANDIDATE_SCHEMA,
            "created_at": fixed_now.isoformat(),
            "expires_at": (fixed_now + timedelta(hours=DEFAULT_MAX_AGE_HOURS)).isoformat(),
            "candidate_state": candidate_state,
            "publication_allowed": candidate_state == "complete",
            "scan_mode": (
                "deterministic-fixture"
                if fixture_mode
                else _real_scan_mode(
                    local_count=sum(_requires_local_sandbox(server) for server in servers),
                    total_count=len(servers),
                )
            ),
            "catalog": {
                "seed_sha256": _sha256(seed_path),
                "server_count": len(catalog_rows),
            },
            "masking": {
                "sha256": _sha256(masked_path),
                "slugs": sorted(masked_slugs),
            },
            "sandbox": sandbox_evidence,
            "scan_counts": {
                "total": len(results),
                "fresh": sum(result["state"] == "fresh" for result in results),
                "masked": sum(result["state"] == "masked" for result in results),
                "failed": sum(result["state"] not in {"fresh", "masked"} for result in results),
            },
            "engine_versions": sorted(
                {
                    str(result["engine_version"])
                    for result in results
                    if result.get("engine_version")
                }
            ),
            "artifacts": _artifact_inventory(temporary),
            "authority": {
                "candidate_creation": True,
                "publication": False,
                "deployment": False,
                "schedule_change": False,
            },
        }
        _write_private(temporary / MANIFEST_NAME, manifest)
        manifest_digest = _sha256(temporary / MANIFEST_NAME)
        _write_private_text(
            temporary / MANIFEST_DIGEST_NAME,
            manifest_digest + "\n",
        )
        _make_files_read_only(temporary)
        os.replace(temporary, final)
        published = True
        _make_read_only(final)
    finally:
        if not published:
            shutil.rmtree(temporary, ignore_errors=True)

    verified = verify_refresh_candidate(
        final,
        now=fixed_now,
        expected_seed_path=seed_path,
        expected_masked_path=masked_path,
    )
    if not verified["structural_valid"]:
        raise RefreshCandidateError(
            "published candidate failed content verification: "
            + ",".join(str(error) for error in verified["errors"])
        )
    return final


def verify_refresh_candidate(
    candidate: Path,
    *,
    now: datetime | None = None,
    max_age_hours: int = DEFAULT_MAX_AGE_HOURS,
    expected_seed_path: Path | None = None,
    expected_masked_path: Path | None = None,
) -> dict[str, object]:
    """Verify manifest, every artifact, freshness, masking, and partial state."""
    fixed_now = now or datetime.now(tz=UTC)
    if fixed_now.tzinfo is None:
        fixed_now = fixed_now.replace(tzinfo=UTC)
    errors: list[str] = []
    if not candidate.is_dir() or candidate.is_symlink():
        return {
            "structural_valid": False,
            "state": "missing" if not candidate.exists() else "invalid",
            "publication_ready": False,
            "errors": ["candidate_missing_or_not_directory"],
        }
    for path in candidate.rglob("*"):
        if path.is_symlink():
            errors.append(f"symlink:{path.relative_to(candidate).as_posix()}")
        elif path.is_file() and path.stat().st_mode & 0o222:
            errors.append(f"writable_artifact:{path.relative_to(candidate).as_posix()}")
        elif path.is_dir() and path.stat().st_mode & 0o222:
            errors.append(f"writable_directory:{path.relative_to(candidate).as_posix()}")
    if candidate.stat().st_mode & 0o222:
        errors.append("writable_candidate_root")

    manifest_path = candidate / MANIFEST_NAME
    digest_path = candidate / MANIFEST_DIGEST_NAME
    try:
        manifest = _load_json(manifest_path)
        expected_manifest_digest = digest_path.read_text(encoding="utf-8").strip()
    except (OSError, RefreshCandidateError):
        manifest = {}
        expected_manifest_digest = ""
        errors.append("manifest_unreadable")
    actual_manifest_digest = _sha256(manifest_path) if manifest_path.is_file() else None
    if not expected_manifest_digest or expected_manifest_digest != actual_manifest_digest:
        errors.append("manifest_digest_mismatch")
    if not isinstance(manifest, dict) or manifest.get("schema") != CANDIDATE_SCHEMA:
        errors.append("manifest_schema_invalid")
        manifest = {}

    listed: set[str] = set()
    artifacts = manifest.get("artifacts")
    if not isinstance(artifacts, list):
        errors.append("artifact_manifest_invalid")
        artifacts = []
    for artifact in artifacts:
        if not isinstance(artifact, dict) or not isinstance(artifact.get("path"), str):
            errors.append("artifact_manifest_invalid")
            continue
        relative = artifact["path"]
        listed.add(relative)
        path = candidate / relative
        if (
            not path.is_file()
            or path.is_symlink()
            or path.stat().st_size != artifact.get("bytes")
            or _sha256(path) != artifact.get("sha256")
        ):
            errors.append(f"artifact_mismatch:{relative}")
    actual = {
        relative
        for path in candidate.rglob("*")
        if path.is_file()
        and (relative := path.relative_to(candidate).as_posix())
        not in {MANIFEST_NAME, MANIFEST_DIGEST_NAME}
    }
    if actual != listed:
        errors.append("artifact_set_mismatch")

    created_at: datetime | None = None
    try:
        created_at = datetime.fromisoformat(str(manifest["created_at"]).replace("Z", "+00:00"))
        if created_at.tzinfo is None:
            created_at = created_at.replace(tzinfo=UTC)
        age_seconds = (fixed_now.astimezone(UTC) - created_at.astimezone(UTC)).total_seconds()
        age_hours = max(0.0, age_seconds / 3600)
        if age_seconds < 0:
            errors.append("candidate_timestamp_in_future")
    except (KeyError, ValueError, TypeError):
        age_hours = None
        errors.append("candidate_timestamp_invalid")

    results_payload: Any = {}
    snapshot_payload: Any = {}
    catalog_payload: Any = {}
    try:
        results_payload = _load_json(candidate / "scan_results.json")
        snapshot_payload = _load_json(candidate / "static_snapshot.json")
        catalog_payload = _load_json(candidate / "catalog_identity.json")
    except RefreshCandidateError:
        errors.append("candidate_projection_unreadable")
    results = results_payload.get("results") if isinstance(results_payload, dict) else None
    if not isinstance(results, list):
        errors.append("scan_results_invalid")
        results = []
    catalog_rows = catalog_payload.get("servers") if isinstance(catalog_payload, dict) else None
    if (
        not isinstance(catalog_payload, dict)
        or catalog_payload.get("schema") != "RefreshCatalogIdentityV1"
        or not isinstance(catalog_rows, list)
    ):
        errors.append("catalog_identity_invalid")
        catalog_payload = {}
        catalog_rows = []
    catalog_slugs = {
        row.get("slug")
        for row in catalog_rows
        if isinstance(row, dict) and isinstance(row.get("slug"), str)
    }
    catalog_by_slug = {
        row["slug"]: row
        for row in catalog_rows
        if isinstance(row, dict) and isinstance(row.get("slug"), str)
    }
    result_slugs = {
        result.get("server_slug")
        for result in results
        if isinstance(result, dict) and isinstance(result.get("server_slug"), str)
    }
    if (
        len(catalog_slugs) != len(catalog_rows)
        or len(result_slugs) != len(results)
        or result_slugs != catalog_slugs
    ):
        errors.append("catalog_scan_coverage_mismatch")
    manifest_catalog = manifest.get("catalog")
    if (
        not isinstance(manifest_catalog, dict)
        or manifest_catalog.get("server_count") != len(catalog_rows)
        or catalog_payload.get("server_count") != len(catalog_rows)
        or manifest_catalog.get("seed_sha256") != catalog_payload.get("seed_sha256")
    ):
        errors.append("catalog_manifest_mismatch")
    manifest_masking = manifest.get("masking")
    declared_masked_slugs = (
        manifest_masking.get("slugs") if isinstance(manifest_masking, dict) else None
    )
    if (
        not isinstance(manifest_masking, dict)
        or not isinstance(manifest_masking.get("sha256"), str)
        or not isinstance(declared_masked_slugs, list)
        or not all(isinstance(slug, str) for slug in declared_masked_slugs)
        or len(set(declared_masked_slugs)) != len(declared_masked_slugs)
    ):
        errors.append("masking_manifest_invalid")
        manifest_masking = {}
        declared_masked_slugs = []
    reviewed_inputs_bound = False
    if (expected_seed_path is None) != (expected_masked_path is None):
        errors.append("reviewed_inputs_incomplete")
    elif expected_seed_path is not None and expected_masked_path is not None:
        try:
            expected_catalog_slugs, expected_catalog_rows = _catalog_slugs(expected_seed_path)
            expected_masked_slugs = _load_string_list(expected_masked_path)
            reviewed_inputs_bound = bool(
                catalog_rows == expected_catalog_rows
                and catalog_slugs == expected_catalog_slugs
                and manifest_catalog.get("seed_sha256") == _sha256(expected_seed_path)
                and manifest_masking.get("sha256") == _sha256(expected_masked_path)
                and set(declared_masked_slugs) == expected_masked_slugs
            )
            if not reviewed_inputs_bound:
                errors.append("reviewed_inputs_mismatch")
        except (OSError, RefreshCandidateError, TypeError, ValueError):
            errors.append("reviewed_inputs_unavailable")
    candidate_state = manifest.get("candidate_state")
    scan_mode = manifest.get("scan_mode")
    catalog_remote_count = sum(
        isinstance(row, dict)
        and isinstance(row.get("source"), dict)
        and row["source"].get("kind") == "remote"
        and row["source"].get("command") is None
        for row in catalog_rows
    )
    expected_real_scan_mode = _real_scan_mode(
        local_count=len(catalog_rows) - catalog_remote_count,
        total_count=len(catalog_rows),
    )
    sandbox_manifest = manifest.get("sandbox")
    sandbox_profiles = (
        sandbox_manifest.get("profiles") if isinstance(sandbox_manifest, dict) else None
    )
    sandbox_profile_rows = sandbox_profiles if isinstance(sandbox_profiles, list) else []
    reviewed_profile_images = {
        profile.get("image")
        for profile in sandbox_profile_rows
        if isinstance(profile, dict)
        and isinstance(profile.get("image"), str)
        and profile.get("kind") == "docker"
        and profile.get("network") == "none"
        and profile.get("read_only_root") is True
        and profile.get("capabilities") == "dropped-all"
        and profile.get("no_new_privileges") is True
        and isinstance(profile.get("memory"), str)
        and isinstance(profile.get("pids_limit"), int)
        and isinstance(profile.get("cpus"), str)
        and isinstance(profile.get("user"), str)
        and isinstance(profile.get("tmpfs"), str)
    }
    successful_results = [
        result
        for result in results
        if isinstance(result, dict) and result.get("state") in {"fresh", "masked"}
    ]
    if candidate_state == "complete":
        for result in successful_results:
            slug = result.get("server_slug")
            slug_label = str(slug) if isinstance(slug, str) else "unknown"
            try:
                scanned_at = datetime.fromisoformat(
                    str(result["scanned_at"]).replace("Z", "+00:00")
                )
                if scanned_at.tzinfo is None:
                    scanned_at = scanned_at.replace(tzinfo=UTC)
            except (KeyError, ValueError, TypeError):
                errors.append(f"scan_timestamp_invalid:{slug_label}")
                continue
            scan_age_seconds = (
                fixed_now.astimezone(UTC) - scanned_at.astimezone(UTC)
            ).total_seconds()
            if scan_age_seconds < 0:
                errors.append(f"scan_timestamp_in_future:{slug_label}")
            elif scan_age_seconds / 3600 > max_age_hours:
                errors.append(f"scan_timestamp_stale:{slug_label}")
            recorded_age = result.get("scan_age_days")
            if created_at is None or not isinstance(recorded_age, (int, float)):
                errors.append(f"scan_age_invalid:{slug_label}")
            else:
                expected_age = _scan_age_days(scanned_at, created_at)
                if abs(float(recorded_age) - expected_age) > 0.000001:
                    errors.append(f"scan_age_mismatch:{slug_label}")
    expected_artifacts = {
        "registry.db",
        "catalog_identity.json",
        "scan_results.json",
        "static_snapshot.json",
    }
    expected_artifacts.update(
        f"receipts/{receipt_ref}"
        for result in results
        if isinstance(result, dict)
        and result.get("state") == "fresh"
        and isinstance((receipt_ref := result.get("receipt")), str)
    )
    if actual != expected_artifacts:
        errors.append("unreferenced_candidate_artifact")
    for result in results:
        if not isinstance(result, dict) or result.get("state") not in {
            "fresh",
            "masked",
        }:
            continue
        if result.get("state") == "masked":
            if (
                result.get("receipt") is not None
                or result.get("scan_id") is not None
                or result.get("receipt_visibility") != "withheld"
                or result.get("fresh_grade") is not None
                or result.get("transparency") is not None
                or result.get("drift") is not None
            ):
                errors.append("masked_scan_evidence_exposed")
            if candidate_state == "complete" and result.get("engine_name") != "mcpaudit":
                errors.append("masked_scan_provenance_invalid")
            continue
        receipt_ref = result.get("receipt")
        if not isinstance(receipt_ref, str) or "/" in receipt_ref or "\\" in receipt_ref:
            errors.append("successful_scan_receipt_ref_invalid")
            continue
        try:
            receipt = _load_json(candidate / "receipts" / receipt_ref)
        except RefreshCandidateError:
            errors.append(f"successful_scan_receipt_missing:{receipt_ref}")
            continue
        if (
            not isinstance(receipt, dict)
            or receipt.get("server_slug") != result.get("server_slug")
            or receipt.get("scan_id") != result.get("scan_id")
        ):
            errors.append(f"successful_scan_receipt_mismatch:{receipt_ref}")
            continue
        if not _fresh_result_matches_persisted_scan(
            candidate,
            result=result,
            receipt=receipt,
        ):
            errors.append(f"fresh_scan_binding_mismatch:{receipt_ref}")
        if candidate_state == "complete":
            scanner = receipt.get("scanner")
            sandbox = receipt.get("sandbox")
            receipt_server = receipt.get("server")
            reviewed_server: Server | None = None
            catalog_row = catalog_by_slug.get(result.get("server_slug"))
            if isinstance(catalog_row, dict) and isinstance(receipt_server, dict):
                try:
                    reviewed_server = _reviewed_server_from_seed(
                        catalog_row,
                        added_at=datetime.fromisoformat(
                            str(receipt_server.get("added_at")).replace("Z", "+00:00")
                        ),
                    )
                except (RefreshCandidateError, TypeError, ValueError):
                    reviewed_server = None
            catalog_bound = bool(
                reviewed_server is not None
                and isinstance(receipt_server, dict)
                and receipt_server == reviewed_server.model_dump(mode="json")
            )
            remote_without_command = bool(
                reviewed_server is not None and not _requires_local_sandbox(reviewed_server)
            )
            receipt_image = (
                sandbox.get("MCP_TRUST_SANDBOX_IMAGE") if isinstance(sandbox, dict) else None
            )
            reviewed_image = (
                reviewed_server.source.sandbox_image if reviewed_server is not None else None
            )
            local_image_valid = bool(
                isinstance(receipt_image, str)
                and receipt_image in reviewed_profile_images
                and (reviewed_image is None or receipt_image == reviewed_image)
            )
            sandbox_valid = bool(
                catalog_bound
                and isinstance(sandbox, dict)
                and (
                    (
                        sandbox.get("mode") == "not_applicable"
                        and sandbox.get("reason") == "remote_endpoint_no_local_process"
                    )
                    if remote_without_command
                    else (
                        sandbox.get("MCP_TRUST_SANDBOX") == "docker"
                        and sandbox.get("MCP_TRUST_SANDBOX_NETWORK") == "none"
                        and local_image_valid
                    )
                )
            )
            if (
                result.get("engine_name") != "mcpaudit"
                or not isinstance(scanner, dict)
                or scanner.get("engine_name") != "mcpaudit"
                or not sandbox_valid
            ):
                errors.append(f"publishable_scan_provenance_invalid:{receipt_ref}")
    excluded = {
        result.get("server_slug")
        for result in results
        if isinstance(result, dict) and result.get("state") not in {"fresh"}
    }
    snapshot_servers = (
        snapshot_payload.get("servers") if isinstance(snapshot_payload, dict) else None
    )
    if not isinstance(snapshot_servers, list):
        errors.append("static_snapshot_invalid")
        snapshot_servers = []
    exposed = {server.get("slug") for server in snapshot_servers if isinstance(server, dict)}
    if excluded & exposed:
        errors.append("failed_or_masked_grade_exposed")
    fresh_slugs = {
        result.get("server_slug")
        for result in results
        if isinstance(result, dict) and result.get("state") == "fresh"
    }
    if candidate_state != "fixture" and exposed != fresh_slugs:
        errors.append("static_snapshot_coverage_mismatch")
    if age_hours is not None and created_at is not None:
        try:
            from mcp_trust.catalog.snapshot import build_snapshot

            expected_snapshot = build_snapshot(
                str(candidate / "registry.db"),
                excluded_slugs=frozenset(str(slug) for slug in excluded if isinstance(slug, str)),
                masked_slugs=frozenset(
                    str(result.get("server_slug"))
                    for result in results
                    if isinstance(result, dict) and result.get("state") == "masked"
                ),
                verified_local_network=(None if candidate_state == "fixture" else "none"),
                now=created_at,
            )
            if snapshot_payload != expected_snapshot:
                errors.append("static_snapshot_scan_binding_mismatch")
        except (OSError, sqlite3.Error, TypeError, ValueError):
            errors.append("static_snapshot_scan_binding_unavailable")
    for server in snapshot_servers:
        if isinstance(server, dict) and not isinstance(server.get("scan_age_days"), (int, float)):
            errors.append("scan_age_missing")

    scan_counts = manifest.get("scan_counts")
    if not isinstance(scan_counts, dict):
        errors.append("scan_counts_invalid")
    else:
        expected_counts = {
            "total": len(results),
            "fresh": sum(
                isinstance(result, dict) and result.get("state") == "fresh" for result in results
            ),
            "masked": sum(
                isinstance(result, dict) and result.get("state") == "masked" for result in results
            ),
            "failed": len(results) - len(successful_results),
        }
        if scan_counts != expected_counts:
            errors.append("scan_counts_mismatch")
    if candidate_state == "complete":
        if (
            scan_mode != expected_real_scan_mode
            or len(successful_results) != len(results)
            or manifest.get("publication_allowed") is not True
            or len(snapshot_servers)
            != sum(
                isinstance(result, dict) and result.get("state") == "fresh" for result in results
            )
        ):
            errors.append("complete_candidate_semantics_invalid")
    elif manifest.get("publication_allowed") is not False:
        errors.append("noncomplete_candidate_claims_publication")
    authority = manifest.get("authority")
    if authority != {
        "candidate_creation": True,
        "publication": False,
        "deployment": False,
        "schedule_change": False,
    }:
        errors.append("candidate_authority_invalid")

    masked_slugs = sorted(
        str(result.get("server_slug"))
        for result in results
        if isinstance(result, dict) and result.get("state") == "masked"
    )
    if masked_slugs != sorted(declared_masked_slugs):
        errors.append("masked_result_authorization_mismatch")
    if masked_slugs:
        try:
            candidate_db = sqlite3.connect(
                f"file:{candidate / 'registry.db'}?mode=ro",
                uri=True,
            )
            try:
                placeholders = ",".join("?" for _ in masked_slugs)
                leaked_count = candidate_db.execute(
                    f"SELECT COUNT(*) FROM scans WHERE server_slug IN ({placeholders})",
                    masked_slugs,
                ).fetchone()[0]
            finally:
                candidate_db.close()
            if leaked_count:
                errors.append("masked_scan_database_history_exposed")
        except (OSError, sqlite3.Error, TypeError):
            errors.append("candidate_database_unreadable")

    structural_valid = not errors
    stale = age_hours is not None and age_hours > max_age_hours
    publication_ready = bool(
        structural_valid
        and not stale
        and candidate_state == "complete"
        and manifest.get("publication_allowed") is True
        and reviewed_inputs_bound
    )
    return {
        "structural_valid": structural_valid,
        "state": "invalid" if errors else "stale" if stale else str(candidate_state),
        "candidate_state": candidate_state,
        "publication_ready": publication_ready,
        "manifest_sha256": actual_manifest_digest,
        "age_hours": round(age_hours, 6) if age_hours is not None else None,
        "scan_counts": manifest.get("scan_counts"),
        "reviewed_inputs_bound": reviewed_inputs_bound,
        "errors": sorted(set(errors)),
    }


def approve_refresh_candidate(
    *,
    candidate: Path,
    approval_path: Path,
    actor: str,
    reason: str,
    publication_target: Path,
    confirmation_digest: str,
    seed_path: Path,
    masked_path: Path,
    now: datetime | None = None,
    ttl_hours: int = 4,
) -> Path:
    """Create a short-lived approval bound to one verified candidate and target."""
    fixed_now = now or datetime.now(tz=UTC)
    verification = verify_refresh_candidate(
        candidate,
        now=fixed_now,
        expected_seed_path=seed_path,
        expected_masked_path=masked_path,
    )
    if not verification["publication_ready"]:
        raise RefreshCandidateError("candidate is not complete, current, and publishable")
    digest = verification["manifest_sha256"]
    if confirmation_digest != digest:
        raise RefreshCandidateError("approval confirmation digest does not match candidate")
    if not actor.strip() or not reason.strip():
        raise RefreshCandidateError("approval actor and reason are required")
    if approval_path.exists():
        raise RefreshCandidateError(f"approval already exists: {approval_path}")
    approval_path.parent.mkdir(parents=True, exist_ok=True)
    _write_private(
        approval_path,
        {
            "schema": APPROVAL_SCHEMA,
            "candidate_manifest_sha256": digest,
            "approved_at": fixed_now.isoformat(),
            "expires_at": (fixed_now + timedelta(hours=ttl_hours)).isoformat(),
            "actor": actor,
            "reason": reason,
            "publication_target": str(publication_target.resolve()),
            "reviewed_seed_sha256": _sha256(seed_path),
            "reviewed_masked_sha256": _sha256(masked_path),
            "deployment_authority": False,
        },
    )
    return approval_path


def publish_refresh_candidate(
    *,
    candidate: Path,
    approval_path: Path | None,
    destination_parent: Path,
    seed_path: Path,
    masked_path: Path,
    now: datetime | None = None,
) -> Path:
    """Atomically stage an approved candidate locally; never deploy it."""
    if approval_path is None:
        raise RefreshCandidateError("publication approval is required")
    fixed_now = now or datetime.now(tz=UTC)
    verification = verify_refresh_candidate(
        candidate,
        now=fixed_now,
        expected_seed_path=seed_path,
        expected_masked_path=masked_path,
    )
    if not verification["publication_ready"]:
        raise RefreshCandidateError("candidate failed immediate publication verification")
    approval = _load_json(approval_path)
    if not isinstance(approval, dict) or approval.get("schema") != APPROVAL_SCHEMA:
        raise RefreshCandidateError("publication approval is invalid")
    try:
        expires = datetime.fromisoformat(str(approval["expires_at"]).replace("Z", "+00:00"))
        if expires.tzinfo is None:
            expires = expires.replace(tzinfo=UTC)
    except (KeyError, ValueError, TypeError) as exc:
        raise RefreshCandidateError("publication approval expiry is invalid") from exc
    if expires <= fixed_now.astimezone(UTC):
        raise RefreshCandidateError("publication approval is expired")
    if approval.get("candidate_manifest_sha256") != verification["manifest_sha256"]:
        raise RefreshCandidateError("publication approval is bound to another candidate")
    if approval.get("publication_target") != str(destination_parent.resolve()):
        raise RefreshCandidateError("publication approval is bound to another target")
    if approval.get("reviewed_seed_sha256") != _sha256(seed_path) or approval.get(
        "reviewed_masked_sha256"
    ) != _sha256(masked_path):
        raise RefreshCandidateError("publication approval is bound to other reviewed inputs")
    if approval.get("deployment_authority") is not False:
        raise RefreshCandidateError("publication approval has an invalid authority claim")

    destination_parent.mkdir(parents=True, exist_ok=True)
    final = destination_parent / candidate.name
    if final.exists():
        raise RefreshCandidateError(f"publication already exists: {final}")
    temporary = Path(tempfile.mkdtemp(prefix=f".{candidate.name}.publish-", dir=destination_parent))
    published = False
    try:
        shutil.copytree(candidate, temporary / "candidate", copy_function=shutil.copy2)
        copied_verification = verify_refresh_candidate(
            temporary / "candidate",
            now=fixed_now,
            expected_seed_path=seed_path,
            expected_masked_path=masked_path,
        )
        if (
            not copied_verification["publication_ready"]
            or copied_verification["manifest_sha256"] != verification["manifest_sha256"]
        ):
            raise RefreshCandidateError("copied candidate failed immediate publication readback")
        _write_private(
            temporary / "PUBLICATION.json",
            {
                "schema": PUBLICATION_SCHEMA,
                "published_at": fixed_now.isoformat(),
                "candidate_manifest_sha256": verification["manifest_sha256"],
                "approval_sha256": _sha256(approval_path),
                "deployment_performed": False,
            },
        )
        _make_files_read_only(temporary)
        os.replace(temporary, final)
        published = True
        _make_read_only(final)
    finally:
        if not published:
            shutil.rmtree(temporary, ignore_errors=True)
    return final
