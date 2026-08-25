"""FastAPI application — serves the MCP Trust Registry HTTP API."""

from __future__ import annotations

import json
import os
import secrets
import sqlite3
import uuid
from collections.abc import Callable
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import HTMLResponse
from pydantic import BaseModel

from mcp_trust.core import grading
from mcp_trust.core.drift import latest_grade_change
from mcp_trust.core.governance import FreshnessState
from mcp_trust.core.models import ScanRecord, Server, TrustGrade
from mcp_trust.core.provenance import DEMO_DISCLOSURE, ScanProvenance, classify, is_real_engine
from mcp_trust.core.public_projection import (
    project_public_scan,
    project_public_server,
    project_public_summary,
)
from mcp_trust.engine.base import ScanEngine, ScanError
from mcp_trust.receipts import write_scan_receipt
from mcp_trust.site.badges import badge_payload
from mcp_trust.store.db import connect, init_schema
from mcp_trust.store.repository import ScanRepository, ServerRepository

_SCAN_TOKEN_ENV = "MCP_TRUST_SCAN_TOKEN"
_SCAN_TOKEN_HEADER = "x-mcp-trust-scan-token"
_PUBLIC_READONLY_ENV = "MCP_TRUST_PUBLIC_READONLY"
_ALLOW_UNAUTHENTICATED_STUB_SCANS_ENV = "MCP_TRUST_ALLOW_UNAUTHENTICATED_STUB_SCANS"
_TRUE_ENV_VALUES = {"1", "true", "yes", "on"}


class ServerSummary(BaseModel):
    slug: str
    name: str
    grade: str
    transparency: str | None
    composite: float | None
    scanned_at: datetime | None
    provenance: str
    stale: bool | None
    masked: bool = False
    operator_masked: bool = False
    grade_withheld: bool = False
    freshness_state: str
    freshness_reason: str
    scan_age_days: float | None
    stale_after: datetime | None


def _is_real_scan_engine(engine: ScanEngine) -> bool:
    return is_real_engine(str(getattr(engine, "name", "")))


def _env_flag(name: str) -> bool:
    return os.environ.get(name, "").strip().lower() in _TRUE_ENV_VALUES


def _presented_scan_token(request: Request) -> str:
    auth_header = request.headers.get("authorization", "")
    scheme, _, token = auth_header.partition(" ")
    if scheme.lower() == "bearer" and token:
        return token
    return request.headers.get(_SCAN_TOKEN_HEADER, "")


def _authorize_scan_trigger(request: Request, engine: ScanEngine) -> None:
    if _env_flag(_PUBLIC_READONLY_ENV):
        raise HTTPException(
            status_code=403,
            detail=(
                f"Scan triggering is disabled in public read-only mode ({_PUBLIC_READONLY_ENV}=1)."
            ),
        )

    if not _is_real_scan_engine(engine) and _env_flag(_ALLOW_UNAUTHENTICATED_STUB_SCANS_ENV):
        return

    expected = os.environ.get(_SCAN_TOKEN_ENV)
    if not expected:
        raise HTTPException(
            status_code=403,
            detail=(f"Scan triggering is disabled until {_SCAN_TOKEN_ENV} is configured."),
        )

    presented = _presented_scan_token(request)
    if not presented or not secrets.compare_digest(presented, expected):
        raise HTTPException(status_code=401, detail="Valid scan trigger token required.")


def _public_scan_payload(
    scan: ScanRecord | None,
    *,
    masked: bool,
    now: datetime | None = None,
    unreadable: bool = False,
) -> dict[str, Any] | None:
    return project_public_scan(
        scan,
        now=now or datetime.now(tz=UTC),
        operator_masked=masked,
        unreadable=unreadable,
    )


def _public_server_payload(server: Server, *, masked: bool) -> dict[str, Any]:
    return project_public_server(server, operator_masked=masked)


# ---------------------------------------------------------------------------
# Factory
# ---------------------------------------------------------------------------


def _runtime_masked_slugs() -> set[str]:
    """Load the mandatory public-runtime masking input fail-closed."""
    configured = os.environ.get("MCP_TRUST_MASKED_GRADES")
    public_readonly = os.environ.get(_PUBLIC_READONLY_ENV, "0").strip().lower() in _TRUE_ENV_VALUES
    if configured is None:
        if public_readonly:
            raise RuntimeError(
                "MCP_TRUST_MASKED_GRADES is required when MCP_TRUST_PUBLIC_READONLY=1"
            )
        return set()
    try:
        loaded = json.loads(Path(configured).read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise RuntimeError("runtime masked-grades input is unreadable") from exc
    if (
        not isinstance(loaded, list)
        or not all(isinstance(slug, str) and slug for slug in loaded)
        or len(loaded) != len(set(loaded))
    ):
        raise RuntimeError("runtime masked-grades input must be a unique string list")
    return set(loaded)


def _validate_masked_slugs(conn: sqlite3.Connection, masked_slugs: set[str]) -> None:
    catalog_slugs = {server.slug for server in ServerRepository(conn).list()}
    unknown = sorted(masked_slugs - catalog_slugs)
    if unknown:
        raise RuntimeError(
            "runtime masked-grades contains unknown catalog slug(s): " + ",".join(unknown)
        )


def create_app(
    conn: sqlite3.Connection | None = None,
    engine: ScanEngine | None = None,
    corrections: list[dict] | None = None,
    masked_slugs: set[str] | None = None,
    clock: Callable[[], datetime] | None = None,
) -> FastAPI:
    """Build and return a configured ``FastAPI`` instance.

    Parameters
    ----------
    conn:
        SQLite connection to use. If ``None`` the connection is opened from
        the ``MCP_TRUST_DB`` env var (default ``./mcp-trust.db``).
    engine:
        Scan engine to use. If ``None`` the engine is selected via
        ``select_engine()`` (reads ``MCP_TRUST_ENGINE`` env var).
    corrections:
        Public corrections-log entries rendered at ``/ui/corrections``.
        ``None`` renders an empty log.
    masked_slugs:
        Slugs whose published grade is operator-withheld pending governance
        review (pages and badges render "withheld / under review").
    """
    _masked: set[str] = (
        set(masked_slugs) if masked_slugs is not None else _runtime_masked_slugs()
    )
    # Resolve dependencies lazily so module-level ``app`` doesn't open a DB
    # at import time in test environments.
    _conn: sqlite3.Connection | None = conn
    _engine: ScanEngine | None = engine
    _clock = clock or (lambda: datetime.now(tz=UTC))

    def _get_conn() -> sqlite3.Connection:
        nonlocal _conn
        if _conn is None:
            db_path = os.environ.get("MCP_TRUST_DB", "./mcp-trust.db")
            _conn = connect(db_path)
            init_schema(_conn)
            _validate_masked_slugs(_conn, _masked)
        return _conn

    def _get_engine() -> ScanEngine:
        nonlocal _engine
        if _engine is None:
            from mcp_trust.engine.factory import select_engine  # noqa: PLC0415

            _engine = select_engine()
        return _engine

    application = FastAPI(
        title="MCP Trust Registry",
        description="A neutral public trust registry for MCP servers.",
        version="0.1.0",
    )

    # Initialise schema on startup when using an injected connection (tests),
    # otherwise it's done lazily in _get_conn.
    if conn is not None:
        init_schema(conn)
        _validate_masked_slugs(conn, _masked)

    # -----------------------------------------------------------------------
    # Routes
    # -----------------------------------------------------------------------

    # Routes are ``async def`` so they run on the single event-loop thread
    # rather than FastAPI's threadpool — the shared SQLite connection is then
    # only ever touched by one thread. Repository calls are fast/local.

    @application.get("/healthz")
    async def healthz() -> dict[str, str]:
        return {"status": "ok"}

    @application.get("/servers", response_model=list[ServerSummary])
    async def list_servers() -> list[dict[str, Any]]:
        db = _get_conn()
        server_repo = ServerRepository(db)
        scan_repo = ScanRepository(db)

        servers = server_repo.list()
        latest_readback = scan_repo.latest_all_readback()
        latest = latest_readback.records

        result: list[dict[str, Any]] = []
        evaluated_at = _clock()
        for srv in servers:
            scan = latest.get(srv.slug)
            unknown_scan = srv.slug in latest_readback.unreadable_slugs
            result.append(
                project_public_summary(
                    srv,
                    scan,
                    now=evaluated_at,
                    operator_masked=srv.slug in _masked,
                    unreadable=unknown_scan,
                )
            )
        return result

    @application.get("/servers/{slug}")
    async def get_server(slug: str) -> dict[str, Any]:
        db = _get_conn()
        server_repo = ServerRepository(db)
        scan_repo = ScanRepository(db)

        server = server_repo.get(slug)
        if server is None:
            raise HTTPException(status_code=404, detail=f"Server {slug!r} not found.")

        try:
            scan = scan_repo.latest(slug)
        except (TypeError, ValueError):
            return {
                "server": _public_server_payload(server, masked=slug in _masked),
                "latest_scan": _public_scan_payload(
                    None,
                    masked=slug in _masked,
                    now=_clock(),
                    unreadable=True,
                ),
                "grade_change": None,
            }
        try:
            history = scan_repo.history(slug)
            grade_change: dict[str, Any] | None = None
        except (TypeError, ValueError):
            history = []
            grade_change = {
                "status": "UNKNOWN",
                "reason_codes": ["SCAN_HISTORY_UNREADABLE"],
            }
        operator_masked = slug in _masked
        scan_masked = operator_masked and scan is not None
        readable_grade_change = latest_grade_change(history)
        return {
            "server": _public_server_payload(server, masked=operator_masked),
            "latest_scan": _public_scan_payload(
                scan,
                masked=operator_masked,
                now=_clock(),
            ),
            "grade_change": (
                None
                if scan_masked
                else grade_change
                or (
                    readable_grade_change.model_dump(mode="json")
                    if readable_grade_change
                    else None
                )
            ),
        }

    @application.post("/servers/{slug}/scan")
    async def scan_server(slug: str, request: Request) -> dict[str, Any]:
        db = _get_conn()
        server_repo = ServerRepository(db)
        scan_repo = ScanRepository(db)

        server = server_repo.get(slug)
        if server is None:
            raise HTTPException(status_code=404, detail=f"Server {slug!r} not found.")

        engine = _get_engine()
        _authorize_scan_trigger(request, engine)
        try:
            result = engine.scan(server.source)
        except ScanError as exc:
            # Engine unavailable (e.g. mcp-audits not installed) or scan failed:
            # surface as 503 so callers can distinguish from a 404/500.
            raise HTTPException(status_code=503, detail=str(exc)) from exc
        trust_grade = grading.grade(result.risk)
        trust_transparency = grading.transparency(result.risk)

        scan = ScanRecord(
            id=uuid.uuid4().hex,
            server_slug=slug,
            engine_name=result.engine_name,
            engine_version=result.engine_version,
            grade=trust_grade,
            transparency=trust_transparency,
            risk=result.risk,
            findings=result.findings,
            evidence=result.evidence,
            scanned_at=_clock(),
            sandbox_image=result.sandbox_image,
            report_ref=None,
        )
        receipt_ref = write_scan_receipt(server, scan)
        if receipt_ref is not None:
            scan = scan.model_copy(update={"report_ref": receipt_ref})
        scan_repo.record(scan)
        public_scan = _public_scan_payload(scan, masked=slug in _masked, now=_clock())
        assert public_scan is not None
        return public_scan

    @application.get("/servers/{slug}/badge.json")
    async def badge(slug: str) -> dict[str, Any]:
        db = _get_conn()
        server_repo = ServerRepository(db)
        scan_repo = ScanRepository(db)

        server = server_repo.get(slug)
        if server is None:
            raise HTTPException(status_code=404, detail=f"Server {slug!r} not found.")

        try:
            scan = scan_repo.latest(slug)
        except (TypeError, ValueError):
            return badge_payload("unknown", ScanProvenance.UNKNOWN)
        # Single payload path with the static badge files (site.badges), so the
        # live embed endpoint can never diverge on provenance, staleness, or
        # operator masking.
        projected = project_public_scan(
            scan,
            now=_clock(),
            operator_masked=slug in _masked,
        )
        if projected is not None and projected["freshness_state"] == str(FreshnessState.UNKNOWN):
            return badge_payload("unknown", ScanProvenance.UNKNOWN)
        stale = bool(projected and projected["stale"] is True)
        masked = bool(projected and projected["grade_withheld"] and slug in _masked)
        grade_str = str(scan.grade) if scan else str(TrustGrade.UNSCANNED)
        return badge_payload(grade_str, classify(scan), stale=stale, masked=masked)

    # -----------------------------------------------------------------------
    # HTML routes
    # -----------------------------------------------------------------------

    @application.get("/", response_class=HTMLResponse)
    async def catalog_page(request: Request) -> HTMLResponse:
        from mcp_trust.api.web import render_catalog  # noqa: PLC0415

        db = _get_conn()
        server_repo = ServerRepository(db)
        scan_repo = ScanRepository(db)

        servers = server_repo.list()
        latest_readback = scan_repo.latest_all_readback()
        latest = latest_readback.records

        rows = []
        has_demo = False
        evaluated_at = _clock()
        for srv in servers:
            scan = latest.get(srv.slug)
            unknown_scan = srv.slug in latest_readback.unreadable_slugs
            has_demo = has_demo or classify(scan) is ScanProvenance.DEMO
            rows.append(
                project_public_summary(
                    srv,
                    scan,
                    now=evaluated_at,
                    operator_masked=srv.slug in _masked,
                    unreadable=unknown_scan,
                )
            )
        return HTMLResponse(
            content=render_catalog(
                rows,
                banner=DEMO_DISCLOSURE if has_demo else None,
                now=evaluated_at,
            )
        )

    @application.get("/ui/servers/{slug}", response_class=HTMLResponse)
    async def server_detail_page(slug: str, request: Request) -> HTMLResponse:
        from mcp_trust.api.web import render_detail, render_not_found  # noqa: PLC0415

        db = _get_conn()
        server_repo = ServerRepository(db)
        scan_repo = ScanRepository(db)

        server = server_repo.get(slug)
        if server is None:
            return HTMLResponse(content=render_not_found(slug), status_code=404)

        try:
            latest_scan = scan_repo.latest(slug)
            unknown_scan = False
        except (TypeError, ValueError):
            history = []
            latest_scan = None
            unknown_scan = True
            unknown_history = False
        else:
            try:
                history = scan_repo.history(slug)
                unknown_history = False
            except (TypeError, ValueError):
                history = []
                unknown_history = True
        base_url = str(request.base_url).rstrip("/")
        return HTMLResponse(
            content=render_detail(
                server,
                latest_scan,
                base_url=base_url,
                banner=(
                    DEMO_DISCLOSURE
                    if classify(latest_scan) is ScanProvenance.DEMO
                    else None
                ),
                now=_clock(),
                masked=slug in _masked,
                unknown_scan=unknown_scan,
                unknown_history=unknown_history,
                history=history,
            )
        )

    @application.get("/ui/methodology", response_class=HTMLResponse)
    async def methodology_page() -> HTMLResponse:
        from mcp_trust.api.web import render_methodology  # noqa: PLC0415

        return HTMLResponse(content=render_methodology())

    @application.get("/ui/dispute", response_class=HTMLResponse)
    async def dispute_page() -> HTMLResponse:
        from mcp_trust.api.web import render_dispute  # noqa: PLC0415

        return HTMLResponse(content=render_dispute())

    @application.get("/ui/corrections", response_class=HTMLResponse)
    async def corrections_page() -> HTMLResponse:
        from mcp_trust.api.web import render_corrections  # noqa: PLC0415

        return HTMLResponse(content=render_corrections(corrections or []))

    return application


# Module-level app for uvicorn: ``uvicorn mcp_trust.api.app:app``
app = create_app()
