"""FastAPI application — serves the MCP Trust Registry HTTP API."""

from __future__ import annotations

import os
import secrets
import sqlite3
import uuid
from datetime import UTC, datetime
from typing import Any

from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import HTMLResponse
from pydantic import BaseModel

from mcp_trust.core import grading
from mcp_trust.core.governance import (
    MASKED_BADGE_MESSAGE,
    MASKED_SERVER_DESCRIPTION,
    is_stale,
)
from mcp_trust.core.models import ScanRecord, Server, TrustGrade
from mcp_trust.core.provenance import classify, is_real_engine
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
    masked: bool = False


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


def _public_scan_payload(scan: ScanRecord | None, *, masked: bool) -> dict[str, Any] | None:
    if scan is None:
        return None
    payload = scan.model_dump(mode="json")
    payload["masked"] = masked
    if masked:
        payload.update(
            {
                "grade": MASKED_BADGE_MESSAGE,
                "transparency": None,
                "risk": None,
                "findings": None,
                "evidence": None,
                "report_ref": None,
                "withheld_reason": "grade_under_governance_review",
            }
        )
    return payload


def _public_server_payload(server: Server, *, masked: bool) -> dict[str, Any]:
    payload = server.model_dump(mode="json")
    if masked:
        payload["description"] = MASKED_SERVER_DESCRIPTION
    return payload


def _public_summary_grade(scan: ScanRecord | None, *, masked: bool) -> str:
    if scan is None:
        return str(TrustGrade.UNSCANNED)
    if masked:
        return MASKED_BADGE_MESSAGE
    return str(scan.grade)


# ---------------------------------------------------------------------------
# Factory
# ---------------------------------------------------------------------------


def create_app(
    conn: sqlite3.Connection | None = None,
    engine: ScanEngine | None = None,
    corrections: list[dict] | None = None,
    masked_slugs: set[str] | None = None,
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
    _masked: set[str] = masked_slugs or set()
    # Resolve dependencies lazily so module-level ``app`` doesn't open a DB
    # at import time in test environments.
    _conn: sqlite3.Connection | None = conn
    _engine: ScanEngine | None = engine

    def _get_conn() -> sqlite3.Connection:
        nonlocal _conn
        if _conn is None:
            db_path = os.environ.get("MCP_TRUST_DB", "./mcp-trust.db")
            _conn = connect(db_path)
            init_schema(_conn)
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
        latest = scan_repo.latest_all()

        result: list[dict[str, Any]] = []
        for srv in servers:
            scan = latest.get(srv.slug)
            masked = srv.slug in _masked and scan is not None
            result.append(
                {
                    "slug": srv.slug,
                    "name": srv.name,
                    "grade": _public_summary_grade(scan, masked=masked),
                    "transparency": None if masked else scan.transparency if scan else None,
                    "composite": None if masked else scan.risk.composite if scan else None,
                    "scanned_at": scan.scanned_at if scan else None,
                    "masked": masked,
                }
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

        scan = scan_repo.latest(slug)
        masked = slug in _masked and scan is not None
        return {
            "server": _public_server_payload(server, masked=masked),
            "latest_scan": _public_scan_payload(scan, masked=masked),
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
            scanned_at=datetime.now(tz=UTC),
            sandbox_image=result.sandbox_image,
            report_ref=None,
        )
        receipt_ref = write_scan_receipt(server, scan)
        if receipt_ref is not None:
            scan = scan.model_copy(update={"report_ref": receipt_ref})
        scan_repo.record(scan)
        return scan.model_dump(mode="json")

    @application.get("/servers/{slug}/badge.json")
    async def badge(slug: str) -> dict[str, Any]:
        db = _get_conn()
        server_repo = ServerRepository(db)
        scan_repo = ScanRepository(db)

        server = server_repo.get(slug)
        if server is None:
            raise HTTPException(status_code=404, detail=f"Server {slug!r} not found.")

        scan = scan_repo.latest(slug)
        # Single payload path with the static badge files (site.badges), so the
        # live embed endpoint can never diverge on provenance, staleness, or
        # operator masking.
        stale = scan is not None and is_stale(scan.scanned_at, datetime.now(tz=UTC))
        masked = slug in _masked and scan is not None
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
        latest = scan_repo.latest_all()

        rows = []
        for srv in servers:
            scan = latest.get(srv.slug)
            rows.append(
                {
                    "slug": srv.slug,
                    "name": srv.name,
                    "grade": str(scan.grade) if scan else str(TrustGrade.UNSCANNED),
                    "transparency": str(scan.transparency) if scan else "",
                    "composite": scan.risk.composite if scan else None,
                    "scanned_at": scan.scanned_at.isoformat() if scan else "",
                    "masked": srv.slug in _masked and scan is not None,
                }
            )
        return HTMLResponse(content=render_catalog(rows, now=datetime.now(tz=UTC)))

    @application.get("/ui/servers/{slug}", response_class=HTMLResponse)
    async def server_detail_page(slug: str, request: Request) -> HTMLResponse:
        from mcp_trust.api.web import render_detail, render_not_found  # noqa: PLC0415

        db = _get_conn()
        server_repo = ServerRepository(db)
        scan_repo = ScanRepository(db)

        server = server_repo.get(slug)
        if server is None:
            return HTMLResponse(content=render_not_found(slug), status_code=404)

        scan = scan_repo.latest(slug)
        base_url = str(request.base_url).rstrip("/")
        return HTMLResponse(
            content=render_detail(
                server,
                scan,
                base_url=base_url,
                now=datetime.now(tz=UTC),
                masked=slug in _masked,
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
