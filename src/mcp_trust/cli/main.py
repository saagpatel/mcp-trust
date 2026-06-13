"""MCP Trust CLI — ``mcp-trust`` entry point."""

from __future__ import annotations

import os
import sqlite3
import uuid
from datetime import UTC, datetime
from pathlib import Path
from typing import Annotated

import typer

from mcp_trust.core import grading
from mcp_trust.core.models import ScanRecord
from mcp_trust.store.db import connect, init_schema
from mcp_trust.store.repository import ScanRepository, ServerRepository

app = typer.Typer(
    name="mcp-trust",
    help="MCP Trust Registry — check MCP server trust grades before connecting.",
    add_completion=False,
)

# ---------------------------------------------------------------------------
# Shared option
# ---------------------------------------------------------------------------

_DB_HELP = "Path to the SQLite database file."
_DB_ENV = "MCP_TRUST_DB"
_DB_DEFAULT = "./mcp-trust.db"


def _open_db(db_path: str) -> tuple[sqlite3.Connection, ServerRepository, ScanRepository]:
    conn = connect(db_path)
    init_schema(conn)
    return conn, ServerRepository(conn), ScanRepository(conn)


# ---------------------------------------------------------------------------
# Commands
# ---------------------------------------------------------------------------


@app.command()
def seed(
    db: Annotated[
        str,
        typer.Option("--db", envvar=_DB_ENV, help=_DB_HELP),
    ] = _DB_DEFAULT,
) -> None:
    """Load the built-in server catalog into the database."""
    from mcp_trust.catalog.seed import seed_into  # noqa: PLC0415

    _, server_repo, _ = _open_db(db)
    count = seed_into(server_repo)
    typer.echo(f"Seeded {count} server(s) into {db}.")


@app.command()
def scan(
    slug: Annotated[str, typer.Argument(help="Server slug to scan.")],
    db: Annotated[
        str,
        typer.Option("--db", envvar=_DB_ENV, help=_DB_HELP),
    ] = _DB_DEFAULT,
    engine_name: Annotated[
        str | None,
        typer.Option("--engine", envvar="MCP_TRUST_ENGINE", help="Engine name."),
    ] = None,
) -> None:
    """Scan a catalog server and persist the result."""
    from mcp_trust.engine.factory import select_engine  # noqa: PLC0415

    _, server_repo, scan_repo = _open_db(db)

    server = server_repo.get(slug)
    if server is None:
        typer.echo(f"Error: server {slug!r} not found. Run 'mcp-trust seed' first.", err=True)
        raise typer.Exit(code=1)

    engine = select_engine(engine_name)
    result = engine.scan(server.source)
    trust_grade = grading.grade(result.risk)

    record = ScanRecord(
        id=uuid.uuid4().hex,
        server_slug=slug,
        engine_name=result.engine_name,
        engine_version=result.engine_version,
        grade=trust_grade,
        risk=result.risk,
        findings=result.findings,
        scanned_at=datetime.now(tz=UTC),
        report_ref=None,
    )
    scan_repo.record(record)

    _print_scan(record)


@app.command()
def check(
    slug: Annotated[str, typer.Argument(help="Server slug to check.")],
    db: Annotated[
        str,
        typer.Option("--db", envvar=_DB_ENV, help=_DB_HELP),
    ] = _DB_DEFAULT,
) -> None:
    """Print the latest stored trust grade for a server (no new scan)."""
    _, _, scan_repo = _open_db(db)

    record = scan_repo.latest(slug)
    if record is None:
        typer.echo(f"No scan on record for {slug!r}. Run 'mcp-trust scan <slug>' to generate one.")
        raise typer.Exit(code=0)

    _print_scan(record)


@app.command()
def serve(
    host: Annotated[str, typer.Option("--host", help="Bind host.")] = "127.0.0.1",
    port: Annotated[int, typer.Option("--port", help="Bind port.")] = 8000,
    db: Annotated[
        str,
        typer.Option("--db", envvar=_DB_ENV, help=_DB_HELP),
    ] = _DB_DEFAULT,
) -> None:
    """Start the HTTP API server (uvicorn)."""
    import uvicorn  # noqa: PLC0415

    # Pass DB path via environment so the module-level app picks it up.
    os.environ[_DB_ENV] = str(Path(db).resolve())
    uvicorn.run("mcp_trust.api.app:app", host=host, port=port)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _print_scan(record: ScanRecord) -> None:
    """Pretty-print a scan result, using rich if available."""
    grade_str = str(record.grade)
    composite = record.risk.composite

    try:
        from rich.console import Console  # noqa: PLC0415
        from rich.table import Table  # noqa: PLC0415

        console = Console()
        console.print(
            f"[bold]Server:[/bold] {record.server_slug}  "
            f"[bold]Grade:[/bold] {grade_str}  "
            f"[bold]Composite:[/bold] {composite:.1f}/10"
        )

        if record.findings:
            table = Table(title="Top Findings", show_lines=True)
            table.add_column("Severity", style="bold")
            table.add_column("Rule")
            table.add_column("Title")
            for finding in record.findings[:5]:
                table.add_row(str(finding.severity), finding.rule_id, finding.title)
            console.print(table)
        else:
            console.print("[green]No findings.[/green]")

    except ImportError:
        # Plain fallback when rich is not installed.
        typer.echo(f"Server: {record.server_slug}")
        typer.echo(f"Grade:  {grade_str}  (composite {composite:.1f}/10)")
        if record.findings:
            typer.echo("Top findings:")
            for finding in record.findings[:5]:
                typer.echo(f"  [{finding.severity}] {finding.rule_id}: {finding.title}")
        else:
            typer.echo("No findings.")
