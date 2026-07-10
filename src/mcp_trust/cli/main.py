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
from mcp_trust.receipts import write_scan_receipt
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

_SITE_OUT_DEFAULT = "./site"
_SITE_BASE_URL_ENV = "MCP_TRUST_SITE_BASE_URL"
# Placeholder base URL: badge embeds only resolve once deployed at the real host,
# so building with this default emits a warning rather than implying a live URL.
_PLACEHOLDER_BASE_URL = "https://mcp-trust.example"


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
    trust_transparency = grading.transparency(result.risk)

    record = ScanRecord(
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
    receipt_ref = write_scan_receipt(server, record)
    if receipt_ref is not None:
        record = record.model_copy(update={"report_ref": receipt_ref})
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
        # Non-zero so CI gates can distinguish "no record" from "found, graded".
        raise typer.Exit(code=1)

    _print_scan(record)


@app.command()
def history(
    slug: Annotated[str, typer.Argument(help="Server slug to show scan history for.")],
    db: Annotated[
        str,
        typer.Option("--db", envvar=_DB_ENV, help=_DB_HELP),
    ] = _DB_DEFAULT,
    limit: Annotated[
        int | None,
        typer.Option("--limit", min=1, help="Show at most this many scans (newest first)."),
    ] = None,
) -> None:
    """Print the stored scan timeline for a server, newest first (no new scan)."""
    _, _, scan_repo = _open_db(db)

    records = scan_repo.history(slug, limit=limit)
    if not records:
        typer.echo(f"No scan on record for {slug!r}. Run 'mcp-trust scan <slug>' to generate one.")
        raise typer.Exit(code=1)

    typer.echo(f"Scan history for {slug} ({len(records)} scan(s), newest first):")
    for record in records:
        danger = grading.danger_score(record.risk)
        typer.echo(
            f"  {record.scanned_at.isoformat()}  grade={record.grade}  "
            f"transparency={record.transparency}  danger={danger:.2f}  "
            f"engine={record.engine_name} {record.engine_version}"
        )


@app.command()
def drift(
    slug: Annotated[
        str | None,
        typer.Argument(help="Server slug to compare. Omit to compare every catalog server."),
    ] = None,
    db: Annotated[
        str,
        typer.Option("--db", envvar=_DB_ENV, help=_DB_HELP),
    ] = _DB_DEFAULT,
    json_out: Annotated[
        bool,
        typer.Option("--json", help="Emit the full drift report as JSON (machine-readable)."),
    ] = False,
) -> None:
    """Compare each server's latest scan against the one before it and attribute
    any movement (surface change, engine change, score movement) — no new scan.

    Compares the scans on record: a server whose most recent re-scan failed
    contributes its previously recorded movement (each entry carries both scan
    timestamps, so consumers can see how fresh a comparison is).

    A report, not a gate: exits 0 whether or not movement was found. Exits 1
    only when a named server lacks the two readable scans a comparison needs.
    """
    from mcp_trust.core.drift import DriftCause, DriftReport, diff_latest  # noqa: PLC0415

    _, server_repo, scan_repo = _open_db(db)

    slugs = [slug] if slug is not None else [s.slug for s in server_repo.list()]
    drifts = []
    skipped_single_scan = 0
    skipped_invalid = 0
    for candidate in slugs:
        try:
            records = scan_repo.history(candidate, limit=2)
        except ValueError as exc:
            # One corrupt scan row must not poison the corpus-wide report;
            # surface the slug and keep comparing the rest.
            if slug is not None:
                typer.echo(f"Cannot read scan history for {candidate!r}: {exc}", err=True)
                raise typer.Exit(code=1) from exc
            typer.echo(f"WARN: skipping {candidate!r}: {exc}", err=True)
            skipped_invalid += 1
            continue
        result = diff_latest(records)
        if result is None:
            if slug is not None:
                typer.echo(
                    f"Need at least two scans of {candidate!r} to compare (found {len(records)}).",
                    err=True,
                )
                raise typer.Exit(code=1)
            skipped_single_scan += 1
            continue
        drifts.append(result)

    report = DriftReport(
        generated_at=datetime.now(tz=UTC),
        compared=len(drifts),
        skipped_single_scan=skipped_single_scan,
        skipped_invalid=skipped_invalid,
        drifts=drifts,
    )

    if json_out:
        typer.echo(report.model_dump_json(indent=2))
        return

    changed = [d for d in report.drifts if d.cause != DriftCause.NO_CHANGE]
    invalid_note = f", {skipped_invalid} unreadable" if skipped_invalid else ""
    typer.echo(
        f"Compared {report.compared} server(s) "
        f"({skipped_single_scan} skipped with fewer than two scans{invalid_note}): "
        f"{len(changed)} with movement."
    )
    for d in report.drifts if slug is not None else changed:
        typer.echo(
            f"  {d.server_slug}  [{d.cause}]  "
            f"(latest scan {d.current_scanned_at.date().isoformat()})  {d.summary}"
        )


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


@app.command(name="mcp-serve")
def mcp_serve() -> None:
    """Serve the trust catalog as a read-only MCP server over stdio.

    Reads the baked catalog snapshot (no database needed), so it runs anywhere
    via `uvx mcp-trust mcp-serve`. Distinct from `serve`, which is the HTTP API.
    """
    from mcp_trust.mcp_server import run  # noqa: PLC0415

    run()


@app.command(name="build-site")
def build_site(
    out: Annotated[
        str,
        typer.Option("--out", help="Output directory for the generated static site."),
    ] = _SITE_OUT_DEFAULT,
    base_url: Annotated[
        str,
        typer.Option(
            "--base-url",
            envvar=_SITE_BASE_URL_ENV,
            help="Absolute deployment URL used for badge-embed snippets.",
        ),
    ] = _PLACEHOLDER_BASE_URL,
    db: Annotated[
        str,
        typer.Option("--db", envvar=_DB_ENV, help=_DB_HELP),
    ] = _DB_DEFAULT,
) -> None:
    """Generate the static catalog site from the registry database.

    Read-only with respect to scanned servers: reads the database and writes
    HTML/JSON files. Grades from the stub engine are labelled as demo data.
    """
    from mcp_trust.site.generator import generate_site  # noqa: PLC0415

    conn, _, _ = _open_db(db)
    build = generate_site(conn, out, base_url=base_url)

    typer.echo(
        f"Built static site for {build.server_count} server(s) "
        f"({build.scanned_count} scanned) → {build.out_dir} "
        f"[{len(build.pages)} files]."
    )
    if base_url == _PLACEHOLDER_BASE_URL:
        typer.echo(
            "Note: using the placeholder --base-url; badge embeds resolve only "
            f"once deployed at the real host (set {_SITE_BASE_URL_ENV} or --base-url).",
        )


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
            f"[bold]Transparency:[/bold] {record.transparency}  "
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
        typer.echo(
            f"Grade:  {grade_str}  transparency: {record.transparency}  "
            f"(composite {composite:.1f}/10)"
        )
        if record.findings:
            typer.echo("Top findings:")
            for finding in record.findings[:5]:
                typer.echo(f"  [{finding.severity}] {finding.rule_id}: {finding.title}")
        else:
            typer.echo("No findings.")
