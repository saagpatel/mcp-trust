# ruff: noqa: E501
"""Typer CLI for local-only portability operations."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Annotated

import typer

from mcp_trust.portability.errors import PortabilityError
from mcp_trust.portability.service import (
    canonical_neutral,
    inspect_host,
    neutral_schema_json,
    parse_neutral,
    render_host,
    round_trip,
    supported_hosts,
)

app = typer.Typer(
    name="portability",
    help="Render and compare explicit MCP host configuration files without discovering real configs.",
    add_completion=False,
)

_INPUT = Annotated[
    Path,
    typer.Argument(
        exists=True,
        dir_okay=False,
        readable=True,
        resolve_path=True,
        help="Explicit input file. Real host configuration is never discovered.",
    ),
]
_HOST = Annotated[
    str,
    typer.Option("--host", help=f"Host adapter: {', '.join(supported_hosts())}."),
]
_REAL_HOST_CONFIG_NAMES = {
    ".claude.json",
    ".mcp.json",
    "claude_desktop_config.json",
    "config.toml",
    "mcp.json",
}


def _read(path: Path) -> str:
    return path.read_text(encoding="utf-8")


def _write(document: str, destination: str) -> None:
    if destination == "-":
        typer.echo(document, nl=False)
        return
    path = Path(destination)
    if path.name in _REAL_HOST_CONFIG_NAMES:
        raise PortabilityError(
            "refusing a real-host configuration filename; use a staging name such as "
            "codex.generated.toml or vscode.generated.json"
        )
    if not path.parent.exists():
        raise PortabilityError(f"destination parent does not exist: {path.parent}")
    if path.is_dir():
        raise PortabilityError(f"destination is a directory: {path}")
    if path.exists():
        raise PortabilityError(f"refusing to overwrite existing destination: {path}")
    path.write_text(document, encoding="utf-8")


def _json(value: object) -> str:
    if hasattr(value, "model_dump"):
        value = value.model_dump(mode="json")
    return json.dumps(value, indent=2, sort_keys=True, ensure_ascii=False) + "\n"


def _fail(exc: Exception) -> None:
    typer.echo(f"portability: {exc}", err=True)
    raise typer.Exit(code=2) from exc


@app.command("validate")
def validate_command(
    input_file: _INPUT,
    output: Annotated[
        str, typer.Option("--output", help="Explicit receipt path or - for stdout.")
    ] = "-",
) -> None:
    """Validate a neutral intent and emit a deterministic safety receipt."""
    try:
        intent = parse_neutral(_read(input_file))
        receipt = {
            "schema_version": "mcp-config-portability-validation.v1",
            "valid": True,
            "neutral_schema_version": intent.schema_version,
            "server_count": len(intent.servers),
            "secret_values_emitted": False,
            "network_calls": 0,
            "host_config_discovery": False,
            "claim_ceiling": "LOCAL_SCHEMA_VALIDATION_ONLY",
        }
        _write(_json(receipt), output)
    except (OSError, UnicodeError, PortabilityError) as exc:
        _fail(exc)


@app.command("render")
def render_command(
    input_file: _INPUT,
    host: _HOST,
    output: Annotated[
        str, typer.Option("--output", help="Explicit host document path or - for stdout.")
    ] = "-",
    report: Annotated[
        str | None, typer.Option("--report", help="Optional explicit report path or - for stdout.")
    ] = None,
) -> None:
    """Render neutral intent to a host document; never installs it."""
    try:
        if report == "-" and output == "-":
            raise PortabilityError("document and report cannot both use stdout")
        result = render_host(parse_neutral(_read(input_file)), host)
        _write(result.document, output)
        if report is not None:
            _write(_json(result.report), report)
    except (OSError, UnicodeError, PortabilityError) as exc:
        _fail(exc)


@app.command("inspect")
def inspect_command(
    input_file: _INPUT,
    host: _HOST,
    output: Annotated[
        str, typer.Option("--output", help="Explicit neutral document path or - for stdout.")
    ] = "-",
    report: Annotated[
        str | None, typer.Option("--report", help="Optional explicit report path or - for stdout.")
    ] = None,
) -> None:
    """Inspect one explicit host document into neutral intent without retaining literals."""
    try:
        if report == "-" and output == "-":
            raise PortabilityError("document and report cannot both use stdout")
        result = inspect_host(_read(input_file), host)
        _write(canonical_neutral(result.intent), output)
        if report is not None:
            _write(_json(result.report), report)
    except (OSError, UnicodeError, PortabilityError) as exc:
        _fail(exc)


@app.command("round-trip")
def round_trip_command(
    input_file: _INPUT,
    host: _HOST,
    output: Annotated[
        str, typer.Option("--output", help="Explicit report path or - for stdout.")
    ] = "-",
) -> None:
    """Render then inspect in memory and report every observed semantic change."""
    try:
        _, report = round_trip(parse_neutral(_read(input_file)), host)
        _write(_json(report), output)
    except (OSError, UnicodeError, PortabilityError) as exc:
        _fail(exc)


@app.command("schema")
def schema_command(
    output: Annotated[
        str, typer.Option("--output", help="Explicit schema path or - for stdout.")
    ] = "-",
) -> None:
    """Export the versioned neutral intent JSON Schema."""
    try:
        _write(neutral_schema_json(), output)
    except (OSError, UnicodeError, PortabilityError) as exc:
        _fail(exc)
