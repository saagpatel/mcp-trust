"""Expose the MCP Trust catalog as a read-only MCP server (stdio).

Serves the baked catalog snapshot (``catalog_snapshot.json``) so an agent can
check a public MCP server's danger grade *before connecting* — "check before you
connect". No database or network is needed at runtime; the snapshot is a
projection of real scans with explicit per-record provenance (see
``scripts/build_snapshot.py``).

Launched as ``mcp-trust mcp-serve`` (or ``uvx mcp-trust mcp-serve``).
"""

from __future__ import annotations

import json
from datetime import UTC, datetime
from functools import lru_cache
from importlib.resources import files
from typing import Any

_METHODOLOGY = """\
MCP Trust grades public MCP servers on two orthogonal axes.

1. Danger grade (A-F). A local-process record is labeled network-off only when
   that Docker context was verified; otherwise its network or sandbox
   provenance is explicitly unknown. A remote endpoint is probed over its live
   network transport without a local process sandbox. Each public record
   discloses its scan mode and sandbox applicability. The real tool surface is
   scored across five
   weighted dimensions — file access, network access, shell execution,
   destructive capability, and exfiltration potential — into a 0-10 composite
   mapped to an A (lowest danger) to F (highest) band. A server with a
   high-confidence destructive or exfiltration capability is capped no better
   than D.

2. Transparency (high/medium/low). How much the server declares about its own
   behavior via tool annotations. Low transparency means "cannot verify safe",
   NOT "known dangerous" — the danger grade is then inferred from spec defaults
   rather than the server's own declarations.

Honesty model:
- Grades are real, derived from a real scan. A server with no scan on record is
  never assigned a letter grade.
- Verified local-process scans are network-off in a locked-down sandbox;
  records without that proof say network or provenance unknown. Remote endpoint
  scanning necessarily uses live network transport and is labeled as such;
  none of these modes proves runtime behavior beyond the observed tool surface.
- Credential-gated local-process servers are scanned with NON-FUNCTIONAL dummy
  values so they reach tool enumeration; the network is off, so nothing can
  authenticate. The enumerated tool surface is real; dummy values are never
  recorded.
- A grade is an automated signal, not an endorsement or a certification.
"""


@lru_cache(maxsize=1)
def _snapshot() -> dict[str, Any]:
    raw = (files("mcp_trust") / "catalog_snapshot.json").read_text(encoding="utf-8")
    return json.loads(raw)


def _servers() -> list[dict[str, Any]]:
    return _snapshot()["servers"]


def _current_server_record(
    server: dict[str, Any],
    *,
    now: datetime | None = None,
) -> dict[str, Any]:
    """Return a copy with scan age recomputed at response time."""
    record = dict(server)
    scanned_at = record.get("scanned_at")
    if not isinstance(scanned_at, str):
        record["scan_age_days"] = None
        return record
    try:
        parsed = datetime.fromisoformat(scanned_at.replace("Z", "+00:00"))
    except ValueError:
        record["scan_age_days"] = None
        return record
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=UTC)
    fixed_now = now or datetime.now(tz=UTC)
    if fixed_now.tzinfo is None:
        fixed_now = fixed_now.replace(tzinfo=UTC)
    record["scan_age_days"] = round(
        max(
            0.0,
            (fixed_now.astimezone(UTC) - parsed.astimezone(UTC)).total_seconds() / 86400,
        ),
        6,
    )
    return record


def list_servers_payload() -> str:
    """JSON summary of every graded server (slug, grade, transparency, score)."""
    rows = [
        {
            "slug": s["slug"],
            "name": s["name"],
            "grade": s["grade"],
            "transparency": s["transparency"],
            "danger_score": s["danger_score"],
            "requires_credentials": s["requires_credentials"],
        }
        for s in _servers()
    ]
    return json.dumps({"server_count": len(rows), "servers": rows}, indent=2)


def check_server_payload(slug: str, *, now: datetime | None = None) -> str:
    """Full JSON record for one server by slug, or an error + the known slugs."""
    for s in _servers():
        if s["slug"] == slug:
            return json.dumps(_current_server_record(s, now=now), indent=2)
    return json.dumps(
        {
            "error": f"No graded server with slug {slug!r}.",
            "known_slugs": [s["slug"] for s in _servers()],
        },
        indent=2,
    )


def build_server() -> Any:
    """Build the FastMCP server with the catalog tools registered."""
    from mcp.server import FastMCP

    app: Any = FastMCP(
        name="mcp-trust",
        instructions=(
            "Check the danger grade of a public MCP server before you connect. "
            "Read-only registry of real scan-derived A-F trust grades with "
            "explicit per-record sandbox and network provenance."
        ),
    )

    @app.tool()  # type: ignore[misc]
    def list_servers() -> str:
        """List every graded MCP server with its trust grade. Returns JSON."""
        return list_servers_payload()

    @app.tool()  # type: ignore[misc]
    def check_server(slug: str) -> str:
        """Look up the full trust grade, dimensions, and findings for one server by slug."""
        return check_server_payload(slug)

    @app.tool()  # type: ignore[misc]
    def get_methodology() -> str:
        """Explain how trust grades are computed and the honesty model behind them."""
        return _METHODOLOGY

    return app


def run() -> None:
    """Run the MCP server on stdio."""
    import asyncio
    import sys

    app = build_server()
    sys.stderr.write("mcp-trust MCP server starting on stdio...\n")
    asyncio.run(app.run_stdio_async())
