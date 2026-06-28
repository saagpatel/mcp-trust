"""Expose the MCP Trust catalog as a read-only MCP server (stdio).

Serves the baked catalog snapshot (``catalog_snapshot.json``) so an agent can
check a public MCP server's danger grade *before connecting* — "check before you
connect". No database or network is needed at runtime; the snapshot is a
projection of a real, sandboxed scan run (see ``scripts/build_snapshot.py``).

Launched as ``mcp-trust mcp-serve`` (or ``uvx mcp-trust mcp-serve``).
"""

from __future__ import annotations

import json
from functools import lru_cache
from importlib.resources import files
from typing import Any

_METHODOLOGY = """\
MCP Trust grades public MCP servers on two orthogonal axes.

1. Danger grade (A-F). Each server is launched in a network-off Docker sandbox
   and its real tool surface is enumerated, then scored across five weighted
   dimensions — file access, network access, shell execution, destructive
   capability, and exfiltration potential — into a 0-10 composite mapped to an
   A (lowest danger) to F (highest) band. A server with a high-confidence
   destructive or exfiltration capability is capped no better than D.

2. Transparency (high/medium/low). How much the server declares about its own
   behavior via tool annotations. Low transparency means "cannot verify safe",
   NOT "known dangerous" — the danger grade is then inferred from spec defaults
   rather than the server's own declarations.

Honesty model:
- Grades are real, derived from a real scan. A server with no scan on record is
  never assigned a letter grade.
- Scanning is network-off in a locked-down sandbox, so a grade reflects the tool
  surface, not live behavior that needs egress.
- Credential-gated servers are scanned with NON-FUNCTIONAL dummy values so they
  reach tool enumeration; the network is off, so nothing can authenticate. The
  enumerated tool surface is real; dummy values are never recorded.
- A grade is an automated signal, not an endorsement or a certification.
"""


@lru_cache(maxsize=1)
def _snapshot() -> dict[str, Any]:
    raw = (files("mcp_trust") / "catalog_snapshot.json").read_text(encoding="utf-8")
    return json.loads(raw)


def _servers() -> list[dict[str, Any]]:
    return _snapshot()["servers"]


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


def check_server_payload(slug: str) -> str:
    """Full JSON record for one server by slug, or an error + the known slugs."""
    for s in _servers():
        if s["slug"] == slug:
            return json.dumps(s, indent=2)
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
            "Read-only registry of real, sandbox-derived A-F trust grades."
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
