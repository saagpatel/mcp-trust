"""Engine factory — select a scan engine by name or environment variable."""

from __future__ import annotations

import os

from mcp_trust.engine.base import ScanEngine


def select_engine(name: str | None = None) -> ScanEngine:
    """Return a ``ScanEngine`` for *name*.

    Resolution order:
    1. The *name* argument (if provided).
    2. The ``MCP_TRUST_ENGINE`` environment variable.
    3. Default: ``"stub"``.

    Raises ``ValueError`` for unknown engine names.
    """
    resolved = name or os.environ.get("MCP_TRUST_ENGINE", "stub")

    if resolved == "stub":
        from mcp_trust.engine.stub import StubEngine  # noqa: PLC0415

        return StubEngine()

    if resolved == "mcpaudit":
        from mcp_trust.engine.mcpaudit import MCPAuditEngine  # noqa: PLC0415

        return MCPAuditEngine()

    raise ValueError(f"Unknown engine {resolved!r}. Valid options: 'stub', 'mcpaudit'.")
