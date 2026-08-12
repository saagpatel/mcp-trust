"""Pure host adapters for the portability studio."""

from mcp_trust.portability.adapters.codex import CodexAdapter
from mcp_trust.portability.adapters.json_hosts import (
    ClaudeCodeAdapter,
    ClaudeDesktopAdapter,
    VSCodeAdapter,
)

__all__ = ["ClaudeCodeAdapter", "ClaudeDesktopAdapter", "CodexAdapter", "VSCodeAdapter"]
