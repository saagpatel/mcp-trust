"""Check the public tool inventories against MCP discovery."""

import asyncio
import json
from pathlib import Path

from mcp_trust.mcp_server import build_server

ROOT = Path(__file__).resolve().parents[1]


def test_published_tool_inventories_match_discovery() -> None:
    tools = asyncio.run(build_server().list_tools())
    inventory = {}
    rows = ["| Tool | Description |", "|---|---|"]
    for tool in tools:
        required = tool.inputSchema.get("required", [])
        description = " ".join(tool.description.split())
        inventory[tool.name] = {"required": required, "description": description}
        signature = f"{tool.name}({', '.join(required)})"
        rows.append(f"| `{signature}` | {description} |")

    readme = (ROOT / "README.md").read_text()
    table = readme[readme.index(rows[0]) :].split("\n\n", 1)[0]
    assert table.splitlines() == rows

    knowledge = json.loads((ROOT / "integrations/personal-ops/project-knowledge.json").read_text())
    interface = next(
        f for f in knowledge["facts"] if f["fact_key"] == "project.readonly_mcp_interface"
    )
    assert interface["metadata"]["tools"] == list(inventory)
    assert interface["metadata"]["tool_inventory"] == inventory
