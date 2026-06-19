"""Approval-gated reference scan corpus for public-launch preparation.

This module is data-only. Importing it must not open the database, import the
real engine, start Docker, or launch MCP server processes.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass

IMAGE_TAG = "mcp-trust-scan:reference-2026-06-19"

SANDBOX_ENV = {
    "MCP_TRUST_ENGINE": "mcpaudit",
    "MCP_TRUST_SANDBOX": "docker",
    "MCP_TRUST_SANDBOX_NETWORK": "none",
    "MCP_TRUST_SANDBOX_IMAGE": IMAGE_TAG,
}


@dataclass(frozen=True)
class ReferenceScanCandidate:
    slug: str
    name: str
    kind: str
    reference: str
    command: str
    description: str = ""
    args: tuple[str, ...] = ()
    env_keys: tuple[str, ...] = ()
    optional_env_keys: tuple[str, ...] = ()
    homepage: str = ""
    notes: str = ""

    def source_preview(self) -> dict[str, object]:
        return {
            "kind": self.kind,
            "reference": self.reference,
            "command": self.command,
            "args": list(self.args),
            "env_keys": list(self.env_keys),
        }

    def seed_preview(self) -> dict[str, object]:
        return {
            "slug": self.slug,
            "name": self.name,
            "description": self.description,
            "source": self.source_preview(),
            "homepage": self.homepage,
        }

    def plan_row(self) -> dict[str, object]:
        row = asdict(self)
        row["args"] = list(self.args)
        row["env_keys"] = list(self.env_keys)
        row["optional_env_keys"] = list(self.optional_env_keys)
        row["source"] = self.source_preview()
        return row


REFERENCE_SCAN_CANDIDATES: tuple[ReferenceScanCandidate, ...] = (
    ReferenceScanCandidate(
        slug="mcp-reference-everything",
        name="MCP Reference Everything",
        kind="npm",
        reference="@modelcontextprotocol/server-everything",
        command="mcp-server-everything",
        description=(
            "Reference MCP test server exposing broad prompts, resources, and tools "
            "for client and scanner validation."
        ),
        homepage="https://github.com/modelcontextprotocol/servers/tree/main/src/everything",
        notes="Broad reference/test server for high-capability calibration.",
    ),
    ReferenceScanCandidate(
        slug="mcp-reference-fetch",
        name="MCP Reference Fetch",
        kind="pypi",
        reference="mcp-server-fetch",
        command="mcp-server-fetch",
        description="Reference server that fetches URLs and converts web content to Markdown.",
        homepage="https://github.com/modelcontextprotocol/servers/tree/main/src/fetch",
        notes=(
            "Network-capable server; network-off scans validate launch and "
            "tool enumeration only."
        ),
    ),
    ReferenceScanCandidate(
        slug="mcp-reference-filesystem",
        name="MCP Reference Filesystem",
        kind="npm",
        reference="@modelcontextprotocol/server-filesystem",
        command="mcp-server-filesystem",
        description=(
            "Reference server for controlled filesystem read/write access within an "
            "approved root."
        ),
        args=("/scan",),
        homepage="https://github.com/modelcontextprotocol/servers/tree/main/src/filesystem",
        notes="Use only the Docker tmpfs workdir, never a host path.",
    ),
    ReferenceScanCandidate(
        slug="mcp-reference-git",
        name="MCP Reference Git",
        kind="pypi",
        reference="mcp-server-git",
        command="mcp-server-git",
        description=(
            "Reference server exposing Git repository tools against a disposable "
            "fixture repo."
        ),
        args=("--repository", "/fixtures/repo"),
        homepage="https://github.com/modelcontextprotocol/servers/tree/main/src/git",
        notes="Uses the read-only fixture repo baked into Dockerfile.scan.",
    ),
    ReferenceScanCandidate(
        slug="mcp-reference-memory",
        name="MCP Reference Memory",
        kind="npm",
        reference="@modelcontextprotocol/server-memory",
        command="mcp-server-memory",
        description=(
            "Reference knowledge graph memory server for entities, relations, and "
            "observations."
        ),
        optional_env_keys=("MEMORY_FILE_PATH",),
        homepage="https://github.com/modelcontextprotocol/servers/tree/main/src/memory",
        notes="Optional memory file should live under Docker tmpfs if enabled later.",
    ),
    ReferenceScanCandidate(
        slug="mcp-reference-sequential-thinking",
        name="MCP Reference Sequential Thinking",
        kind="npm",
        reference="@modelcontextprotocol/server-sequential-thinking",
        command="mcp-server-sequential-thinking",
        description="Reference reasoning helper server for structured multi-step thinking.",
        optional_env_keys=("DISABLE_THOUGHT_LOGGING",),
        homepage=(
            "https://github.com/modelcontextprotocol/servers/tree/main/src/sequentialthinking"
        ),
        notes="Low I/O reasoning tool and expected low-danger anchor.",
    ),
    ReferenceScanCandidate(
        slug="mcp-reference-time",
        name="MCP Reference Time",
        kind="pypi",
        reference="mcp-server-time",
        command="mcp-server-time",
        description="Reference server for current time and timezone conversion.",
        optional_env_keys=("LOCAL_TIMEZONE",),
        homepage="https://pypi.org/project/mcp-server-time/",
        notes="Expected low-danger anchor for first sandboxed smoke scan.",
    ),
)


def plan_payload() -> dict[str, object]:
    return {
        "notice": (
            "Dry-run only. This payload does not edit seed data, build Docker images, "
            "or launch MCP server processes."
        ),
        "image_tag": IMAGE_TAG,
        "sandbox_env": dict(SANDBOX_ENV),
        "candidates": [candidate.plan_row() for candidate in REFERENCE_SCAN_CANDIDATES],
    }
