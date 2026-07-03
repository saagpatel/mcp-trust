"""Approval-gated scan corpus for the public catalog.

Two cohorts share one network-off image: the maintained official *reference*
servers and the *archived* official servers (moved to
modelcontextprotocol/servers-archived). ``seed_servers.json`` is the projection
of this typed plan; a test keeps the two in lockstep.

This module is data-only. Importing it must not open the database, import the
real engine, start Docker, or launch MCP server processes.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass

IMAGE_TAG = "mcp-trust-scan:corpus-2026-06-28"

SANDBOX_ENV = {
    "MCP_TRUST_ENGINE": "mcpaudit",
    "MCP_TRUST_SANDBOX": "docker",
    "MCP_TRUST_SANDBOX_NETWORK": "none",
    "MCP_TRUST_SANDBOX_IMAGE": IMAGE_TAG,
    # Required for the credentialed cohort (gitlab/slack/brave-search/google-maps/
    # everart) to enumerate; a no-op for servers without env_keys, so it is safe to
    # set for the whole corpus run.
    "MCP_TRUST_SCAN_CREDENTIALS": "dummy",
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
    # Purpose-built network-off image this server is baked into, when it is NOT
    # in the corpus default image. Projected into the seed source so a
    # whole-corpus refresh scans it against the right image instead of silently
    # keeping a stale grade. Empty = corpus default.
    sandbox_image: str = ""

    def source_preview(self) -> dict[str, object]:
        preview: dict[str, object] = {
            "kind": self.kind,
            "reference": self.reference,
            "command": self.command,
            "args": list(self.args),
            "env_keys": list(self.env_keys),
        }
        if self.sandbox_image:
            preview["sandbox_image"] = self.sandbox_image
        return preview

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
            "Network-capable server; network-off scans validate launch and tool enumeration only."
        ),
    ),
    ReferenceScanCandidate(
        slug="mcp-reference-filesystem",
        name="MCP Reference Filesystem",
        kind="npm",
        reference="@modelcontextprotocol/server-filesystem",
        command="mcp-server-filesystem",
        description=(
            "Reference server for controlled filesystem read/write access within an approved root."
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
            "Reference server exposing Git repository tools against a disposable fixture repo."
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
            "Reference knowledge graph memory server for entities, relations, and observations."
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
    # --- Archived official servers (corpus expansion 2026-06-27) -------------
    # Moved to modelcontextprotocol/servers-archived; no longer maintained.
    # Network-off scans validate launch + tool enumeration only. This batch is
    # the subset that enumerates offline with NO credentials. The token/API-key
    # gated archived servers (gitlab, slack, brave-search, google-maps, everart)
    # are scanned via the credentialed-sandboxed mode below. postgres/redis stay
    # out: they need a reachable backing service, not just a token.
    ReferenceScanCandidate(
        slug="mcp-archived-github",
        name="GitHub (archived)",
        kind="npm",
        reference="@modelcontextprotocol/server-github",
        command="mcp-server-github",
        description=(
            "Archived official reference server for GitHub repository, issue, and "
            "pull-request operations. Moved to modelcontextprotocol/servers-archived "
            "and no longer actively maintained."
        ),
        env_keys=("GITHUB_PERSONAL_ACCESS_TOKEN",),
        homepage="https://github.com/modelcontextprotocol/servers-archived/tree/main/src/github",
        notes="Archived; tool enumeration expected without a token (calls would fail).",
    ),
    ReferenceScanCandidate(
        slug="mcp-archived-aws-kb-retrieval",
        name="AWS KB Retrieval (archived)",
        kind="npm",
        reference="@modelcontextprotocol/server-aws-kb-retrieval",
        command="mcp-server-aws-kb-retrieval",
        description=(
            "Archived official reference server for AWS Bedrock knowledge-base "
            "retrieval. Moved to modelcontextprotocol/servers-archived and no longer "
            "actively maintained."
        ),
        env_keys=("AWS_ACCESS_KEY_ID", "AWS_SECRET_ACCESS_KEY", "AWS_REGION"),
        homepage="https://github.com/modelcontextprotocol/servers-archived/tree/main/src/aws-kb-retrieval-server",
        notes="Archived; tool enumeration expected without AWS credentials.",
    ),
    ReferenceScanCandidate(
        slug="mcp-archived-sqlite",
        name="SQLite (archived)",
        kind="pypi",
        reference="mcp-server-sqlite",
        command="mcp-server-sqlite",
        description=(
            "Archived official reference server for SQLite database queries and "
            "analysis. Moved to modelcontextprotocol/servers-archived and no longer "
            "actively maintained."
        ),
        args=("--db-path", "/scan/probe.db"),
        homepage="https://pypi.org/project/mcp-server-sqlite/",
        notes="Archived; creates a throwaway DB under the Docker tmpfs to enumerate.",
    ),
    # --- Credentialed-sandboxed archived servers (corpus expansion 2026-06-28) -
    # Token/API-key gated. Scanned network-off with NON-FUNCTIONAL dummy values
    # (MCP_TRUST_SCAN_CREDENTIALS=dummy) so they pass startup presence/format
    # checks and enumerate their real tool surface; no value can authenticate
    # because the network is off. A server that validates its token against a
    # live API at boot will still fail closed (honest).
    ReferenceScanCandidate(
        slug="mcp-archived-gitlab",
        name="GitLab (archived)",
        kind="npm",
        reference="@modelcontextprotocol/server-gitlab",
        command="mcp-server-gitlab",
        description=(
            "Archived official reference server for GitLab project, issue, and "
            "merge-request operations. Moved to modelcontextprotocol/servers-archived "
            "and no longer actively maintained."
        ),
        env_keys=("GITLAB_PERSONAL_ACCESS_TOKEN",),
        optional_env_keys=("GITLAB_API_URL",),
        homepage="https://github.com/modelcontextprotocol/servers-archived/tree/main/src/gitlab",
        notes="Credentialed-sandboxed; dummy token to enumerate, network-off.",
    ),
    ReferenceScanCandidate(
        slug="mcp-archived-slack",
        name="Slack (archived)",
        kind="npm",
        reference="@modelcontextprotocol/server-slack",
        command="mcp-server-slack",
        description=(
            "Archived official reference server for Slack channel, message, and user "
            "operations. Moved to modelcontextprotocol/servers-archived and no longer "
            "actively maintained."
        ),
        env_keys=("SLACK_BOT_TOKEN", "SLACK_TEAM_ID"),
        homepage="https://github.com/modelcontextprotocol/servers-archived/tree/main/src/slack",
        notes="Credentialed-sandboxed; dummy token to enumerate, network-off.",
    ),
    ReferenceScanCandidate(
        slug="mcp-archived-brave-search",
        name="Brave Search (archived)",
        kind="npm",
        reference="@modelcontextprotocol/server-brave-search",
        command="mcp-server-brave-search",
        description=(
            "Archived official reference server for Brave Search web and local "
            "queries. Moved to modelcontextprotocol/servers-archived and no longer "
            "actively maintained."
        ),
        env_keys=("BRAVE_API_KEY",),
        homepage="https://github.com/modelcontextprotocol/servers-archived/tree/main/src/brave-search",
        notes="Credentialed-sandboxed; dummy API key to enumerate, network-off.",
    ),
    ReferenceScanCandidate(
        slug="mcp-archived-google-maps",
        name="Google Maps (archived)",
        kind="npm",
        reference="@modelcontextprotocol/server-google-maps",
        command="mcp-server-google-maps",
        description=(
            "Archived official reference server for Google Maps geocoding, places, "
            "and directions. Moved to modelcontextprotocol/servers-archived and no "
            "longer actively maintained."
        ),
        env_keys=("GOOGLE_MAPS_API_KEY",),
        homepage="https://github.com/modelcontextprotocol/servers-archived/tree/main/src/google-maps",
        notes="Credentialed-sandboxed; dummy API key to enumerate, network-off.",
    ),
    ReferenceScanCandidate(
        slug="mcp-archived-everart",
        name="EverArt (archived)",
        kind="npm",
        reference="@modelcontextprotocol/server-everart",
        command="mcp-server-everart",
        description=(
            "Archived official reference server for EverArt AI image generation. "
            "Moved to modelcontextprotocol/servers-archived and no longer actively "
            "maintained."
        ),
        env_keys=("EVERART_API_KEY",),
        homepage="https://github.com/modelcontextprotocol/servers-archived/tree/main/src/everart",
        notes="Credentialed-sandboxed; dummy API key to enumerate, network-off.",
    ),
    # --- Registry-derived no-auth sandboxed corpus (2026-07-02) ---------------
    # Selected from the official MCP Registry as discovery/provenance metadata,
    # then scanned in an approved network-off temp lane. Registry metadata is
    # not tool-surface truth; these entries are included only because receipt
    # evidence exists for the exact versioned slug.
    ReferenceScanCandidate(
        slug="com-mythsensus-mythsensus-mcp-0-2-1",
        name="com.mythsensus/mythsensus-mcp",
        kind="npm",
        reference="mythsensus-mcp",
        command="mythsensus-mcp",
        description=(
            "Reviewed MCP Trust live-scan corpus candidate. Public meaning remains "
            "limited to controlled first-pass scan evidence and receipt caveats."
        ),
        homepage="https://github.com/PattrickChenforclaudeuse/mythsensus-mcp",
        notes=(
            "Registry-derived no-auth sandboxed candidate; exact version 0.2.1 "
            "is encoded in the catalog slug and covered by temp receipt evidence."
        ),
        sandbox_image="mcp-trust-live-batch:20260628",
    ),
    ReferenceScanCandidate(
        slug="com-pulsemcp-image-diff-0-1-3",
        name="com.pulsemcp/image-diff",
        kind="npm",
        reference="@pulsemcp/image-diff-mcp-server",
        command="image-diff-mcp-server",
        description=(
            "Reviewed MCP Trust live-scan corpus candidate. Public meaning remains "
            "limited to controlled first-pass scan evidence and receipt caveats."
        ),
        homepage="https://github.com/pulsemcp/mcp-servers",
        notes=(
            "Registry-derived no-auth sandboxed candidate; exact version 0.1.3 "
            "is encoded in the catalog slug and covered by temp receipt evidence. "
            "Source mapping was reviewed against the monorepo tag/path."
        ),
        sandbox_image="mcp-trust-live-batch:20260628",
    ),
    ReferenceScanCandidate(
        slug="com-seanwinslow-intent-engineering-0-2-0",
        name="com.seanwinslow/intent-engineering",
        kind="npm",
        reference="@swins/intent-engineering-mcp",
        command="intent-engineering-mcp",
        description=(
            "Reviewed MCP Trust live-scan corpus candidate. Public meaning remains "
            "limited to controlled first-pass scan evidence and receipt caveats."
        ),
        homepage="https://github.com/seanwinslow28/sw-mcp-intent-engineering",
        notes=(
            "Registry-derived no-auth sandboxed candidate; exact version 0.2.0 "
            "is encoded in the catalog slug and covered by temp receipt evidence. "
            "Source mapping was reviewed against the v0.2.0 source tag."
        ),
        sandbox_image="mcp-trust-live-batch:20260628",
    ),
    ReferenceScanCandidate(
        slug="eu-regulatoryai-sovereign-ai-act-mcp-1-2-0",
        name="eu.regulatoryai/sovereign-ai-act-mcp",
        kind="npm",
        reference="sovereign-ai-act-mcp",
        command="sovereign-ai-act-mcp",
        description=(
            "Reviewed MCP Trust live-scan corpus candidate. Public meaning remains "
            "limited to controlled first-pass scan evidence and receipt caveats."
        ),
        homepage="https://github.com/saidbazyar/sovereign-ai-act-mcp",
        notes=(
            "Registry-derived no-auth sandboxed candidate; exact version 1.2.0 "
            "is encoded in the catalog slug and covered by temp receipt evidence."
        ),
        sandbox_image="mcp-trust-live-batch:20260628",
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
