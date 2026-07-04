"""Domain models for the MCP Trust Registry.

These are the registry's *own* normalized models — deliberately decoupled from
any specific scanning engine's internal types. A scan engine returns an
``EngineResult`` (see ``mcp_trust.engine.base``) built from ``RiskSummary`` and
``Finding`` below; the registry maps that into a persisted ``ScanRecord``.

Keeping these independent of the engine is the core architectural boundary:
engines are swappable, the registry's contract is stable.
"""

from __future__ import annotations

import re
from datetime import datetime
from enum import StrEnum

from pydantic import BaseModel, Field, field_validator

# A slug is both a URL path component and a filesystem path component, so it is
# constrained to strict kebab-case: lowercase alphanumerics in dash-separated
# groups, no leading/trailing dash. This forbids path separators, ``..``
# traversal, whitespace, dots, and uppercase at the trust boundary, so a hostile
# slug from an ingested public server list can never reach a path-join or a URL.
_SLUG_RE = re.compile(r"^[a-z0-9]+(?:-[a-z0-9]+)*$")


class SourceKind(StrEnum):
    """How a public MCP server is obtained and launched."""

    NPM = "npm"
    PYPI = "pypi"
    GIT = "git"
    BINARY = "binary"
    REMOTE = "remote"  # hosted HTTP/SSE endpoint


class ServerSource(BaseModel):
    """A reproducible pointer to a public MCP server.

    ``env_keys`` records the *names* of environment variables a server expects
    (e.g. ``API_TOKEN``) so the catalog can document required config — it never
    stores values. Secrets must never enter the registry.
    """

    kind: SourceKind
    reference: str = Field(description="Package name, git URL, or endpoint URL.")
    command: str | None = Field(default=None, description="Launch command, if applicable.")
    args: list[str] = Field(default_factory=list)
    env_keys: list[str] = Field(default_factory=list, description="Required env var NAMES only.")
    sandbox_image: str | None = Field(
        default=None,
        description=(
            "Purpose-built network-off scan image this server is baked into. "
            "Overrides the corpus-wide MCP_TRUST_SANDBOX_IMAGE default — a server "
            "absent from the default image cannot launch network-off there, and a "
            "whole-corpus refresh would silently keep its stale grade."
        ),
    )
    trusted: bool = Field(
        default=False,
        description=(
            "Whether this is a vetted reference server that may be scanned WITHOUT "
            "a sandbox. Defaults False (fail-closed): an untrusted source must be "
            "scanned inside a sandbox or the engine refuses. Only the validated "
            "reference-server flow should set this True."
        ),
    )


class Server(BaseModel):
    """A catalog entry for a public MCP server."""

    slug: str = Field(description="Stable URL-safe identifier, e.g. 'mcp-reference-time'.")
    name: str
    description: str = ""
    source: ServerSource
    homepage: str | None = None
    added_at: datetime

    @field_validator("slug")
    @classmethod
    def _validate_slug(cls, value: str) -> str:
        if not _SLUG_RE.match(value):
            raise ValueError(
                f"slug must be strict kebab-case ([a-z0-9] groups joined by '-'); got {value!r}"
            )
        return value


class Severity(StrEnum):
    """Normalized finding severity, ordered most-to-least severe."""

    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


class Finding(BaseModel):
    """A single normalized risk finding from a scan engine."""

    rule_id: str = Field(description="Engine-native rule id, e.g. 'MCP007'.")
    title: str
    severity: Severity
    category: str = Field(description="Risk dimension, e.g. 'injection', 'exfiltration'.")
    detail: str = ""


class ToolEvidence(BaseModel):
    """Public-safe readback evidence for one enumerated MCP tool.

    Raw input schemas can be large, unstable, or contain implementation detail,
    so receipts store only a canonical hash plus presence flags.
    """

    name: str
    has_input_schema: bool = False
    input_schema_sha256: str | None = None
    has_annotations: bool = False


class ScanEvidence(BaseModel):
    """Public-safe evidence captured during live MCP readback."""

    tool_count: int = 0
    tools: list[ToolEvidence] = Field(default_factory=list)
    prompt_count: int = 0
    resource_count: int = 0
    schema_hash_algorithm: str = "sha256"


class RiskSummary(BaseModel):
    """Normalized multi-dimensional risk for one server. All scores are 0–10.

    Mirrors the shape of common MCP scanners (composite + weighted dimensions)
    without binding to any one engine's class. Higher = riskier.
    """

    composite: float = Field(ge=0, le=10)
    file_access: float = Field(ge=0, le=10, default=0)
    network_access: float = Field(ge=0, le=10, default=0)
    shell_execution: float = Field(ge=0, le=10, default=0)
    destructive: float = Field(ge=0, le=10, default=0)
    exfiltration: float = Field(ge=0, le=10, default=0)
    findings_by_severity: dict[Severity, int] = Field(default_factory=dict)
    annotation_coverage: float = Field(
        ge=0,
        le=1,
        default=1.0,
        description="Fraction of tools that declare behavior annotations. Drives the "
        "transparency axis: low coverage means the danger score is inferred from "
        "spec-defaults, not the server's own declarations.",
    )

    def count(self, severity: Severity) -> int:
        return self.findings_by_severity.get(severity, 0)


class TrustGrade(StrEnum):
    """Public-facing trust grade. ``UNSCANNED`` = no scan on record."""

    A = "A"
    B = "B"
    C = "C"
    D = "D"
    F = "F"
    UNSCANNED = "unscanned"


class TransparencyLevel(StrEnum):
    """Second axis, orthogonal to the danger grade: how much the server declares
    about its own behavior. ``LOW`` means the danger grade is largely inferred —
    "cannot verify safe", NOT "known dangerous"."""

    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"


class ScanRecord(BaseModel):
    """A persisted scan result: the unit the registry stores and serves."""

    id: str = Field(description="Scan id (uuid hex).")
    server_slug: str
    engine_name: str
    engine_version: str
    grade: TrustGrade
    transparency: TransparencyLevel = Field(
        default=TransparencyLevel.HIGH,
        description="Annotation-coverage axis, orthogonal to grade.",
    )
    risk: RiskSummary
    findings: list[Finding] = Field(default_factory=list)
    evidence: ScanEvidence | None = Field(
        default=None,
        description="Public-safe tool/readback evidence captured by the scan engine.",
    )
    scanned_at: datetime
    sandbox_image: str | None = Field(
        default=None,
        description=(
            "The container image this scan actually ran in (per-server pin > env "
            "default), captured by the engine. Provenance for the receipt: recorded "
            "as ground truth rather than re-derived from ambient env, which is blind "
            "to per-server image pins. None when no isolating sandbox was used."
        ),
    )
    report_ref: str | None = Field(
        default=None, description="Portable receipt/report artifact reference, if archived."
    )
