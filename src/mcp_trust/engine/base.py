"""Scan-engine boundary.

The registry does NOT implement vulnerability detection. It delegates to a
pluggable ``ScanEngine`` and consumes a normalized ``EngineResult``. The shipping
backend is ``MCPAuditEngine`` (wraps the public ``mcp-audits`` PyPI package);
``StubEngine`` provides a deterministic implementation so the registry runs,
tests, and demos end-to-end without the heavy engine installed.

To add an engine: implement ``ScanEngine`` and map the engine's native output
onto ``RiskSummary`` + ``Finding``. Nothing else in the registry changes.
"""

from __future__ import annotations

from typing import Protocol, runtime_checkable

from pydantic import BaseModel, Field

from mcp_trust.core.models import Finding, RiskSummary, ScanEvidence, ServerSource


class ScanError(RuntimeError):
    """Raised when an engine cannot complete a scan (unreachable server, bad spec)."""


class EngineResult(BaseModel):
    """What every ``ScanEngine.scan`` returns. Built from core models so the
    registry's mapping to a ``ScanRecord`` is trivial and engine-agnostic."""

    engine_name: str
    engine_version: str
    risk: RiskSummary
    findings: list[Finding] = Field(default_factory=list)
    evidence: ScanEvidence | None = None
    sandbox_image: str | None = Field(
        default=None,
        description=(
            "The container image the scan actually ran in, as resolved by the "
            "engine (per-server pin > env default). Ground-truth provenance the "
            "receipt records instead of re-reading ambient env. None when the "
            "scan used no isolating sandbox (host passthrough or the stub engine)."
        ),
    )


@runtime_checkable
class ScanEngine(Protocol):
    """A backend that scans a public MCP server and returns normalized risk.

    Implementations MUST be side-effect free with respect to the host: scanning
    an untrusted server is itself a security boundary, so engines are expected to
    sandbox any execution. The registry treats this as the engine's contract.
    """

    name: str
    version: str

    def scan(self, source: ServerSource) -> EngineResult:
        """Scan one server source. Raise ``ScanError`` on failure."""
        ...
