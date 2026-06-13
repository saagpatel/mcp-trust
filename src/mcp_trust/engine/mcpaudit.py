"""MCPAuditEngine — adapter wrapping the public ``mcp-audits`` PyPI package.

``mcp_audit`` is an optional dependency (``pip install 'mcp-trust[engine]'``).
This module imports it LAZILY inside ``scan`` so the rest of the registry
imports cleanly without ``mcp-audits`` installed.

Mapping:
  ``ServerSource``  →  mcp-audits ``ServerConfig``
  ``ServerAudit``   →  ``EngineResult`` (``RiskSummary`` + ``Finding`` list)

The adapter is integration-gated: it must import cleanly and raise a clear
``ScanError`` at runtime if ``mcp_audit`` is absent.
"""

from __future__ import annotations

import logging

from mcp_trust.core.models import Finding, RiskSummary, ServerSource, Severity
from mcp_trust.engine.base import EngineResult, ScanEngine, ScanError

logger = logging.getLogger(__name__)

# mcp-audits version that ships the ServerAudit/RiskScore API this adapter targets.
_ENGINE_VERSION = "2.1.0"

# Map mcp-audits severity strings → our Severity enum.
_SEV_MAP: dict[str, Severity] = {
    "critical": Severity.CRITICAL,
    "high": Severity.HIGH,
    "medium": Severity.MEDIUM,
    "low": Severity.LOW,
    "info": Severity.INFO,
}


def _map_severity(raw: str) -> Severity:
    return _SEV_MAP.get(raw.lower(), Severity.INFO)


def _clamp(v: float) -> float:
    return max(0.0, min(10.0, float(v)))


class MCPAuditEngine:
    """Scan engine backed by the public ``mcp-audits`` package.

    Raises ``ScanError`` if ``mcp-audits`` is not installed.  Install it with::

        pip install 'mcp-trust[engine]'
    """

    name: str = "mcpaudit"
    version: str = _ENGINE_VERSION

    def scan(self, source: ServerSource) -> EngineResult:  # noqa: C901
        """Run ``mcp-audits`` against *source* and return normalized results.

        The entire ``mcp_audit`` import is deferred here so the module loads
        cleanly without the optional dependency.
        """
        try:
            from mcp_audit.analyzer import analyze  # noqa: PLC0415
            from mcp_audit.models import ServerConfig  # noqa: PLC0415
        except ImportError as exc:
            raise ScanError(
                "mcp-audits is not installed. "
                "Run: pip install 'mcp-trust[engine]' to enable real scanning."
            ) from exc

        # Build mcp-audits ServerConfig from our ServerSource.
        # mcp-audits expects: name, command, args, env (dict of key→value or None).
        env: dict[str, str | None] = {k: None for k in source.env_keys}

        try:
            server_cfg = ServerConfig(
                name=source.reference,
                command=source.command or source.reference,
                args=source.args,
                env=env,
            )
        except Exception as exc:
            logger.warning("ServerConfig build failed for %r: %s", source.reference, exc)
            raise ScanError(
                f"Failed to build ServerConfig for {source.reference!r}: {exc}"
            ) from exc

        # Run the mcp-audits analyzer.
        try:
            audit = analyze(server_cfg)
        except Exception as exc:
            logger.warning("mcp-audits analysis failed for %r: %s", source.reference, exc)
            raise ScanError(f"mcp-audits analysis failed for {source.reference!r}: {exc}") from exc

        # --- Map ServerAudit → our models ---
        # audit.risk_score: RiskScore with fields:
        #   composite, file_access, network_access, shell_execution,
        #   destructive, exfiltration  (all numeric 0–10)
        rs = audit.risk_score

        findings: list[Finding] = []
        findings_by_severity: dict[Severity, int] = {}

        # audit.capability_findings is a list of finding objects.
        for cf in getattr(audit, "capability_findings", []):
            sev = _map_severity(getattr(cf, "severity", "info"))
            findings.append(
                Finding(
                    rule_id=getattr(cf, "rule_id", "MCPA000"),
                    title=getattr(cf, "title", str(cf)),
                    severity=sev,
                    category=getattr(cf, "category", "capability"),
                    detail=getattr(cf, "detail", "") or "",
                )
            )
            findings_by_severity[sev] = findings_by_severity.get(sev, 0) + 1

        risk = RiskSummary(
            composite=_clamp(rs.composite),
            file_access=_clamp(getattr(rs, "file_access", 0)),
            network_access=_clamp(getattr(rs, "network_access", 0)),
            shell_execution=_clamp(getattr(rs, "shell_execution", 0)),
            destructive=_clamp(getattr(rs, "destructive", 0)),
            exfiltration=_clamp(getattr(rs, "exfiltration", 0)),
            findings_by_severity=findings_by_severity,
        )

        # Detect installed mcp_audit version if possible.
        try:
            import importlib.metadata  # noqa: PLC0415

            engine_ver = importlib.metadata.version("mcp-audits")
        except Exception:
            engine_ver = _ENGINE_VERSION

        return EngineResult(
            engine_name=self.name,
            engine_version=engine_ver,
            risk=risk,
            findings=findings,
        )


# Satisfy the Protocol at import time without mcp_audit present.
_: ScanEngine = MCPAuditEngine()  # type: ignore[assignment]
