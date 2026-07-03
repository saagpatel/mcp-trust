"""MCPAuditEngine — adapter wrapping the public ``mcp-audits`` PyPI package.

``mcp_audit`` is an optional dependency (``pip install 'mcp-trust[engine]'``).
This module imports it LAZILY inside ``scan`` so the rest of the registry
imports cleanly without ``mcp-audits`` installed.

The real ``mcp-audits`` scan is a pipeline, not a single function:

    connector = ServerConnector(timeout)
    audit     = await connector.connect(server_config)   # launches the server
    perms     = PermissionAnalyzer().analyze_server(audit.tools)
    risk      = RiskScorer().score_server(perms)          # -> RiskScore

This adapter drives that pipeline and maps the result onto our engine-agnostic
``EngineResult`` (``RiskSummary`` + ``Finding`` list).

SECURITY NOTE: connecting to an MCP server *launches the server process* (e.g.
``npx <pkg>``), which runs third-party code. Execution is isolated by a pluggable
``Sandbox`` (see ``engine.sandbox``): pass one to the constructor or set
``MCP_TRUST_SANDBOX=docker`` to run untrusted servers in a locked-down container.
The sandbox default is ``NoSandbox`` (passthrough), so this engine is FAIL-CLOSED:
scanning a source that is not marked ``trusted`` without an explicit sandbox raises
rather than launching third-party code on the host. Only a vetted reference server
(``ServerSource.trusted=True``) may be scanned on the host via ``NoSandbox``.
"""

from __future__ import annotations

import asyncio
import hashlib
import json
import logging
import os
import threading
from collections.abc import Awaitable, Callable
from typing import TypeVar

from mcp_trust.core.models import (
    Finding,
    RiskSummary,
    ScanEvidence,
    ServerSource,
    Severity,
    SourceKind,
    ToolEvidence,
)
from mcp_trust.engine.base import EngineResult, ScanEngine, ScanError
from mcp_trust.engine.credentials import build_dummy_env
from mcp_trust.engine.sandbox import DockerSandbox, Sandbox, select_sandbox

logger = logging.getLogger(__name__)

# Opt-in credentialed-sandboxed scan mode: inject non-functional dummy values for
# a server's required secret env keys so the cloud-API tier reaches tool
# enumeration. "none" (default) leaves env empty; "dummy" enables injection.
_CREDENTIALS_ENV = "MCP_TRUST_SCAN_CREDENTIALS"


def _credentials_mode() -> str:
    return os.environ.get(_CREDENTIALS_ENV, "none").lower()


def _apply_dummy_credentials(sandbox: Sandbox, source: ServerSource) -> None:
    """Inject dummy credentials for *source*'s env_keys when credentialed mode is on.

    Safety invariant: dummy credentials run ONLY inside the docker sandbox with
    network off. Injecting them while running untrusted code on the host, or with
    a reachable network (where a real-looking token could authenticate or
    exfiltrate), is refused. Remote (HTTP/SSE) sources connect over the live
    network outside the sandbox, so credentialed mode does not apply to them and
    is refused rather than silently producing a misleading "network-off" receipt.
    No-op when the mode is off or the server needs no credentials — but a reused
    sandbox is always reset first, so it never carries a prior scan's credentials
    into a later (possibly no-credential) scan.
    """
    # Reset any prior scan's dummy env up front. Without this, the early-return
    # paths below (mode off / no env_keys) would leave a reused sandbox emitting
    # the previous server's --env flags.
    if isinstance(sandbox, DockerSandbox):
        sandbox.env = {}
    if _credentials_mode() != "dummy" or not source.env_keys:
        return
    if source.kind == SourceKind.REMOTE:
        raise ScanError(
            "credentialed scan (MCP_TRUST_SCAN_CREDENTIALS=dummy) applies to sandboxed "
            "stdio servers only; a remote endpoint connects over the live network and "
            "no credentials are injected into the sandbox."
        )
    if not isinstance(sandbox, DockerSandbox):
        raise ScanError(
            "credentialed scan (MCP_TRUST_SCAN_CREDENTIALS=dummy) requires the docker "
            "sandbox; refusing to inject credentials while running on the host."
        )
    if sandbox.network != "none":
        raise ScanError(
            "credentialed scan requires network-off (MCP_TRUST_SANDBOX_NETWORK=none); "
            "refusing to inject credentials with a reachable network."
        )
    # Assign the fresh dummy env (the sandbox was reset above, so this never
    # accumulates across scans).
    sandbox.env = build_dummy_env(source.env_keys)


_T = TypeVar("_T")

# Fallback if the installed version can't be read at runtime.
_FALLBACK_VERSION = "2.1.0"

# mcp-audits PermissionFinding has no per-finding severity (severity is implied by
# the scoring weights). We normalize confidence + category into our Severity:
# a high-confidence destructive/exfiltration permission is the disqualifying case.
_HIGH_CONFIDENCE = {"high", "llm"}
_CRITICAL_CATEGORIES = {"destructive", "exfiltration"}


def _run_sync(factory: Callable[[], Awaitable[_T]]) -> _T:
    """Run an async coroutine to completion from sync code.

    Uses ``asyncio.run`` when no loop is active; if called from inside a running
    loop (e.g. an async web handler) it runs the coroutine on a worker thread
    with its own loop, so it never collides with the caller's loop.
    """
    try:
        asyncio.get_running_loop()
    except RuntimeError:
        return asyncio.run(factory())

    box: dict[str, _T] = {}
    err: dict[str, BaseException] = {}

    def worker() -> None:
        try:
            box["v"] = asyncio.run(factory())
        except BaseException as exc:  # noqa: BLE001 - re-raised on the calling thread
            err["e"] = exc

    thread = threading.Thread(target=worker, daemon=True)
    thread.start()
    thread.join()
    if "e" in err:
        raise err["e"]
    return box["v"]


def _severity_for(category: str, confidence: str) -> Severity:
    cat = category.lower()
    conf = confidence.lower()
    if cat in _CRITICAL_CATEGORIES and conf in _HIGH_CONFIDENCE:
        return Severity.CRITICAL
    if conf in _HIGH_CONFIDENCE:
        return Severity.HIGH
    if conf == "medium":
        return Severity.MEDIUM
    return Severity.LOW


def _clamp(value: float) -> float:
    return max(0.0, min(10.0, float(value)))


def _schema_hash(schema: dict[str, object] | None) -> str | None:
    if not schema:
        return None
    canonical = json.dumps(schema, sort_keys=True, separators=(",", ":"), ensure_ascii=True)
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


def _build_evidence(audit) -> ScanEvidence:  # noqa: ANN001 - mcp-audits runtime model
    tools = [
        ToolEvidence(
            name=str(tool.name),
            has_input_schema=bool(tool.input_schema),
            input_schema_sha256=_schema_hash(tool.input_schema),
            has_annotations=tool.annotations is not None,
        )
        for tool in audit.tools
    ]
    return ScanEvidence(
        tool_count=len(audit.tools),
        tools=tools,
        prompt_count=len(audit.prompts),
        resource_count=len(audit.resources),
    )


class MCPAuditEngine:
    """Scan engine backed by the public ``mcp-audits`` package.

    Raises ``ScanError`` if ``mcp-audits`` is not installed or a scan cannot
    complete (server unreachable, connection failed/timed out).
    """

    name: str = "mcpaudit"
    version: str = _FALLBACK_VERSION

    def __init__(self, timeout: float = 15.0, sandbox: Sandbox | None = None) -> None:
        self._timeout = timeout
        # None → resolve from MCP_TRUST_SANDBOX at scan time (default: NoSandbox).
        self._sandbox = sandbox

    def _resolve_sandbox(self, source: ServerSource) -> Sandbox:
        """Resolve the sandbox for one scan: injected > per-server image > env.

        Fail-closed for untrusted sources: a stdio source that launches a local
        process may only be scanned inside a sandbox. If resolution yields
        ``NoSandbox`` (the default when ``MCP_TRUST_SANDBOX`` is unset) it is
        allowed ONLY for a source explicitly marked ``trusted``; otherwise this
        raises rather than silently running third-party code on the host. Remote
        (HTTP) sources launch no local process, so the gate does not apply.
        """
        if self._sandbox is not None:
            sandbox = self._sandbox
        else:
            sandbox = select_sandbox(image=source.sandbox_image)
        launches_process = not (source.kind == SourceKind.REMOTE and not source.command)
        # Key off the sandbox's declared isolation CAPABILITY, not its class, so
        # any passthrough (NoSandbox or a custom one) is caught. Absent/false
        # ``isolates`` is treated as non-isolating (fail-closed).
        if launches_process and not getattr(sandbox, "isolates", False) and not source.trusted:
            raise ScanError(
                f"Refusing to scan untrusted source {source.reference!r} without a "
                "sandbox: launching its process would run third-party code on the "
                "host with the host environment. Set MCP_TRUST_SANDBOX=docker to "
                "isolate it, or mark the source trusted for the vetted "
                "reference-server flow."
            )
        return sandbox

    def scan(self, source: ServerSource) -> EngineResult:
        """Run the ``mcp-audits`` pipeline against *source* and normalize results."""
        try:
            from mcp_audit.analyzer import PermissionAnalyzer  # noqa: PLC0415
            from mcp_audit.connector import ServerConnector  # noqa: PLC0415
            from mcp_audit.models import ClientType, ServerConfig, TransportType  # noqa: PLC0415
            from mcp_audit.scorer import RiskScorer  # noqa: PLC0415
        except ImportError as exc:
            raise ScanError(
                "mcp-audits is not installed. "
                "Run: pip install 'mcp-trust[engine]' to enable real scanning."
            ) from exc

        sandbox = self._resolve_sandbox(source)
        if not sandbox.available():
            raise ScanError(
                f"Sandbox {sandbox.name!r} is not available on this host "
                "(is docker installed and running?)."
            )
        _apply_dummy_credentials(sandbox, source)

        cfg = self._build_config(source, ServerConfig, ClientType, TransportType, sandbox)

        connector = ServerConnector(timeout=self._timeout)
        analyzer = PermissionAnalyzer()
        scorer = RiskScorer()

        try:
            audit = _run_sync(lambda: connector.connect(cfg))
        except Exception as exc:
            logger.warning("mcp-audits connect failed for %r: %s", source.reference, exc)
            raise ScanError(f"Failed to connect to {source.reference!r}: {exc}") from exc

        status = (audit.connection_status or "").lower()
        if status in {"failed", "timeout"}:
            raise ScanError(
                f"Could not scan {source.reference!r}: connection {status}. "
                "A trust grade requires a successful connection to enumerate tools."
            )

        # The analyze -> score -> map stretch reads mcp-audits objects by bare
        # attribute access, so an upstream field rename would otherwise surface
        # as a raw AttributeError mid-scan. Normalize any such drift into
        # ScanError — the registry's one engine-failure contract.
        try:
            permissions = analyzer.analyze_server(audit.tools)
            risk_score = scorer.score_server(permissions)

            findings: list[Finding] = []
            by_severity: dict[Severity, int] = {}
            for perm in permissions:
                sev = _severity_for(str(perm.category), str(perm.confidence))
                findings.append(
                    Finding(
                        rule_id=perm.rule_id,
                        title=perm.title,
                        severity=sev,
                        category=str(perm.category),
                        detail="; ".join(perm.evidence),
                    )
                )
                by_severity[sev] = by_severity.get(sev, 0) + 1

            # annotation_coverage drives the transparency axis (0–1). Default to 0.0
            # when the audit doesn't report it, since absence of declared annotations
            # is exactly the low-transparency case we want to surface.
            coverage = float(getattr(audit, "annotation_coverage", 0.0) or 0.0)

            risk = RiskSummary(
                composite=_clamp(risk_score.composite),
                file_access=_clamp(risk_score.file_access),
                network_access=_clamp(risk_score.network_access),
                shell_execution=_clamp(risk_score.shell_execution),
                destructive=_clamp(risk_score.destructive),
                exfiltration=_clamp(risk_score.exfiltration),
                findings_by_severity=by_severity,
                annotation_coverage=max(0.0, min(1.0, coverage)),
            )
            evidence = _build_evidence(audit)
        except Exception as exc:
            logger.warning("mcp-audits analyze/map failed for %r: %s", source.reference, exc)
            raise ScanError(
                f"mcp-audits returned an unexpected result shape while scanning "
                f"{source.reference!r}: {exc}. The installed mcp-audits version is "
                "likely incompatible with this registry build."
            ) from exc

        return EngineResult(
            engine_name=self.name,
            engine_version=self._installed_version(),
            risk=risk,
            findings=findings,
            evidence=evidence,
        )

    def _build_config(self, source, ServerConfig, ClientType, TransportType, sandbox):  # noqa: ANN001
        """Translate a ``ServerSource`` into an mcp-audits ``ServerConfig``.

        For stdio servers the launch command is wrapped by *sandbox* so the
        untrusted server process runs isolated. Remote (HTTP) servers launch no
        local process, so the sandbox does not apply.
        """
        # config_path is a required provenance field in mcp-audits; the registry
        # is the source of this entry rather than a client config file.
        base = {
            "name": source.reference,
            "client": ClientType.CLAUDE_CODE,
            "config_path": "<mcp-trust-registry>",
            "env_keys": list(source.env_keys),
        }

        if source.kind == SourceKind.REMOTE and not source.command:
            return ServerConfig(**base, transport=TransportType.HTTP, url=source.reference)

        command, args = self._launch_spec(source)
        command, args = sandbox.wrap(command, args)
        return ServerConfig(**base, transport=TransportType.STDIO, command=command, args=args)

    @staticmethod
    def _launch_spec(source) -> tuple[str, list[str]]:  # noqa: ANN001
        """Resolve (command, args) for a stdio server. Explicit command wins."""
        if source.command:
            return source.command, list(source.args)
        if source.kind == SourceKind.NPM:
            return "npx", ["-y", source.reference, *source.args]
        if source.kind == SourceKind.PYPI:
            return "uvx", [source.reference, *source.args]
        if source.kind == SourceKind.BINARY:
            return source.reference, list(source.args)
        # GIT or anything else without an explicit command is ambiguous to launch.
        raise ScanError(
            f"Cannot infer a launch command for {source.reference!r} "
            f"(kind={source.kind}); set an explicit `command` on the source."
        )

    def _installed_version(self) -> str:
        try:
            import importlib.metadata  # noqa: PLC0415

            return importlib.metadata.version("mcp-audits")
        except Exception:  # noqa: BLE001 - version is best-effort metadata
            return _FALLBACK_VERSION


# Satisfy the Protocol at import time without mcp_audit present.
_: ScanEngine = MCPAuditEngine()  # type: ignore[assignment]
