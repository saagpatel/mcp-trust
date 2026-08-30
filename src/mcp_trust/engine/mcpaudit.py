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
import math
import os
import subprocess
import threading
import time
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
from mcp_trust.engine.base import EngineResult, ScanEngine, ScanError, ScanTimeoutError
from mcp_trust.engine.credentials import build_dummy_env
from mcp_trust.engine.sandbox import (
    DockerSandbox,
    DockerSandboxCleanupError,
    DockerSandboxRuntimeReadbackError,
    Sandbox,
    select_sandbox,
)

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


def _run_sync(
    factory: Callable[[], Awaitable[_T]],
    *,
    outer_timeout: float | None = None,
    runtime_probe: Callable[[], dict[str, object]] | None = None,
) -> tuple[_T, dict[str, object] | None]:
    """Run an async coroutine to completion from sync code.

    Uses ``asyncio.run`` when no loop is active; if called from inside a running
    loop (e.g. an async web handler) it runs the coroutine on a worker thread
    with its own loop, so it never collides with the caller's loop.
    """
    if outer_timeout is None:
        if runtime_probe is not None:
            raise ValueError("a runtime probe requires an outer deadline")
        try:
            asyncio.get_running_loop()
        except RuntimeError:
            return asyncio.run(factory()), None

    box: dict[str, _T] = {}
    err: dict[str, BaseException] = {}

    def worker() -> None:
        try:
            box["v"] = asyncio.run(factory())
        except BaseException as exc:  # noqa: BLE001 - re-raised on the calling thread
            err["e"] = exc

    thread = threading.Thread(target=worker, daemon=True)
    deadline = None if outer_timeout is None else time.monotonic() + outer_timeout
    thread.start()
    runtime_readback: dict[str, object] | None = None
    runtime_error: BaseException | None = None
    if runtime_probe is not None:
        try:
            runtime_readback = runtime_probe()
        except BaseException as exc:  # cleanup is owned by the lifecycle caller
            runtime_error = exc
    if runtime_error is not None:
        raise runtime_error
    remaining = None if deadline is None else max(0.0, deadline - time.monotonic())
    thread.join(timeout=remaining)
    if thread.is_alive():
        raise TimeoutError("scan connector exceeded the repository outer deadline")
    if "e" in err:
        raise err["e"]
    return box["v"], runtime_readback


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


def launch_spec(source: ServerSource) -> tuple[str, list[str]]:
    """Resolve the exact in-container server argv without executing it."""
    if source.command:
        return source.command, list(source.args)
    if source.kind == SourceKind.NPM:
        return "npx", ["-y", source.reference, *source.args]
    if source.kind == SourceKind.PYPI:
        return "uvx", [source.reference, *source.args]
    if source.kind == SourceKind.BINARY:
        return source.reference, list(source.args)
    raise ScanError(
        f"Cannot infer a launch command for {source.reference!r} "
        f"(kind={source.kind}); set an explicit `command` on the source."
    )


def repository_outer_timeout_seconds(connector_timeout: float) -> float:
    """Repository hard deadline including the bounded runtime probe."""
    return connector_timeout + max(1.0, min(5.0, connector_timeout * 0.1))


class MCPAuditEngine:
    """Scan engine backed by the public ``mcp-audits`` package.

    Raises ``ScanError`` if ``mcp-audits`` is not installed or a scan cannot
    complete (server unreachable, connection failed/timed out).
    """

    name: str = "mcpaudit"
    version: str = _FALLBACK_VERSION

    @staticmethod
    def outer_timeout_seconds(connector_timeout: float) -> float:
        """Repository hard deadline including the bounded runtime probe."""
        return repository_outer_timeout_seconds(connector_timeout)

    def __init__(
        self,
        timeout: float = 15.0,
        sandbox: Sandbox | None = None,
        *,
        cleanup_runner: Callable[..., subprocess.CompletedProcess[str]] = subprocess.run,
    ) -> None:
        if not math.isfinite(timeout) or timeout <= 0:
            raise ValueError("scan timeout must be one positive finite number")
        self._timeout = timeout
        # None → resolve from MCP_TRUST_SANDBOX at scan time (default: NoSandbox).
        self._sandbox = sandbox
        self._cleanup_runner = cleanup_runner

    def _connect_with_lifecycle(
        self,
        connector: object,
        cfg: object,
        sandbox: Sandbox,
        *,
        launches_process: bool,
    ) -> tuple[object, str | None, dict[str, object] | None]:
        """Connect within a bounded Docker lifecycle and verify cleanup."""
        connect_error: BaseException | None = None
        audit: object | None = None
        runtime_readback: dict[str, object] | None = None
        try:
            # The connector owns its configured protocol timeout. Docker scans
            # also get a repository-owned outer deadline so an uncooperative
            # coroutine or active-loop bridge cannot block the caller forever.
            outer_timeout = self.outer_timeout_seconds(self._timeout)
            audit, runtime_readback = _run_sync(
                lambda: connector.connect(cfg),  # type: ignore[attr-defined]
                outer_timeout=(
                    outer_timeout
                    if launches_process and isinstance(sandbox, DockerSandbox)
                    else None
                ),
                runtime_probe=(
                    lambda: sandbox.capture_runtime_readback(runner=self._cleanup_runner)
                )
                if launches_process and isinstance(sandbox, DockerSandbox)
                else None,
            )
        except BaseException as exc:  # cleanup must also run for cancellation/system exit
            connect_error = exc

        cleanup_evidence: str | None = None
        if launches_process and isinstance(sandbox, DockerSandbox):
            try:
                cleanup_evidence = sandbox.cleanup_owned_container(
                    runner=self._cleanup_runner
                )
            except DockerSandboxCleanupError as exc:
                raise ScanError(
                    "Docker scan cleanup could not prove the owned container absent; "
                    "refusing to return scan evidence."
                ) from exc

        if connect_error is not None:
            if isinstance(connect_error, (KeyboardInterrupt, SystemExit)):
                raise connect_error
            if isinstance(connect_error, TimeoutError):
                logger.warning(
                    "mcp-audits connect exceeded the outer deadline: %s", connect_error
                )
                raise ScanTimeoutError(
                    "Could not scan: configured connection timeout expired.",
                    hard_termination_evidence=(
                        "CONTAINER_ABSENCE_VERIFIED_AFTER_TIMEOUT"
                        if cleanup_evidence == "CONTAINER_ABSENCE_VERIFIED"
                        else "UNKNOWN"
                    ),
                ) from connect_error
            if isinstance(connect_error, DockerSandboxRuntimeReadbackError):
                failed_controls = connect_error.failed_controls
                diagnostic = (
                    "; failed controls: " + ", ".join(failed_controls)
                    if failed_controls
                    else ""
                )
                raise ScanError(
                    "Docker live runtime controls could not be attested"
                    f"{diagnostic}; refusing to return scan evidence."
                ) from connect_error
            raise connect_error
        if audit is None:
            raise ScanError("mcp-audits returned no connection result")
        if launches_process and isinstance(sandbox, DockerSandbox) and runtime_readback is None:
            raise ScanError(
                "Docker live runtime controls were not attested; refusing to return "
                "scan evidence."
            )
        return audit, cleanup_evidence, runtime_readback

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
        launches_process = self._launches_local_process(source)
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
        if (
            launches_process
            and getattr(sandbox, "isolates", False)
            and not isinstance(sandbox, DockerSandbox)
        ):
            raise ScanError(
                "Refusing an isolating sandbox without the repository-owned "
                "container lifecycle contract."
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

        launches_process = self._launches_local_process(source)
        prepared_launch: tuple[str, list[str]] | None = None
        if launches_process and isinstance(sandbox, DockerSandbox):
            command, args = self._launch_spec(source)
            try:
                prepared_launch = sandbox.prepare_owned_container(
                    command,
                    args,
                    allow_python_console_script=(
                        source.kind == SourceKind.PYPI and source.command is not None
                    ),
                    runner=self._cleanup_runner,
                )
            except DockerSandboxCleanupError as exc:
                raise ScanError(
                    "Docker could not establish a uniquely owned scan lifecycle."
                ) from exc
        try:
            cfg = self._build_config(
                source,
                ServerConfig,
                ClientType,
                TransportType,
                sandbox,
                launch_override=prepared_launch,
            )
        except BaseException:
            if prepared_launch is not None:
                try:
                    sandbox.cleanup_owned_container(runner=self._cleanup_runner)
                except DockerSandboxCleanupError as exc:
                    raise ScanError(
                        "Docker scan configuration failed and cleanup could not prove "
                        "the owned container absent."
                    ) from exc
            raise

        connector = ServerConnector(timeout=self._timeout)
        analyzer = PermissionAnalyzer()
        scorer = RiskScorer()

        try:
            audit, cleanup_evidence, runtime_readback = self._connect_with_lifecycle(
                connector,
                cfg,
                sandbox,
                launches_process=launches_process,
            )
        except ScanTimeoutError:
            raise
        except TimeoutError as exc:
            logger.warning("mcp-audits connect timed out for %r: %s", source.reference, exc)
            raise ScanTimeoutError(
                f"Could not scan {source.reference!r}: configured connection timeout expired."
            ) from exc
        except ScanError:
            raise
        except Exception as exc:
            logger.warning("mcp-audits connect failed for %r: %s", source.reference, exc)
            raise ScanError(f"Failed to connect to {source.reference!r}: {exc}") from exc

        status = (audit.connection_status or "").lower()
        if status == "timeout":
            raise ScanTimeoutError(
                f"Could not scan {source.reference!r}: connection timeout. "
                "A trust grade requires a successful connection to enumerate tools.",
                hard_termination_evidence=(
                    "CONTAINER_ABSENCE_VERIFIED_AFTER_TIMEOUT"
                    if cleanup_evidence == "CONTAINER_ABSENCE_VERIFIED"
                    else "UNKNOWN"
                ),
            )
        if status == "failed":
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
            # Record the image the scan actually ran in — the resolved sandbox's
            # own image (per-server pin > env default), not a later re-read of
            # ambient env. None for remote scans or non-isolating passthroughs.
            sandbox_image=getattr(sandbox, "image", None) if launches_process else None,
            sandbox_cleanup_evidence=(cleanup_evidence if launches_process else None),
            sandbox_runtime_readback=(runtime_readback if launches_process else None),
        )

    def _build_config(  # noqa: ANN001
        self,
        source,
        ServerConfig,
        ClientType,
        TransportType,
        sandbox,
        *,
        launch_override: tuple[str, list[str]] | None = None,
    ):
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

        if not self._launches_local_process(source):
            return ServerConfig(**base, transport=TransportType.HTTP, url=source.reference)

        if launch_override is None:
            command, args = self._launch_spec(source)
            command, args = sandbox.wrap(command, args)
        else:
            command, args = launch_override
        return ServerConfig(**base, transport=TransportType.STDIO, command=command, args=args)

    @staticmethod
    def _launch_spec(source) -> tuple[str, list[str]]:  # noqa: ANN001
        """Resolve (command, args) for a stdio server. Explicit command wins."""
        return launch_spec(source)

    @staticmethod
    def _launches_local_process(source: ServerSource) -> bool:
        """Whether this source starts a local server process for mcp-audits."""
        return not (source.kind == SourceKind.REMOTE and not source.command)

    def _installed_version(self) -> str:
        try:
            import importlib.metadata  # noqa: PLC0415

            return importlib.metadata.version("mcp-audits")
        except Exception:  # noqa: BLE001 - version is best-effort metadata
            return _FALLBACK_VERSION


# Satisfy the Protocol at import time without mcp_audit present.
_: ScanEngine = MCPAuditEngine()  # type: ignore[assignment]
