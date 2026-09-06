"""Tests for the MCPAuditEngine adapter.

The pure mapping logic (`_severity_for`, `_launch_spec`) needs no engine and
always runs. The full-scan integration test launches a real server process and
is opt-in (set MCP_TRUST_RUN_INTEGRATION=1 with the engine extra installed).
"""

from __future__ import annotations

import asyncio
import importlib.util
import json
import os
import subprocess
import threading
import time
import traceback

import pytest

from mcp_trust.core.models import ServerSource, Severity, SourceKind
from mcp_trust.engine.base import ScanError, ScanTimeoutError
from mcp_trust.engine.mcpaudit import (
    MCPAuditEngine,
    _run_sync,
    _severity_for,
    docker_launch_spec,
    docker_process_title,
    gate_connector_teardown_for_runtime_attestation,
)
from mcp_trust.engine.sandbox import (
    DockerSandbox,
    DockerSandboxRuntimeReadbackError,
    sandbox_server_process_digest,
)

_HAS_ENGINE = importlib.util.find_spec("mcp_audit") is not None


def _empty_cleanup_runner(
    command: list[str], **_kwargs: object
) -> subprocess.CompletedProcess[str]:
    return subprocess.CompletedProcess(command, 0, "", "")


def _docker_lifecycle_runner(
    sandbox: DockerSandbox,
    *,
    process_override: dict[str, object] | None = None,
):  # noqa: ANN202
    container_id = "d" * 64
    image_id = "sha256:" + "1" * 64
    present = False
    server_process_digest = ""

    def runner(
        command: list[str], **_kwargs: object
    ) -> subprocess.CompletedProcess[str]:
        nonlocal present, server_process_digest
        if "create" in command:
            present = True
            image_index = command.index(sandbox.image)
            server_process_digest = sandbox_server_process_digest(
                command[image_index + 1], command[image_index + 2 :]
            )
            return subprocess.CompletedProcess(command, 0, container_id + "\n", "")
        if "inspect" in command and "container" in command:
            payload = {
                "Id": container_id,
                "Name": f"/{sandbox.container_name}",
                "Image": image_id,
                "State": {"Running": True},
                "Config": {
                    "Env": ["PATH=/bin", "HOME=/scan", "TMPDIR=/scan"],
                    "User": "1000:1000",
                    "WorkingDir": "/scan",
                    "Labels": {"com.mcp-trust.scan-owner": sandbox._owner_token},
                },
                "HostConfig": {
                    "NetworkMode": "none",
                    "ReadonlyRootfs": True,
                    "CapDrop": ["ALL"],
                    "SecurityOpt": ["no-new-privileges"],
                    "Memory": 512 * 1024 * 1024,
                    "MemorySwap": 512 * 1024 * 1024,
                    "NanoCpus": 1_000_000_000,
                    "PidsLimit": 256,
                    "Privileged": False,
                    "Binds": None,
                    "Tmpfs": {"/scan": "rw,size=67108864,mode=1777"},
                },
                "Mounts": [],
            }
            return subprocess.CompletedProcess(command, 0, json.dumps([payload]), "")
        if "inspect" in command and "image" in command:
            return subprocess.CompletedProcess(
                command,
                0,
                json.dumps([{"Id": image_id, "Config": {"Env": ["PATH=/bin"]}}]),
                "",
            )
        if "exec" in command:
            process = {
                "uid": 1000,
                "gid": 1000,
                "environment_names": ["HOME", "HOSTNAME", "PATH", "TMPDIR"],
                "network_interfaces": ["lo"],
                "cap_eff": "0000000000000000",
                "no_new_privs": "1",
                "root_mount_options": ["ro"],
                "workdir_mount_options": ["rw"],
                "workdir_filesystem": "tmpfs",
                "root_write_denied": True,
                "workdir_write_verified": True,
                "memory_max": str(512 * 1024 * 1024),
                "pids_max": "256",
                "cpu_quota": "100000",
                "cpu_period": "100000",
                "server_process_cmdline_digest": server_process_digest,
                "server_process_state": "S (sleeping)",
                "same_network_namespace": True,
                "same_mount_namespace": True,
                "same_cgroup": True,
            }
            if process_override:
                process.update(process_override)
            return subprocess.CompletedProcess(command, 0, json.dumps(process), "")
        if "ls" in command:
            assert "--no-trunc" in command
            stdout = container_id + "\n" if present else ""
            return subprocess.CompletedProcess(command, 0, stdout, "")
        if "rm" in command:
            present = False
            return subprocess.CompletedProcess(command, 0, container_id + "\n", "")
        return subprocess.CompletedProcess(command, 0, "", "")

    return runner


@pytest.mark.parametrize("timeout", [0.0, -1.0, float("nan"), float("inf")])
def test_engine_rejects_invalid_timeout(timeout: float) -> None:
    with pytest.raises(ValueError, match="positive finite"):
        MCPAuditEngine(timeout=timeout)


def test_docker_lifecycle_success_requires_verified_absence() -> None:
    class _Connector:
        async def connect(self, _cfg: object) -> object:
            return object()

    sandbox = DockerSandbox()
    runner = _docker_lifecycle_runner(sandbox)
    sandbox.prepare_owned_container("npx", ["server"], runner=runner)
    audit, evidence, runtime_readback = MCPAuditEngine(
        timeout=1.0,
        cleanup_runner=runner,
    )._connect_with_lifecycle(
        _Connector(), object(), sandbox, launches_process=True
    )

    assert audit is not None
    assert evidence == "CONTAINER_ABSENCE_VERIFIED"
    assert runtime_readback is not None
    assert runtime_readback["state"] == "VERIFIED"


def test_fast_connector_stays_live_until_runtime_attestation_finishes() -> None:
    release = threading.Event()
    started = threading.Event()

    class _Connector:
        live = False

        async def _list_capabilities(self, _session: object, _name: str) -> object:
            return object()

        async def connect(self, _cfg: object) -> object:
            self.live = True
            started.set()
            try:
                return await self._list_capabilities(object(), "fast-server")
            finally:
                self.live = False

    connector = _Connector()
    gate_connector_teardown_for_runtime_attestation(
        connector,
        release=release,
        timeout=1.0,
    )

    def runtime_probe() -> dict[str, object]:
        assert started.wait(1.0) is True
        assert connector.live is True
        return {"state": "VERIFIED"}

    audit, readback = _run_sync(
        lambda: connector.connect(object()),
        outer_timeout=1.0,
        runtime_probe=runtime_probe,
        attestation_release=release,
    )

    assert audit is not None
    assert readback == {"state": "VERIFIED"}
    assert connector.live is False


def test_docker_lifecycle_accepts_source_qualified_python_console_identity() -> None:
    class _Connector:
        async def connect(self, _cfg: object) -> object:
            return object()

    sandbox = DockerSandbox()
    process_digest = sandbox_server_process_digest(
        "/opt/venv/bin/python", ["/opt/venv/bin/mcp-server-time"]
    )
    runner = _docker_lifecycle_runner(
        sandbox,
        process_override={"server_process_cmdline_digest": process_digest},
    )
    sandbox.prepare_owned_container(
        "mcp-server-time", [], allow_python_console_script=True, runner=runner
    )

    _, _, runtime_readback = MCPAuditEngine(
        timeout=1.0, cleanup_runner=runner
    )._connect_with_lifecycle(_Connector(), object(), sandbox, launches_process=True)

    assert runtime_readback is not None
    assert runtime_readback["observed"]["server_process_cmdline_digest"] == process_digest


def test_docker_lifecycle_rejects_unrelated_python_console_identity() -> None:
    class _Connector:
        async def connect(self, _cfg: object) -> object:
            return object()

    sandbox = DockerSandbox()
    runner = _docker_lifecycle_runner(
        sandbox,
        process_override={
            "server_process_cmdline_digest": sandbox_server_process_digest(
                "/opt/venv/bin/python", ["/opt/venv/bin/unrelated-server"]
            )
        },
    )
    sandbox.prepare_owned_container(
        "mcp-server-time", [], allow_python_console_script=True, runner=runner
    )

    with pytest.raises(ScanError, match="failed controls: server_process_identity") as caught:
        MCPAuditEngine(timeout=1.0, cleanup_runner=runner)._connect_with_lifecycle(
            _Connector(), object(), sandbox, launches_process=True
        )

    assert isinstance(caught.value.__cause__, DockerSandboxRuntimeReadbackError)
    assert caught.value.__cause__.failed_controls == ("server_process_identity",)


def test_docker_outer_deadline_verifies_absence_before_timeout_result() -> None:
    class _Connector:
        async def connect(self, _cfg: object) -> object:
            await asyncio.sleep(2.0)
            return object()

    sandbox = DockerSandbox()
    runner = _docker_lifecycle_runner(sandbox)
    sandbox.prepare_owned_container("npx", ["server"], runner=runner)
    engine = MCPAuditEngine(timeout=0.001, cleanup_runner=runner)

    with pytest.raises(ScanTimeoutError) as caught:
        engine._connect_with_lifecycle(
            _Connector(), object(), sandbox, launches_process=True
        )

    assert (
        caught.value.hard_termination_evidence
        == "CONTAINER_ABSENCE_VERIFIED_AFTER_TIMEOUT"
    )


def test_docker_cleanup_failure_refuses_scan_evidence() -> None:
    class _Connector:
        async def connect(self, _cfg: object) -> object:
            return object()

    def failed_runner(
        command: list[str], **_kwargs: object
    ) -> subprocess.CompletedProcess[str]:
        return subprocess.CompletedProcess(command, 1, "", "daemon unavailable")

    with pytest.raises(ScanError, match="refusing to return scan evidence"):
        MCPAuditEngine(timeout=1.0, cleanup_runner=failed_runner)._connect_with_lifecycle(
            _Connector(), object(), DockerSandbox(), launches_process=True
        )


def test_runtime_probe_failure_does_not_wait_for_connector_deadline() -> None:
    class _Connector:
        async def connect(self, _cfg: object) -> object:
            await asyncio.sleep(2.0)
            return object()

    sandbox = DockerSandbox()
    base_runner = _docker_lifecycle_runner(sandbox)
    private_error = "/Users/operator/private/runtime-command-error"

    def failed_probe_runner(
        command: list[str], **kwargs: object
    ) -> subprocess.CompletedProcess[str]:
        if "exec" in command:
            raise OSError(private_error)
        return base_runner(command, **kwargs)

    sandbox.prepare_owned_container("npx", ["server"], runner=failed_probe_runner)
    started = time.monotonic()
    with pytest.raises(ScanError, match="runtime controls could not be attested") as caught:
        MCPAuditEngine(
            timeout=5.0,
            cleanup_runner=failed_probe_runner,
        )._connect_with_lifecycle(
            _Connector(), object(), sandbox, launches_process=True
        )

    assert time.monotonic() - started < 1.0
    assert private_error not in "".join(traceback.format_exception(caught.value))
    assert isinstance(caught.value.__cause__, DockerSandboxRuntimeReadbackError)
    assert caught.value.__cause__.__cause__ is None
    assert caught.value.__cause__.__context__ is None


def test_runtime_control_failure_preserves_only_sanitized_names_to_direct_caller() -> None:
    class _Connector:
        async def connect(self, _cfg: object) -> object:
            return object()

    private_runtime_value = "/Users/operator/private/network-observation"
    sandbox = DockerSandbox()
    runner = _docker_lifecycle_runner(
        sandbox,
        process_override={"network_interfaces": ["lo", private_runtime_value]},
    )
    sandbox.prepare_owned_container("npx", ["server"], runner=runner)

    with pytest.raises(ScanError, match="failed controls: network_none") as caught:
        MCPAuditEngine(timeout=1.0, cleanup_runner=runner)._connect_with_lifecycle(
            _Connector(), object(), sandbox, launches_process=True
        )

    assert private_runtime_value not in str(caught.value)
    assert isinstance(caught.value.__cause__, DockerSandboxRuntimeReadbackError)
    assert caught.value.__cause__.failed_controls == ("network_none",)


def test_malformed_runtime_value_is_absent_from_direct_caller_exception_chain() -> None:
    class _Connector:
        async def connect(self, _cfg: object) -> object:
            return object()

    private_runtime_value = "/Users/operator/private/runtime-numeric-value"
    sandbox = DockerSandbox()
    runner = _docker_lifecycle_runner(
        sandbox,
        process_override={"uid": private_runtime_value},
    )
    sandbox.prepare_owned_container("npx", ["server"], runner=runner)

    with pytest.raises(ScanError, match="runtime controls could not be attested") as caught:
        MCPAuditEngine(timeout=1.0, cleanup_runner=runner)._connect_with_lifecycle(
            _Connector(), object(), sandbox, launches_process=True
        )

    rendered = "".join(traceback.format_exception(caught.value))
    assert private_runtime_value not in rendered
    assert isinstance(caught.value.__cause__, DockerSandboxRuntimeReadbackError)
    assert caught.value.__cause__.failed_controls == ()
    assert caught.value.__cause__.__cause__ is None
    assert caught.value.__cause__.__context__ is None


@pytest.mark.parametrize(
    ("category", "confidence", "expected"),
    [
        ("destructive", "high", Severity.CRITICAL),
        ("exfiltration", "llm", Severity.CRITICAL),
        ("destructive", "medium", Severity.MEDIUM),  # high category, low confidence -> not critical
        ("file_read", "high", Severity.HIGH),
        ("network", "medium", Severity.MEDIUM),
        ("file_read", "low", Severity.LOW),
        ("file_read", "declared", Severity.LOW),
    ],
)
def test_severity_normalization(category: str, confidence: str, expected: Severity) -> None:
    assert _severity_for(category, confidence) == expected


def test_launch_spec_npm() -> None:
    src = ServerSource(kind=SourceKind.NPM, reference="@acme/server", args=["--flag"])
    assert MCPAuditEngine._launch_spec(src) == ("npx", ["-y", "@acme/server", "--flag"])


def test_launch_spec_pypi() -> None:
    src = ServerSource(kind=SourceKind.PYPI, reference="acme-mcp")
    assert MCPAuditEngine._launch_spec(src) == ("uvx", ["acme-mcp"])


def test_launch_spec_binary() -> None:
    src = ServerSource(kind=SourceKind.BINARY, reference="/usr/local/bin/acme", args=["serve"])
    assert MCPAuditEngine._launch_spec(src) == ("/usr/local/bin/acme", ["serve"])


def test_launch_spec_explicit_command_wins() -> None:
    src = ServerSource(kind=SourceKind.NPM, reference="@acme/server", command="node", args=["x.js"])
    assert MCPAuditEngine._launch_spec(src) == ("node", ["x.js"])


def test_docker_launch_spec_uses_exact_node_console_script_path() -> None:
    src = ServerSource(
        kind=SourceKind.NPM,
        reference="@adeu/mcp-server",
        command="adeu-mcp-server",
        args=["--flag"],
    )

    assert docker_launch_spec(src) == (
        "/usr/local/bin/node",
        ["/opt/npm/node_modules/.bin/adeu-mcp-server", "--flag"],
    )


def test_chrome_devtools_process_title_is_bound_to_exact_source() -> None:
    src = ServerSource(
        kind=SourceKind.NPM,
        reference="chrome-devtools-mcp",
        command="chrome-devtools-mcp",
    )
    assert docker_process_title(src) == "chrome-devtools-mcp"

    drifted = src.model_copy(update={"command": "chrome-devtools"})
    with pytest.raises(ScanError, match="process-title binding is not qualified"):
        docker_process_title(drifted)


def test_docker_launch_spec_rejects_npm_path_alias() -> None:
    src = ServerSource(
        kind=SourceKind.NPM,
        reference="@adeu/mcp-server",
        command="/opt/npm/node_modules/.bin/adeu-mcp-server",
    )

    with pytest.raises(ScanError, match="not qualified"):
        docker_launch_spec(src)


@pytest.mark.parametrize(
    ("reference", "command"),
    [
        ("@adeu/mcp-server", "wrong-command"),
        ("@adeu/mcp-server", "npx"),
    ],
)
def test_docker_launch_spec_rejects_unqualified_npm_binding(
    reference: str, command: str
) -> None:
    src = ServerSource(kind=SourceKind.NPM, reference=reference, command=command)
    with pytest.raises(ScanError, match="not qualified"):
        docker_launch_spec(src)


def test_launch_spec_git_without_command_raises() -> None:
    src = ServerSource(kind=SourceKind.GIT, reference="https://example.com/acme.git")
    with pytest.raises(ScanError):
        MCPAuditEngine._launch_spec(src)


def test_scan_raises_clear_error_without_engine() -> None:
    if _HAS_ENGINE:
        pytest.skip("engine installed; this asserts the missing-engine path")
    src = ServerSource(kind=SourceKind.NPM, reference="@acme/server")
    with pytest.raises(ScanError, match="mcp-audits is not installed"):
        MCPAuditEngine().scan(src)


@pytest.mark.skipif(not _HAS_ENGINE, reason="needs mcp-audits installed")
def test_scan_refuses_untrusted_without_sandbox(monkeypatch: pytest.MonkeyPatch) -> None:
    # End-to-end: the public scan() path must fail closed for an untrusted,
    # process-launching source with no sandbox — locks the contract against a
    # refactor that stops calling _resolve_sandbox() from inside scan().
    monkeypatch.delenv("MCP_TRUST_SANDBOX", raising=False)
    src = ServerSource(kind=SourceKind.NPM, reference="@acme/untrusted")
    with pytest.raises(ScanError, match="Refusing to scan untrusted"):
        MCPAuditEngine().scan(src)


@pytest.mark.skipif(not _HAS_ENGINE, reason="needs mcp-audits installed")
def test_scan_wraps_engine_shape_drift_in_scan_error(monkeypatch: pytest.MonkeyPatch) -> None:
    """An upstream attribute rename must surface as ScanError, not raw AttributeError.

    Simulates mcp-audits changing its result shape (here: RiskScore losing its
    fields) after a successful connect — the analyze/score/map stretch must
    normalize that into the registry's one engine-failure contract.
    """

    class _Stub:
        connection_status = "connected"
        tools: list = []

    async def fake_connect(self: object, cfg: object) -> _Stub:
        return _Stub()

    def fake_score(self: object, permissions: object) -> object:
        return object()  # no .composite / dimensions — a renamed-field upstream

    monkeypatch.setattr("mcp_audit.connector.ServerConnector.connect", fake_connect)
    monkeypatch.setattr("mcp_audit.scorer.RiskScorer.score_server", fake_score)

    src = ServerSource(kind=SourceKind.NPM, reference="@acme/server", trusted=True)
    with pytest.raises(ScanError, match="unexpected result shape"):
        MCPAuditEngine().scan(src)


@pytest.mark.skipif(not _HAS_ENGINE, reason="needs mcp-audits installed")
def test_scan_classifies_connection_timeout_distinctly(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    class _TimedOut:
        connection_status = "timeout"

    async def fake_connect(self: object, cfg: object) -> _TimedOut:
        return _TimedOut()

    monkeypatch.setattr("mcp_audit.connector.ServerConnector.connect", fake_connect)
    src = ServerSource(kind=SourceKind.NPM, reference="@acme/server", trusted=True)

    with pytest.raises(ScanTimeoutError, match="connection timeout"):
        MCPAuditEngine(timeout=90.0).scan(src)


@pytest.mark.skipif(not _HAS_ENGINE, reason="needs mcp-audits installed")
def test_scan_surfaces_resolved_sandbox_image(monkeypatch: pytest.MonkeyPatch) -> None:
    """The engine records the image the scan actually ran in on the EngineResult.

    Locks the provenance source-of-truth: a refactor that stops threading the
    resolved sandbox's image into EngineResult would silently reintroduce the
    Gate-0 receipt gap (per-server pins recorded as the env default).
    """

    class _Audit:
        connection_status = "connected"
        tools: list = []
        prompts: list = []
        resources: list = []
        annotation_coverage = 1.0

    class _Score:
        composite = 1.0
        file_access = 0.0
        network_access = 0.0
        shell_execution = 0.0
        destructive = 0.0
        exfiltration = 0.0

    async def fake_connect(self: object, cfg: object) -> _Audit:
        return _Audit()

    monkeypatch.setattr("mcp_audit.connector.ServerConnector.connect", fake_connect)
    monkeypatch.setattr(
        "mcp_audit.analyzer.PermissionAnalyzer.analyze_server", lambda self, tools: []
    )
    monkeypatch.setattr("mcp_audit.scorer.RiskScorer.score_server", lambda self, perms: _Score())

    # Inject a Docker sandbox pinned to a per-server image; the engine must
    # surface that exact image (not the env default) on the result.
    sandbox = DockerSandbox(image="mcp-trust-batch4:20260703")
    src = ServerSource(kind=SourceKind.NPM, reference="@acme/server", trusted=True)
    result = MCPAuditEngine(
        sandbox=sandbox,
        cleanup_runner=_docker_lifecycle_runner(sandbox),
    ).scan(src)
    assert result.sandbox_image == "mcp-trust-batch4:20260703"
    assert result.sandbox_cleanup_evidence == "CONTAINER_ABSENCE_VERIFIED"
    assert result.sandbox_runtime_readback is not None
    assert result.sandbox_runtime_readback["state"] == "VERIFIED"


@pytest.mark.skipif(not _HAS_ENGINE, reason="needs mcp-audits installed")
def test_scan_omits_sandbox_image_for_remote_endpoint(monkeypatch: pytest.MonkeyPatch) -> None:
    """Remote scans do not launch inside Docker, even when a Docker sandbox exists."""

    class _Audit:
        connection_status = "connected"
        tools: list = []
        prompts: list = []
        resources: list = []
        annotation_coverage = 1.0

    class _Score:
        composite = 1.0
        file_access = 0.0
        network_access = 0.0
        shell_execution = 0.0
        destructive = 0.0
        exfiltration = 0.0

    async def fake_connect(self: object, cfg: object) -> _Audit:
        return _Audit()

    monkeypatch.setattr("mcp_audit.connector.ServerConnector.connect", fake_connect)
    monkeypatch.setattr(
        "mcp_audit.analyzer.PermissionAnalyzer.analyze_server", lambda self, tools: []
    )
    monkeypatch.setattr("mcp_audit.scorer.RiskScorer.score_server", lambda self, perms: _Score())

    sandbox = DockerSandbox(image="mcp-trust-batch4:20260703")
    src = ServerSource(kind=SourceKind.REMOTE, reference="https://example.test/mcp")
    result = MCPAuditEngine(sandbox=sandbox).scan(src)
    assert result.sandbox_image is None


@pytest.mark.skipif(
    not (_HAS_ENGINE and os.environ.get("MCP_TRUST_RUN_INTEGRATION") == "1"),
    reason="opt-in: needs mcp-audits + MCP_TRUST_RUN_INTEGRATION=1 (launches a real server)",
)
def test_integration_scan_reference_server() -> None:
    from mcp_trust.core.grading import grade
    from mcp_trust.core.models import TrustGrade

    src = ServerSource(
        kind=SourceKind.NPM,
        reference="@modelcontextprotocol/server-everything",
        trusted=True,
    )
    result = MCPAuditEngine(timeout=60.0).scan(src)
    assert result.engine_name == "mcpaudit"
    assert 0.0 <= result.risk.composite <= 10.0
    assert grade(result.risk) in set(TrustGrade)
    assert result.findings  # the everything server exposes many capabilities
