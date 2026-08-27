"""Tests for execution sandboxing. The wrap/select logic is pure and always
runs; actual container execution is integration-gated (needs a Docker daemon)."""

from __future__ import annotations

import subprocess

import pytest

from mcp_trust.core.models import ServerSource, SourceKind
from mcp_trust.engine.base import ScanError
from mcp_trust.engine.mcpaudit import MCPAuditEngine
from mcp_trust.engine.sandbox import (
    DockerSandbox,
    DockerSandboxCleanupError,
    NoSandbox,
    Sandbox,
    select_sandbox,
)


def test_no_sandbox_is_passthrough() -> None:
    sb = NoSandbox()
    assert isinstance(sb, Sandbox)
    assert sb.available() is True
    assert sb.wrap("npx", ["-y", "@acme/server"]) == ("npx", ["-y", "@acme/server"])


def test_docker_wrap_runs_original_command_inside_container() -> None:
    sb = DockerSandbox(image="node:22-slim")
    cmd, args = sb.wrap("npx", ["-y", "@acme/server", "--flag"])
    assert cmd == "docker"
    # The image then the original command + args come last, in order.
    assert args[-5:] == ["node:22-slim", "npx", "-y", "@acme/server", "--flag"]


def test_docker_wrap_applies_isolation_flags() -> None:
    sandbox = DockerSandbox()
    cmd, args = sandbox.wrap("uvx", ["acme-mcp"])
    assert cmd == "docker"
    joined = " ".join(args)
    # No egress, no privileges, no caps, read-only fs, resource ceilings.
    assert "--network none" in joined
    assert "--security-opt no-new-privileges" in joined
    assert "--cap-drop ALL" in joined
    assert "--read-only" in args
    assert "--pids-limit" in args
    assert "--memory" in args
    assert "/scan:rw,size=64m,mode=1777" in args
    assert "-i" in args  # stdio transport stays open
    assert args[args.index("--name") + 1] == sandbox.container_name
    assert "com.mcp-trust.scan-owner=" in args[args.index("--label") + 1]
    # original command lands after the image
    assert args[-2:] == ["uvx", "acme-mcp"]


def test_docker_scan_identity_is_unique() -> None:
    assert DockerSandbox().container_name != DockerSandbox().container_name


def test_docker_prepares_immutable_container_before_connector_launch() -> None:
    sandbox = DockerSandbox(host="unix:///tmp/controlled-docker.sock")
    container_id = "c" * 64

    def runner(command: list[str], **_kwargs: object) -> subprocess.CompletedProcess[str]:
        return subprocess.CompletedProcess(command, 0, container_id + "\n", "")

    command, args = sandbox.prepare_owned_container("npx", ["server"], runner=runner)

    assert command == "docker"
    assert args == [
        "--host",
        "unix:///tmp/controlled-docker.sock",
        "container",
        "start",
        "--attach",
        "--interactive",
        container_id,
    ]


def test_docker_create_timeout_cleans_delayed_daemon_materialization(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    sandbox = DockerSandbox()
    container_id = "e" * 64
    calls: list[list[str]] = []
    list_queries = 0
    removed = False
    monkeypatch.setattr("mcp_trust.engine.sandbox.time.sleep", lambda _seconds: None)

    def runner(command: list[str], **_kwargs: object) -> subprocess.CompletedProcess[str]:
        nonlocal list_queries, removed
        calls.append(command)
        if "create" in command:
            raise subprocess.TimeoutExpired(command, 10.0)
        if "ls" in command:
            list_queries += 1
            stdout = container_id + "\n" if list_queries == 7 and not removed else ""
            return subprocess.CompletedProcess(command, 0, stdout, "")
        if "rm" in command:
            removed = True
            return subprocess.CompletedProcess(command, 0, container_id + "\n", "")
        raise AssertionError(command)

    with pytest.raises(DockerSandboxCleanupError, match="could not create"):
        sandbox.prepare_owned_container("npx", ["server"], runner=runner)

    assert any("rm" in command and container_id in command for command in calls)
    assert "ls" in calls[-1]


def test_docker_cleanup_removes_only_owned_container_id_and_proves_absence() -> None:
    sandbox = DockerSandbox(host="unix:///tmp/controlled-docker.sock")
    container_id = "a" * 64
    calls: list[list[str]] = []
    list_results = iter([container_id + "\n", ""])

    def runner(command: list[str], **_kwargs: object) -> subprocess.CompletedProcess[str]:
        calls.append(command)
        if "ls" in command:
            return subprocess.CompletedProcess(command, 0, next(list_results), "")
        return subprocess.CompletedProcess(command, 0, container_id + "\n", "")

    assert (
        sandbox.cleanup_owned_container(runner=runner)
        == "CONTAINER_ABSENCE_VERIFIED"
    )
    assert calls[1][-4:] == ["container", "rm", "--force", container_id]
    for query in (calls[0], calls[2]):
        assert query[:3] == ["docker", "--host", "unix:///tmp/controlled-docker.sock"]
        assert f"name=^/{sandbox.container_name}$" in query
        assert any(
            value.startswith("label=com.mcp-trust.scan-owner=") for value in query
        )


def test_docker_cleanup_empty_readback_is_verified_without_removal() -> None:
    calls: list[list[str]] = []

    def runner(command: list[str], **_kwargs: object) -> subprocess.CompletedProcess[str]:
        calls.append(command)
        return subprocess.CompletedProcess(command, 0, "", "")

    assert DockerSandbox().cleanup_owned_container(runner=runner) == (
        "CONTAINER_ABSENCE_VERIFIED"
    )
    assert len(calls) == 2
    assert all("ls" in command for command in calls)


@pytest.mark.parametrize("stdout", ["not-an-id\n", "a" * 12 + "\n" + "b" * 12 + "\n"])
def test_docker_cleanup_rejects_ambiguous_identity(stdout: str) -> None:
    def runner(command: list[str], **_kwargs: object) -> subprocess.CompletedProcess[str]:
        return subprocess.CompletedProcess(command, 0, stdout, "")

    with pytest.raises(DockerSandboxCleanupError, match="ambiguous"):
        DockerSandbox().cleanup_owned_container(runner=runner)


def test_docker_cleanup_fails_closed_when_daemon_query_fails() -> None:
    def runner(command: list[str], **_kwargs: object) -> subprocess.CompletedProcess[str]:
        return subprocess.CompletedProcess(command, 1, "", "daemon unavailable")

    with pytest.raises(DockerSandboxCleanupError, match="could not query"):
        DockerSandbox().cleanup_owned_container(runner=runner)


def test_docker_wrap_binds_the_preflighted_local_daemon() -> None:
    host = "unix:///Users/operator/.colima/default/docker.sock"

    command, args = DockerSandbox(host=host).wrap("npx", ["x"])

    assert command == "docker"
    assert args[:3] == ["--host", host, "run"]


def test_docker_network_is_configurable() -> None:
    _, args = DockerSandbox(network="bridge").wrap("npx", ["x"])
    assert "bridge" in args


def test_docker_runs_non_root_by_default() -> None:
    _, default_args = DockerSandbox().wrap("npx", ["x"])
    assert "--user" in default_args and "1000:1000" in default_args
    # HOME/TMPDIR point at the writable tmpfs so the unprivileged user can run.
    assert "HOME=/scan" in default_args and "TMPDIR=/scan" in default_args
    # Explicit override is honored.
    _, custom = DockerSandbox(user="65534:65534").wrap("npx", ["x"])
    assert "65534:65534" in custom
    # Opt out to root (for an image that requires it) with user=None.
    _, rooted = DockerSandbox(user=None).wrap("npx", ["x"])
    assert "--user" not in rooted


def test_select_sandbox_by_name_and_env(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("MCP_TRUST_SANDBOX", raising=False)
    assert isinstance(select_sandbox("none"), NoSandbox)
    assert isinstance(select_sandbox("docker"), DockerSandbox)
    assert isinstance(select_sandbox(), NoSandbox)  # default
    monkeypatch.setenv("MCP_TRUST_SANDBOX", "docker")
    assert isinstance(select_sandbox(), DockerSandbox)


def test_select_sandbox_uses_only_the_dedicated_preflighted_host(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    expected = "unix:///Users/operator/.colima/default/docker.sock"
    monkeypatch.setenv("DOCKER_HOST", "tcp://remote.example:2375")
    monkeypatch.setenv("MCP_TRUST_DOCKER_HOST", expected)

    sandbox = select_sandbox("docker")

    assert isinstance(sandbox, DockerSandbox)
    assert sandbox.host == expected


def test_select_sandbox_unknown_raises() -> None:
    with pytest.raises(ValueError, match="Unknown sandbox"):
        select_sandbox("vm")


def test_select_sandbox_per_server_image_overrides_env(monkeypatch: pytest.MonkeyPatch) -> None:
    # A server baked into a purpose-built image must scan against THAT image
    # even when the corpus-wide default is set — otherwise a whole-corpus
    # refresh silently keeps stale grades for it.
    monkeypatch.setenv("MCP_TRUST_SANDBOX_IMAGE", "corpus-default:1")
    sandbox = select_sandbox("docker", image="live-batch:2")
    assert isinstance(sandbox, DockerSandbox)
    assert sandbox.image == "live-batch:2"

    fallback = select_sandbox("docker", image=None)
    assert isinstance(fallback, DockerSandbox)
    assert fallback.image == "corpus-default:1"


def test_select_sandbox_image_ignored_for_none(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("MCP_TRUST_SANDBOX", raising=False)
    assert isinstance(select_sandbox("none", image="live-batch:2"), NoSandbox)


def test_engine_resolves_per_server_sandbox_image(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("MCP_TRUST_SANDBOX", "docker")
    monkeypatch.setenv("MCP_TRUST_SANDBOX_IMAGE", "corpus-default:1")

    pinned = ServerSource(
        kind=SourceKind.NPM, reference="@acme/baked", sandbox_image="live-batch:2"
    )
    unpinned = ServerSource(kind=SourceKind.NPM, reference="@acme/plain")

    engine = MCPAuditEngine()
    resolved = engine._resolve_sandbox(pinned)
    assert isinstance(resolved, DockerSandbox)
    assert resolved.image == "live-batch:2"

    default = engine._resolve_sandbox(unpinned)
    assert isinstance(default, DockerSandbox)
    assert default.image == "corpus-default:1"

    # An explicitly injected sandbox wins the SANDBOX CHOICE (test/CLI injection
    # seam) — but trust enforcement still applies, so use a trusted source.
    injected = NoSandbox()
    trusted = ServerSource(kind=SourceKind.NPM, reference="@acme/ref", trusted=True)
    assert MCPAuditEngine(sandbox=injected)._resolve_sandbox(trusted) is injected


def test_engine_wraps_launch_through_sandbox() -> None:
    # Verify the engine's launch spec composes with the sandbox without needing
    # mcp-audits installed: launch_spec -> sandbox.wrap.
    src = ServerSource(kind=SourceKind.NPM, reference="@acme/server", args=["--x"])
    base_cmd, base_args = MCPAuditEngine._launch_spec(src)
    assert (base_cmd, base_args) == ("npx", ["-y", "@acme/server", "--x"])

    wrapped_cmd, wrapped_args = DockerSandbox().wrap(base_cmd, base_args)
    assert wrapped_cmd == "docker"
    assert wrapped_args[-4:] == ["npx", "-y", "@acme/server", "--x"]


def test_engine_refuses_untrusted_without_sandbox(monkeypatch: pytest.MonkeyPatch) -> None:
    # Fail-closed: an untrusted stdio source with no sandbox (default NoSandbox)
    # must raise rather than launch third-party code on the host.
    monkeypatch.delenv("MCP_TRUST_SANDBOX", raising=False)
    engine = MCPAuditEngine()

    untrusted = ServerSource(kind=SourceKind.NPM, reference="@acme/untrusted")
    with pytest.raises(ScanError, match="Refusing to scan untrusted"):
        engine._resolve_sandbox(untrusted)

    # An injected NoSandbox cannot bypass the trust gate for an untrusted source.
    with pytest.raises(ScanError, match="Refusing to scan untrusted"):
        MCPAuditEngine(sandbox=NoSandbox())._resolve_sandbox(untrusted)

    # Capability-based, not class-based: a custom passthrough of a DIFFERENT
    # class that does not isolate (no truthy ``isolates``) is also refused.
    class _FakePassthrough:
        name = "fake"

        def available(self) -> bool:
            return True

        def wrap(self, command: str, args: list[str]) -> tuple[str, list[str]]:
            return command, list(args)

    with pytest.raises(ScanError, match="Refusing to scan untrusted"):
        MCPAuditEngine(sandbox=_FakePassthrough())._resolve_sandbox(untrusted)

    class _UnmanagedIsolatingSandbox(_FakePassthrough):
        isolates = True

    with pytest.raises(ScanError, match="lifecycle contract"):
        MCPAuditEngine(sandbox=_UnmanagedIsolatingSandbox())._resolve_sandbox(untrusted)

    # A trusted source may use NoSandbox — the vetted reference-server flow.
    trusted = ServerSource(kind=SourceKind.NPM, reference="@acme/ref", trusted=True)
    assert isinstance(engine._resolve_sandbox(trusted), NoSandbox)

    # A remote (no-launch) source is exempt — no local process is spawned.
    remote = ServerSource(kind=SourceKind.REMOTE, reference="https://example.com/mcp")
    assert isinstance(engine._resolve_sandbox(remote), NoSandbox)
