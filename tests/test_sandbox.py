"""Tests for execution sandboxing. The wrap/select logic is pure and always
runs; actual container execution is integration-gated (needs a Docker daemon)."""

from __future__ import annotations

import pytest

from mcp_trust.core.models import ServerSource, SourceKind
from mcp_trust.engine.base import ScanError
from mcp_trust.engine.mcpaudit import MCPAuditEngine
from mcp_trust.engine.sandbox import (
    DockerSandbox,
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
    cmd, args = DockerSandbox().wrap("uvx", ["acme-mcp"])
    assert cmd == "docker"
    joined = " ".join(args)
    # No egress, no privileges, no caps, read-only fs, resource ceilings.
    assert "--network none" in joined
    assert "--security-opt no-new-privileges" in joined
    assert "--cap-drop ALL" in joined
    assert "--read-only" in args
    assert "--pids-limit" in args
    assert "--memory" in args
    assert "-i" in args  # stdio transport stays open
    # original command lands after the image
    assert args[-2:] == ["uvx", "acme-mcp"]


def test_docker_network_is_configurable() -> None:
    _, args = DockerSandbox(network="bridge").wrap("npx", ["x"])
    assert "bridge" in args


def test_docker_optional_user_flag() -> None:
    _, with_user = DockerSandbox(user="1000:1000").wrap("npx", ["x"])
    assert "--user" in with_user and "1000:1000" in with_user
    _, without = DockerSandbox().wrap("npx", ["x"])
    assert "--user" not in without


def test_select_sandbox_by_name_and_env(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("MCP_TRUST_SANDBOX", raising=False)
    assert isinstance(select_sandbox("none"), NoSandbox)
    assert isinstance(select_sandbox("docker"), DockerSandbox)
    assert isinstance(select_sandbox(), NoSandbox)  # default
    monkeypatch.setenv("MCP_TRUST_SANDBOX", "docker")
    assert isinstance(select_sandbox(), DockerSandbox)


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

    # A trusted source may use NoSandbox — the vetted reference-server flow.
    trusted = ServerSource(kind=SourceKind.NPM, reference="@acme/ref", trusted=True)
    assert isinstance(engine._resolve_sandbox(trusted), NoSandbox)

    # A remote (no-launch) source is exempt — no local process is spawned.
    remote = ServerSource(kind=SourceKind.REMOTE, reference="https://example.com/mcp")
    assert isinstance(engine._resolve_sandbox(remote), NoSandbox)
