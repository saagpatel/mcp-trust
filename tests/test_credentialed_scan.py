"""Tests for the credentialed-sandboxed scan mode.

The dummy-credential policy and the engine's safety guards are pure logic and
always run; actual container execution stays integration-gated (needs Docker).
The receipt test pins the honesty invariant: dummy values never leak.
"""

from __future__ import annotations

from datetime import datetime

import pytest

from mcp_trust.core.models import (
    RiskSummary,
    ScanRecord,
    Server,
    ServerSource,
    SourceKind,
    TrustGrade,
)
from mcp_trust.engine.base import ScanError
from mcp_trust.engine.credentials import build_dummy_env
from mcp_trust.engine.mcpaudit import _apply_dummy_credentials
from mcp_trust.engine.sandbox import DockerSandbox, NoSandbox
from mcp_trust.receipts import build_scan_receipt

_FAKE = "0" * 40


# --- dummy-credential policy ---------------------------------------------------


def test_build_dummy_env_uses_format_plausible_prefixes() -> None:
    env = build_dummy_env(["GITHUB_PERSONAL_ACCESS_TOKEN", "SLACK_BOT_TOKEN", "GITLAB_TOKEN"])
    assert env["GITHUB_PERSONAL_ACCESS_TOKEN"] == f"ghp_{_FAKE}"
    assert env["SLACK_BOT_TOKEN"] == f"xoxb-{_FAKE}"
    assert env["GITLAB_TOKEN"] == f"glpat-{_FAKE}"


def test_build_dummy_env_generic_fallback_and_empty() -> None:
    assert build_dummy_env(["BRAVE_API_KEY"]) == {"BRAVE_API_KEY": f"mcp-trust-dummy-{_FAKE}"}
    assert build_dummy_env([]) == {}
    # Falsy entries are skipped rather than producing a bare-prefix value.
    assert build_dummy_env([""]) == {}


def test_dummy_values_are_obviously_fake() -> None:
    # All-zeros payload reads as a placeholder, never a plausible real secret.
    for value in build_dummy_env(["GITHUB_TOKEN", "OTHER_KEY"]).values():
        assert _FAKE in value


# --- docker env injection ------------------------------------------------------


def test_docker_wrap_emits_env_flags_and_keeps_network_off() -> None:
    sb = DockerSandbox(env={"GITHUB_TOKEN": f"ghp_{_FAKE}"})
    _, args = sb.wrap("npx", ["-y", "@acme/server"])
    assert "--env" in args
    assert f"GITHUB_TOKEN=ghp_{_FAKE}" in args
    assert "--network" in args and "none" in args
    # Env flags precede the image; original command + args still land last.
    assert args[-4:] == ["node:22-slim", "npx", "-y", "@acme/server"]
    assert args.index("--env") < args.index("node:22-slim")


def test_docker_wrap_no_env_by_default() -> None:
    _, args = DockerSandbox().wrap("npx", ["x"])
    assert "--env" not in args


# --- engine safety guards ------------------------------------------------------


def _src() -> ServerSource:
    return ServerSource(kind=SourceKind.NPM, reference="@acme/server", env_keys=["GITHUB_TOKEN"])


def test_credentials_off_by_default_is_noop(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("MCP_TRUST_SCAN_CREDENTIALS", raising=False)
    sb = DockerSandbox()
    _apply_dummy_credentials(sb, _src())
    assert sb.env == {}


def test_credentials_dummy_injects_into_docker(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("MCP_TRUST_SCAN_CREDENTIALS", "dummy")
    sb = DockerSandbox()
    _apply_dummy_credentials(sb, _src())
    assert sb.env == {"GITHUB_TOKEN": f"ghp_{_FAKE}"}


def test_credentials_dummy_noop_when_source_needs_none(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("MCP_TRUST_SCAN_CREDENTIALS", "dummy")
    sb = DockerSandbox()
    _apply_dummy_credentials(sb, ServerSource(kind=SourceKind.NPM, reference="@acme/server"))
    assert sb.env == {}


def test_credentials_dummy_refuses_host_sandbox(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("MCP_TRUST_SCAN_CREDENTIALS", "dummy")
    with pytest.raises(ScanError, match="requires the docker sandbox"):
        _apply_dummy_credentials(NoSandbox(), _src())


def test_credentials_dummy_refuses_reachable_network(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("MCP_TRUST_SCAN_CREDENTIALS", "dummy")
    with pytest.raises(ScanError, match="requires network-off"):
        _apply_dummy_credentials(DockerSandbox(network="bridge"), _src())


def test_credentials_dummy_refuses_remote_source(monkeypatch: pytest.MonkeyPatch) -> None:
    # Remote endpoints connect over the live network outside the sandbox, so
    # credentialed mode must refuse rather than emit a false "network-off" receipt.
    monkeypatch.setenv("MCP_TRUST_SCAN_CREDENTIALS", "dummy")
    remote = ServerSource(
        kind=SourceKind.REMOTE, reference="https://x.example/mcp", env_keys=["API_TOKEN"]
    )
    with pytest.raises(ScanError, match="sandboxed stdio servers only"):
        _apply_dummy_credentials(DockerSandbox(), remote)


def test_credentials_dummy_overwrites_not_accumulates(monkeypatch: pytest.MonkeyPatch) -> None:
    # A reused sandbox must not carry dummy keys from a prior scan into the next.
    monkeypatch.setenv("MCP_TRUST_SCAN_CREDENTIALS", "dummy")
    sb = DockerSandbox()
    _apply_dummy_credentials(
        sb, ServerSource(kind=SourceKind.NPM, reference="a", env_keys=["GITHUB_TOKEN"])
    )
    _apply_dummy_credentials(
        sb, ServerSource(kind=SourceKind.NPM, reference="b", env_keys=["SLACK_BOT_TOKEN"])
    )
    assert set(sb.env) == {"SLACK_BOT_TOKEN"}


# --- receipt honesty -----------------------------------------------------------


def _server() -> Server:
    return Server(
        slug="acme-server",
        name="Acme Server",
        source=_src(),
        added_at=datetime(2026, 6, 28),
    )


def _scan() -> ScanRecord:
    return ScanRecord(
        id="deadbeef",
        server_slug="acme-server",
        engine_name="mcpaudit",
        engine_version="2.2.3",
        grade=TrustGrade.C,
        risk=RiskSummary(composite=5.0),
        scanned_at=datetime(2026, 6, 28),
    )


def test_receipt_records_credentialed_caveat_not_values(monkeypatch: pytest.MonkeyPatch) -> None:
    import json

    monkeypatch.setenv("MCP_TRUST_SCAN_CREDENTIALS", "dummy")
    receipt = build_scan_receipt(_server(), _scan())

    assert any("dummy credentials" in c for c in receipt["caveats"])
    # The mode name is recorded as provenance...
    assert receipt["sandbox"]["MCP_TRUST_SCAN_CREDENTIALS"] == "dummy"
    # ...but no dummy VALUE ever appears anywhere in the serialized receipt,
    # while the env key NAME is preserved (names-only invariant).
    blob = json.dumps(receipt)
    assert _FAKE not in blob
    assert "ghp_" not in blob
    assert "GITHUB_TOKEN" in blob


def test_receipt_has_no_credentialed_caveat_when_off(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("MCP_TRUST_SCAN_CREDENTIALS", raising=False)
    receipt = build_scan_receipt(_server(), _scan())
    assert not any("dummy credentials" in c for c in receipt["caveats"])
