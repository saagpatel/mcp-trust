"""Tests for the credentialed-sandboxed scan mode.

The dummy-credential policy and the engine's safety guards are pure logic and
always run; actual container execution stays integration-gated (needs Docker).
The receipt test pins the honesty invariant: dummy values never leak.
"""

from __future__ import annotations

import json
from datetime import datetime

import pytest

from mcp_trust.core.models import (
    RiskSummary,
    ScanEvidence,
    ScanRecord,
    Server,
    ServerSource,
    SourceKind,
    ToolEvidence,
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


def test_docker_wrap_no_credentials_by_default() -> None:
    _, args = DockerSandbox().wrap("npx", ["x"])
    # Infra HOME/TMPDIR env is always present so the non-root user can run; no
    # dummy CREDENTIALS are injected unless credentialed mode populates sandbox.env.
    env_values = [args[i + 1] for i, a in enumerate(args) if a == "--env"]
    assert set(env_values) == {"HOME=/scan", "TMPDIR=/scan"}


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


def test_credentials_clears_stale_env_on_noop(monkeypatch: pytest.MonkeyPatch) -> None:
    # A reused sandbox must shed prior dummy creds on a later no-op scan, or it
    # would emit the previous server's --env flags.
    monkeypatch.setenv("MCP_TRUST_SCAN_CREDENTIALS", "dummy")
    sb = DockerSandbox()
    _apply_dummy_credentials(sb, _src())
    assert sb.env  # populated by the credentialed scan

    # Mode turned off on the next scan -> stale env cleared.
    monkeypatch.delenv("MCP_TRUST_SCAN_CREDENTIALS", raising=False)
    _apply_dummy_credentials(sb, _src())
    assert sb.env == {}

    # Re-inject, then a source with no env_keys (mode on) -> also cleared.
    monkeypatch.setenv("MCP_TRUST_SCAN_CREDENTIALS", "dummy")
    _apply_dummy_credentials(sb, _src())
    assert sb.env
    _apply_dummy_credentials(sb, ServerSource(kind=SourceKind.NPM, reference="x"))
    assert sb.env == {}


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


def test_receipt_no_caveat_for_no_envkeys_server(monkeypatch: pytest.MonkeyPatch) -> None:
    # Dummy mode on, but this server declares no env_keys -> nothing was injected,
    # so the receipt must not claim credentials were.
    monkeypatch.setenv("MCP_TRUST_SCAN_CREDENTIALS", "dummy")
    server = Server(
        slug="no-creds",
        name="No Creds",
        source=ServerSource(kind=SourceKind.NPM, reference="@acme/server"),
        added_at=datetime(2026, 6, 28),
    )
    receipt = build_scan_receipt(server, _scan())
    assert not any("dummy credentials" in c for c in receipt["caveats"])


def test_receipt_records_effective_sandbox_image_not_env(monkeypatch: pytest.MonkeyPatch) -> None:
    # A corpus-wide env default image is set for the batch...
    monkeypatch.setenv("MCP_TRUST_SANDBOX_IMAGE", "mcp-trust-scan:corpus-default")
    # ...but THIS scan actually ran in a per-server pinned image (the engine honors
    # source.sandbox_image). The receipt must record the image that truly ran, not
    # the ambient env default it is blind to — otherwise per-server pins can't be
    # proven from the served receipt (Gate-0 provenance gap, 2026-07-03).
    scan = _scan().model_copy(update={"sandbox_image": "mcp-trust-batch4:20260703"})
    receipt = build_scan_receipt(_server(), scan)
    assert receipt["sandbox"]["MCP_TRUST_SANDBOX_IMAGE"] == "mcp-trust-batch4:20260703"


def test_receipt_omits_phantom_env_image_when_scan_used_no_container(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # The scan carries no image (host passthrough via NoSandbox, or the stub engine):
    # no container ran, so the receipt must NOT stamp the ambient env image as if it
    # had — that is the same false-provenance defect class as the per-server-pin gap.
    monkeypatch.setenv("MCP_TRUST_SANDBOX_IMAGE", "mcp-trust-scan:corpus-default")
    receipt = build_scan_receipt(_server(), _scan())
    assert "MCP_TRUST_SANDBOX_IMAGE" not in receipt["sandbox"]


def test_receipt_no_caveat_for_stub_engine(monkeypatch: pytest.MonkeyPatch) -> None:
    # Dummy mode on and the server has env_keys, but the stub engine never launches
    # a sandbox, so no injection happened -> no caveat.
    monkeypatch.setenv("MCP_TRUST_SCAN_CREDENTIALS", "dummy")
    stub_scan = ScanRecord(
        id="cafef00d",
        server_slug="acme-server",
        engine_name="stub",
        engine_version="0",
        grade=TrustGrade.C,
        risk=RiskSummary(composite=5.0),
        scanned_at=datetime(2026, 6, 28),
    )
    receipt = build_scan_receipt(_server(), stub_scan)
    assert not any("dummy credentials" in c for c in receipt["caveats"])


def test_receipt_records_scan_evidence_without_raw_schema(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.delenv("MCP_TRUST_SCAN_CREDENTIALS", raising=False)
    scan = _scan().model_copy(
        update={
            "evidence": ScanEvidence(
                tool_count=1,
                tools=[
                    ToolEvidence(
                        name="search_docs",
                        has_input_schema=True,
                        input_schema_sha256="b" * 64,
                        has_annotations=True,
                    )
                ],
                prompt_count=2,
                resource_count=3,
            )
        }
    )
    receipt = build_scan_receipt(_server(), scan)

    assert receipt["evidence"]["tool_count"] == 1
    assert receipt["evidence"]["tools"][0]["name"] == "search_docs"
    assert receipt["evidence"]["tools"][0]["input_schema_sha256"] == "b" * 64
    assert "properties" not in json.dumps(receipt["evidence"])
