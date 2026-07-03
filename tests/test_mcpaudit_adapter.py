"""Tests for the MCPAuditEngine adapter.

The pure mapping logic (`_severity_for`, `_launch_spec`) needs no engine and
always runs. The full-scan integration test launches a real server process and
is opt-in (set MCP_TRUST_RUN_INTEGRATION=1 with the engine extra installed).
"""

from __future__ import annotations

import importlib.util
import os

import pytest

from mcp_trust.core.models import ServerSource, Severity, SourceKind
from mcp_trust.engine.base import ScanError
from mcp_trust.engine.mcpaudit import MCPAuditEngine, _severity_for

_HAS_ENGINE = importlib.util.find_spec("mcp_audit") is not None


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
