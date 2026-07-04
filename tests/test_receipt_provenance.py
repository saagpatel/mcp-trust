"""Receipt sandbox-image provenance.

The receipt must record the image the engine actually resolves — per-server
pin ahead of the ``MCP_TRUST_SANDBOX_IMAGE`` corpus default — not just the
env value. Regression for the Gate-0 finding where every pinned row's current
receipt recorded the corpus image while the engine scanned in the pinned one.
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
from mcp_trust.engine.sandbox import effective_docker_image, select_sandbox
from mcp_trust.receipts import build_scan_receipt

_PIN = "mcp-trust-batch4:20260703"
_CORPUS = "mcp-trust-scan:corpus-2026-07-03"


def _server(sandbox_image: str | None = None) -> Server:
    return Server(
        slug="acme-server",
        name="Acme Server",
        source=ServerSource(
            kind=SourceKind.NPM, reference="@acme/server", sandbox_image=sandbox_image
        ),
        added_at=datetime(2026, 7, 3),
    )


def _remote_server(command: str | None = None) -> Server:
    return Server(
        slug="acme-remote",
        name="Acme Remote",
        source=ServerSource(
            kind=SourceKind.REMOTE,
            reference="https://acme.example/mcp",
            command=command,
            sandbox_image=_PIN,
        ),
        added_at=datetime(2026, 7, 3),
    )


def _scan(engine_name: str = "mcpaudit") -> ScanRecord:
    return ScanRecord(
        id="deadbeef",
        server_slug="acme-server",
        engine_name=engine_name,
        engine_version="2.4.0",
        grade=TrustGrade.F,
        risk=RiskSummary(composite=8.6),
        scanned_at=datetime(2026, 7, 3),
    )


def _docker_env(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("MCP_TRUST_SANDBOX", "docker")
    monkeypatch.setenv("MCP_TRUST_SANDBOX_IMAGE", _CORPUS)


def test_receipt_records_pinned_image_not_env_default(monkeypatch: pytest.MonkeyPatch) -> None:
    _docker_env(monkeypatch)
    receipt = build_scan_receipt(_server(sandbox_image=_PIN), _scan())
    # The env value stays recorded as config, but image_used is the pin.
    assert receipt["sandbox"]["MCP_TRUST_SANDBOX_IMAGE"] == _CORPUS
    assert receipt["sandbox"]["image_used"] == _PIN


def test_receipt_records_corpus_default_when_unpinned(monkeypatch: pytest.MonkeyPatch) -> None:
    _docker_env(monkeypatch)
    receipt = build_scan_receipt(_server(), _scan())
    assert receipt["sandbox"]["image_used"] == _CORPUS


def test_no_image_used_without_docker_sandbox(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("MCP_TRUST_SANDBOX", raising=False)
    monkeypatch.delenv("MCP_TRUST_SANDBOX_IMAGE", raising=False)
    receipt = build_scan_receipt(_server(sandbox_image=_PIN), _scan())
    assert "image_used" not in receipt["sandbox"]


def test_no_image_used_for_stub_engine(monkeypatch: pytest.MonkeyPatch) -> None:
    # The stub engine never launches a sandbox; claiming an image would be
    # false provenance even when the env is configured for docker.
    _docker_env(monkeypatch)
    receipt = build_scan_receipt(_server(sandbox_image=_PIN), _scan(engine_name="stub"))
    assert "image_used" not in receipt["sandbox"]


def test_no_image_used_for_remote_url_scan(monkeypatch: pytest.MonkeyPatch) -> None:
    # Remote endpoints connect directly over HTTP; the engine does not wrap them
    # in Docker even when the batch env selects the docker sandbox.
    _docker_env(monkeypatch)
    receipt = build_scan_receipt(_remote_server(), _scan())
    assert receipt["sandbox"]["MCP_TRUST_SANDBOX_IMAGE"] == _CORPUS
    assert "image_used" not in receipt["sandbox"]


def test_image_used_for_remote_source_with_explicit_command(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # A remote-kind source with an explicit command follows the stdio launch path
    # and is wrapped by the sandbox, so image provenance is accurate.
    _docker_env(monkeypatch)
    receipt = build_scan_receipt(_remote_server(command="mcp-proxy"), _scan())
    assert receipt["sandbox"]["image_used"] == _PIN


def test_receipt_and_engine_resolve_the_same_image(monkeypatch: pytest.MonkeyPatch) -> None:
    # Single-source-of-truth check: the image select_sandbox builds the docker
    # sandbox with must equal what the receipt records for the same source.
    _docker_env(monkeypatch)
    for pin in (_PIN, None):
        sandbox = select_sandbox(image=pin)
        assert sandbox.image == effective_docker_image(pin)
        receipt = build_scan_receipt(_server(sandbox_image=pin), _scan())
        assert receipt["sandbox"]["image_used"] == sandbox.image
