"""Synthetic adversarial checks for cross-cutting trust boundaries.

The cases in this module never launch a server or select a real scan engine.
They exercise domain, receipt, snapshot, repository, and projection boundaries
with local in-memory or temporary-file fixtures only.
"""

from __future__ import annotations

import json
from datetime import UTC, datetime
from importlib.resources import files
from pathlib import Path

import pytest
from pydantic import ValidationError

from mcp_trust.catalog.runtime_snapshot import (
    CatalogSnapshotValidationError,
    parse_catalog_snapshot,
)
from mcp_trust.core.models import (
    RiskSummary,
    ScanRecord,
    Server,
    ServerSource,
    SourceKind,
    TransparencyLevel,
    TrustGrade,
)
from mcp_trust.receipts import write_scan_receipt

_CORPUS_PATH = Path(__file__).parent / "fixtures/adversarial-trust-boundaries-v1.json"
_CORPUS = json.loads(_CORPUS_PATH.read_text(encoding="utf-8"))


def _cases(target: str) -> list[dict[str, str]]:
    return [case for case in _CORPUS["cases"] if case["target"] == target]


def _server(*, slug: str = "acme-server") -> Server:
    return Server(
        slug=slug,
        name="Acme Server",
        source=ServerSource(kind=SourceKind.NPM, reference="@acme/server"),
        added_at=datetime(2026, 1, 1, tzinfo=UTC),
    )


def _scan(*, server_slug: str = "acme-server", id: str = "scan-001") -> ScanRecord:
    return ScanRecord(
        id=id,
        server_slug=server_slug,
        engine_name="stub",
        engine_version="1",
        grade=TrustGrade.C,
        transparency=TransparencyLevel.MEDIUM,
        risk=RiskSummary(composite=5),
        scanned_at=datetime(2026, 1, 2, tzinfo=UTC),
    )


@pytest.mark.parametrize("case", _cases("env_key"), ids=lambda case: case["id"])
def test_environment_names_follow_adversarial_corpus(case: dict[str, str]) -> None:
    if case["expected"] == "accept":
        source = ServerSource(
            kind=SourceKind.NPM,
            reference="@acme/server",
            env_keys=[case["value"]],
        )
        assert source.env_keys == [case["value"]]
    else:
        with pytest.raises(ValidationError):
            ServerSource(
                kind=SourceKind.NPM,
                reference="@acme/server",
                env_keys=[case["value"]],
            )


def test_environment_names_preserve_valid_order_and_reject_duplicates() -> None:
    source = ServerSource(
        kind=SourceKind.NPM,
        reference="@acme/server",
        env_keys=["API_TOKEN", "_PRIVATE_TOKEN", "TOKEN_2"],
    )
    assert source.env_keys == ["API_TOKEN", "_PRIVATE_TOKEN", "TOKEN_2"]

    with pytest.raises(ValidationError):
        ServerSource(
            kind=SourceKind.NPM,
            reference="@acme/server",
            env_keys=["API_TOKEN", "API_TOKEN"],
        )


@pytest.mark.parametrize("case", _cases("slug"), ids=lambda case: case["id"])
def test_catalog_slugs_follow_adversarial_corpus(case: dict[str, str]) -> None:
    if case["expected"] == "accept":
        assert _server(slug=case["value"]).slug == case["value"]
    else:
        with pytest.raises(ValidationError):
            _server(slug=case["value"])


@pytest.mark.parametrize("case", _cases("scan_id"), ids=lambda case: case["id"])
def test_receipt_ids_follow_adversarial_corpus(case: dict[str, str]) -> None:
    if case["expected"] == "accept":
        assert _scan(id=case["value"]).id == case["value"]
    else:
        with pytest.raises(ValidationError):
            _scan(id=case["value"])


def test_adversarial_fixture_is_versioned_large_and_partitioned() -> None:
    assert _CORPUS["schema_version"] == "mcp-trust-adversarial-corpus.v1"
    assert len(_CORPUS["cases"]) >= 50
    assert len({case["id"] for case in _CORPUS["cases"]}) == len(_CORPUS["cases"])
    assert all(case["partition"] for case in _CORPUS["cases"])


def test_receipt_write_rejects_server_scan_identity_mismatch_before_writing(tmp_path) -> None:
    destination = tmp_path / "receipts"

    with pytest.raises(ValueError, match="identity"):
        write_scan_receipt(
            _server(slug="alpha"),
            _scan(server_slug="beta"),
            destination,
        )

    assert not destination.exists()


def test_receipt_write_preserves_legitimate_portable_filename(tmp_path) -> None:
    destination = tmp_path / "receipts"
    reference = write_scan_receipt(
        _server(slug="acme-server"),
        _scan(server_slug="acme-server", id="scan-001.alpha"),
        destination,
    )

    assert reference == "acme-server-scan-001.alpha.json"
    assert (destination / reference).is_file()


def test_packaged_snapshot_rejects_oversized_json_before_semantic_validation() -> None:
    snapshot_path = files("mcp_trust").joinpath("catalog_snapshot.json")
    payload = json.loads(snapshot_path.read_text(encoding="utf-8"))
    payload["synthetic_padding"] = "x" * 1_100_000

    with pytest.raises(CatalogSnapshotValidationError) as exc_info:
        parse_catalog_snapshot(json.dumps(payload))

    assert exc_info.value.reason_codes == ("JSON_TOO_LARGE",)


def test_packaged_snapshot_accepts_current_under_limit_control() -> None:
    snapshot_path = files("mcp_trust").joinpath("catalog_snapshot.json")
    parsed = parse_catalog_snapshot(snapshot_path.read_text(encoding="utf-8"))

    assert parsed["server_count"] == len(parsed["servers"])
