"""Focused corruption tests for runtime catalog snapshot admission."""

from __future__ import annotations

import json
from copy import deepcopy
from pathlib import Path
from typing import Any

import pytest

from mcp_trust.catalog.runtime_snapshot import (
    CatalogSnapshotValidationError,
    parse_catalog_snapshot,
)

_SNAPSHOT = Path(__file__).resolve().parents[1] / "src/mcp_trust/catalog_snapshot.json"
_SNAPSHOT_TEXT = _SNAPSHOT.read_text(encoding="utf-8")


def _valid_snapshot() -> dict[str, Any]:
    return json.loads(_SNAPSHOT_TEXT)


def _assert_invalid(snapshot: Any, expected_reason: str) -> CatalogSnapshotValidationError:
    with pytest.raises(CatalogSnapshotValidationError) as raised:
        parse_catalog_snapshot(json.dumps(snapshot))
    assert expected_reason in raised.value.reason_codes
    assert raised.value.reason_codes == tuple(sorted(set(raised.value.reason_codes)))
    return raised.value


def test_current_catalog_snapshot_validates_without_semantic_rewrite() -> None:
    parsed = parse_catalog_snapshot(_SNAPSHOT_TEXT)

    assert parsed == json.loads(_SNAPSHOT_TEXT)
    assert parsed["server_count"] == len(parsed["servers"]) == 23


@pytest.mark.parametrize("raw", ["{", "NaN", "[1, 2,"])
def test_invalid_json_fails_closed(raw: str) -> None:
    with pytest.raises(CatalogSnapshotValidationError) as raised:
        parse_catalog_snapshot(raw)

    assert raised.value.reason_codes == ("JSON_INVALID",)


def test_non_object_top_level_fails_closed() -> None:
    with pytest.raises(CatalogSnapshotValidationError) as raised:
        parse_catalog_snapshot("[]")

    assert raised.value.reason_codes == ("TOP_LEVEL_NOT_OBJECT",)


@pytest.mark.parametrize(
    "raw",
    [
        '{"schema_version":2,"schema_version":2}',
        _SNAPSHOT_TEXT.replace('"kind": "npm"', '"kind": "npm", "kind": "pypi"', 1),
    ],
)
def test_duplicate_keys_at_any_object_depth_fail_before_last_value_use(raw: str) -> None:
    with pytest.raises(CatalogSnapshotValidationError) as raised:
        parse_catalog_snapshot(raw)

    assert raised.value.reason_codes == ("JSON_DUPLICATE_KEY",)


def test_missing_servers_fails_closed() -> None:
    snapshot = _valid_snapshot()
    del snapshot["servers"]

    _assert_invalid(snapshot, "SERVERS_MISSING")


def test_unknown_schema_version_fails_closed() -> None:
    snapshot = _valid_snapshot()
    snapshot["schema_version"] = 3

    _assert_invalid(snapshot, "SCHEMA_VERSION_UNSUPPORTED")


def test_server_count_mismatch_fails_closed() -> None:
    snapshot = _valid_snapshot()
    snapshot["server_count"] += 1

    _assert_invalid(snapshot, "SERVER_COUNT_MISMATCH")


def test_non_list_servers_fails_closed() -> None:
    snapshot = _valid_snapshot()
    snapshot["servers"] = {}

    _assert_invalid(snapshot, "SERVERS_NOT_LIST")


def test_duplicate_slug_fails_closed() -> None:
    snapshot = _valid_snapshot()
    snapshot["servers"][1]["slug"] = snapshot["servers"][0]["slug"]

    _assert_invalid(snapshot, "SLUG_DUPLICATE")


def test_duplicate_source_coordinate_fails_closed() -> None:
    snapshot = _valid_snapshot()
    snapshot["servers"][1]["source"] = deepcopy(snapshot["servers"][0]["source"])
    snapshot["servers"][1]["requires_credentials"] = bool(
        snapshot["servers"][1]["source"]["env_keys"]
    )

    _assert_invalid(snapshot, "SOURCE_COORDINATE_DUPLICATE")


@pytest.mark.parametrize("source", [None, [], {"kind": "npm"}])
def test_missing_or_invalid_source_fails_closed(source: Any) -> None:
    snapshot = _valid_snapshot()
    snapshot["servers"][0]["source"] = source

    _assert_invalid(snapshot, "SOURCE_INVALID")


@pytest.mark.parametrize(
    ("field", "value", "reason"),
    [
        ("grade", "endorsed", "GRADE_UNSUPPORTED"),
        ("grade", [], "GRADE_UNSUPPORTED"),
        ("transparency", "opaque", "TRANSPARENCY_UNSUPPORTED"),
        ("transparency", {}, "TRANSPARENCY_UNSUPPORTED"),
        ("sandbox", {"mode": "container"}, "SANDBOX_INVALID"),
    ],
)
def test_invalid_grade_transparency_or_sandbox_fails_closed(
    field: str,
    value: Any,
    reason: str,
) -> None:
    snapshot = _valid_snapshot()
    snapshot["servers"][0][field] = value

    _assert_invalid(snapshot, reason)


def test_scan_mode_and_sandbox_must_agree() -> None:
    snapshot = _valid_snapshot()
    snapshot["servers"][0]["sandbox"]["network"] = "none"

    _assert_invalid(snapshot, "SCAN_MODE_SANDBOX_MISMATCH")


@pytest.mark.parametrize("scanned_at", ["2026-08-01T00:00:00", "not-a-timestamp", []])
def test_scanned_at_must_be_a_timezone_aware_timestamp(scanned_at: Any) -> None:
    snapshot = _valid_snapshot()
    snapshot["servers"][0]["scanned_at"] = scanned_at

    _assert_invalid(snapshot, "SCANNED_AT_INVALID")


def test_findings_must_be_a_list() -> None:
    snapshot = _valid_snapshot()
    snapshot["servers"][0]["findings"] = {}

    _assert_invalid(snapshot, "FINDINGS_INVALID")


def test_credential_names_and_presence_flag_are_internally_consistent() -> None:
    snapshot = _valid_snapshot()
    snapshot["servers"][0]["source"]["env_keys"] = ["not-a-credential-name"]
    snapshot["servers"][0]["requires_credentials"] = False

    error = _assert_invalid(snapshot, "CREDENTIAL_NAMES_INVALID")
    assert "not-a-credential-name" not in str(error)

    snapshot = _valid_snapshot()
    snapshot["servers"][0]["requires_credentials"] = True
    _assert_invalid(snapshot, "REQUIRES_CREDENTIALS_MISMATCH")


def test_malformed_evidence_fails_closed() -> None:
    snapshot = _valid_snapshot()
    snapshot["servers"][0]["evidence"]["tool_count"] += 1

    _assert_invalid(snapshot, "EVIDENCE_INVALID")


def test_additive_unknown_v2_fields_are_preserved() -> None:
    snapshot = _valid_snapshot()
    snapshot["future_top"] = {"enabled": True}
    snapshot["servers"][0]["future_record"] = ["preserved"]
    snapshot["servers"][0]["source"]["future_source"] = 7
    snapshot["servers"][0]["findings"][0]["future_finding"] = None

    parsed = parse_catalog_snapshot(json.dumps(snapshot))

    assert parsed["future_top"] == {"enabled": True}
    assert parsed["servers"][0]["future_record"] == ["preserved"]
    assert parsed["servers"][0]["source"]["future_source"] == 7
    assert parsed["servers"][0]["findings"][0]["future_finding"] is None


def test_multiple_failures_return_only_sorted_non_sensitive_reason_codes() -> None:
    snapshot = _valid_snapshot()
    snapshot["servers"][0]["grade"] = "RAW_PRIVATE_GRADE"
    snapshot["servers"][0]["transparency"] = "RAW_PRIVATE_TRANSPARENCY"
    raw = json.dumps(snapshot)

    errors: list[CatalogSnapshotValidationError] = []
    for _ in range(2):
        with pytest.raises(CatalogSnapshotValidationError) as raised:
            parse_catalog_snapshot(raw)
        errors.append(raised.value)

    assert errors[0].reason_codes == (
        "GRADE_UNSUPPORTED",
        "TRANSPARENCY_UNSUPPORTED",
    )
    assert errors[0].reason_codes == errors[1].reason_codes
    assert "RAW_PRIVATE" not in str(errors[0])


@pytest.mark.parametrize(
    ("grade", "danger_score"),
    [("A", 10), ("B", 0), ("C", 8), ("F", 2)],
)
def test_grade_must_match_normalized_danger_band(grade: str, danger_score: float) -> None:
    snapshot = _valid_snapshot()
    snapshot["servers"][0]["grade"] = grade
    snapshot["servers"][0]["danger_score"] = danger_score
    snapshot["servers"][0]["findings"] = []

    _assert_invalid(snapshot, "GRADE_DANGER_MISMATCH")


def test_critical_finding_cap_is_part_of_snapshot_grade_binding() -> None:
    snapshot = _valid_snapshot()
    server = snapshot["servers"][0]
    server["grade"] = "A"
    server["danger_score"] = 0
    server["findings"] = [
        {"rule_id": "SYNTHETIC", "title": "Synthetic", "severity": "critical", "category": "test"}
    ]

    _assert_invalid(snapshot, "GRADE_DANGER_MISMATCH")


@pytest.mark.parametrize(
    ("transparency", "coverage"),
    [("high", 0.0), ("medium", 0.1), ("low", 1.0)],
)
def test_transparency_must_match_annotation_coverage(
    transparency: str,
    coverage: float,
) -> None:
    snapshot = _valid_snapshot()
    snapshot["servers"][0]["transparency"] = transparency
    snapshot["servers"][0]["annotation_coverage"] = coverage

    _assert_invalid(snapshot, "TRANSPARENCY_COVERAGE_MISMATCH")


def test_snapshot_server_collection_has_a_deterministic_ceiling() -> None:
    snapshot = _valid_snapshot()
    template = snapshot["servers"][0]
    snapshot["servers"] = []
    for index in range(257):
        record = deepcopy(template)
        record["slug"] = f"synthetic-{index}"
        record["source"]["reference"] = f"synthetic-{index}"
        record["findings"] = []
        record["evidence"] = None
        snapshot["servers"].append(record)
    snapshot["server_count"] = len(snapshot["servers"])
    raw = json.dumps(snapshot, separators=(",", ":"))
    assert len(raw.encode()) < 1024 * 1024

    _assert_invalid(snapshot, "SERVER_LIMIT_EXCEEDED")


def test_snapshot_nested_collections_have_deterministic_ceilings() -> None:
    snapshot = _valid_snapshot()
    finding = {"rule_id": "S", "title": "S", "severity": "low", "category": "S"}
    snapshot["servers"][0]["findings"] = [finding] * 1025
    _assert_invalid(snapshot, "FINDINGS_LIMIT_EXCEEDED")

    snapshot = _valid_snapshot()
    tool = {
        "name": "synthetic",
        "has_input_schema": False,
        "input_schema_sha256": None,
        "has_annotations": False,
    }
    snapshot["servers"][0]["evidence"]["tools"] = [
        {**tool, "name": f"synthetic-{index}"} for index in range(2049)
    ]
    snapshot["servers"][0]["evidence"]["tool_count"] = 2049
    _assert_invalid(snapshot, "TOOLS_LIMIT_EXCEEDED")


@pytest.mark.parametrize("field", ["name", "slug"])
def test_snapshot_public_strings_have_a_deterministic_ceiling(field: str) -> None:
    snapshot = _valid_snapshot()
    snapshot["servers"][0][field] = "x" * 4097

    _assert_invalid(snapshot, "SERVER_STRING_LIMIT_EXCEEDED")


@pytest.mark.parametrize(
    ("source", "remote_scan", "admit"),
    [
        ({"kind": "npm"}, True, False),
        ({"kind": "remote", "command": "fixture-launcher"}, True, False),
        ({"kind": "remote", "command": ""}, True, False),
        ({"kind": "remote"}, True, True),
        ({"kind": "remote", "command": None}, True, True),
        ({"kind": "remote", "command": "fixture-launcher"}, False, True),
    ],
)
def test_catalog_scan_mode_agrees_with_declared_launcher(source, remote_scan, admit):
    snapshot = _valid_snapshot()
    record = snapshot["servers"][0]
    record["source"] = {"reference": "https://fixture.invalid/mcp", "env_keys": [], **source}
    record["requires_credentials"] = False
    snapshot.update(servers=[record], server_count=1, generated_from_scan_at=record["scanned_at"])
    if remote_scan:
        record["scan_mode"] = "mcpaudit-remote-live-network"
        record["sandbox"] = {"mode": "not_applicable", "reason": "remote_endpoint_no_local_process"}
    else:
        record["scan_mode"] = "mcpaudit-local-provenance-unknown"
        record["sandbox"] = {"mode": "unknown", "network": "unknown", "image": None}
    if admit:
        assert parse_catalog_snapshot(json.dumps(snapshot)) == snapshot
    else:
        _assert_invalid(snapshot, "SCAN_MODE_SOURCE_MISMATCH")


def test_additive_overflowing_float_is_invalid_json() -> None:
    raw = _SNAPSHOT_TEXT.replace('"engine_version":', '"extra":1e309,"engine_version":', 1)
    with pytest.raises(CatalogSnapshotValidationError) as raised:
        parse_catalog_snapshot(raw)
    assert raised.value.reason_codes == ("JSON_INVALID",)


@pytest.mark.parametrize(
    ("field", "value", "reason"),
    [
        ("generated_at", "0001-01-01T00:00:00+00:01", "GENERATED_AT_INVALID"),
        ("scan_age_days", 10**309, "SCAN_AGE_INVALID"),
    ],
)
def test_freshness_overflow_is_a_validation_error(field: str, value: Any, reason: str) -> None:
    snapshot = _valid_snapshot()
    target = snapshot if field == "generated_at" else snapshot["servers"][0]
    target[field] = value
    _assert_invalid(snapshot, reason)


def test_late_calendar_deadline_remains_a_validation_error() -> None:
    snapshot = _valid_snapshot()
    snapshot["servers"] = [snapshot["servers"][0]]
    snapshot["generated_at"] = "9999-12-01T00:00:00Z"
    snapshot["servers"][0].update(
        scanned_at=snapshot["generated_at"], scan_age_days=0, stale_after="9999-12-31T00:00:00Z"
    )
    _assert_invalid(snapshot, "STALE_AFTER_MISMATCH")


def test_danger_score_must_be_attainable_from_dimensions() -> None:
    snapshot = _valid_snapshot()
    server = snapshot["servers"][0]
    server["dimensions"] = dict.fromkeys(server["dimensions"], 0)
    _assert_invalid(snapshot, "DANGER_DIMENSIONS_MISMATCH")


def test_rounded_dimensions_and_score_must_admit_the_same_grade() -> None:
    snapshot = _valid_snapshot()
    server = snapshot["servers"][0]
    server.update(danger_score=2.0, grade="B", findings=[], grade_change=None)
    server["dimensions"] = dict.fromkeys(server["dimensions"], 0)
    server["dimensions"].update(file_access=1.01, network_access=0.80)

    # E.g. 1.0055 * 1.2 + 0.7955 gives 2.0021, which displays as 2.00.
    assert parse_catalog_snapshot(json.dumps(snapshot)) == snapshot
    server["grade"] = "A"
    _assert_invalid(snapshot, "GRADE_DANGER_MISMATCH")

    # With these dimensions the score can genuinely fall on either side of 2.00.
    server["dimensions"].update(file_access=1.00)
    for grade in ("A", "B"):
        server["grade"] = grade
        assert parse_catalog_snapshot(json.dumps(snapshot)) == snapshot


def test_dimension_rounding_endpoints_at_grade_boundary() -> None:
    snapshot = _valid_snapshot()
    server = snapshot["servers"][0]
    server.update(
        danger_score=7.50,
        grade="F",
        findings=[
            {
                "rule_id": "fixture",
                "title": "Synthetic finding",
                "severity": "critical",
                "category": "fixture",
            }
        ],
        grade_change=None,
    )
    server["dimensions"] = dict.fromkeys(server["dimensions"], 0)
    server["dimensions"].update(shell_execution=3.13, exfiltration=3.13)
    assert parse_catalog_snapshot(json.dumps(snapshot)) == snapshot
    server["grade"] = "D"
    _assert_invalid(snapshot, "GRADE_DANGER_MISMATCH")
    server["dimensions"].update(shell_execution=3.38, exfiltration=1.88)
    assert parse_catalog_snapshot(json.dumps(snapshot)) == snapshot
