"""Fail-closed admission for the packaged MCP catalog snapshot.

This module validates internal consistency only. It does not authenticate the
package resource, establish freshness, or endorse any catalog record.
"""

from __future__ import annotations

import json
import math
import re
from collections.abc import Iterable
from datetime import datetime
from typing import Any, NoReturn

_SCHEMA_VERSION = 2
_GRADES = frozenset({"A", "B", "C", "D", "F"})
_TRANSPARENCY_LEVELS = frozenset({"high", "medium", "low"})
_SOURCE_KINDS = frozenset({"npm", "pypi", "git", "binary", "remote"})
_FINDING_SEVERITIES = frozenset({"critical", "high", "medium", "low", "info"})
_SCAN_MODES = frozenset(
    {
        "mcpaudit-local-network-off",
        "mcpaudit-local-network-unknown",
        "mcpaudit-local-provenance-unknown",
        "mcpaudit-remote-live-network",
    }
)
_GRADE_CHANGE_CAUSES = frozenset(
    {"surface-changed", "engine-changed", "score-moved", "undetermined", "no-change"}
)
_SURFACE_COMPARISONS = frozenset({"changed", "unchanged", "unknown"})
_DIMENSIONS = frozenset(
    {"file_access", "network_access", "shell_execution", "destructive", "exfiltration"}
)
_SERVER_REQUIRED_FIELDS = frozenset(
    {
        "slug",
        "name",
        "description",
        "homepage",
        "grade",
        "transparency",
        "danger_score",
        "dimensions",
        "annotation_coverage",
        "findings",
        "evidence",
        "source",
        "engine",
        "engine_version",
        "scan_mode",
        "sandbox",
        "scanned_at",
        "scan_age_days",
        "grade_change",
        "requires_credentials",
    }
)
_SLUG_RE = re.compile(r"^[a-z0-9]+(?:-[a-z0-9]+)*$")
_CREDENTIAL_NAME_RE = re.compile(r"^[A-Z_][A-Z0-9_]*$")
_SHA256_RE = re.compile(r"^[0-9a-f]{64}$")


class CatalogSnapshotValidationError(ValueError):
    """Typed admission failure with stable, non-sensitive reason codes."""

    def __init__(self, reason_codes: Iterable[str]) -> None:
        codes = tuple(sorted(set(reason_codes)))
        if not codes:
            raise ValueError("catalog validation failure requires at least one reason code")
        self.reason_codes = codes
        super().__init__(f"catalog snapshot validation failed: {','.join(codes)}")


def _reject_nonstandard_constant(_value: str) -> NoReturn:
    raise ValueError("non-standard JSON constant")


def parse_catalog_snapshot(raw_text: str) -> dict[str, Any]:
    """Parse and validate one schema-v2 snapshot, preserving additive fields.

    Duplicate keys are detected by ``object_pairs_hook`` for every JSON object.
    Validation failures never include raw keys or values in their reason codes.
    """

    duplicate_key_found = False

    def object_pairs(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
        nonlocal duplicate_key_found
        parsed: dict[str, Any] = {}
        for key, value in pairs:
            if key in parsed:
                duplicate_key_found = True
            parsed[key] = value
        return parsed

    if not isinstance(raw_text, str):
        raise CatalogSnapshotValidationError({"JSON_INVALID"})
    try:
        snapshot = json.loads(
            raw_text,
            object_pairs_hook=object_pairs,
            parse_constant=_reject_nonstandard_constant,
        )
    except (json.JSONDecodeError, RecursionError, TypeError, ValueError):
        raise CatalogSnapshotValidationError({"JSON_INVALID"}) from None

    if duplicate_key_found:
        raise CatalogSnapshotValidationError({"JSON_DUPLICATE_KEY"})
    if not isinstance(snapshot, dict):
        raise CatalogSnapshotValidationError({"TOP_LEVEL_NOT_OBJECT"})

    reasons = _validation_reasons(snapshot)
    if reasons:
        raise CatalogSnapshotValidationError(reasons)
    return snapshot


def _validation_reasons(snapshot: dict[str, Any]) -> set[str]:
    reasons: set[str] = set()

    if "schema_version" not in snapshot:
        reasons.add("SCHEMA_VERSION_MISSING")
    elif (
        not _is_integer(snapshot["schema_version"])
        or snapshot["schema_version"] != _SCHEMA_VERSION
    ):
        reasons.add("SCHEMA_VERSION_UNSUPPORTED")

    if "server_count" not in snapshot:
        reasons.add("SERVER_COUNT_MISSING")
        server_count: int | None = None
    elif not _is_integer(snapshot["server_count"]) or snapshot["server_count"] < 0:
        reasons.add("SERVER_COUNT_INVALID")
        server_count = None
    else:
        server_count = snapshot["server_count"]

    servers_value = snapshot.get("servers")
    if "servers" not in snapshot:
        reasons.add("SERVERS_MISSING")
        servers: list[Any] | None = None
    elif not isinstance(servers_value, list):
        reasons.add("SERVERS_NOT_LIST")
        servers = None
    else:
        servers = servers_value

    if servers is not None and server_count is not None and server_count != len(servers):
        reasons.add("SERVER_COUNT_MISMATCH")

    if not _timezone_aware_datetime(snapshot.get("generated_at")):
        reasons.add("GENERATED_AT_INVALID")
    generated_from = snapshot.get("generated_from_scan_at")
    if not (
        isinstance(generated_from, str)
        and (
            _timezone_aware_datetime(generated_from)
            or (generated_from == "" and servers is not None and not servers)
        )
    ):
        reasons.add("GENERATED_FROM_SCAN_AT_INVALID")

    if servers is not None:
        _validate_servers(servers, reasons)
    return reasons


def _validate_servers(servers: list[Any], reasons: set[str]) -> None:
    slugs: set[str] = set()
    source_coordinates: set[tuple[str, str]] = set()

    for server in servers:
        if not isinstance(server, dict):
            reasons.add("SERVER_RECORD_NOT_OBJECT")
            continue

        missing = _SERVER_REQUIRED_FIELDS.difference(server)
        if missing:
            reasons.add("SERVER_REQUIRED_FIELD_MISSING")
            _add_missing_field_reasons(missing, reasons)

        slug = server.get("slug")
        if not isinstance(slug, str) or _SLUG_RE.fullmatch(slug) is None:
            reasons.add("SLUG_INVALID")
        elif slug in slugs:
            reasons.add("SLUG_DUPLICATE")
        else:
            slugs.add(slug)

        _validate_basic_fields(server, reasons)
        _validate_grade_fields(server, reasons)
        _validate_dimensions(server.get("dimensions"), reasons)
        _validate_findings(server.get("findings"), reasons)
        _validate_evidence(server.get("evidence"), reasons)

        coordinate, has_credentials = _validate_source(server.get("source"), reasons)
        if coordinate is not None:
            if coordinate in source_coordinates:
                reasons.add("SOURCE_COORDINATE_DUPLICATE")
            else:
                source_coordinates.add(coordinate)

        requires_credentials = server.get("requires_credentials")
        if not isinstance(requires_credentials, bool):
            reasons.add("SERVER_FIELD_TYPE_INVALID")
        elif has_credentials is not None and requires_credentials != has_credentials:
            reasons.add("REQUIRES_CREDENTIALS_MISMATCH")

        scan_mode = server.get("scan_mode")
        if not _supported_string(scan_mode, _SCAN_MODES):
            reasons.add("SCAN_MODE_UNSUPPORTED")
        _validate_sandbox(server.get("sandbox"), scan_mode, reasons)

        if not _timezone_aware_datetime(server.get("scanned_at")):
            reasons.add("SCANNED_AT_INVALID")
        if not _number_in_range(server.get("scan_age_days"), minimum=0):
            reasons.add("SCAN_AGE_INVALID")
        _validate_grade_change(server.get("grade_change"), server.get("grade"), reasons)


def _add_missing_field_reasons(missing: set[str] | frozenset[str], reasons: set[str]) -> None:
    mapping = {
        "annotation_coverage": "ANNOTATION_COVERAGE_INVALID",
        "danger_score": "DANGER_SCORE_INVALID",
        "dimensions": "DIMENSIONS_INVALID",
        "engine": "ENGINE_INVALID",
        "evidence": "EVIDENCE_INVALID",
        "findings": "FINDINGS_INVALID",
        "grade": "GRADE_UNSUPPORTED",
        "grade_change": "GRADE_CHANGE_INVALID",
        "sandbox": "SANDBOX_INVALID",
        "scan_age_days": "SCAN_AGE_INVALID",
        "scan_mode": "SCAN_MODE_UNSUPPORTED",
        "scanned_at": "SCANNED_AT_INVALID",
        "slug": "SLUG_INVALID",
        "source": "SOURCE_INVALID",
        "transparency": "TRANSPARENCY_UNSUPPORTED",
    }
    reasons.update(mapping[field] for field in missing if field in mapping)


def _validate_basic_fields(server: dict[str, Any], reasons: set[str]) -> None:
    if not _nonempty_string(server.get("name")):
        reasons.add("SERVER_FIELD_TYPE_INVALID")
    if not isinstance(server.get("description"), str):
        reasons.add("SERVER_FIELD_TYPE_INVALID")
    homepage = server.get("homepage")
    if homepage is not None and not _nonempty_string(homepage):
        reasons.add("SERVER_FIELD_TYPE_INVALID")
    if server.get("engine") != "mcpaudit":
        reasons.add("ENGINE_INVALID")
    if not _nonempty_string(server.get("engine_version")):
        reasons.add("SERVER_FIELD_TYPE_INVALID")


def _validate_grade_fields(server: dict[str, Any], reasons: set[str]) -> None:
    if not _supported_string(server.get("grade"), _GRADES):
        reasons.add("GRADE_UNSUPPORTED")
    if not _supported_string(server.get("transparency"), _TRANSPARENCY_LEVELS):
        reasons.add("TRANSPARENCY_UNSUPPORTED")
    if not _number_in_range(server.get("danger_score"), minimum=0, maximum=10):
        reasons.add("DANGER_SCORE_INVALID")
    if not _number_in_range(server.get("annotation_coverage"), minimum=0, maximum=1):
        reasons.add("ANNOTATION_COVERAGE_INVALID")


def _validate_dimensions(value: Any, reasons: set[str]) -> None:
    if not isinstance(value, dict):
        reasons.add("DIMENSIONS_INVALID")
        return
    if not _DIMENSIONS.issubset(value):
        reasons.add("DIMENSIONS_INVALID")
    if any(
        key in value and not _number_in_range(value[key], minimum=0, maximum=10)
        for key in _DIMENSIONS
    ):
        reasons.add("DIMENSIONS_INVALID")


def _validate_findings(value: Any, reasons: set[str]) -> None:
    if not isinstance(value, list):
        reasons.add("FINDINGS_INVALID")
        return
    required = frozenset({"rule_id", "title", "severity", "category"})
    for finding in value:
        if not isinstance(finding, dict) or not required.issubset(finding):
            reasons.add("FINDING_INVALID")
            continue
        if not all(_nonempty_string(finding[field]) for field in ("rule_id", "title", "category")):
            reasons.add("FINDING_INVALID")
        if not _supported_string(finding["severity"], _FINDING_SEVERITIES):
            reasons.add("FINDING_INVALID")


def _validate_evidence(value: Any, reasons: set[str]) -> None:
    if value is None:
        return
    required = frozenset(
        {"tool_count", "tools", "prompt_count", "resource_count", "schema_hash_algorithm"}
    )
    if not isinstance(value, dict) or not required.issubset(value):
        reasons.add("EVIDENCE_INVALID")
        return
    for field in ("tool_count", "prompt_count", "resource_count"):
        if not _is_integer(value[field]) or value[field] < 0:
            reasons.add("EVIDENCE_INVALID")
    if value["schema_hash_algorithm"] != "sha256":
        reasons.add("EVIDENCE_INVALID")

    tools = value["tools"]
    if not isinstance(tools, list):
        reasons.add("EVIDENCE_INVALID")
        return
    if _is_integer(value["tool_count"]) and value["tool_count"] != len(tools):
        reasons.add("EVIDENCE_INVALID")

    names: set[str] = set()
    tool_required = frozenset(
        {"name", "has_input_schema", "input_schema_sha256", "has_annotations"}
    )
    for tool in tools:
        if not isinstance(tool, dict) or not tool_required.issubset(tool):
            reasons.add("EVIDENCE_INVALID")
            continue
        name = tool["name"]
        if not _nonempty_string(name) or name in names:
            reasons.add("EVIDENCE_INVALID")
        else:
            names.add(name)
        has_input_schema = tool["has_input_schema"]
        has_annotations = tool["has_annotations"]
        if not isinstance(has_input_schema, bool) or not isinstance(has_annotations, bool):
            reasons.add("EVIDENCE_INVALID")
        schema_hash = tool["input_schema_sha256"]
        if has_input_schema is True:
            if not isinstance(schema_hash, str) or _SHA256_RE.fullmatch(schema_hash) is None:
                reasons.add("EVIDENCE_INVALID")
        elif schema_hash is not None:
            reasons.add("EVIDENCE_INVALID")


def _validate_source(
    value: Any,
    reasons: set[str],
) -> tuple[tuple[str, str] | None, bool | None]:
    required = frozenset({"kind", "reference", "env_keys"})
    if not isinstance(value, dict) or not required.issubset(value):
        reasons.add("SOURCE_INVALID")
        return None, None

    kind = value["kind"]
    reference = value["reference"]
    if not _supported_string(kind, _SOURCE_KINDS):
        reasons.add("SOURCE_KIND_UNSUPPORTED")
    if not _nonempty_string(reference):
        reasons.add("SOURCE_REFERENCE_INVALID")

    env_keys = value["env_keys"]
    if not isinstance(env_keys, list):
        reasons.add("CREDENTIAL_NAMES_INVALID")
        has_credentials: bool | None = None
    else:
        valid_names = all(
            isinstance(item, str) and _CREDENTIAL_NAME_RE.fullmatch(item) is not None
            for item in env_keys
        )
        if not valid_names or len(env_keys) != len(set(env_keys)):
            reasons.add("CREDENTIAL_NAMES_INVALID")
        has_credentials = bool(env_keys)

    coordinate = (
        (kind, reference)
        if _supported_string(kind, _SOURCE_KINDS) and _nonempty_string(reference)
        else None
    )
    return coordinate, has_credentials


def _validate_sandbox(value: Any, scan_mode: Any, reasons: set[str]) -> None:
    if not isinstance(value, dict):
        reasons.add("SANDBOX_INVALID")
        return

    mode = value.get("mode")
    network = value.get("network")
    if mode == "docker":
        if not _supported_string(network, frozenset({"none", "unknown"})) or not (
            _nonempty_string(value.get("image"))
        ):
            reasons.add("SANDBOX_INVALID")
        if "reason" in value:
            reasons.add("SANDBOX_INVALID")
    elif mode == "unknown":
        if network != "unknown" or value.get("image") is not None or "reason" in value:
            reasons.add("SANDBOX_INVALID")
    elif mode == "not_applicable":
        if value.get("reason") != "remote_endpoint_no_local_process":
            reasons.add("SANDBOX_INVALID")
        if "network" in value or "image" in value:
            reasons.add("SANDBOX_INVALID")
    else:
        reasons.add("SANDBOX_INVALID")

    expected_by_scan_mode = {
        "mcpaudit-local-network-off": ("docker", "none"),
        "mcpaudit-local-network-unknown": ("docker", "unknown"),
        "mcpaudit-local-provenance-unknown": ("unknown", "unknown"),
        "mcpaudit-remote-live-network": ("not_applicable", None),
    }
    expected = expected_by_scan_mode.get(scan_mode) if isinstance(scan_mode, str) else None
    if expected is not None and (mode, network) != expected:
        reasons.add("SCAN_MODE_SANDBOX_MISMATCH")


def _validate_grade_change(value: Any, current_grade: Any, reasons: set[str]) -> None:
    if value is None:
        return
    required = frozenset(
        {"changed_at", "previous_grade", "current_grade", "cause", "surface_comparison"}
    )
    if not isinstance(value, dict) or not required.issubset(value):
        reasons.add("GRADE_CHANGE_INVALID")
        return
    if not _timezone_aware_datetime(value["changed_at"]):
        reasons.add("GRADE_CHANGE_INVALID")
    previous = value["previous_grade"]
    current = value["current_grade"]
    if (
        not _supported_string(previous, _GRADES)
        or not _supported_string(current, _GRADES)
        or previous == current
    ):
        reasons.add("GRADE_CHANGE_INVALID")
    if current != current_grade:
        reasons.add("GRADE_CHANGE_INVALID")
    if (
        not _supported_string(value["cause"], _GRADE_CHANGE_CAUSES)
        or value["cause"] == "no-change"
    ):
        reasons.add("GRADE_CHANGE_INVALID")
    if not _supported_string(value["surface_comparison"], _SURFACE_COMPARISONS):
        reasons.add("GRADE_CHANGE_INVALID")


def _timezone_aware_datetime(value: Any) -> bool:
    if not isinstance(value, str) or not value:
        return False
    normalized = f"{value[:-1]}+00:00" if value.endswith("Z") else value
    try:
        parsed = datetime.fromisoformat(normalized)
    except ValueError:
        return False
    return parsed.tzinfo is not None and parsed.utcoffset() is not None


def _nonempty_string(value: Any) -> bool:
    return isinstance(value, str) and bool(value.strip())


def _is_integer(value: Any) -> bool:
    return isinstance(value, int) and not isinstance(value, bool)


def _supported_string(value: Any, allowed: frozenset[str]) -> bool:
    return isinstance(value, str) and value in allowed


def _number_in_range(value: Any, *, minimum: float, maximum: float | None = None) -> bool:
    if not isinstance(value, (int, float)) or isinstance(value, bool):
        return False
    try:
        numeric = float(value)
    except OverflowError:
        return False
    if not math.isfinite(numeric) or numeric < minimum:
        return False
    return maximum is None or numeric <= maximum
