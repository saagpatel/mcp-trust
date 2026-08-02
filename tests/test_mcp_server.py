"""Tests for the read-only MCP server over the baked catalog snapshot."""

from __future__ import annotations

import hashlib
import json
from copy import deepcopy
from datetime import UTC, datetime
from pathlib import Path

from mcp_trust import mcp_server

_SNAPSHOT = Path(__file__).resolve().parents[1] / "src/mcp_trust/catalog_snapshot.json"


def _corrupt_snapshot_inputs() -> list[str]:
    base = json.loads(_SNAPSHOT.read_text(encoding="utf-8"))
    base["private_value"] = "DO_NOT_LEAK"

    def changed(mutator) -> str:  # noqa: ANN001
        snapshot = deepcopy(base)
        mutator(snapshot)
        return json.dumps(snapshot)

    def duplicate_coordinate(snapshot) -> None:  # noqa: ANN001
        snapshot["servers"][1]["source"] = deepcopy(snapshot["servers"][0]["source"])
        snapshot["servers"][1]["requires_credentials"] = bool(
            snapshot["servers"][1]["source"]["env_keys"]
        )

    serialized = json.dumps(base)
    return [
        "{",
        serialized.replace('"schema_version": 2', '"schema_version": 2, "schema_version": 2', 1),
        serialized.replace('"kind": "npm"', '"kind": "npm", "kind": "pypi"', 1),
        changed(lambda value: value.pop("servers")),
        changed(lambda value: value.__setitem__("schema_version", 3)),
        changed(lambda value: value.__setitem__("server_count", 24)),
        changed(lambda value: value.__setitem__("servers", {})),
        changed(lambda value: value["servers"][1].__setitem__("slug", value["servers"][0]["slug"])),
        changed(duplicate_coordinate),
        changed(lambda value: value["servers"][0].pop("source")),
        changed(lambda value: value["servers"][0].__setitem__("source", [])),
        changed(lambda value: value["servers"][0].__setitem__("grade", "endorsed")),
        changed(lambda value: value["servers"][0].__setitem__("transparency", "opaque")),
        changed(lambda value: value["servers"][0].__setitem__("sandbox", {"mode": "container"})),
        changed(lambda value: value["servers"][0].__setitem__("scanned_at", "2026-08-01T00:00:00")),
        changed(lambda value: value["servers"][0].__setitem__("findings", {})),
    ]


def test_snapshot_ships_with_real_grades() -> None:
    snap = json.loads(_SNAPSHOT.read_text(encoding="utf-8"))
    assert snap["schema_version"] == 2
    assert snap["server_count"] == len(snap["servers"]) >= 15
    valid = {"A", "B", "C", "D", "F"}
    for s in snap["servers"]:
        assert s["grade"] in valid  # never "unscanned" in the baked snapshot
        assert s["engine"] == "mcpaudit"  # only real grades are baked
        assert s["scan_mode"] == "mcpaudit-local-network-unknown"
        assert s["sandbox"]["mode"] == "docker"
        assert s["sandbox"]["network"] == "unknown"


def test_list_servers_payload_is_complete_json() -> None:
    payload = json.loads(mcp_server.list_servers_payload())
    assert payload["server_count"] >= 15
    sample = payload["servers"][0]
    assert {
        "slug",
        "name",
        "grade",
        "transparency",
        "danger_score",
        "scanned_at",
        "scan_age_days",
        "stale",
    } <= set(sample)


def test_valid_snapshot_payload_bytes_remain_compatible() -> None:
    fixed_now = datetime(2026, 8, 1, tzinfo=UTC)
    payloads = {
        "list": mcp_server.list_servers_payload(now=fixed_now),
        "known": mcp_server.check_server_payload(
            "mcp-archived-brave-search",
            now=fixed_now,
        ),
        "unknown": mcp_server.check_server_payload("does-not-exist", now=fixed_now),
    }

    payload_hashes = {
        name: hashlib.sha256(value.encode()).hexdigest() for name, value in payloads.items()
    }
    assert payload_hashes == {
        "list": "7f6d514f26e144631afcd04286f91af29e467fb2dbd5e435c73774a87431c61e",
        "known": "309514eed9f5fafe994420f0a70acd5a5e61afd93ef448e248bdfa9cbf1cf808",
        "unknown": "da2aa20cb35aa3339f459668f339c7e14d1727239c37014152498dfdb9c482a6",
    }


def test_check_server_payload_returns_full_record() -> None:
    payload = json.loads(mcp_server.check_server_payload("mcp-archived-brave-search"))
    assert payload["slug"] == "mcp-archived-brave-search"
    assert payload["grade"] == "B"
    assert payload["requires_credentials"] is True
    assert "BRAVE_API_KEY" in payload["source"]["env_keys"]
    assert isinstance(payload["findings"], list)
    assert "grade_change" in payload


def test_check_server_payload_preserves_public_grade_change_summary(monkeypatch) -> None:
    monkeypatch.setattr(
        mcp_server,
        "_snapshot",
        lambda: {
            "servers": [
                {
                    "slug": "changed",
                    "grade": "B",
                    "grade_change": {
                        "changed_at": "2026-07-08T00:00:00Z",
                        "previous_grade": "D",
                        "current_grade": "B",
                        "cause": "engine-changed",
                        "surface_comparison": "unknown",
                    },
                }
            ]
        },
    )
    payload = json.loads(mcp_server.check_server_payload("changed"))
    assert payload["grade_change"]["cause"] == "engine-changed"
    assert payload["grade_change"]["surface_comparison"] == "unknown"


def test_check_server_payload_recomputes_scan_age_at_response_time(monkeypatch) -> None:
    monkeypatch.setattr(
        mcp_server,
        "_snapshot",
        lambda: {
            "servers": [
                {
                    "slug": "aged",
                    "scanned_at": "2026-07-01T00:00:00+00:00",
                    "scan_age_days": 0.0,
                }
            ]
        },
    )

    payload = json.loads(
        mcp_server.check_server_payload(
            "aged",
            now=datetime(2026, 8, 1, tzinfo=UTC),
        )
    )

    assert payload["scan_age_days"] == 31.0


def test_list_servers_payload_reports_freshness(monkeypatch) -> None:
    monkeypatch.setattr(
        mcp_server,
        "_snapshot",
        lambda: {
            "servers": [
                {
                    "slug": "fresh-server",
                    "name": "Fresh",
                    "grade": "A",
                    "transparency": "high",
                    "danger_score": 1.0,
                    "requires_credentials": False,
                    "scanned_at": "2026-07-01T00:00:00+00:00",
                    "scan_age_days": 0.0,
                },
                {
                    "slug": "stale-server",
                    "name": "Stale",
                    "grade": "B",
                    "transparency": "medium",
                    "danger_score": 3.0,
                    "requires_credentials": True,
                    "scanned_at": "2026-04-01T00:00:00+00:00",
                    "scan_age_days": 0.0,
                },
            ]
        },
    )

    payload = json.loads(mcp_server.list_servers_payload(now=datetime(2026, 8, 1, tzinfo=UTC)))

    fresh, stale = payload["servers"]
    assert fresh["scanned_at"] == "2026-07-01T00:00:00+00:00"
    assert fresh["scan_age_days"] == 31.0
    assert fresh["stale"] is False
    assert stale["scan_age_days"] == 122.0
    assert stale["stale"] is True


def test_list_servers_payload_staleness_boundary_uses_governance_horizon(monkeypatch) -> None:
    # 2026-05-03 -> 2026-08-01 is exactly 90 days: at the horizon, not past it.
    monkeypatch.setattr(
        mcp_server,
        "_snapshot",
        lambda: {
            "servers": [
                {
                    "slug": "at-horizon",
                    "name": "At Horizon",
                    "grade": "A",
                    "transparency": "high",
                    "danger_score": 1.0,
                    "requires_credentials": False,
                    "scanned_at": "2026-05-03T00:00:00+00:00",
                    "scan_age_days": 0.0,
                }
            ]
        },
    )

    payload = json.loads(mcp_server.list_servers_payload(now=datetime(2026, 8, 1, tzinfo=UTC)))

    row = payload["servers"][0]
    assert row["scan_age_days"] == 90.0
    assert row["stale"] is False


def test_list_servers_payload_unscanned_record_reports_null_freshness(monkeypatch) -> None:
    monkeypatch.setattr(
        mcp_server,
        "_snapshot",
        lambda: {
            "servers": [
                {
                    "slug": "never-scanned",
                    "name": "Never Scanned",
                    "grade": "unscanned",
                    "transparency": "low",
                    "danger_score": 0.0,
                    "requires_credentials": False,
                }
            ]
        },
    )

    payload = json.loads(mcp_server.list_servers_payload(now=datetime(2026, 8, 1, tzinfo=UTC)))

    row = payload["servers"][0]
    assert row["scanned_at"] is None
    assert row["scan_age_days"] is None
    assert row["stale"] is None


def test_check_server_payload_reports_stale_flag(monkeypatch) -> None:
    monkeypatch.setattr(
        mcp_server,
        "_snapshot",
        lambda: {
            "servers": [
                {
                    "slug": "aged",
                    "scanned_at": "2026-04-01T00:00:00+00:00",
                    "scan_age_days": 0.0,
                }
            ]
        },
    )

    payload = json.loads(
        mcp_server.check_server_payload("aged", now=datetime(2026, 8, 1, tzinfo=UTC))
    )

    assert payload["stale"] is True


def test_check_server_payload_unknown_slug_errors_with_known_list() -> None:
    payload = json.loads(mcp_server.check_server_payload("does-not-exist"))
    assert "error" in payload
    assert "mcp-archived-brave-search" in payload["known_slugs"]


def test_invalid_snapshot_returns_one_stable_zero_record_envelope(monkeypatch) -> None:
    raw = _SNAPSHOT.read_text(encoding="utf-8").replace(
        '"server_count": 23',
        '"server_count": 24, "private_value": "DO_NOT_LEAK"',
        1,
    )
    mcp_server._snapshot.cache_clear()
    monkeypatch.setattr(mcp_server, "_read_snapshot_text", lambda: raw)

    list_payload = mcp_server.list_servers_payload()
    check_payload = mcp_server.check_server_payload("mcp-archived-brave-search")
    repeated_payload = mcp_server.list_servers_payload()

    assert list_payload == check_payload == repeated_payload
    assert json.loads(list_payload) == {
        "schema": "mcp-trust-mcp-error.v1",
        "status": "UNKNOWN",
        "error_code": "CATALOG_SNAPSHOT_INVALID",
        "reason_codes": ["SERVER_COUNT_MISMATCH"],
        "server_count_served": 0,
    }
    assert "DO_NOT_LEAK" not in list_payload
    assert "servers" not in json.loads(list_payload)
    mcp_server._snapshot.cache_clear()


def test_entire_corruption_matrix_returns_no_partial_rows(monkeypatch) -> None:
    for raw in _corrupt_snapshot_inputs():
        mcp_server._snapshot.cache_clear()
        monkeypatch.setattr(mcp_server, "_read_snapshot_text", lambda raw=raw: raw)

        list_payload = mcp_server.list_servers_payload()
        check_payload = mcp_server.check_server_payload("mcp-archived-brave-search")
        repeated_payload = mcp_server.list_servers_payload()

        assert list_payload == check_payload == repeated_payload
        body = json.loads(list_payload)
        assert body["server_count_served"] == 0
        assert body["reason_codes"] == sorted(set(body["reason_codes"]))
        assert "servers" not in body
        assert "known_slugs" not in body
        assert "DO_NOT_LEAK" not in list_payload
    mcp_server._snapshot.cache_clear()


def test_failed_snapshot_is_not_cached_but_valid_snapshot_is(monkeypatch) -> None:
    valid = _SNAPSHOT.read_text(encoding="utf-8")
    reads = 0

    def changing_resource() -> str:
        nonlocal reads
        reads += 1
        return "{" if reads == 1 else valid

    mcp_server._snapshot.cache_clear()
    monkeypatch.setattr(mcp_server, "_read_snapshot_text", changing_resource)

    # A fixed now isolates the caching property under test: scan_age_days is
    # recomputed per response, so wall-clock calls are not byte-identical.
    fixed_now = datetime(2026, 8, 1, tzinfo=UTC)
    invalid = json.loads(mcp_server.list_servers_payload(now=fixed_now))
    first_valid = mcp_server.list_servers_payload(now=fixed_now)
    second_valid = mcp_server.list_servers_payload(now=fixed_now)

    assert invalid["error_code"] == "CATALOG_SNAPSHOT_INVALID"
    assert json.loads(first_valid)["server_count"] == 23
    assert first_valid == second_valid
    assert reads == 2
    mcp_server._snapshot.cache_clear()


def test_unreadable_snapshot_resource_returns_typed_envelope(monkeypatch) -> None:
    def unreadable() -> str:
        raise OSError("private resource path")

    mcp_server._snapshot.cache_clear()
    monkeypatch.setattr(mcp_server, "_read_snapshot_text", unreadable)

    payload = json.loads(mcp_server.check_server_payload("anything"))

    assert payload["reason_codes"] == ["SNAPSHOT_RESOURCE_UNREADABLE"]
    assert payload["server_count_served"] == 0
    assert "private resource path" not in json.dumps(payload)
    mcp_server._snapshot.cache_clear()


def test_snapshot_never_leaks_dummy_credential_values() -> None:
    blob = _SNAPSHOT.read_text(encoding="utf-8")
    # Env var NAMES are recorded...
    assert "BRAVE_API_KEY" in blob
    assert "AWS_SECRET_ACCESS_KEY" in blob
    # ...but no injected dummy VALUE ever appears.
    for leak in ("ghp_", "glpat-", "xoxb-", "mcp-trust-dummy", "0000000000"):
        assert leak not in blob, f"dummy value pattern leaked into snapshot: {leak}"


def test_build_server_constructs() -> None:
    app = mcp_server.build_server()
    assert app is not None
    assert app.name == "mcp-trust"


def test_methodology_does_not_flatten_unknown_local_provenance() -> None:
    methodology = mcp_server._METHODOLOGY  # pyright: ignore[reportPrivateUsage]
    assert "only when" in methodology
    assert "provenance is explicitly unknown" in methodology


def test_methodology_states_freshness_policy_from_governance_constant() -> None:
    from mcp_trust.core.governance import STALE_AFTER_DAYS

    methodology = mcp_server._METHODOLOGY  # pyright: ignore[reportPrivateUsage]
    assert f"{STALE_AFTER_DAYS} days" in methodology
    assert "stale" in methodology
