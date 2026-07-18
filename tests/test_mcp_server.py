"""Tests for the read-only MCP server over the baked catalog snapshot."""

from __future__ import annotations

import json
from datetime import UTC, datetime
from pathlib import Path

from mcp_trust import mcp_server

_SNAPSHOT = Path(__file__).resolve().parents[1] / "src/mcp_trust/catalog_snapshot.json"


def test_snapshot_ships_with_real_grades() -> None:
    snap = json.loads(_SNAPSHOT.read_text(encoding="utf-8"))
    assert snap["schema_version"] == 2
    assert snap["server_count"] == len(snap["servers"]) >= 15
    valid = {"A", "B", "C", "D", "F"}
    for s in snap["servers"]:
        assert s["grade"] in valid  # never "unscanned" in the baked snapshot
        assert s["engine"] == "mcpaudit"  # only real grades are baked
        assert s["scan_mode"] == "mcpaudit-local-network-off"
        assert s["sandbox"]["mode"] == "docker"


def test_list_servers_payload_is_complete_json() -> None:
    payload = json.loads(mcp_server.list_servers_payload())
    assert payload["server_count"] >= 15
    sample = payload["servers"][0]
    assert {"slug", "name", "grade", "transparency", "danger_score"} <= set(sample)


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


def test_check_server_payload_unknown_slug_errors_with_known_list() -> None:
    payload = json.loads(mcp_server.check_server_payload("does-not-exist"))
    assert "error" in payload
    assert "mcp-archived-brave-search" in payload["known_slugs"]


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
