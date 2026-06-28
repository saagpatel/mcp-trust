"""Tests for the read-only MCP server over the baked catalog snapshot."""

from __future__ import annotations

import json
from pathlib import Path

from mcp_trust import mcp_server

_SNAPSHOT = Path(__file__).resolve().parents[1] / "src/mcp_trust/catalog_snapshot.json"


def test_snapshot_ships_with_real_grades() -> None:
    snap = json.loads(_SNAPSHOT.read_text(encoding="utf-8"))
    assert snap["schema_version"] == 1
    assert snap["server_count"] == len(snap["servers"]) >= 15
    valid = {"A", "B", "C", "D", "F"}
    for s in snap["servers"]:
        assert s["grade"] in valid  # never "unscanned" in the baked snapshot
        assert s["engine"] == "mcpaudit"  # only real grades are baked


def test_list_servers_payload_is_complete_json() -> None:
    payload = json.loads(mcp_server.list_servers_payload())
    assert payload["server_count"] >= 15
    sample = payload["servers"][0]
    assert {"slug", "name", "grade", "transparency", "danger_score"} <= set(sample)


def test_check_server_payload_returns_full_record() -> None:
    payload = json.loads(mcp_server.check_server_payload("mcp-archived-gitlab"))
    assert payload["slug"] == "mcp-archived-gitlab"
    assert payload["grade"] == "D"
    assert payload["requires_credentials"] is True
    assert "GITLAB_PERSONAL_ACCESS_TOKEN" in payload["source"]["env_keys"]
    assert isinstance(payload["findings"], list)


def test_check_server_payload_unknown_slug_errors_with_known_list() -> None:
    payload = json.loads(mcp_server.check_server_payload("does-not-exist"))
    assert "error" in payload
    assert "mcp-archived-gitlab" in payload["known_slugs"]


def test_snapshot_never_leaks_dummy_credential_values() -> None:
    blob = _SNAPSHOT.read_text(encoding="utf-8")
    # Env var NAMES are recorded...
    assert "GITLAB_PERSONAL_ACCESS_TOKEN" in blob
    assert "SLACK_BOT_TOKEN" in blob
    # ...but no injected dummy VALUE ever appears.
    for leak in ("ghp_", "glpat-", "xoxb-", "mcp-trust-dummy", "0000000000"):
        assert leak not in blob, f"dummy value pattern leaked into snapshot: {leak}"


def test_build_server_constructs() -> None:
    app = mcp_server.build_server()
    assert app is not None
    assert app.name == "mcp-trust"
