from __future__ import annotations

import importlib.util
import io
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SCRIPTS = ROOT / "scripts"


def _load_module(name: str, path: Path):
    spec = importlib.util.spec_from_file_location(name, path)
    assert spec is not None
    assert spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


def test_reference_scan_plan_is_network_off_and_complete() -> None:
    plan = _load_module("reference_scan_plan", SCRIPTS / "reference_scan_plan.py")

    payload = plan.plan_payload()

    assert payload["sandbox_env"]["MCP_TRUST_ENGINE"] == "mcpaudit"
    assert payload["sandbox_env"]["MCP_TRUST_SANDBOX"] == "docker"
    assert payload["sandbox_env"]["MCP_TRUST_SANDBOX_NETWORK"] == "none"
    assert len(payload["candidates"]) == 17

    slugs = {candidate["slug"] for candidate in payload["candidates"]}
    assert "mcp-reference-time" in slugs
    assert "mcp-reference-git" in slugs

    for candidate in payload["candidates"]:
        source = candidate["source"]
        assert source["command"] not in {"npx", "uvx"}
        assert "env_values" not in source

    git_source = next(
        candidate["source"]
        for candidate in payload["candidates"]
        if candidate["slug"] == "mcp-reference-git"
    )
    filesystem_source = next(
        candidate["source"]
        for candidate in payload["candidates"]
        if candidate["slug"] == "mcp-reference-filesystem"
    )
    assert filesystem_source["args"] == ["/scan"]

    assert git_source["args"] == ["--repository", "/fixtures/repo"]


def test_seed_catalog_matches_reference_scan_plan() -> None:
    plan = _load_module("reference_scan_plan", SCRIPTS / "reference_scan_plan.py")
    seed = json.loads((ROOT / "src/mcp_trust/catalog/seed_servers.json").read_text())

    assert seed == [candidate.seed_preview() for candidate in plan.REFERENCE_SCAN_CANDIDATES]


def test_reference_scan_shell_plan_is_dry_run_text() -> None:
    _load_module("reference_scan_plan", SCRIPTS / "reference_scan_plan.py")
    planner = _load_module("plan_reference_scans", SCRIPTS / "plan_reference_scans.py")
    out = io.StringIO()

    planner.write_shell_plan(out)
    text = out.getvalue()

    assert "Dry-run only" in text
    assert "docker build -f Dockerfile.scan" in text
    assert text.count("mcp-trust scan ") == 17
    assert "docker run" not in text
    assert "MCP_TRUST_SCAN_TOKEN" not in text
