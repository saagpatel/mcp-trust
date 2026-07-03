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
    assert len(payload["candidates"]) == 19

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


def test_registry_derived_candidates_pin_live_batch_sandbox_image() -> None:
    # These four are baked only into the live-batch image, not the corpus image.
    # Without a per-server pin, a whole-corpus refresh launches them network-off
    # in an image that lacks their binary — the scan fails and the freshness
    # lane silently keeps their stale grades.
    plan = _load_module("reference_scan_plan", SCRIPTS / "reference_scan_plan.py")
    by_slug = {c.slug: c for c in plan.REFERENCE_SCAN_CANDIDATES}
    live_batch_only = {
        "com-mythsensus-mythsensus-mcp-0-2-1",
        "com-pulsemcp-image-diff-0-1-3",
        "com-seanwinslow-intent-engineering-0-2-0",
        "eu-regulatoryai-sovereign-ai-act-mcp-1-2-0",
    }

    for slug in live_batch_only:
        candidate = by_slug[slug]
        assert candidate.sandbox_image == "mcp-trust-live-batch:20260628"
        # The pin must survive projection into the seed catalog's source spec.
        assert candidate.source_preview()["sandbox_image"] == "mcp-trust-live-batch:20260628"

    for slug, candidate in by_slug.items():
        if slug not in live_batch_only:
            assert candidate.sandbox_image == ""
            assert "sandbox_image" not in candidate.source_preview()

    # And it must survive the seed LOADER too — load_seed constructs
    # ServerSource field-by-field, which silently dropped the pin once already.
    from mcp_trust.catalog.seed import load_seed

    loaded = {server.slug: server for server in load_seed()}
    for slug in live_batch_only:
        assert loaded[slug].source.sandbox_image == "mcp-trust-live-batch:20260628"
    for slug, server in loaded.items():
        if slug not in live_batch_only:
            assert server.source.sandbox_image is None


def test_reference_scan_shell_plan_is_dry_run_text() -> None:
    _load_module("reference_scan_plan", SCRIPTS / "reference_scan_plan.py")
    planner = _load_module("plan_reference_scans", SCRIPTS / "plan_reference_scans.py")
    out = io.StringIO()

    planner.write_shell_plan(out)
    text = out.getvalue()

    assert "Dry-run only" in text
    assert "docker build -f Dockerfile.scan" in text
    assert text.count("mcp-trust scan ") == 19
    assert "docker run" not in text
    assert "MCP_TRUST_SCAN_TOKEN" not in text
