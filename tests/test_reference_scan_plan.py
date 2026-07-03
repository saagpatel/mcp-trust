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
    assert len(payload["candidates"]) == 31

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


def test_registry_derived_candidates_pin_their_batch_sandbox_image() -> None:
    # These servers are baked only into a purpose-built batch image, not the
    # corpus image. Without a per-server pin, a whole-corpus refresh launches
    # them network-off in an image that lacks their binary — the scan fails and
    # the freshness lane silently keeps their stale grades.
    plan = _load_module("reference_scan_plan", SCRIPTS / "reference_scan_plan.py")
    by_slug = {c.slug: c for c in plan.REFERENCE_SCAN_CANDIDATES}
    pinned_images = {
        "com-mythsensus-mythsensus-mcp-0-2-1": "mcp-trust-live-batch:20260628",
        "com-pulsemcp-image-diff-0-1-3": "mcp-trust-live-batch:20260628",
        "com-seanwinslow-intent-engineering-0-2-0": "mcp-trust-live-batch:20260628",
        "eu-regulatoryai-sovereign-ai-act-mcp-1-2-0": "mcp-trust-live-batch:20260628",
        # Deferred-cohort integration (operator-approved 2026-07-03).
        "ai-adeu-adeu-1-7-1": "mcp-trust-live-batch:20260628",
        "ai-ravenmcp-raven-mcp-1-3-3": "mcp-trust-live-batch:20260628",
        "com-kage-core-kage-2-3-0": "mcp-trust-live-batch:20260628",
        "com-kogcat-kogcat-mcp-0-46-2": "mcp-trust-live-batch:20260628",
        # Batch-3 cohort (operator-approved 2026-07-03).
        "com-microsoft-powerbi-modeling-mcp-0-5-0-beta-11": "mcp-trust-batch3:20260703",
        "io-github-nickjlamb-redacta-mcp-1-2-1": "mcp-trust-batch3:20260703",
        # Batch-4 cohort (operator-approved 2026-07-03).
        "io-github-microsoft-playwright-mcp-0-0-77": "mcp-trust-batch4:20260703",
        "io-github-chromedevtools-chrome-devtools-mcp-1-5-0": "mcp-trust-batch4:20260703",
        "io-github-discourse-mcp-0-2-9": "mcp-trust-batch4:20260703",
        "io-github-ui5-webcomponents-react-mcp-server-2-23-2": "mcp-trust-batch4:20260703",
        "io-github-nvidia-elements-2-1-4": "mcp-trust-batch4:20260703",
        "io-github-basicmachines-co-basic-memory-0-22-1": "mcp-trust-batch4:20260703",
    }

    for slug, image in pinned_images.items():
        candidate = by_slug[slug]
        assert candidate.sandbox_image == image
        # The pin must survive projection into the seed catalog's source spec.
        assert candidate.source_preview()["sandbox_image"] == image

    for slug, candidate in by_slug.items():
        if slug not in pinned_images:
            assert candidate.sandbox_image == ""
            assert "sandbox_image" not in candidate.source_preview()

    # And it must survive the seed LOADER too — load_seed constructs
    # ServerSource field-by-field, which silently dropped the pin once already.
    from mcp_trust.catalog.seed import load_seed

    loaded = {server.slug: server for server in load_seed()}
    for slug, image in pinned_images.items():
        assert loaded[slug].source.sandbox_image == image
    for slug, server in loaded.items():
        if slug not in pinned_images:
            assert server.source.sandbox_image is None


def test_reference_scan_shell_plan_is_dry_run_text() -> None:
    _load_module("reference_scan_plan", SCRIPTS / "reference_scan_plan.py")
    planner = _load_module("plan_reference_scans", SCRIPTS / "plan_reference_scans.py")
    out = io.StringIO()

    planner.write_shell_plan(out)
    text = out.getvalue()

    assert "Dry-run only" in text
    assert "docker build -f Dockerfile.scan" in text
    assert text.count("mcp-trust scan ") == 31
    assert "docker run" not in text
    assert "MCP_TRUST_SCAN_TOKEN" not in text
