"""Tests for ``scripts/build_site.py`` — the catalog rebuild orchestrator.

The production rebuild must be HONEST by default: a server with no real scan is
shown as ``unscanned``, never given a fabricated letter grade. Stub/demo grades
are an explicit opt-in (``--demo-fill``) and, when used, must be loudly labelled.
"""

from __future__ import annotations

import importlib.util
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


build_site = _load_module("build_site_script", SCRIPTS / "build_site.py")


def test_default_build_is_honest_no_demo_fill(tmp_path: Path) -> None:
    """Default rebuild fabricates no grades: unscanned servers stay unscanned."""
    db = tmp_path / "registry.db"
    out = tmp_path / "site"

    rc = build_site.main(["--db", str(db), "--out", str(out), "--base-url", "https://x.example"])

    assert rc == 0
    index = (out / "index.html").read_text(encoding="utf-8")
    assert "DEMO DATA" not in index  # nothing was really scanned -> no demo banner
    # A seeded-but-unscanned server is reported honestly, not given a letter grade.
    badge = (out / "servers" / "mcp-reference-time" / "badge.json").read_text(encoding="utf-8")
    assert "unscanned" in badge


def test_demo_fill_opt_in_labels_demo_data(tmp_path: Path) -> None:
    """``--demo-fill`` stub-scans unscanned servers and labels them as demo."""
    db = tmp_path / "registry.db"
    out = tmp_path / "site"

    rc = build_site.main(
        [
            "--db",
            str(db),
            "--out",
            str(out),
            "--base-url",
            "https://x.example",
            "--demo-fill",
        ]
    )

    assert rc == 0
    index = (out / "index.html").read_text(encoding="utf-8")
    assert "DEMO DATA" in index  # opt-in stub fill must be loudly labelled
    badge = (out / "servers" / "mcp-reference-time" / "badge.json").read_text(encoding="utf-8")
    assert "(demo)" in badge  # the fabricated grade is marked demo, not bare
