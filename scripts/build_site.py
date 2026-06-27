#!/usr/bin/env python3
"""Regenerate the static MCP Trust catalog from the registry database.

This is the low-ops "rebuild the catalog" entrypoint, mirroring the
portfolio-index static-generator pattern. It runs the full demo pipeline:

    seed (if empty) → stub-scan unscanned servers → build static site → verify

SAFETY: this pipeline uses the deterministic ``StubEngine`` only. It performs no
network I/O and never executes an untrusted MCP server. Real, sandboxed scans
(the ``mcpaudit`` engine) remain an explicit, separately-gated step; the grades
this script produces are demo data and are labelled as such on every page.

Usage::

    uv run python scripts/build_site.py [--db PATH] [--out DIR] [--base-url URL]

Exits non-zero if the verification gate fails, so a scheduled job can detect a
broken build.
"""

from __future__ import annotations

import argparse
import json
import sys
import uuid
from contextlib import closing
from datetime import UTC, datetime

from mcp_trust.catalog.seed import seed_into
from mcp_trust.core import grading
from mcp_trust.core.models import ScanRecord
from mcp_trust.engine.stub import StubEngine
from mcp_trust.site.generator import generate_site
from mcp_trust.store.db import connect, init_schema
from mcp_trust.store.repository import ScanRepository, ServerRepository

_DEFAULT_DB = "./registry.db"
_DEFAULT_OUT = "./site"
_PLACEHOLDER_BASE_URL = "https://mcp-trust.example"


def _stub_scan_unscanned(server_repo: ServerRepository, scan_repo: ScanRepository) -> int:
    """Stub-scan every server that has no scan yet. Returns the count scanned."""
    engine = StubEngine()
    latest = scan_repo.latest_all()
    scanned = 0
    for server in server_repo.list():
        if server.slug in latest:
            continue
        result = engine.scan(server.source)
        scan_repo.record(
            ScanRecord(
                id=uuid.uuid4().hex,
                server_slug=server.slug,
                engine_name=result.engine_name,
                engine_version=result.engine_version,
                grade=grading.grade(result.risk),
                transparency=grading.transparency(result.risk),
                risk=result.risk,
                findings=result.findings,
                scanned_at=datetime.now(tz=UTC),
                report_ref=None,
            )
        )
        scanned += 1
    return scanned


def _verify(build, *, servers) -> list[str]:
    """Return a list of verification failures (empty == passed)."""
    failures: list[str] = []
    out = build.out_dir

    index = out / "index.html"
    if not index.is_file():
        failures.append("index.html is missing")
    elif build.demo_count and "DEMO DATA" not in index.read_text(encoding="utf-8"):
        failures.append("catalog has demo data but no DEMO banner")

    if not (out / "404.html").is_file():
        failures.append("404.html is missing")

    for server in servers:
        detail = out / "ui" / "servers" / server.slug / "index.html"
        badge = out / "servers" / server.slug / "badge.json"
        if not detail.is_file():
            failures.append(f"detail page missing for {server.slug}")
        if not badge.is_file():
            failures.append(f"badge.json missing for {server.slug}")
        elif "message" not in json.loads(badge.read_text(encoding="utf-8")):
            failures.append(f"badge.json malformed for {server.slug}")

    return failures


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--db", default=_DEFAULT_DB, help="Registry SQLite path.")
    parser.add_argument("--out", default=_DEFAULT_OUT, help="Static site output directory.")
    parser.add_argument(
        "--base-url",
        default=_PLACEHOLDER_BASE_URL,
        help="Absolute deployment URL for badge-embed snippets.",
    )
    args = parser.parse_args(argv)

    with closing(connect(args.db)) as conn:
        init_schema(conn)
        server_repo = ServerRepository(conn)
        scan_repo = ScanRepository(conn)

        if not server_repo.list():
            seeded = seed_into(server_repo)
            print(f"Seeded {seeded} server(s) into {args.db}.")

        newly_scanned = _stub_scan_unscanned(server_repo, scan_repo)
        if newly_scanned:
            print(f"Stub-scanned {newly_scanned} previously-unscanned server(s).")

        build = generate_site(conn, args.out, base_url=args.base_url)
        print(
            f"Built static site for {build.server_count} server(s) "
            f"({build.scanned_count} scanned) → {build.out_dir} [{len(build.pages)} files]."
        )

        failures = _verify(build, servers=server_repo.list())

    if failures:
        print("VERIFY FAILED:", file=sys.stderr)
        for failure in failures:
            print(f"  - {failure}", file=sys.stderr)
        return 1

    print("VERIFY OK — every server has a detail page and badge; demo data is labelled.")
    if args.base_url == _PLACEHOLDER_BASE_URL:
        print(
            "Note: placeholder --base-url; badge embeds resolve only once deployed "
            "at the real host."
        )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
