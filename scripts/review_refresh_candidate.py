#!/usr/bin/env python3
"""Render one immutable refresh candidate as a read-only review surface.

All formats are written to stdout.  This command has no approval, publication,
deployment, scheduling, database-write, or network authority.
"""

from __future__ import annotations

import argparse
from datetime import datetime
from pathlib import Path

from mcp_trust.review_room import (
    build_review_surface,
    render_review_room_html,
    render_review_room_json,
    render_review_room_text,
)


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("candidate", type=Path)
    parser.add_argument(
        "--seed",
        type=Path,
        default=Path("src/mcp_trust/catalog/seed_servers.json"),
    )
    parser.add_argument(
        "--masked-grades",
        type=Path,
        default=Path("masked-grades.json"),
    )
    parser.add_argument("--format", choices=("html", "text", "json"), default="text")
    parser.add_argument(
        "--now",
        type=datetime.fromisoformat,
        help="Fixed ISO timestamp for deterministic review or testing.",
    )
    return parser


def main(argv: list[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    surface = build_review_surface(
        args.candidate,
        expected_seed_path=args.seed,
        expected_masked_path=args.masked_grades,
        now=args.now,
    )
    renderer = {
        "html": render_review_room_html,
        "text": render_review_room_text,
        "json": render_review_room_json,
    }[args.format]
    print(renderer(surface), end="")
    return 1 if surface.status in {"stale", "blocked"} else 0


if __name__ == "__main__":
    raise SystemExit(main())
