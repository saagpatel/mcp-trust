#!/usr/bin/env python3
"""Build a dry-run MCP Registry corpus candidate manifest from saved JSON.

This script reads an already-fetched official MCP Registry response and prints a
candidate manifest. It never scans, installs, launches, authenticates, contacts
MCP servers, writes catalog data, or assigns danger grades.
"""

from __future__ import annotations

import argparse
import json
import sys
from datetime import datetime
from pathlib import Path
from typing import Any

from mcp_trust.corpus.registry import build_registry_candidate_manifest


def _load_payload(path: Path) -> dict[str, Any] | list[Any]:
    with path.open(encoding="utf-8") as handle:
        payload = json.load(handle)
    if not isinstance(payload, (dict, list)):
        raise TypeError("registry export must be a JSON object or list")
    return payload


def _parse_datetime(value: str | None) -> datetime | None:
    if value is None:
        return None
    return datetime.fromisoformat(value.replace("Z", "+00:00"))


def _write_summary(manifest: dict[str, Any]) -> None:
    print(manifest["notice"])
    print(f"input servers: {manifest['source']['input_servers']}")
    print(f"candidates: {manifest['counts']['candidates']}")
    print(f"eligible for first live batch: {manifest['counts']['eligible_for_first_live_batch']}")
    print("modes:")
    for mode, count in manifest["counts"]["modes"].items():
        print(f"  {mode}: {count}")
    print("selected candidates:")
    for candidate in manifest["candidates"]:
        if candidate["selected_for_first_batch"]:
            print(
                f"  {candidate['stable_id']} "
                f"({candidate['registry_name']}, mode={candidate['recommended_mode']})"
            )


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--input",
        required=True,
        type=Path,
        help="Saved official MCP Registry JSON response. No network fetch is performed.",
    )
    parser.add_argument(
        "--limit",
        type=int,
        default=25,
        help="Maximum eligible no-auth sandboxed candidates to mark for the first batch.",
    )
    parser.add_argument(
        "--generated-at",
        help="Optional RFC3339 timestamp for deterministic manifests.",
    )
    parser.add_argument(
        "--format",
        choices=("json", "summary"),
        default="json",
        help="Output format. Both formats are dry-run only.",
    )
    args = parser.parse_args(argv)

    manifest = build_registry_candidate_manifest(
        _load_payload(args.input),
        generated_at=_parse_datetime(args.generated_at),
        first_batch_limit=args.limit,
    )

    if args.format == "summary":
        _write_summary(manifest)
    else:
        print(json.dumps(manifest, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except Exception as exc:  # noqa: BLE001 - CLI boundary
        print(f"plan_registry_corpus failed: {exc}", file=sys.stderr)
        raise SystemExit(1) from exc
