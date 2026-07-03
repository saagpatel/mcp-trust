#!/usr/bin/env python3
"""Plan public catalog integration from reviewed corpus records.

This is a no-write planner. It reads a reviewed ``CorpusRecordSet`` artifact and
the current seed catalog, optionally reads an isolated temp source DB for launch
source specs, and prints the exact catalog/snapshot/site work that still needs
approval. It does not edit ``seed_servers.json``, update ``registry.db``, copy
receipts, build snapshots, deploy, publish badges, or run scans.
"""

from __future__ import annotations

import argparse
import json
import sqlite3
import sys
from pathlib import Path
from typing import Any

from mcp_trust.corpus.records import CorpusRecordStatus, PublicCorpusRecord, load_corpus_records

DEFAULT_SEED_PATH = Path("src/mcp_trust/catalog/seed_servers.json")


def _load_seed(path: Path) -> list[dict[str, Any]]:
    payload = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(payload, list):
        raise TypeError(f"{path} must contain a JSON array")
    return payload


def _load_source_specs(db_path: Path | None) -> dict[str, dict[str, Any]]:
    if db_path is None:
        return {}
    conn = sqlite3.connect(db_path)
    conn.row_factory = sqlite3.Row
    try:
        rows = conn.execute(
            """
            SELECT slug, name, description, source_json, homepage
            FROM servers
            ORDER BY slug
            """
        ).fetchall()
    finally:
        conn.close()
    return {
        row["slug"]: {
            "name": row["name"],
            "description": row["description"],
            "source": json.loads(row["source_json"]),
            "homepage": row["homepage"],
        }
        for row in rows
    }


def _package_fallback_source(record: PublicCorpusRecord) -> dict[str, Any] | None:
    if record.package is None:
        return None
    return {
        "kind": record.package.registry_type,
        "reference": record.package.identifier,
        "command": None,
        "args": [],
        "env_keys": [],
    }


def _seed_preview(record: PublicCorpusRecord, source_row: dict[str, Any] | None) -> dict[str, Any]:
    source = source_row["source"] if source_row else _package_fallback_source(record)
    return {
        "slug": record.record_id,
        "name": record.display_name,
        "description": (
            "Reviewed MCP Trust live-scan corpus candidate. Public meaning remains "
            "limited to controlled first-pass scan evidence and receipt caveats."
        ),
        "source": source,
        "homepage": (source_row or {}).get("homepage")
        or (record.package.repository_url if record.package else None),
    }


def _catalog_action(
    record: PublicCorpusRecord,
    *,
    seed_by_slug: dict[str, dict[str, Any]],
    source_specs: dict[str, dict[str, Any]],
) -> dict[str, Any]:
    source_row = source_specs.get(record.record_id)
    seed_preview = _seed_preview(record, source_row)
    source = seed_preview["source"]
    blockers: list[str] = []
    if source_row is None:
        blockers.append("missing source spec readback; pass --source-db or review manually")
    if source is None:
        blockers.append("missing package/source data")
    elif not source.get("command"):
        blockers.append("missing launch command; cannot seed a runnable catalog entry")
    if record.receipt is None:
        blockers.append("missing receipt evidence")

    if record.record_id in seed_by_slug:
        action = "already-seeded"
    elif blockers:
        action = "blocked"
    else:
        action = "add-seed-entry"

    return {
        "record_id": record.record_id,
        "registry_name": record.registry_name,
        "action": action,
        "blockers": blockers,
        "seed_preview": seed_preview,
        "receipt_ref": record.receipt.receipt_ref if record.receipt else None,
        "grade": str(record.receipt.grade) if record.receipt else None,
        "transparency": str(record.receipt.transparency) if record.receipt else None,
        "tool_count": record.receipt.tool_count if record.receipt else None,
        "approval_ref": record.receipt.approval_ref if record.receipt else None,
        "required_followups": [
            "copy or regenerate receipt evidence only after catalog integration approval",
            "scan integrated catalog slug in a temp DB before public DB mutation",
            "run launch-state validation after any approved catalog DB update",
            "rebuild snapshot/site only after DB and receipt parity are confirmed",
        ],
    }


def build_integration_plan(
    input_path: Path,
    *,
    seed_path: Path = DEFAULT_SEED_PATH,
    source_db: Path | None = None,
) -> dict[str, Any]:
    """Build a no-write integration plan for reviewed published corpus records."""
    record_set = load_corpus_records(input_path)
    seed = _load_seed(seed_path)
    seed_by_slug = {str(entry["slug"]): entry for entry in seed}
    source_specs = _load_source_specs(source_db)
    published = [
        record for record in record_set.records if record.status == CorpusRecordStatus.PUBLISHED
    ]
    deferred = [
        record.record_id
        for record in record_set.records
        if record.status == CorpusRecordStatus.DEFERRED
    ]
    actions = [
        _catalog_action(record, seed_by_slug=seed_by_slug, source_specs=source_specs)
        for record in published
    ]
    action_counts: dict[str, int] = {}
    for action in actions:
        action_counts[action["action"]] = action_counts.get(action["action"], 0) + 1

    return {
        "format_version": 1,
        "mode": "no-write-catalog-integration-plan",
        "inputs": {
            "record_set": str(input_path),
            "seed_catalog": str(seed_path),
            "source_db": str(source_db) if source_db else None,
        },
        "summary": {
            "seeded_count": len(seed),
            "record_count": len(record_set.records),
            "published_records": len(published),
            "deferred_records": len(deferred),
            "actions": dict(sorted(action_counts.items())),
        },
        "actions": actions,
        "deferred_record_ids": deferred,
        "non_mutation_boundaries": [
            "does not edit seed_servers.json",
            "does not update registry.db",
            "does not copy receipts into public receipt directories",
            "does not rebuild catalog_snapshot.json or static site output",
            "does not deploy or publish badges",
            "does not run MCP scans",
        ],
        "approval_required_before": [
            "adding seed entries",
            "copying or regenerating receipts",
            "mutating registry.db",
            "building snapshots or site output",
            "deploying public catalog or badge artifacts",
        ],
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--input", required=True, type=Path, help="Reviewed corpus record set.")
    parser.add_argument(
        "--seed",
        default=DEFAULT_SEED_PATH,
        type=Path,
        help="Current seed catalog JSON. Read-only.",
    )
    parser.add_argument(
        "--source-db",
        type=Path,
        help="Optional temp DB used only to recover launch source specs.",
    )
    parser.add_argument(
        "--out",
        type=Path,
        help="Optional JSON output path, preferably under tmp/.",
    )
    args = parser.parse_args(argv)

    plan = build_integration_plan(args.input, seed_path=args.seed, source_db=args.source_db)
    payload = json.dumps(plan, indent=2, sort_keys=True) + "\n"
    if args.out is not None:
        args.out.parent.mkdir(parents=True, exist_ok=True)
        args.out.write_text(payload, encoding="utf-8")
    print(payload, end="")
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except Exception as exc:  # noqa: BLE001 - CLI boundary
        print(f"plan_corpus_catalog_integration failed: {exc}", file=sys.stderr)
        raise SystemExit(1) from exc
