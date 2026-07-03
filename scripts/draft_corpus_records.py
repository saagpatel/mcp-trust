#!/usr/bin/env python3
"""Draft reviewed corpus records from an isolated temp scan lane.

This is a review-only bridge from temp live-scan evidence to a
``CorpusRecordSet`` JSON artifact. It does not scan, publish, edit
``seed_servers.json``, or mutate the public catalog. Grades enter the draft only
through existing receipt-backed controlled live-scan evidence.
"""

from __future__ import annotations

import argparse
import json
import re
import sqlite3
import sys
from pathlib import Path
from typing import Any

from mcp_trust.core.models import TransparencyLevel, TrustGrade
from mcp_trust.corpus.records import (
    CorpusRecordSet,
    CorpusRecordStatus,
    PackageSource,
    PublicCorpusRecord,
    ReceiptEvidenceRef,
    summarize_corpus_records,
)
from mcp_trust.corpus.registry import CandidateMode, Freshness

_VERSION_SUFFIX_RE = re.compile(r"-(\d+(?:-\d+)+(?:-[a-z0-9]+)*)$")


def _load_json(path: Path) -> dict[str, Any]:
    payload = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(payload, dict):
        raise TypeError(f"{path} must contain a JSON object")
    return payload


def _load_servers(db_path: Path) -> dict[str, dict[str, Any]]:
    conn = sqlite3.connect(db_path)
    conn.row_factory = sqlite3.Row
    try:
        rows = conn.execute(
            "SELECT slug, name, homepage, source_json FROM servers ORDER BY slug"
        ).fetchall()
    finally:
        conn.close()
    servers: dict[str, dict[str, Any]] = {}
    for row in rows:
        source = json.loads(row["source_json"])
        servers[row["slug"]] = {
            "name": row["name"],
            "homepage": row["homepage"],
            "source": source,
        }
    return servers


def _version_from_slug(slug: str, *, registry_type: str = "npm") -> str:
    match = _VERSION_SUFFIX_RE.search(slug)
    if match is None:
        raise ValueError(f"cannot infer exact package version from slug {slug!r}")
    if registry_type.lower() != "npm":
        return match.group(1).replace("-", ".")
    segments = match.group(1).split("-")
    # Semver: up to three leading numeric segments form the release core;
    # anything after is a dot-separated prerelease tail (e.g. the slug suffix
    # "0-5-0-beta-11" must become "0.5.0-beta.11", not "0.5.0.beta.11").
    core: list[str] = []
    while segments and segments[0].isdigit() and len(core) < 3:
        core.append(segments.pop(0))
    version = ".".join(core)
    if segments:
        version += "-" + ".".join(segments)
    return version


def _record_from_receipt(
    receipt_path: Path,
    *,
    db_servers: dict[str, dict[str, Any]],
    receipt_root: Path,
) -> PublicCorpusRecord:
    receipt = _load_json(receipt_path)
    slug = str(receipt["server_slug"])
    server = dict(receipt["server"])
    db_server = db_servers.get(slug)
    if db_server is None:
        raise ValueError(f"receipt {receipt_path} references slug {slug!r} missing from DB")

    source = dict(db_server["source"])
    receipt_source = dict(server["source"])
    if source != receipt_source:
        raise ValueError(f"receipt {receipt_path} source does not match DB source for {slug!r}")

    version = _version_from_slug(slug, registry_type=str(source["kind"]))
    package = PackageSource(
        registry_type=str(source["kind"]),
        identifier=str(source["reference"]),
        version=version,
        repository_url=db_server.get("homepage"),
    )
    evidence = receipt.get("evidence") or {}
    scan = receipt.get("scan") or {}
    sandbox = receipt.get("sandbox") or {}
    approval = receipt.get("approval") or {}
    relative_receipt = receipt_path.relative_to(receipt_root.parent).as_posix()

    return PublicCorpusRecord(
        record_id=slug,
        registry_name=str(db_server["name"]),
        display_name=str(db_server["name"]),
        status=CorpusRecordStatus.SCANNED_TEMP,
        recommended_mode=CandidateMode.NO_AUTH_SANDBOXED,
        package=package,
        freshness=Freshness.UNKNOWN,
        dedupe_keys=[
            key
            for key in [
                f"package:{package.registry_type}:{package.identifier}:{package.version}",
                f"repo:{package.repository_url}" if package.repository_url else "",
                f"registry:{db_server['name']}:{package.version}",
            ]
            if key
        ],
        source_caveats=[
            "Registry/package metadata is discovery and provenance only.",
            "Exact version was inferred from the approved temp scan slug.",
            "This record is review-only and is not a public catalog entry.",
        ],
        receipt=ReceiptEvidenceRef(
            receipt_ref=relative_receipt,
            approval_ref=str(approval.get("approval_ref") or ""),
            scanned_at=str(scan["scanned_at"]),
            scan_mode=CandidateMode.NO_AUTH_SANDBOXED,
            sandbox_image=sandbox.get("MCP_TRUST_SANDBOX_IMAGE"),
            sandbox_network=sandbox.get("MCP_TRUST_SANDBOX_NETWORK"),
            grade=TrustGrade(scan["grade"]),
            transparency=TransparencyLevel(scan["transparency"]),
            tool_count=int(evidence.get("tool_count") or 0),
            schema_hash_algorithm=str(evidence.get("schema_hash_algorithm") or "sha256"),
        ),
        publish_caveats=[
            "Do not publish until source/provenance review is complete.",
            "Network-off sandboxing may suppress behavior requiring live egress.",
            "Danger grade and transparency are separate signals.",
        ],
    )


def build_record_set(db_path: Path, receipts_dir: Path) -> CorpusRecordSet:
    """Build a review-only corpus record set from temp DB + receipt artifacts."""
    db_servers = _load_servers(db_path)
    receipt_paths = sorted(receipts_dir.glob("*.json"))
    if not receipt_paths:
        raise ValueError(f"no receipt JSON files found in {receipts_dir}")
    records = [
        _record_from_receipt(path, db_servers=db_servers, receipt_root=receipts_dir)
        for path in receipt_paths
    ]
    return CorpusRecordSet(records=records)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--db", required=True, type=Path, help="Temp scan SQLite DB.")
    parser.add_argument(
        "--receipts-dir",
        required=True,
        type=Path,
        help="Temp receipt directory for one approved scan batch.",
    )
    parser.add_argument(
        "--out",
        required=True,
        type=Path,
        help="Output JSON path. Use tmp/ for review-only artifacts.",
    )
    args = parser.parse_args(argv)

    record_set = build_record_set(args.db, args.receipts_dir)
    args.out.parent.mkdir(parents=True, exist_ok=True)
    args.out.write_text(
        json.dumps(record_set.model_dump(mode="json"), indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    summary = summarize_corpus_records(record_set)
    print(json.dumps(summary, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except Exception as exc:  # noqa: BLE001 - CLI boundary
        print(f"draft_corpus_records failed: {exc}", file=sys.stderr)
        raise SystemExit(1) from exc
