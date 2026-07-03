#!/usr/bin/env python3
"""Promote reviewed temp corpus records into a review-only published set.

This is a guarded review transformer. It reads a ``CorpusRecordSet`` JSON file,
promotes only explicitly named receipt-backed ``scanned-temp`` records to
``published``, and writes a new JSON file. It does not scan, publish, edit
``seed_servers.json``, update ``registry.db``, build snapshots, deploy, or
generate badge artifacts.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from mcp_trust.corpus.records import (
    CorpusRecordSet,
    CorpusRecordStatus,
    PublicCorpusRecord,
    load_corpus_records,
    summarize_corpus_records,
)


def _append_unique(items: list[str], value: str) -> list[str]:
    if value in items:
        return items
    return [*items, value]


def _promote_record(record: PublicCorpusRecord, *, promotion_ref: str) -> PublicCorpusRecord:
    if record.status != CorpusRecordStatus.SCANNED_TEMP:
        raise ValueError(
            f"{record.record_id!r} must be scanned-temp before review-only promotion; "
            f"got {record.status!s}"
        )
    if record.receipt is None:
        raise ValueError(f"{record.record_id!r} cannot be promoted without receipt evidence")
    caveats = _append_unique(
        list(record.publish_caveats),
        f"Review-only promotion artifact: {promotion_ref}.",
    )
    return record.model_copy(
        update={
            "status": CorpusRecordStatus.PUBLISHED,
            "publish_caveats": caveats,
        }
    )


def _defer_record(record: PublicCorpusRecord, *, reason: str) -> PublicCorpusRecord:
    caveats = _append_unique(list(record.publish_caveats), f"Deferred: {reason}.")
    return record.model_copy(
        update={
            "status": CorpusRecordStatus.DEFERRED,
            "publish_caveats": caveats,
        }
    )


def promote_record_set(
    input_path: Path,
    *,
    promote_ids: set[str],
    promotion_ref: str,
    defer_unpromoted: bool = False,
    defer_reason: str = "not selected for this reviewed promotion cohort",
) -> CorpusRecordSet:
    """Return a review-only record set with explicitly named records promoted."""
    if not promote_ids:
        raise ValueError("at least one --promote record id is required")

    record_set = load_corpus_records(input_path)
    records_by_id = {record.record_id: record for record in record_set.records}
    if len(records_by_id) != len(record_set.records):
        raise ValueError("input corpus record set contains duplicate record_id values")

    missing = sorted(promote_ids.difference(records_by_id))
    if missing:
        raise ValueError(f"promote ids not found in input record set: {', '.join(missing)}")

    promoted: list[PublicCorpusRecord] = []
    for record in record_set.records:
        if record.record_id in promote_ids:
            promoted.append(_promote_record(record, promotion_ref=promotion_ref))
        elif defer_unpromoted:
            promoted.append(_defer_record(record, reason=defer_reason))
        else:
            promoted.append(record)
    return CorpusRecordSet(format_version=record_set.format_version, records=promoted)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--input", required=True, type=Path, help="Reviewed input record set.")
    parser.add_argument(
        "--promote",
        required=True,
        action="append",
        dest="promote_ids",
        help="Record id to mark published in the output. Repeat for each approved record.",
    )
    parser.add_argument(
        "--promotion-ref",
        required=True,
        help="Operator approval/reference string for this review-only promotion artifact.",
    )
    parser.add_argument(
        "--defer-unpromoted",
        action="store_true",
        help="Mark non-promoted input records deferred in the output.",
    )
    parser.add_argument(
        "--defer-reason",
        default="not selected for this reviewed promotion cohort",
        help="Reason appended to deferred records when --defer-unpromoted is used.",
    )
    parser.add_argument(
        "--out",
        required=True,
        type=Path,
        help="Output JSON path. Use tmp/ until public catalog integration is approved.",
    )
    args = parser.parse_args(argv)

    record_set = promote_record_set(
        args.input,
        promote_ids=set(args.promote_ids),
        promotion_ref=args.promotion_ref,
        defer_unpromoted=args.defer_unpromoted,
        defer_reason=args.defer_reason,
    )
    args.out.parent.mkdir(parents=True, exist_ok=True)
    args.out.write_text(
        json.dumps(record_set.model_dump(mode="json"), indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    print(json.dumps(summarize_corpus_records(record_set), indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except Exception as exc:  # noqa: BLE001 - CLI boundary
        print(f"promote_corpus_records failed: {exc}", file=sys.stderr)
        raise SystemExit(1) from exc
