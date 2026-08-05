#!/usr/bin/env python3
"""Read-only decision assessment for an MCP evidence lineage ledger."""

from __future__ import annotations

import argparse
import json
import sys
from datetime import datetime
from pathlib import Path

from pydantic import ValidationError

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from mcp_trust.corpus.lineage import (  # noqa: E402
    AssessmentStatus,
    LineageDecision,
    assess_lineage,
    canonical_payload_sha256,
    load_evidence_lineage_ledger,
)

OUTPUT_SCHEMA = "mcp-trust-evidence-lineage-assessment-set.v1"
ERROR_SCHEMA = "mcp-trust-evidence-lineage-error.v1"


def _datetime(value: str) -> datetime:
    normalized = f"{value[:-1]}+00:00" if value.endswith("Z") else value
    try:
        parsed = datetime.fromisoformat(normalized)
    except ValueError as exc:
        raise argparse.ArgumentTypeError("must be an ISO-8601 datetime") from exc
    if parsed.tzinfo is None or parsed.utcoffset() is None:
        raise argparse.ArgumentTypeError("must include a timezone offset")
    return parsed


def _successful(decision: LineageDecision, statuses: set[AssessmentStatus]) -> bool:
    allowed = {
        LineageDecision.ADMIT: {AssessmentStatus.ALLOWED},
        LineageDecision.REFRESH: {AssessmentStatus.NOT_REQUIRED},
        LineageDecision.PUBLISH: {AssessmentStatus.ALLOWED},
        LineageDecision.WITHDRAW: {
            AssessmentStatus.COMPLETE,
            AssessmentStatus.NOT_REQUIRED,
        },
    }
    return statuses <= allowed[decision]


def _emit_error(reason_code: str, *, pretty: bool) -> None:
    print(
        json.dumps(
            {
                "schema": ERROR_SCHEMA,
                "status": "UNKNOWN",
                "reason_codes": [reason_code],
            },
            indent=2 if pretty else None,
            separators=None if pretty else (",", ":"),
            sort_keys=True,
        )
    )


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("ledger", type=Path)
    parser.add_argument(
        "--decision",
        choices=[item.value for item in LineageDecision],
        required=True,
    )
    parser.add_argument("--now", type=_datetime, required=True)
    parser.add_argument("--expected-version")
    parser.add_argument("--pretty", action="store_true")
    args = parser.parse_args()

    try:
        ledger = load_evidence_lineage_ledger(args.ledger)
    except OSError:
        _emit_error("LEDGER_UNREADABLE", pretty=args.pretty)
        return 2
    except json.JSONDecodeError:
        _emit_error("LEDGER_JSON_INVALID", pretty=args.pretty)
        return 2
    except ValidationError:
        _emit_error("LEDGER_INVALID", pretty=args.pretty)
        return 2
    decision = LineageDecision(args.decision)
    assessments = [
        assess_lineage(
            record,
            decision,
            now=args.now,
            expected_version=args.expected_version,
        )
        for record in ledger.records
    ]
    payload = {
        "schema": OUTPUT_SCHEMA,
        "ledger_id": ledger.ledger_id,
        "ledger_sha256": canonical_payload_sha256(ledger),
        "decision": decision,
        "assessed_at": assessments[0].assessed_at.isoformat(),
        "records": [item.model_dump(mode="json", by_alias=True) for item in assessments],
    }
    print(
        json.dumps(
            payload,
            ensure_ascii=False,
            indent=2 if args.pretty else None,
            separators=None if args.pretty else (",", ":"),
            sort_keys=True,
        )
    )
    statuses = {item.status for item in assessments}
    return 0 if _successful(decision, statuses) else 1


if __name__ == "__main__":
    raise SystemExit(main())
