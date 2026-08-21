"""Verify the committed seven-server reference-corpus evidence and launch docs."""

from __future__ import annotations

import argparse
import json
import re
from collections import Counter
from pathlib import Path
from typing import Any

_EVIDENCE_PATH = Path("docs/reference-corpus-evidence-v1.json")
_DOC_PATHS = (Path("LAUNCH-CATALOG.md"), Path("LAUNCH-GATE.md"))
_SLUGS = {
    "mcp-reference-everything",
    "mcp-reference-fetch",
    "mcp-reference-filesystem",
    "mcp-reference-git",
    "mcp-reference-memory",
    "mcp-reference-sequential-thinking",
    "mcp-reference-time",
}
_GRADES = ("A", "B", "C", "D", "F")
_TRANSPARENCY = ("high", "medium", "low")
_SHA256 = re.compile(r"^[0-9a-f]{64}$")
_SCAN_ID = re.compile(r"^[0-9a-f]{32}$")
_STALE_DOC_CLAIMS = (
    "A=1, B=2, C=1, D=1, F=2",
    "| `mcp-reference-everything` | F | low | 8.0 |",
    "| `mcp-reference-sequential-thinking` | F | low | 8.6 |",
)


class EvidenceError(ValueError):
    """Raised when the committed evidence or a derived launch claim drifts."""


def load_evidence(path: Path) -> dict[str, Any]:
    payload = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(payload, dict):
        raise EvidenceError("evidence root must be an object")
    return payload


def validate_evidence(payload: dict[str, Any]) -> dict[str, dict[str, int]]:
    if payload.get("schema") != "ReferenceCorpusEvidenceV1":
        raise EvidenceError("unexpected evidence schema")

    source = payload.get("source")
    execution = payload.get("execution")
    rows = payload.get("rows")
    if not isinstance(source, dict) or not isinstance(execution, dict):
        raise EvidenceError("source and execution must be objects")
    if not isinstance(rows, list) or len(rows) != len(_SLUGS):
        raise EvidenceError("evidence must contain exactly seven rows")

    if source.get("engine_name") != "mcpaudit":
        raise EvidenceError("reference corpus must use mcpaudit")
    if not isinstance(source.get("engine_version"), str):
        raise EvidenceError("engine_version must be a string")
    if execution.get("sandbox") != "docker" or execution.get("network") != "none":
        raise EvidenceError("reference corpus must be Docker sandboxed with network none")
    if execution.get("scan_count") != 7 or execution.get("receipt_count") != 7:
        raise EvidenceError("execution counts must both equal seven")

    for key in (
        "dockerfile_sha256",
        "seed_catalog_sha256",
        "docker_image_digest",
    ):
        value = source.get(key)
        candidate = value.removeprefix("sha256:") if isinstance(value, str) else ""
        if not _SHA256.fullmatch(candidate):
            raise EvidenceError(f"source.{key} must be a SHA-256 identity")
    for key in ("status_sha256", "registry_db_sha256", "receipt_set_sha256"):
        if not _SHA256.fullmatch(str(execution.get(key, ""))):
            raise EvidenceError(f"execution.{key} must be a SHA-256 identity")

    slugs: list[str] = []
    scan_ids: list[str] = []
    report_refs: list[str] = []
    grades: Counter[str] = Counter()
    transparencies: Counter[str] = Counter()
    for row in rows:
        if not isinstance(row, dict):
            raise EvidenceError("each evidence row must be an object")
        slug = row.get("slug")
        scan_id = row.get("scan_id")
        report_ref = row.get("report_ref")
        if slug not in _SLUGS:
            raise EvidenceError(f"unexpected reference slug: {slug!r}")
        if not _SCAN_ID.fullmatch(str(scan_id)):
            raise EvidenceError(f"{slug}: invalid scan_id")
        if report_ref != f"{slug}-{scan_id}.json":
            raise EvidenceError(f"{slug}: report_ref does not bind scan_id")
        if not _SHA256.fullmatch(str(row.get("receipt_sha256", ""))):
            raise EvidenceError(f"{slug}: invalid receipt_sha256")
        if row.get("grade") not in _GRADES:
            raise EvidenceError(f"{slug}: invalid grade")
        if row.get("transparency") not in _TRANSPARENCY:
            raise EvidenceError(f"{slug}: invalid transparency")
        if not isinstance(row.get("composite"), (int, float)):
            raise EvidenceError(f"{slug}: composite must be numeric")
        slugs.append(slug)
        scan_ids.append(scan_id)
        report_refs.append(report_ref)
        grades[row["grade"]] += 1
        transparencies[row["transparency"]] += 1

    if set(slugs) != _SLUGS or len(set(slugs)) != 7:
        raise EvidenceError("reference slugs must be exact and unique")
    if len(set(scan_ids)) != 7 or len(set(report_refs)) != 7:
        raise EvidenceError("scan IDs and report refs must be unique")

    computed = {
        "grades": {grade: grades[grade] for grade in _GRADES},
        "transparency": {level: transparencies[level] for level in _TRANSPARENCY},
    }
    if payload.get("distribution") != computed:
        raise EvidenceError("recorded distribution does not match evidence rows")
    return computed


def validate_docs(root: Path, payload: dict[str, Any]) -> None:
    distribution = validate_evidence(payload)
    grade_summary = ", ".join(
        f"{grade}={distribution['grades'][grade]}" for grade in _GRADES
    )
    transparency_summary = ", ".join(
        f"{level}={distribution['transparency'][level]}" for level in _TRANSPARENCY
    )
    rows = payload["rows"]
    engine_version = payload["source"]["engine_version"]

    for relative in _DOC_PATHS:
        text = (root / relative).read_text(encoding="utf-8")
        for stale in _STALE_DOC_CLAIMS:
            if stale in text:
                raise EvidenceError(f"{relative}: stale corpus claim remains: {stale}")
        if grade_summary not in text:
            raise EvidenceError(f"{relative}: grade distribution drift")
        if transparency_summary not in text:
            raise EvidenceError(f"{relative}: transparency distribution drift")
        if f"MCPAudit {engine_version}" not in text:
            raise EvidenceError(f"{relative}: engine version is not evidence-bound")
        if str(_EVIDENCE_PATH) not in text:
            raise EvidenceError(f"{relative}: committed evidence path is missing")
        for row in rows:
            table_prefix = (
                f"| `{row['slug']}` | {row['grade']} | {row['transparency']} | "
                f"{row['composite']:.1f} |"
            )
            if table_prefix not in text:
                raise EvidenceError(f"{relative}: table row drift for {row['slug']}")


def verify(root: Path, evidence_path: Path = _EVIDENCE_PATH) -> dict[str, Any]:
    payload = load_evidence(root / evidence_path)
    distribution = validate_evidence(payload)
    validate_docs(root, payload)
    return {
        "schema": payload["schema"],
        "engine": f"{payload['source']['engine_name']}@{payload['source']['engine_version']}",
        "rows": len(payload["rows"]),
        "distribution": distribution,
        "evidence": str(evidence_path),
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, default=Path("."))
    parser.add_argument("--evidence", type=Path, default=_EVIDENCE_PATH)
    args = parser.parse_args(argv)
    try:
        result = verify(args.root, args.evidence)
    except (EvidenceError, FileNotFoundError, json.JSONDecodeError) as exc:
        print(f"reference-corpus evidence verification failed: {exc}")
        return 1
    print(json.dumps(result, indent=2, sort_keys=True))
    print("reference-corpus evidence verification passed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
