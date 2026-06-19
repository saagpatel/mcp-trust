"""Corpus scan for band calibration.

Scans a set of trusted, official public MCP servers with MCPAuditEngine and
emits the raw dimension vectors + a distribution summary, so grade bands can be
calibrated against real data rather than guessed.

NOT a test. Launches real server processes. Run with the engine extra installed:
    PYTHONPATH=src python scripts/corpus_scan.py

For public-launch prep, review LAUNCH-CATALOG.md first and run with the
Docker sandbox env printed by scripts/plan_reference_scans.py.
"""

from __future__ import annotations

import json
import statistics
import sys

from reference_scan_plan import REFERENCE_SCAN_CANDIDATES

from mcp_trust.core.grading import grade, transparency
from mcp_trust.core.models import ServerSource, SourceKind
from mcp_trust.engine.mcpaudit import MCPAuditEngine

_DIMS = ("file_access", "network_access", "shell_execution", "destructive", "exfiltration")


def main() -> None:
    engine = MCPAuditEngine(timeout=90.0)
    rows: list[dict] = []
    for candidate in REFERENCE_SCAN_CANDIDATES:
        src = ServerSource(
            kind=SourceKind(candidate.kind),
            reference=candidate.reference,
            command=candidate.command,
            args=list(candidate.args),
            env_keys=list(candidate.env_keys),
        )
        sys.stderr.write(f"scanning {candidate.slug} ...\n")
        sys.stderr.flush()
        try:
            r = engine.scan(src)
        except Exception as exc:  # noqa: BLE001 - corpus driver: record + continue
            rows.append(
                {
                    "label": candidate.slug,
                    "ref": candidate.reference,
                    "error": f"{type(exc).__name__}: {exc}",
                }
            )
            continue
        rk = r.risk
        rows.append(
            {
                "label": candidate.slug,
                "ref": candidate.reference,
                "composite": round(rk.composite, 3),
                "dims": {d: round(getattr(rk, d), 3) for d in _DIMS},
                "annotation_coverage": round(rk.annotation_coverage, 3),
                "grade": str(grade(rk)),
                "transparency": str(transparency(rk)),
                "n_findings": len(r.findings),
                "by_severity": {str(k): v for k, v in rk.findings_by_severity.items()},
            }
        )

    print(json.dumps(rows, indent=2))

    ok = [r for r in rows if "error" not in r]
    print("\n================ SUMMARY ================", file=sys.stderr)
    print(f"scanned ok: {len(ok)}/{len(rows)}", file=sys.stderr)
    if ok:
        comps = sorted(r["composite"] for r in ok)
        print(
            f"composite: min={comps[0]} max={comps[-1]} "
            f"median={statistics.median(comps):.2f} mean={statistics.mean(comps):.2f}",
            file=sys.stderr,
        )
        for d in _DIMS:
            vals = [r["dims"][d] for r in ok]
            print(
                f"  {d:16s} min={min(vals):.1f} max={max(vals):.1f} "
                f"mean={statistics.mean(vals):.2f}",
                file=sys.stderr,
            )
    for r in rows:
        if "error" in r:
            print(f"  FAILED {r['label']}: {r['error']}", file=sys.stderr)


if __name__ == "__main__":
    main()
