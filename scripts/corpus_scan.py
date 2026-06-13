"""Corpus scan for band calibration.

Scans a set of trusted, official public MCP servers with MCPAuditEngine and
emits the raw dimension vectors + a distribution summary, so grade bands can be
calibrated against real data rather than guessed.

NOT a test. Launches real server processes. Run with the engine extra installed:
    PYTHONPATH=src python scripts/corpus_scan.py
"""

from __future__ import annotations

import json
import statistics
import sys

from mcp_trust.core.grading import grade, transparency
from mcp_trust.core.models import ServerSource, SourceKind
from mcp_trust.engine.mcpaudit import MCPAuditEngine

# (label, kind, reference, args). Official reference servers that launch without
# credentials, spanning capability profiles from trivial to kitchen-sink.
CORPUS = [
    ("sequential-thinking", SourceKind.NPM, "@modelcontextprotocol/server-sequential-thinking", []),
    ("memory", SourceKind.NPM, "@modelcontextprotocol/server-memory", []),
    ("everything", SourceKind.NPM, "@modelcontextprotocol/server-everything", []),
    ("filesystem", SourceKind.NPM, "@modelcontextprotocol/server-filesystem", ["/tmp"]),
    ("time", SourceKind.PYPI, "mcp-server-time", []),
    ("fetch", SourceKind.PYPI, "mcp-server-fetch", []),
    ("git", SourceKind.PYPI, "mcp-server-git", []),
    ("sqlite", SourceKind.PYPI, "mcp-server-sqlite", ["--db-path", "/tmp/corpus_probe.db"]),
]

_DIMS = ("file_access", "network_access", "shell_execution", "destructive", "exfiltration")


def main() -> None:
    engine = MCPAuditEngine(timeout=90.0)
    rows: list[dict] = []
    for label, kind, ref, args in CORPUS:
        src = ServerSource(kind=kind, reference=ref, args=args)
        sys.stderr.write(f"scanning {label} ...\n")
        sys.stderr.flush()
        try:
            r = engine.scan(src)
        except Exception as exc:  # noqa: BLE001 - corpus driver: record + continue
            rows.append({"label": label, "ref": ref, "error": f"{type(exc).__name__}: {exc}"})
            continue
        rk = r.risk
        rows.append(
            {
                "label": label,
                "ref": ref,
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
                f"  {d:16s} min={min(vals):.1f} max={max(vals):.1f} mean={statistics.mean(vals):.2f}",
                file=sys.stderr,
            )
    for r in rows:
        if "error" in r:
            print(f"  FAILED {r['label']}: {r['error']}", file=sys.stderr)


if __name__ == "__main__":
    main()
