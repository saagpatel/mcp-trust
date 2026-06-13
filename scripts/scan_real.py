"""Manual integration driver: run MCPAuditEngine against trusted public servers.

Not part of the test suite (it launches real server processes over the network).
Run with the engine extra installed:  python scripts/scan_real.py
"""

from __future__ import annotations

from mcp_trust.core.grading import grade
from mcp_trust.core.models import ServerSource, SourceKind
from mcp_trust.engine.mcpaudit import MCPAuditEngine

# Trusted, official reference servers (Anthropic-maintained). Safe-ish targets to
# validate the adapter end-to-end without launching unknown third-party code.
TARGETS = [
    ("everything", "@modelcontextprotocol/server-everything", []),
    ("filesystem", "@modelcontextprotocol/server-filesystem", ["/tmp"]),
]


def main() -> None:
    engine = MCPAuditEngine(timeout=60.0)
    for label, ref, args in TARGETS:
        src = ServerSource(kind=SourceKind.NPM, reference=ref, args=args)
        print(f"\n=== {label} ({ref}) ===")
        try:
            result = engine.scan(src)
        except Exception as exc:  # noqa: BLE001 - driver: report and continue
            print(f"  SCAN FAILED: {type(exc).__name__}: {exc}")
            continue
        g = grade(result.risk)
        r = result.risk
        print(f"  grade={g}  composite={r.composite:.2f}  engine={result.engine_version}")
        print(
            f"  dims: file={r.file_access:.1f} net={r.network_access:.1f} "
            f"shell={r.shell_execution:.1f} destr={r.destructive:.1f} exfil={r.exfiltration:.1f}"
        )
        print(f"  findings: {len(result.findings)}  by_severity={dict(r.findings_by_severity)}")
        for f in result.findings[:6]:
            print(f"    [{f.severity}] {f.rule_id} {f.title} — {f.detail[:70]}")


if __name__ == "__main__":
    main()
