# AGENTS.md - MCP Trust API Surface

## Review guidelines

Treat API routes as public trust surfaces. Review changes for grade/risk
masking, `report_ref` exposure, server-description leakage, stale scan state,
operator scan-trigger boundaries, and any JSON field that could imply a safety
or provenance claim.

When a slug is operator-masked, server metadata should stay neutral even if
there is no `latest_scan`. When a masked scan exists, grade, risk, findings,
transparency, composite score, and report references must be withheld together.

Missing sandbox, network, receipt, source-binding, or scan provenance data must
be rendered as unknown. Do not approve wording or payload behavior that turns
missing evidence into a claim of safe sandboxing, vendor-hosted execution, or
clean provenance.
