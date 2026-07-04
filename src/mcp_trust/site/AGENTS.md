# AGENTS.md - MCP Trust Web And Static Site Surface

## Review guidelines

Treat rendered HTML, generated static pages, catalog tables, and badge payloads
as public trust surfaces. If masking or provenance logic changes, verify both
the live renderer and the static generator; they must not diverge on grade
visibility, description wording, stale state, or provenance claims.

Operator masking applies to page metadata before any scan exists. Scan-specific
masking applies to grade/risk/finding details only when a scan exists. Badges
may still show `unscanned` for unscanned entries, but detail pages and catalog
copy must not leak grade-bearing catalog prose for operator-masked slugs.

Demo/stub provenance should be visibly labeled before remote-source wording.
Remote entries with a local launch command are not plain hosted endpoints; keep
the local-launch and sandbox context honest.
