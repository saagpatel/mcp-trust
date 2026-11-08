# Importing Trust Before Connect verdicts (experimental)

`mcp-audit trust TARGET` (MCPAudit, experimental) checks an MCP server before
you install it: it resolves the server's registry metadata, runs packages in a
throwaway container behind a network sinkhole, and writes a verdict card
(`card.json`, schema `mcp-audit.trust-card/1`) plus a `pin.json` of the tool
surface.

`mcp-trust import-card` turns that card into a catalog entry:

```bash
mcp-trust import-card ./mcp-audit-trust/nws-weather-mcp-server/card.json \
  --pin ./mcp-audit-trust/nws-weather-mcp-server/pin.json
mcp-trust check cyanheads-nws-weather-mcp-server
```

## What is stored

- **Server:** what the card resolved: the npm or PyPI identifier, or the
  remote URL, plus declared environment variable names. The default slug is
  `<namespace owner>-<name>` (for example `io.github.cyanheads/nws-weather-mcp-server`
  becomes `cyanheads-nws-weather-mcp-server`); `--slug` overrides it. A slug
  already owned by a different source is refused.
- **Scan:** engine `mcp-audit-trust`, graded by the registry's own rubric
  (`core.grading`). Findings are the card's verdict (`TBC-VERDICT`, info), an
  outside-only note for remote servers, and each card mismatch at its own
  severity. A `do_not_install` verdict, or tool text matching prompt-injection
  patterns, adds a critical finding, which caps the grade. Other mismatches
  (for example `TBC-DRIFT`) are listed but do not cap it; the card's own verdict
  stays visible as `TBC-VERDICT`.
- **No receipt:** imports never write a scan receipt. A receipt is a public
  proof packet stamped with the importing shell's scan settings, which say
  nothing about the MCPAudit run behind the card.
- **Evidence:** tool names, annotation presence and input-schema hashes, only
  when `--pin` is given. The pin must come from the same run as the card: same
  server, package and version, created within five minutes of the card, with
  the same tool names and well-formed hashes. Without a pin, no tool evidence
  is stored rather than implying the tools have no schema.
- **Time:** the scan is stamped with the card's `generated_at`, not the import
  time, so importing an old card never supersedes newer evidence.

## What is refused

- Anything but a complete observation with a graded verdict
  (`no_mismatches_observed`, `review` or `do_not_install`). Every evidence field
  scoring reads (tools, phases, file changes, network events, mismatches) must
  be present and well-typed; missing evidence is never read as "nothing seen".
- A package card with no identifier, and a pin from another run.
- A slug already owned by a different source kind or reference.
- A mapped server or scan beyond the repository's admission limits (findings,
  tools, stored JSON size). Nothing is written in that case.
- A slug whose latest scan or server row cannot be read.
- Superseding a server's real latest scan with a newer card, unless `--replace`
  is passed: an imported verdict is demo-classified and would hide the real
  grade. A card older than the real scan imports without it and stays behind it.
- Re-importing the same card with the same evidence is a no-op. Re-importing
  it with different evidence (for example adding `--pin` later) needs
  `--replace`, which supersedes the earlier import of that card.
- Concurrent writers: the whole import is one write-locked transaction, so
  ownership and latest-scan checks cannot be raced; a busy database is refused.

## How dimensions are scored

Keyword-inferred capabilities are weak signal, so the score rests on what the
sandbox observed and what tools declared:

| Dimension | Score (0–10) |
| --- | --- |
| file_access | writes outside home, any write during a read-only tool's call, or a truncated change list (worst case), 8; writes in home 3, temporary-entry churn 1; tools not declared read-only add up to 3 by share |
| network_access | closed-world violation 8, unprompted egress (startup or shutdown) 6, remote server 3, egress during read-only calls 2 |
| shell_execution, exfiltration | 10 × share of tools not declared read-only whose text suggests the capability |
| destructive | 10 × share of tools declaring `destructiveHint` |

## Limits

- Experimental on both sides. The card format, rules and this calibration may
  change.
- Imported verdicts are **demo-classified**: `mcp-audit-trust` is not in
  `REAL_ENGINE_NAMES`, so the public site and snapshots do not present them as
  real scans until that provenance decision is made.
- Incomplete cards are refused. Remote cards are outside-view only: the
  remote's own writes and egress were never observable.
- Importing does not publish anything. Public snapshots still go through the
  operator publication flow.
