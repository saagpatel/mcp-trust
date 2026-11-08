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
  severity. A `do_not_install` verdict adds a critical finding, which caps the
  grade.
- **Evidence:** tool names, annotation presence, and input-schema hashes when
  `--pin` (a `mcp-audit.trust-pin/1` file) is given.
- **Time:** the scan is stamped with the card's `generated_at`, not the import
  time, so importing an old card never supersedes newer evidence.

## What is refused

- Anything but a complete observation with a graded verdict
  (`no_mismatches_observed`, `review` or `do_not_install`), or a card whose
  evidence fields have the wrong types.
- A slug already owned by a different source kind or reference.
- A mapped record beyond the repository's admission limits (findings, tools,
  stored JSON size). Nothing is written in that case.
- Superseding a server whose latest scan is a real scan, unless `--replace` is
  passed: an imported verdict is demo-classified and would hide the real grade.

## How dimensions are scored

Keyword-inferred capabilities are weak signal, so the score rests on what the
sandbox observed and what tools declared:

| Dimension | Score (0–10) |
| --- | --- |
| file_access | writes outside home 8, writes in home 3, temporary-entry churn 1; tools not declared read-only add up to 3 by share |
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
