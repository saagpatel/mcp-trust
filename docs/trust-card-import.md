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

## Bundled cards

`src/mcp_trust/catalog/trust_cards/` ships real cards, each with its pin, from
`mcp-audit trust` runs against servers in the official MCP Registry that need no
credentials. Load them all into a registry database with:

```bash
mcp-trust import-cards            # bundled cards; or: mcp-trust import-cards DIR
```

Each card is imported on its own, atomically; a refused card does not stop the
rest. They stay demo-classified like any imported verdict. Servers whose run was
incomplete (for example a package that fails to start) have no card, because
there is nothing to grade.

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

## Calibrated rubric

An imported card carries two separate judgements:

- **The card verdict**, decided by MCPAudit from claims versus behaviour, is kept
  as the `TBC-VERDICT` finding.
- **The registry grade** reflects only what the sandbox observed the server do.

Capabilities the sandbox cannot observe (shell execution, exfiltration,
destructive actions) and tools it did not call never move the grade. They show
up on the transparency axis instead: LOW transparency means "cannot verify
safe", as it does for every other scan.

| Card verdict | Registry grade | What it means |
| --- | --- | --- |
| `no_mismatches_observed` | A–B | Nothing observed contradicted the server's claims. **A**: no lasting writes, at most expected egress during tool calls. **B**: lasting writes inside its home directory. |
| `review`, caused by behaviour | C–D | It did something it didn't announce. **C**: one concern (unprompted egress at startup or shutdown, a contradicted "local" claim, or writes outside home). **D**: more than one. |
| `review`, caused by metadata only | the behaviour grade (A–B) | Registry or namespace warnings, such as a missing repository URL. The grade covers behaviour only; the verdict stays visible as a finding. |
| `do_not_install` | D–F | A high-severity contradiction. **F** when observed behaviour broke a declaration (a read-only tool wrote files, or a closed-world tool reached the network). **D** (the critical cap) when the cause is tool text or a failed ownership check. |

The dimensions that implement the rubric under `core.grading`'s frozen weights:

| Dimension | Score (0–10) |
| --- | --- |
| file_access | a write during a read-only tool's call, or a truncated change list (worst case), 8; writes outside home 3; lasting writes in home 2; temporary-entry churn only 1 |
| network_access | egress breaking a closed-world declaration 8; unprompted egress or a contradicted local claim 3.6; remote server observed from outside 2; egress during tool calls 1 |
| shell_execution, exfiltration, destructive | 0 (not observable by the sandbox) |

A test checks every bundled card against this rubric.

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
