# Adversarial Trust-Boundary Campaign

This ledger tracks the synthetic-only reliability campaign started from live
remote `main` at `939f042b2dc8396f818037bf2fe5575985c163f7` on 2026-08-14.
It is an upgrade to MCP Trust Registry. It does not authorize real engine
scans, untrusted process launches, grade publication, deployment, or external
writes.

Allowed states are `READY`, `WORKING`, `BLOCKED`, `VERIFIED`, and `DROPPED`.
An item reaches `VERIFIED` only with a named local test or static receipt.

## Baseline

- Worktree: `/Users/d/Projects/_codex-worktrees/mcp-trust-adversarial-hardening-20260814`
- Branch: `codex/mcp-trust-adversarial-hardening-20260814`
- Safe baseline: `762 passed, 5 skipped` with the existing development
  environment and bytecode/cache writes disabled.
- Current full safe gate: `855 passed, 5 skipped`; the one warning is a
  third-party Starlette/httpx deprecation from the existing environment.
- Engine boundary: `StubEngine` and synthetic/local fixtures only.

## Family inventory

| ID | Family | Existing evidence at baseline | Candidate gap or invariant | State |
|---|---|---|---|---|
| CAT-01 | Catalog and registry ingestion | Strict ASCII slug validation; schema-v2 duplicate-key, required-field, enum, source-coordinate, timestamp, sandbox, evidence, and credential-name tests | Versioned 52-case hostile identifier corpus plus registry confusable/future-time/environment and corpus-record path/duplicate/size partitions | VERIFIED |
| PROV-01 | Provenance and source binding | Stub/real classification, sandbox-image provenance, source/receipt tests, snapshot trust tests | Receipt identity is bound before writes; demo, stale, missing, corrupt, and future-dated evidence remain explicit and cannot acquire real/current wording | VERIFIED |
| GRADE-01 | Grade and UNKNOWN semantics | Grade bands, danger/transparency separation, masking, drift-cause precedence, unknown surface comparison, unreadable drift-history diagnostics | Packaged grade/transparency fields are semantically bound; critical caps apply; corrupt newest history is `UNKNOWN` without fallback, while unreadable older history preserves only the readable latest claim | VERIFIED |
| SURF-01 | Public claim parity | API, live web, static generator, badge, README snippet, snapshot, and portability tests exist | Synthetic demo, stale-real, and corrupt-newest scenarios agree across API summary/detail, live HTML, static HTML, badges, and snapshot behavior | VERIFIED |
| AUTH-01 | Scan-trigger and secrets | Public-readonly denial, token-required engine, invalid/valid header paths, stub opt-in, dummy-credential isolation, portability redaction | Domain rejects invalid/duplicate environment names; denied scan authorization runs before engines; corrupt/oversized diagnostics do not echo synthetic secrets | VERIFIED |
| DB-01 | Database reliability | Schema creation/idempotence, additive migration, deterministic latest/history tie breaks, invalid server-row skipping | Duplicate scan-ID constraint failure is atomic and connection recovers; corrupt/oversized newest readback is explicit and never falls back; stored JSON and nested collections are bounded | VERIFIED |
| CLI-01 | CLI and corpus-wide operation | Command exit codes, history limits, drift JSON, per-slug failures, corpus unreadable-row continuation, portability JSON stability | Corpus-wide partial-failure JSON remains parseable/deterministic and content-free; oversized portability and lineage inputs exit fail-closed | VERIFIED |
| PERF-01 | Bounded resource abuse | Network/auth metadata and release-readback paths have body/time bounds | Snapshot, reviewed corpus, evidence-lineage, and portability inputs have pre-parse byte ceilings; snapshot server/finding/tool/string collections have stable limits | VERIFIED |

## Queue

| Item | Source to sink / invariant | Proof before fix | Narrow fix boundary | State | Evidence |
|---|---|---|---|---|---|
| Q-001 | `ServerSource.env_keys` reaches dummy-env and Docker `--env`; only environment-variable names are allowed and duplicates must not create contradictory launch metadata | Focused Pydantic model test with valid controls plus invalid names, confusables, separators, and duplicates | `ServerSource` field validator shared by every ingestion path | VERIFIED | `test_adversarial_trust_boundaries.py` env-key corpus |
| Q-002 | `ScanRecord.server_slug` and `id` reach receipt filenames; receipt server and scan identities must match and neither component may contain a path | Focused receipt test attempted traversal/mismatch and proved no directory write | Domain identifier validation plus receipt identity check before directory creation | VERIFIED | `test_adversarial_trust_boundaries.py` receipt and identifier cases |
| Q-003 | `parse_catalog_snapshot` called `json.loads` before any resource budget | Oversized raw JSON, server/finding/tool collections, and public strings initially passed | Pre-parse byte ceiling and bounded collections | VERIFIED | `test_runtime_snapshot.py`; stable limit reason codes |
| Q-004 | Corrupt newest scan rows crashed API/static/snapshot consumers and could invite older-grade fallback | Valid older row plus corrupt newer row crashed static generation before the repair | Preserve newest-row selection, expose typed unreadable identity, render `UNKNOWN`, block snapshot construction | VERIFIED | `test_adversarial_claim_parity.py::test_corrupt_latest_scan_is_unknown_everywhere_without_older_grade_fallback` |
| Q-005 | Cross-surface claims drifted across API, live HTML, static HTML, badge JSON, and snapshot projection | Demo provenance/staleness fields were absent from API and demo disclosure wording differed | Shared disclosure and public scan payload; product changes only for observed mismatches | VERIFIED | Three scenario tests in `test_adversarial_claim_parity.py` |
| Q-006 | CLI corpus-wide drift must continue deterministically across readable, single-scan, and corrupt histories without leaking corrupt payloads | Existing partial-failure matrix extended with a synthetic secret in corrupt JSON | No CLI mutation needed; repository readback change preserves stable continuation | VERIFIED | `test_cli.py` corpus-wide unreadable-history JSON test |
| Q-007 | SQLite schema migration and record writes must be idempotent and atomic under constraint failures | Synthetic duplicate-ID transaction probe | No repository mutation needed; SQLite transaction behavior already met the invariant | VERIFIED | `test_store.py::test_duplicate_scan_id_is_atomic_and_connection_recovers` |
| Q-008 | Final saturation searches across source, tests, and contracts | Independent source, test-inventory, and contract/documentation searches | Replenished Q-009 through Q-012; final post-fix repeat of all three found no new material safe item | VERIFIED | source/test/contract saturation receipts below |
| Q-009 | Reviewed corpus records and evidence-lineage ledgers accepted path-bearing/duplicate identities or unbounded JSON | Focused traversal, duplicate, and oversized-input tests failed before fixes | Model validators and 1 MiB pre-parse ceilings | VERIFIED | `test_corpus_records.py`; `test_evidence_lineage.py` |
| Q-010 | Portability CLI read arbitrary-size explicit inputs before validation | Oversized synthetic input reached schema diagnostics before the fix | 1 MiB pre-read ceiling with content-free error | VERIFIED | `test_portability.py::test_cli_rejects_oversized_portability_input_without_echoing_content` |
| Q-011 | SQLite source and scan JSON accepted oversized values and validation logging could include rejected content | Oversized but semantically valid source/risk JSON remained readable before the fix | 1 MiB stored-field ceiling, finding/tool count limits, and content-free repository diagnostics | VERIFIED | `test_store.py` oversized source/latest readback cases |
| Q-012 | Timestamp ties and corrupt older history could resurrect a lower-ID latest row or crash static generation / erase a readable latest claim | Corrupt highest-ID tie returned the lower row; corrupt older history made static generation raise | Highest-ID tie disposition plus separate latest-claim and history-UNKNOWN handling | VERIFIED | `test_store.py` tie case; `test_adversarial_claim_parity.py` older-history parity case |

## Dispositions and proof rules

- A missing real-engine, runtime, deployment, scheduler, publication, or human
  receipt is `UNKNOWN`; this campaign does not try to manufacture it.
- A case that requires launching any server, Docker/Colima, network scanning,
  grade publication, external credentials, or MCPAudit is `BLOCKED` and remains
  outside local completion.
- Tests must exercise product-owned boundaries. Pure helper tests are supporting
  evidence only when an integration path is not safely available.
- Cross-surface changes require API, live web, static, badge, and portable
  projection checks before verification.

## Local commit ledger

- `e555de0` — `test: harden adversarial ingestion boundaries`
- `a8ceb92` — `fix: fail closed across stored claim surfaces`
- The documentation/evidence commit contains this ledger; its exact SHA is
  reported in the final task handoff to avoid a self-referential commit hash.

## Gate ledger

- Focused adversarial boundary suite: `93 passed` after initial repairs.
- API/web/static/store/snapshot/CLI affected suite: `129 passed`.
- Runtime snapshot subsystem: `41 passed` after the numeric type narrowing.
- Corpus record promotion/integration subsystem: `28 passed`.
- Evidence-lineage subsystem: `11 passed`.
- Portability subsystem: `90 passed`.
- Full configured pytest gate: `855 passed, 5 skipped, 1 third-party warning`
  after every campaign repair and documentation update.
- Ruff: passed after campaign source changes.
- `generate_web_release_readback_contract.py --check`: deterministic/current.
- `git diff --check`: passed.
- No project type-checker gate is configured. An isolated advisory whole-tree
  mypy run reports 48 pre-existing errors in 14 files; it reports no campaign-
  introduced error. The sole error in a touched file, `catalog/snapshot.py`, is
  present at the base commit and was not widened by this campaign.

## Saturation ledger

1. Source-boundary search covered JSON readers, path/file sinks, latest-history
   selection, authorization/token handling, environment metadata, secrets, and
   `UNKNOWN` projections. It found Q-009, Q-010, and then Q-011 on the first
   repeats; all were repaired red-first. A final repeat is required before Q-008
   can be verified.
2. Test-inventory search mapped hostile input, provenance/staleness/masking,
   authorization, database ordering/atomicity, CLI exits/partial failures,
   secret redaction, and resource limits to executable tests. No uncovered
   listed family remained.
3. Contract/documentation search compared API payload descriptions, badge and
   README snippets, portable references, snapshot claims, and local-only claim
   ceilings. It found stale API shape and resource-limit wording; `README.md`,
   `SPEC.md`, and the lineage/portability docs now match the tested behavior.

After Q-012, all three searches were restarted and repeated against the final
source, tests, and contracts. Source readers/sinks and latest/history selection
were accounted for; the test inventory contained no skip/xfail/TODO marker in
the campaign suites; contract wording and the generated readback contract were
current. No new material safe item was found in any of the three final passes.
