# MCP Trust — Session Handoff

_Last updated: 2026-07-03 (engine 2.4.0 regrade). Repo: `main` tracking
`origin/main`; working tree has regenerated local scan artifacts._

## Live / Local State

- Public site `https://mcp-trust.vercel.app` now serves the **25-server** static
  catalog on engine `mcpaudit 2.4.0` (locked floor `>=2.4.0,<3`; full-corpus
  regrade 2026-07-03 was grade-neutral — warnings-as-data is additive, detection
  unchanged; 25/25 rescanned, zero WARNs, distribution identical). The prior
  deploy `dpl_4fh9WYwnwsb4PAYQ2PKBjirKLzb2` (2026-07-03) followed the batch-3
  integration: `com.microsoft/powerbi-modeling-mcp` 0.5.0-beta.11 (F, low
  transparency; first-party Microsoft scope, prerelease caveat) and
  `io.github.nickjlamb/redacta-mcp` 1.2.1 (C, low transparency),
  operator-approved 2026-07-03 (promotion ref
  `batch3-live-corpus-promotion-20260703`, review evidence
  `tmp/batch3-promotion-review-20260703.md`). Four batch-3 candidates failed
  closed with documented evidence (gk-cli and black-duck require runtime
  downloads; agentmetal and mcp-safeguard are broken as published) — no public
  entries, no grades; evidence stays local under `tmp/`.
- Purpose-built image pins: the 8 live-batch servers pin
  `mcp-trust-live-batch:20260628`; the 2 batch-3 servers pin
  `mcp-trust-batch3:20260703` (node:24-slim base, `HOME=/scan` for the
  read-only sandbox fs, .NET invariant globalization). The whole-corpus refresh
  scans 25/25 under the corpus default env — no silent stale grades.
- Local launch catalog now has 25 seeded servers and 25 latest real `mcpaudit`
  scans in `./registry.db`.
- Launch validation passes:
  `python scripts/validate_launch_state.py --db ./registry.db --receipts-dir ./receipts`.
- Latest grade distribution: A=1, B=8, C=6, D=4, F=6.
- Transparency distribution: high=3, low=22.
- Evidence parity is complete for the launch corpus: all latest scan rows have
  `evidence_json`, and latest receipts include public-safe tool readback
  evidence.

## What Changed In This Lane

- Added public-safe live-readback evidence plumbing:
  tool names, tool counts, schema SHA-256 hashes, prompt/resource counts, and
  annotation flags.
- Persisted evidence in SQLite via `scans.evidence_json`, with migration support
  for existing DBs.
- Included evidence in scan records, receipts, API/site/snapshot projections, and
  tests.
- Added the discovery-only Registry corpus-builder slice:
  `CORPUS-BUILDER.md`, `src/mcp_trust/corpus/registry.py`,
  `scripts/plan_registry_corpus.py`, and `tests/test_registry_corpus_plan.py`.
- Added reviewed corpus record models in `src/mcp_trust/corpus/records.py`.
  This is the bridge from discovery manifests to public corpus integration:
  proposed records can exist without receipts, but published records require
  receipt-backed controlled live-scan evidence.
- Ran the credentialed archived seed batch using dummy credentials inside the
  Docker sandbox with runtime network disabled.
- Reran the full 15-server launch corpus with approval ref
  `launch-corpus-evidence-parity-20260702`.
- Integrated the first two reviewed Registry-derived no-auth sandboxed corpus
  entries into the local seed catalog, registry DB, receipts, baked snapshot,
  and generated site:
  `com.mythsensus/mythsensus-mcp` and
  `eu.regulatoryai/sovereign-ai-act-mcp`.
- Integrated the next two source-mapped Registry-derived no-auth sandboxed
  corpus entries into the local seed catalog, registry DB, receipts, baked
  snapshot, and generated site:
  `com.pulsemcp/image-diff` and
  `com.seanwinslow/intent-engineering`.

## Important Evidence

Latest launch corpus receipts are under `./receipts/` and point back to the
latest DB rows. Receipt caveats explicitly state that automated scan output is
not an endorsement, danger grade and transparency are separate signals, low
transparency means "cannot verify safe," and network-off sandboxing can suppress
behavior that requires live egress.

Credentialed archived scans used:

```bash
MCP_TRUST_SCAN_CREDENTIALS=dummy
MCP_TRUST_SANDBOX=docker
MCP_TRUST_SANDBOX_NETWORK=none
MCP_TRUST_SANDBOX_IMAGE=mcp-trust-scan:corpus-2026-06-28
```

Dummy credential values were injected only inside the network-off container and
are not persisted. Receipts record env key names and the dummy-credential caveat,
not values.

## Registry Corpus Decision

The official MCP Registry is a discovery, provenance, and staleness feed only.
It does not declare actual runtime tools, prompts, resources, input schemas, or
annotations. Do not infer danger grades from Registry metadata. Public grades
must come from controlled live readback evidence plus explicit receipt caveats.

The original approved no-auth Registry live-scan batch was rerun in a temp lane:

- DB: `./tmp/registry-live-batch-20260628.db`
- Receipts: `./tmp/live-batch-receipts-20260702-evidence/`
- Approval ref: `first-live-corpus-batch-20260628-evidence-rerun`

All 8 candidates from that lane are now integrated into the local public catalog
evidence path. The last 4 (`ai.adeu/adeu`, `ai.ravenmcp/raven-mcp`,
`com.kage-core/kage`, and `com.kogcat/kogcat-mcp`) were promoted after explicit
operator approval on 2026-07-03; no Registry-derived candidates remain deferred.

Future integration steps should use `PublicCorpusRecord` / `CorpusRecordSet`
rather than editing `seed_servers.json` directly. Keep any newly discovered
candidate non-public until it has explicit source review, scan mode, approval
reference, receipt evidence, and public caveats.

`scripts/draft_corpus_records.py` now creates the review-only bridge artifact
from the temp scan lane. Current generated draft:

- `tmp/live-batch-corpus-records-20260702.json`
- 8 records, all `scanned-temp`
- mode: `no-auth-sandboxed`
- receipt-backed grade summary: C=2, F=6
- published records: 0

`scripts/promote_corpus_records.py` now creates a guarded promotion artifact from
reviewed corpus records. It promotes only explicitly named receipt-backed
`scanned-temp` records and writes a new JSON file. It does not edit
`seed_servers.json`, update `registry.db`, rebuild `catalog_snapshot.json`,
deploy, publish badges, or certify a server.

Earlier promotion review evidence is local-only under `tmp/`:

- `tmp/live-batch-promotion-review-20260702.md`
- recommended first promotion cohort:
  `com.mythsensus/mythsensus-mcp` and
  `eu.regulatoryai/sovereign-ai-act-mcp`
- `tmp/live-batch-published-review-20260702.json`
  marks those two records `published` inside a review artifact only; the other
  six records are `deferred`.

`scripts/plan_corpus_catalog_integration.py` now creates the next no-write
integration plan from that reviewed promotion artifact. It can read the temp DB
for launch source specs, compare against `seed_servers.json`, and list the seed,
scan, receipt, snapshot, site, deploy, and badge approvals still required. It
does not mutate any of those surfaces.

The first approved four-entry integration was applied locally:

- `src/mcp_trust/catalog/seed_servers.json` contains 19 entries.
- `./registry.db` contains latest `mcpaudit` scan rows for all 19 seeded slugs.
- `./receipts/` contains matching latest receipts for all 19 seeded slugs.
- `src/mcp_trust/catalog_snapshot.json` contains 19 real scanned entries.
- `site/` was rebuilt locally for 19 servers.
- The 19-server site was deployed to Vercel production as
  `dpl_ErxnVWYH1d9T4pHAqNKmj7Y65TNc`.

The deferred-cohort integration has also been applied and deployed:

- `src/mcp_trust/catalog/seed_servers.json` contains 23 entries.
- `./registry.db` contains latest `mcpaudit` scan rows for all 23 seeded slugs.
- `./receipts/` contains matching latest receipts for all 23 seeded slugs.
- `src/mcp_trust/catalog_snapshot.json` contains 23 real scanned entries.
- `site/` was rebuilt locally for 23 servers.
- The 23-server site was deployed to Vercel production as
  `dpl_F9y4uvb7sfESGS8Daq4RFfhMQeNS`.

The next corpus expansion should stay small and approval-gated:

- no-auth sandboxed entries first;
- exact package versions;
- public source/provenance;
- no required secrets, OAuth, host mounts, live backing services, or runtime
  egress;
- diverse but boring capability coverage.

`CORPUS-DEFERRED-REVIEW.md` records the source-review and approval basis for the
four deferred-cohort entries. For Kage and Kogcat, keep the no-tag/no-package-
source provenance caveats visible in public catalog descriptions and receipt
caveats; do not collapse them to a normal homepage-only source claim.

## Current Verification

Last verified after the 23-server deferred-cohort catalog integration:

```bash
python scripts/validate_launch_state.py --db ./registry.db --receipts-dir ./receipts
uv run --all-extras --frozen pytest -q
uv run --all-extras --frozen ruff check src scripts tests
```

Results:

- launch-state validation passed;
- `214 passed, 2 skipped`;
- Ruff passed.

## Next Recommended Move

Monitor the 23-server production catalog and keep the weekly freshness lane
ready. The repo-owned freshness defaults use the current production base URL and
`mcp-trust-scan:corpus-2026-06-28`, with auto-deploy still opt-in. The 8
Registry-derived live-batch servers are baked only into
`mcp-trust-live-batch:20260628`, so preserve their per-server `sandbox_image`
pins during refresh or catalog edits.

## Local Scheduler Checkpoint

As of 2026-07-03, the weekly LaunchAgent is installed locally at
`~/Library/LaunchAgents/com.d.mcp-trust-refresh.plist` and loaded under
`launchctl`:

- schedule: Monday 09:00 local time;
- state at install verification: loaded, not running, zero runs;
- working directory: `/Users/d/Projects/mcp-trust`;
- base URL: `https://mcp-trust.vercel.app`;
- auto-deploy: off (`MCP_TRUST_AUTO_DEPLOY` is not set).

No manual refresh run was started during installation verification.
