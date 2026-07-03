# MCP Trust — Session Handoff

_Last updated: 2026-07-02. Repo: `main` tracking `origin/main`; working tree has
in-flight evidence/corpus-builder changes plus regenerated local scan artifacts._

## Live / Local State

- Public site remains `https://mcp-trust.vercel.app`; no deploy was run in this
  lane.
- Local launch catalog now has 15 seeded servers and 15 latest real `mcpaudit`
  scans in `./registry.db`.
- Launch validation passes:
  `python scripts/validate_launch_state.py --db ./registry.db --receipts-dir ./receipts`.
- Latest grade distribution: A=1, B=3, C=3, D=3, F=5.
- Transparency distribution: high=3, low=12.
- Evidence parity is complete for the launch corpus: all 15 latest scan rows have
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

## Temp Live-Scan Batch

The first approved no-auth Registry live-scan batch was rerun in a temp lane:

- DB: `./tmp/registry-live-batch-20260628.db`
- Receipts: `./tmp/live-batch-receipts-20260702-evidence/`
- Approval ref: `first-live-corpus-batch-20260628-evidence-rerun`

Those 8 candidates are not in the public catalog. Treat them as reviewed temp
evidence until a separate corpus-integration decision is made.

## Registry Corpus Decision

The official MCP Registry is a discovery, provenance, and staleness feed only.
It does not declare actual runtime tools, prompts, resources, input schemas, or
annotations. Do not infer danger grades from Registry metadata. Public grades
must come from controlled live readback evidence plus explicit receipt caveats.

The next integration step should use `PublicCorpusRecord` / `CorpusRecordSet`
rather than editing `seed_servers.json` directly. Keep the 8 temp live-scan
candidates non-public until each record has explicit source review, scan mode,
approval reference, receipt evidence, and caveats.

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

Current promotion review evidence is local-only under `tmp/`:

- `tmp/live-batch-promotion-review-20260702.md`
- recommended first promotion cohort:
  `com.mythsensus/mythsensus-mcp` and
  `eu.regulatoryai/sovereign-ai-act-mcp`

The next corpus expansion should stay small and approval-gated:

- no-auth sandboxed entries first;
- exact package versions;
- public source/provenance;
- no required secrets, OAuth, host mounts, live backing services, or runtime
  egress;
- diverse but boring capability coverage.

## Current Verification

Last verified after the full evidence-parity rescan:

```bash
python scripts/validate_launch_state.py --db ./registry.db --receipts-dir ./receipts
uv run --all-extras --frozen pytest -q
uv run --all-extras --frozen ruff check src scripts tests
```

Results:

- launch-state validation passed;
- `194 passed, 2 skipped`;
- Ruff passed.

## Next Recommended Move

Review the diff as one cohesive change set, then decide whether to commit the
evidence model + discovery-only corpus builder. After that, decide whether the
8 temp live-batch candidates become a public experimental corpus lane or remain
local evidence. Do not deploy or publish until that catalog-integration decision
is made.
