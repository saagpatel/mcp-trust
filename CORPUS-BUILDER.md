# MCP Trust Live-Scan Corpus Builder

This is the first discovery-only contract for growing the public MCP Trust
catalog without confusing metadata for scan evidence.

## Boundary

The official MCP Registry is a discovery and staleness feed. It can tell us a
server's registry name, package/remotes, source links, version metadata, env key
names, and status. It does not declare the actual runtime tools, prompts,
resources, input schemas, or annotations. Those surfaces are negotiated only
after connecting to an MCP server.

Therefore:

- Registry metadata can create **candidate manifests**.
- Registry metadata can create **freshness/provenance caveats**.
- Registry metadata cannot create an A-F danger grade.
- Registry metadata cannot prove a server is safe, malicious, read-only, or
  fully transparent.

MCP Trust owns corpus selection, dedupe, freshness, public grades, and public
receipts. MCPAudit owns scanner mechanics and tool-surface analysis. Trust
Receipt Generator is the receipt-model reference for limitation-forward public
evidence; it is not the scanner.

## Dry-Run Manifest Path

Use `scripts/plan_registry_corpus.py` with a saved Registry API response:

```bash
uv run python scripts/plan_registry_corpus.py \
  --input registry-servers.json \
  --limit 25 \
  --format json
```

The script reads local JSON and writes the manifest to stdout. It does not fetch
the Registry, scan servers, install packages, launch processes, authenticate,
write the catalog, edit `seed_servers.json`, or assign danger grades.

Accepted input shapes:

- `{"servers": [...]}` from the Registry list API.
- `{"server": {...}}` from a detail-style wrapper.
- A plain JSON list of server objects.

## Candidate Modes

`no-auth-sandboxed`
: Package-backed server with an exact package version and no required secret env
  key names. This is the only mode eligible for the first live batch by default.

`credentialed-sandboxed`
: Package-backed server that declares required secret env key names. It needs a
  separate dummy/scoped credential policy before live scanning.

`networked-sandboxed`
: Package-backed server without an exact package version. It may need registry
  resolution or network at scan/build time, so it is not a first-batch default.

`remote-networked`
: Remote MCP endpoint. It requires endpoint-specific readback limits, auth-mode
  handling, and non-invasive rate limits before any scan.

`package-only`
: Metadata/provenance-only lane for deprecated, deleted, non-latest, incomplete,
  or otherwise non-runnable entries. It can support freshness/source caveats, not
  danger grades.

## Dedupe Keys

The manifest records multiple keys because the same server can appear through
different registry rows or install paths:

- `registry:<name>:<version>`
- `package:<registryType>:<identifier>:<version>`
- `remote:<normalized-url>`
- `repo:<normalized-url>`

Candidate review should merge rows that share package, remote, or repository
identity before adding public catalog slugs.

## Freshness

Freshness is metadata-only:

- `fresh`: updated or published within 30 days.
- `aging`: 31-180 days.
- `stale`: older than 180 days.
- `deprecated` / `deleted`: explicit registry status.
- `unknown`: no usable timestamp.

A scan also becomes stale when the package/source/registry metadata changes
after the latest receipt, or when the scan age exceeds the operator-approved
rescan interval.

## First Batch Selection

The first expansion batch should be small and boring on purpose:

- Start with at most 25 live-scan candidates.
- Select only `no-auth-sandboxed` entries by default.
- Require active latest Registry status when that metadata exists.
- Prefer exact package versions and public repository/source references.
- Exclude required or optional secret key names, OAuth flows, remote endpoint
  metadata, live backing services, host filesystem mounts, destructive fixtures,
  and arbitrary network egress.
- Keep capability diversity, but do not chase breadth at the expense of scan
  controls.

## Receipt Evidence

Public receipts for live-scanned entries should include:

- Registry identity, package/remotes, source repository, and dedupe keys.
- Scan mode and approval reference.
- MCPAudit version and mcp-trust git ref.
- Sandbox profile: image, network mode, mounts, user, caps, CPU/memory/PID
  limits.
- Tool readback summary: tool names, schema hashes, prompt/resource counts, and
  annotation coverage.
- Danger grade, transparency, risk dimensions, findings, and caveats.
- Package/source metadata and freshness state.

Receipts must exclude credential values, raw token-bearing configs, private
paths, arbitrary tool-call outputs, private prompts, source snippets, raw
operator logs, and claims of certification.

## Reviewed Corpus Records

Candidate manifests are not public catalog records. The reviewed bridge is
`mcp_trust.corpus.records`:

- `PublicCorpusRecord` stores a reviewed candidate identity, exact package/source
  reference, recommended scan mode, freshness state, dedupe keys, approval
  notes, and optional receipt evidence.
- `ReceiptEvidenceRef` is the only place a grade can enter this layer. It
  requires a receipt reference, approval ref, scan mode, scanned timestamp,
  grade, transparency, tool count, and sandbox metadata.
- `CorpusRecordSet` is a versioned collection for operator review or future
  static publishing.
- `summarize_corpus_records()` gives an operator summary without reading raw
  receipt contents or inventing grades.

Safety invariants:

- A record can be `proposed` or `approved-for-scan` without a receipt.
- A `published` record must have receipt-backed scan evidence.
- Receipt scan mode must match the reviewed recommended mode.
- No-auth sandboxed records require an exact package version.
- Registry metadata alone must never populate grade, transparency, tool count,
  schema hashes, or findings.

Use `scripts/draft_corpus_records.py` to convert an already-approved isolated
temp scan lane into a review-only record set:

```bash
uv run python scripts/draft_corpus_records.py \
  --db tmp/registry-live-batch-20260628.db \
  --receipts-dir tmp/live-batch-receipts-20260702-evidence \
  --out tmp/live-batch-corpus-records-20260702.json
```

This writes only the requested JSON artifact and prints an operator summary. It
does not scan, install, authenticate, edit `seed_servers.json`, update
`registry.db`, publish records, or deploy. The output remains temp evidence
until an explicit promotion decision changes record statuses and integrates a
public catalog path.

Use `scripts/promote_corpus_records.py` only after that explicit review decision
exists. It promotes named, receipt-backed `scanned-temp` records into another
review-only JSON artifact:

```bash
uv run python scripts/promote_corpus_records.py \
  --input tmp/live-batch-corpus-records-20260702.json \
  --promote com-mythsensus-mythsensus-mcp-0-2-1 \
  --promote eu-regulatoryai-sovereign-ai-act-mcp-1-2-0 \
  --promotion-ref first-live-corpus-promotion-review-20260702 \
  --defer-unpromoted \
  --out tmp/live-batch-published-review-20260702.json
```

This still does not edit `seed_servers.json`, update `registry.db`, rebuild
`catalog_snapshot.json`, deploy, publish badges, or claim certification. It is
the last review artifact before a separately approved catalog integration.

## Approval Gate

Moving from candidate manifest to live scans requires a concrete approved batch:

- final slugs and display names;
- source specs and env key names only;
- sandbox image/build plan;
- fixture directories and no-host-mount proof;
- network policy, if any;
- receipt fields and public caveats;
- verification commands and expected outputs.

## Current Local Evidence State

As of 2026-07-02, the local launch corpus has evidence parity:

- `./registry.db` contains 15 seeded servers.
- The latest row for each seeded server is a real `mcpaudit` scan.
- Each latest scan has `evidence_json`.
- `./receipts/` contains matching latest receipts for all 15 rows.
- Launch validation passes with:

```bash
python scripts/validate_launch_state.py --db ./registry.db --receipts-dir ./receipts
```

The evidence-parity rescan used approval ref
`launch-corpus-evidence-parity-20260702`, Docker sandboxing, runtime network
disabled, and the image `mcp-trust-scan:corpus-2026-06-28`.

The first 8 Registry-derived no-auth candidates remain a temp reviewed evidence
lane, not public catalog records:

- DB: `./tmp/registry-live-batch-20260628.db`
- Receipts: `./tmp/live-batch-receipts-20260702-evidence/`
- Approval ref: `first-live-corpus-batch-20260628-evidence-rerun`

Do not copy those candidates into the public catalog, assign public meaning, or
publish their grades until a separate integration decision is approved.
