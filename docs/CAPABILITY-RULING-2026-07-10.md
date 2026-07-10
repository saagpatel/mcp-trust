# Capability Ruling — 2026-07-10

**Decision: build grade-drift detection with cause attribution.** The registry
already accumulates the scan history a drift capability needs, already exhibits
real grade movement in that history, and currently cannot explain a single one
of those movements to a consumer. Provenance attestation and registry analytics
are deferred; the drift slice builds the comparison primitive attestation would
reuse.

## What the repo supports today (orientation read, full tree)

- **Append-only scan history.** `scans` is insert-only with an index on
  `(server_slug, scanned_at)` (`store/db.py`). The live `registry.db` holds
  **322 scan rows across 31 servers, up to 14 per server** (2026-06-20 →
  2026-07-04). History is written but never read: `ScanRepository` exposes only
  `latest()` and `latest_all()` — there is no history or comparison query
  anywhere in the codebase.
- **A comparison primitive already persisted per scan.** `evidence_json`
  carries tool names, tool counts, and per-tool input-schema SHA-256 hashes for
  all 31 latest scans (evidence parity complete per HANDOFF). Two scans of the
  same server can be diffed for tool-surface change without re-running
  anything.
- **A standing weekly re-scan lane with zero diffing.**
  `scripts/refresh_and_publish.sh` (launchd, Mon 09:00, armed) re-scans the
  whole corpus and rebuilds the site, but never compares the new scan to the
  previous one. A failed scan silently keeps the previous grade with only a
  log-line WARN — no surfaced freshness delta below the 90-day grey-out in
  `core/governance.py`.
- **Honesty machinery exists for everything except change.** Provenance
  labeling (`core/provenance.py`), staleness grey-out and dispute SLA
  (`core/governance.py`), grade masking (`masked-grades.json`), receipt
  evidence — all shipped. Grade *change over time* is the one public claim the
  registry makes (every deploy can move grades) with no supporting explanation
  anywhere.

## The empirical finding that decides this

> Provenance: the figures in this section were read from the local
> `registry.db` on 2026-07-10. The database is a local artifact by repo policy
> (gitignored, like `receipts/`), so these counts are not verifiable from the
> committed tree; re-derive them with `mcp-trust history <slug>` or direct
> queries against the live registry.

Seven of 31 servers already show more than one distinct grade in their history.
Attribution of those changes, from the data itself:

| Signal | Observed |
|---|---|
| Grade changes coinciding with an engine version bump (2.1.0 → 2.3.0 → 2.4.0) | **7 of 7** |
| Tool-surface (evidence hash) changes across all 31 servers, all history | **0** |

Example: `mcp-archived-aws-kb-retrieval` moved **F → B** on 2026-07-03. Its
declared tool surface was unchanged; the engine version is the input that
moved (per the honesty wording, an unchanged surface is not proof the server
did not change — it is the absence of any observed server-side change). The
registry re-published the new grade
with no record of the movement or its cause. A consumer (or the graded vendor)
who noticed has no answer to "did this server get safer, or did the grading
input change?" For a registry whose product is honest grades, an unexplained
grade movement is a data-quality defect: the weekly lane will now produce a
fresh scan per server per week, so movements become a standing weekly event.

Drift detection here is therefore not speculative monitoring for upstream
change — it is **attribution of grade movement the registry is already
publishing**, with upstream tool-surface change detection included for when it
does appear (three weeks of history is too short to conclude it won't).

## Options weighed

### a. Drift detection — CHOSEN
- **Data support:** complete. History rows, evidence hashes, engine
  name/version per row — every input already persisted.
- **Cost:** low. One new pure `core/` module + one read-only repository method
  + two CLI commands + a refresh-lane hook. No schema change, no engine change,
  no public-surface change in the v-slice.
- **Value:** converts the registry's largest unexplained public behavior
  (grades that move between deploys) into an attributed, queryable record.
  Directly feeds the weekly lane. The tool-surface diff is the same primitive a
  future attestation feature needs.

### b. Provenance attestation (running server vs graded record)
- **Data support:** partial — the graded side (schema hashes) exists, but the
  live side needs a new readback client outside the engine, and the shipped
  MCP server is deliberately snapshot-only/no-network (`mcp_server.py`).
- **Cost:** moderate-high. New live-enumeration machinery, launch/isolation
  posture decisions for local-launch sources, and a design exception to the
  no-network MCP surface — or a CLI-only scope that still needs the client.
- **Verdict: defer.** Zero observed tool-surface change in the corpus today
  means no consumer can yet act on an attestation mismatch. The drift slice
  ships the hash-comparison core; attestation becomes a thinner follow-on when
  surface drift is actually observed in the wild.

### c. Registry analytics / consumable API
- **Data support:** fine, but `/servers` JSON, the baked snapshot, and the
  static site already serve the catalog three ways.
- **Cost:** low, **value: lowest.** 31 servers need no aggregate layer, and no
  consumer is asking for one. Rejected.

## V-slice (finishes this session)

Feature branch `feat/grade-drift`, test-first, all additive:

1. **`src/mcp_trust/core/drift.py`** — pure comparison over two `ScanRecord`s
   → typed `ScanDrift`: grade change, danger-score delta, per-dimension deltas,
   transparency change, engine change, tool-surface delta (added / removed /
   schema-changed tools from evidence hashes), plus an attributed cause:
   - `surface-changed` — evidence hashes differ (the server's declared tool
     surface moved);
   - `engine-changed` — same surface, different engine version (re-evaluation,
     not server change);
   - `score-moved` — same surface, same engine (scan-environment variance);
   - `undetermined` — movement with no comparable surface and the same engine
     (the registry names what it cannot attribute rather than guessing);
   - `no-change`.
   Honest-wording rule inherited from the review guidance: missing evidence on
   either side is reported as *unknown surface comparison*, never as "no
   change".
2. **`store/repository.py`** — `ScanRepository.history(slug, limit)` (read-only
   addition; contract files `core/models.py`, `engine/base.py` untouched).
3. **CLI** — `mcp-trust history <slug>` (grade/engine/scanned-at timeline) and
   `mcp-trust drift [<slug>] [--json]` (latest vs previous, corpus-wide when no
   slug; `--json` for machine consumption by the refresh lane).
4. **Refresh lane** — `refresh_and_publish.sh` runs `mcp-trust drift --json`
   after the re-scan loop and archives the report next to receipts, so every
   weekly run leaves an attributed change record instead of a silent overwrite.
5. **Tests** — `tests/test_drift.py` (attribution matrix incl. missing-evidence
   honesty), history round-trip in `test_store.py`, CLI coverage in
   `test_cli.py`.

**Verification (inherited from AGENTS.md / HANDOFF):**
`uv run --all-extras --frozen pytest -q` and
`uv run --all-extras --frozen ruff check src scripts tests`.

## Deploy-pipeline implications

None in the v-slice: the public snapshot, site, badges, and MCP tools are
untouched, so the Monday 09:00 auto-deploy lane (currently deploy-opt-in and
off) is unaffected. The natural follow-on — surfacing "grade changed on <date>,
cause: <attribution>" on server detail pages and in `check_server` — **does**
touch the snapshot schema, site generator, and deployed payload, and should go
through the usual masked/provenance wording review before any deploy. The
refresh-script edit (step 4) changes weekly-lane behavior additively (one extra
read-only report); it does not alter scan, build, or deploy steps.

## Out of scope (named, not silently cut)

Public site/snapshot drift surfacing, MCP `check_server` history fields,
attestation of running servers, drift-triggered re-grade masking, and any
grading-band change. Each is a follow-on ruling once the attributed record
exists.
