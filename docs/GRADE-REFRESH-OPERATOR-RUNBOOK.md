# Grade-refresh operator runbook

## 0. Dependency materialization and image qualification

On a clean isolated worktree, and only with explicit registry/build approval,
recreate the ignored offline bundles from the committed locks:

```bash
uv run --frozen python scripts/prepare_refresh_dependencies.py --materialize
uv run --frozen python scripts/prepare_basic_memory_dependencies.py materialize
```

The standard preparer executes registry clients only and disables package
lifecycle code. The dedicated `basic-memory` preparer rebuilds its two exact
source-only dependencies twice in network-none sandboxes, then downloads only
hash-locked binary wheels. Both refuse a bundle whose digest differs from its
tracked descriptor. Then run the exact network-none, no-cache double builds:

```bash
uv run --frozen python scripts/qualify_refresh_images.py
```

Every cohort must produce two identical image IDs and a receipt that passes
readback. Existing or expired qualification receipts are not overwritten;
requalification is a reviewed source revision, not an in-place refresh.

## 1. Inventory and preflight (no server execution)

```bash
uv run --frozen --extra engine python scripts/grade_refresh.py inventory \
  --out dist/grade-refresh/inventory.json

uv run --frozen --extra engine python scripts/grade_refresh.py preflight \
  --repo-root "$PWD" \
  --out dist/grade-refresh/preflight.json
```

Stop unless the receipt says `status: READY` and
`safe_to_execute_catalog: true`. Missing image tags, missing immutable IDs,
missing deterministic build source, remote Docker authority, missing engine
runtime, or incomplete sandbox controls are terminal preflight blockers. Do
not pull, rebuild, retag, or substitute an image without explicit approval.
Blocked catalog rows remain excluded; do not widen execution to make the
preflight green.

## 2. Deterministic fixtures

```bash
uv run --frozen --extra dev python scripts/grade_refresh.py fixture-repeat \
  --out dist/grade-refresh/fixture-repeatability.json
```

This runs no third-party process. Both digests must match. It does not qualify
Docker or a real server.

## 3. Controlled sandbox execution

Only after `READY`, run the repository-approved, exact pinned target. First use
the smallest reference target. Never use host execution, live credentials,
broad egress, a backing service, or an unreviewed image. Preserve the preflight
receipt and actual image ID in the scan receipt.

If any row is blocked, record it and continue independent rows only when their
dependencies and exact images are separately READY. Do not retain an old grade
as fresh.

## 4. Candidate creation and verification

```bash
uv run --frozen --extra engine python scripts/refresh_candidate.py create \
  --db ./registry.db \
  --out-dir ./dist/refresh-candidates \
  --policy ./src/mcp_trust/catalog/refresh_policy.json \
  --qualification-receipt ./dist/grade-refresh/preflight.json

uv run --frozen --extra engine python scripts/refresh_candidate.py verify \
  ./dist/refresh-candidates/<candidate>
```

Candidate creation loads the source-bound policy before Docker preflight. Only
`scannable` rows enter preflight or the scanner. A `blocked` row is emitted as
`blocked-policy`, exposes no fresh grade, preserves any prior timestamp only as
historical context, and keeps the candidate partial/non-publishable. A nonzero
verify exit is therefore the expected honest result while any row is blocked.

The candidate is local and immutable. Its manifest binds the exact READY
preflight receipt, source and policy digests, tool versions, image build
provenance, and execution-time image IDs. Creation or verification does not
approve, publish, deploy, or schedule it.

## 5. Triage and operator package

```bash
uv run --frozen --extra dev python scripts/grade_refresh.py triage \
  --candidate ./dist/refresh-candidates/<candidate> \
  --repeat-candidate ./dist/refresh-candidates/<repeat-candidate> \
  --preflight ./dist/grade-refresh/preflight.json \
  --repeatability ./dist/grade-refresh/fixture-repeatability.json \
  --out ./dist/grade-refresh/triage.json

uv run --frozen --extra dev python scripts/grade_refresh.py package \
  --candidate ./dist/refresh-candidates/<candidate> \
  --repeat-candidate ./dist/refresh-candidates/<repeat-candidate> \
  --preflight ./dist/grade-refresh/preflight.json \
  --repeatability ./dist/grade-refresh/fixture-repeatability.json \
  --triage ./dist/grade-refresh/triage.json \
  --task-id <codex-task-id> \
  --out-dir ./dist/grade-refresh/operator-package
```

Review Critical, High, Medium, then Low. The triage normalizes the two
independently verified controlled candidates while excluding receipt IDs and
timestamps; every grade/evidence inconsistency, upgrade, large change, new
mask, provenance gap, or policy change requires disposition.

Review the neutral disposition for every intentionally masked row and build the
deterministic publication decision packet:

```bash
uv run --frozen --extra dev python scripts/grade_refresh.py publication-review \
  --candidate ./dist/refresh-candidates/<candidate> \
  --repeat-candidate ./dist/refresh-candidates/<repeat-candidate> \
  --preflight ./dist/grade-refresh/preflight.json \
  --repeatability ./dist/grade-refresh/fixture-repeatability.json \
  --triage ./dist/grade-refresh/triage.json \
  --accepted-review ./src/mcp_trust/catalog/accepted_publication_review_v38.json \
  --out ./dist/grade-refresh/publication-review.json \
  --markdown-out ./dist/grade-refresh/publication-review.md \
  --state-card-out ./dist/grade-refresh/publication-review-state-card.json
```

The tracked V2 disposition policy binds the exact V38 proposal receipt and the
separate receipt-bound V38 acceptance artifact. V20/V33 evidence remains lineage
only and is not transferred. Backing-service and archived/unsupported rows keep
their specific limitations; all eight entries remain masked. The packet verifies
the accepted dispositions and exact V37 source, policy, masking, candidate,
repeatability, triage, image, and tool bindings; preserves the historical
baseline as `UNKNOWN`; and returns `NO_GO`. Current-source acceptance is not
publication or deployment authority and does not prove production freshness,
safety, endorsement, backing-service behavior, or credentialed behavior.

## 6. Build the immutable local site candidate

Use only the exact verified refresh candidate, bundled V38 proposal receipt, and
accepted disposition artifact. The builder renders in a fresh sibling temporary
directory, fixes the rendering time to the candidate timestamp, writes a
canonical per-file manifest,
and atomically finalizes the output. Run it only from the clean locally landed
commit: the manifest binds that exact Git revision and a SHA-256 projection of
its complete Git tree. A dirty or untracked implementation fails closed:

```bash
uv run --frozen python scripts/build_site_candidate.py \
  --candidate ./dist/refresh-candidates/<candidate> \
  --out ./dist/site-candidates/<name>
uv run --frozen python scripts/build_site_candidate.py \
  --verify ./dist/site-candidates/<name>
uv run --frozen python scripts/build_site_candidate.py \
  --readback-manifest ./dist/site-candidates/<name> \
  > ./dist/site-candidates/<name>-exact-readback.json
```

New builds emit `McpTrustSiteCandidateV2` from `RefreshCandidateV2`. V1 inputs
remain reviewable history but are not publication-eligible. V2 binds the static
historical freshness mode, 90-day horizon, state counts, earliest expiry,
semantic projection digests, and exact source/tool/input lineage.

The candidate receipt binds an exact body SHA-256 assertion for every generated
public route, including the expected 404 body. The extracted manifest is a
credential-free GET-only readback input; it is not publication or deployment
authority. A future approved preview and production lane must run it through
`scripts/web_release_readback.py` and require every route to match before making
a source-adoption claim.

With the current policy this succeeds only as
`REVIEW_ONLY_ACCEPTED_FOR_SOURCE_REVIEW`; both authority booleans remain
false. Rollback evidence can be supplied through exactly one of two paths:

- `--rollback-candidate` accepts only a retained, independently verified,
  deployment-qualified site artifact. A pending, accepted-review-only, or
  otherwise non-deployable prior artifact is rejected.
- `--provider-rollback-binding` plus
  `--provider-rollback-binding-receipt` accepts an exact, current,
  receipt-bound `McpTrustProviderNativeRollbackBindingV1` base case for the
  first following same-project publication. The contract binds the alias,
  deployment ID, immutable URL, project/team, provider source revision/tree,
  public-tree witness, provenance receipts, freshness, invalidation
  conditions, and explicit `UNKNOWN` fields.

The provider-native path emits
`PROVIDER_NATIVE_FIRST_PUBLICATION_REVIEW_BOUND`, but it remains review-only.
It does not set either authority boolean, does not prove exercised rollback,
and adds a mandatory pre-publication provider-revalidation and publication-
approval gate. The two rollback paths are mutually exclusive. If neither is
supplied, rollback stays `UNKNOWN` and remains an additional publication
block. No publication promotion or provider invocation is enabled by this
builder. Repeat the build to a second new path and require byte-identical
output.
Raw `build_site.py --db` output is a development preview and is never a
deployment-qualified artifact.

## 7. Publication gate

Stop. Publication, Vercel deployment, scheduler enablement, and outreach require
separate explicit approval. Use the package's `HumanGateResumeCapsuleV1.json`
for the chat gate. Re-read the live public route separately; local equivalence
does not prove production uptake.

## 8. Rollback preparation

Before any future publication retain the exact prior deployment identifier,
source revision, site artifact digest, snapshot digest, masking digest, and
readback receipt. The operator package contains the rollback sequence. It does
not authorize provider mutation.
