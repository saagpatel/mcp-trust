# Grade-refresh operator runbook

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
  --qualification-receipt ./dist/grade-refresh/preflight.json

uv run --frozen --extra engine python scripts/refresh_candidate.py verify \
  ./dist/refresh-candidates/<candidate>
```

The candidate is local and immutable. Its manifest binds the exact READY
preflight receipt, source and policy digests, tool versions, image build
provenance, and execution-time image IDs. Creation or verification does not
approve, publish, deploy, or schedule it.

## 5. Triage and operator package

```bash
uv run --frozen --extra dev python scripts/grade_refresh.py triage \
  --candidate ./dist/refresh-candidates/<candidate> \
  --preflight ./dist/grade-refresh/preflight.json \
  --repeatability ./dist/grade-refresh/fixture-repeatability.json \
  --out ./dist/grade-refresh/triage.json

uv run --frozen --extra dev python scripts/grade_refresh.py package \
  --preflight ./dist/grade-refresh/preflight.json \
  --repeatability ./dist/grade-refresh/fixture-repeatability.json \
  --triage ./dist/grade-refresh/triage.json \
  --task-id <codex-task-id> \
  --out-dir ./dist/grade-refresh/operator-package
```

Review Critical, High, Medium, then Low. Every upgrade, large change, new mask,
repeat inconsistency, provenance gap, or policy change requires disposition.

## 6. Publication gate

Stop. Publication, Vercel deployment, scheduler enablement, and outreach require
separate explicit approval. Use the package's `HumanGateResumeCapsuleV1.json`
for the chat gate. Re-read the live public route separately; local equivalence
does not prove production uptake.

## 7. Rollback preparation

Before any future publication retain the exact prior deployment identifier,
source revision, site artifact digest, snapshot digest, masking digest, and
readback receipt. The operator package contains the rollback sequence. It does
not authorize provider mutation.
