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
tracked descriptor. Descriptor, Dockerfile, manifest, and lock containment and
source-policy validation happens before any Docker or package-manager command;
the locally built preparation image is executed only by its inspected immutable
image ID. Then run the exact network-none, no-cache double builds:

```bash
: "${MCP_TRUST_QUALIFICATION_RECEIPT_SET:?set a new reviewed task-owned receipt-set name}"
uv run --frozen python scripts/grade_refresh.py host-capacity \
  --anchor "$PWD" \
  --out dist/grade-refresh/host-capacity.json
for cohort in reference live-batch batch3 batch4 basic-memory; do
  uv run --frozen python scripts/grade_refresh.py qualification-capacity \
    --anchor "$PWD" \
    --operation qualification \
    --receipt-set "${MCP_TRUST_QUALIFICATION_RECEIPT_SET}" \
    --cohort "$cohort" \
    --out "dist/grade-refresh/qualification-capacity-$cohort.json"
  uv run --frozen python scripts/qualify_refresh_images.py \
    --cohort "$cohort" \
    --host-capacity "dist/grade-refresh/qualification-capacity-$cohort.json" \
    --receipt-set "${MCP_TRUST_QUALIFICATION_RECEIPT_SET}"
done
```

Every cohort must produce two identical image IDs and a receipt that passes
readback. Existing or expired qualification receipts are not overwritten;
requalification is a reviewed source revision, not an in-place refresh.
The generic preflight capacity receipt above does not authorize qualification.
For each cohort, the qualifier requires a distinct wrapper binding one exact
host-capacity receipt to the set name, cohort, and `qualification` operation. It
revalidates its
integrity, 120-second freshness, filesystem-device binding, 5 GiB floor, and
less-than-100-percent policy immediately before every Docker or Buildx
subprocess. It never creates, refreshes, or replaces that receipt. A long build
may outlive the receipt; the next Docker or Buildx call then fails closed,
including any Docker-side tag inspection, removal, or restoration. Filesystem
OCI outputs are still removed, no qualification receipt is emitted, and any
remaining Docker-side cleanup is `UNKNOWN`. A pessimistic immutable attempt
intent exists before the first Docker mutation and blocks retry of that cohort.
Do not infer that another cohort remained admitted and do not reuse any scoped
capacity receipt.

After separately authorizing cleanup, bind a new two-reading receipt to the
exact interrupted cohort and run only its cleanup mode:

```bash
cohort=reference # replace with the one exact unresolved cohort
uv run --frozen python scripts/grade_refresh.py qualification-capacity \
  --anchor "$PWD" \
  --operation cleanup \
  --receipt-set "${MCP_TRUST_QUALIFICATION_RECEIPT_SET}" \
  --cohort "$cohort" \
  --out "dist/grade-refresh/cleanup-capacity-$cohort.json"
uv run --frozen python scripts/qualify_refresh_images.py \
  --cleanup-cohort "$cohort" \
  --host-capacity "dist/grade-refresh/cleanup-capacity-$cohort.json" \
  --receipt-set "${MCP_TRUST_QUALIFICATION_RECEIPT_SET}"
```

Cleanup is exact-intent-only: it removes the recorded temporary tag and OCI
outputs plus any recorded validation receipt and digest-bound tool snapshot,
re-reads the final tag, and appends a cleanup completion receipt. Cleanup never
rewrites the final tag: the current value must be either the recorded baseline
or the exact task-owned image ID written before final-tag mutation; any other
concurrent or ambiguous value is refused. Expiry
or ambiguous readback appends no cleanup completion and leaves the attempt
unresolved and `UNKNOWN`. A normal successful qualification instead appends a
qualification completion binding and does not require cleanup.
Qualification is bound to the exact owner-held local Unix Docker context and
its same-name running `docker` Buildx builder. Redirecting Docker, Buildx, or
proxy environment variables are stripped; the exact approved context is then
set internally. The private `tmp/qualification/` output directory must be empty
before the run. Docker and Buildx are copied into an owner-private, executable-
only tool directory, the subprocess `PATH` is restricted to those digest-pinned
copies, and the directory is removed after the run. The approved Docker socket
must be owner-held and have no group or world write permissions. First-build
tags must not pre-exist; temporary OCI outputs and tags are removed on success
or failure. A failure after final-tag load never triggers an automatic rewrite;
the append-only ownership evidence and later cleanup readback must classify the
tag as baseline-unchanged or task-owned-retained. Qualification receipts
persist only the
abstract execution-boundary assertions, exact-allowlisted logical commands,
exact Docker, Buildx, and BuildKit version tokens, and Docker/Buildx executable
digests. Raw builder inspection output, host paths, socket paths, endpoints,
UUIDs, addresses, and other machine-specific metadata are rejected and must
never be landed.
Legacy receipts containing raw builder output are invalid under this contract;
do not rewrite their digests or describe them as sanitized. Replace them only
with newly generated, reviewed receipts in a new safe single-component receipt
set and update policy references in the same later reviewed source revision.
The first cohort creates one immutable set manifest binding the qualification
execution-source digest map, originating revision, dependency inputs, ordered
five-cohort denominator, and every cohort build input. Later cohorts may append
only when the execution-source digest map and all non-revision manifest fields
match exactly. The originating revision is immutable provenance, not a reopen
equality field. The digest map includes qualifier/runtime code, Dockerfiles,
locks, artifact descriptors, and nested source-build evidence. It excludes only
generated `docker/refresh/qualification/` evidence and
`src/mcp_trust/catalog/refresh_policy.json`, whose receipt pointers change when
reviewed evidence is adopted. If a dynamic executable or build input resolves
inside either exclusion, qualification fails closed. Receipt integrity and the
append-only attempt/ownership/completion graph are always revalidated
independently. Dependency-bundle bytes are not part of the tracked-source map;
the qualifier revalidates each bundle against its descriptor `bundle_sha256`
before every build and records the bound artifact independently.
An owner-private nonblocking lock serializes every invocation in one set, and the
temporary tag is attempt-specific, so two processes cannot share cohort
mutation state. The lock is released by the operating system after interruption;
the append-only attempt intent remains the durable recovery authority.
If a process stops after tool snapshotting but before its attempt intent, a
later invocation removes that residue only when both files are exact
owner-private, executable-only, digest-identical copies of the currently
resolved approved tools; any mismatch remains blocked as ambiguous.
Absolute, traversal, symlinked, legacy/unmanifested, source-drifted, collision,
overwritten, and unknown-artifact sets are refused before Docker or Buildx is
invoked. A partial valid set is resumable only for an absent cohort with no
unresolved attempt; the set is never repaired or rewritten in place.
The five exact `qualification_receipt` paths in
`src/mcp_trust/catalog/refresh_policy.json` are authoritative. All five receipts
must remain present, current under their maximum-age contract, and locally
reviewed; missing or expired receipts make preflight fail closed. A version
label in documentation is never authority. Legacy top-level receipts are
historical only.

## 1. Inventory and preflight (no server execution)

Dependency materialization is a separate, explicitly approved lane. Runtime
commands never invoke a package manager or hydrate missing packages. Prepare the
frozen `[engine]` environment first under its own exact registry authority. The
receipt commands below are observation-only: they do not run `uv sync`, install
packages, contact PyPI, invoke Docker, or start an MCP server. After the separately
approved materialization action, bind and independently reproduce the environment:

```bash
PYTHON=./.venv/bin/python
test -x "$PYTHON"

"$PYTHON" scripts/grade_refresh.py engine-materialization \
  --repo-root "$PWD" \
  --out dist/grade-refresh/engine-materialization.json

"$PYTHON" scripts/grade_refresh.py verify-engine-materialization \
  dist/grade-refresh/engine-materialization.json \
  --repo-root "$PWD"

"$PYTHON" scripts/grade_refresh.py inventory \
  --out dist/grade-refresh/inventory.json

"$PYTHON" scripts/grade_refresh.py host-capacity \
  --anchor "$PWD" \
  --out dist/grade-refresh/host-capacity.json
```

Stop unless the host-capacity receipt says `status: READY` and
`safe_to_start_runtime: true`. It requires at least 5 GiB available and less
than 100 percent capacity in two readings at least 30 seconds apart. The receipt
binds the filesystem device and exact byte counters but no host path. It expires
after 120 seconds and is revalidated before Docker, MCP, or registry-database
work. This source contract does not observe Colima state and cannot prove that
an operator kept Colima stopped until the gate passed; that ordering requires
fresh operator/runtime evidence. Its SHA-256 is an integrity checksum, not an
operator signature: observation authenticity and same-user replacement remain
`UNKNOWN` without a separately sealed operator binding.

Only after that READY decision, start the separately approved Colima instance.
Then create the preflight while the capacity receipt is still current:

```bash
"$PYTHON" scripts/grade_refresh.py preflight \
  --repo-root "$PWD" \
  --engine-materialization dist/grade-refresh/engine-materialization.json \
  --host-capacity dist/grade-refresh/host-capacity.json \
  --out dist/grade-refresh/preflight.json
```

Stop unless the engine receipt says `status: READY` and `safe_to_execute: true`.
`UNKNOWN` means provenance or runtime evidence is missing; `BLOCKED` means a
known binding or policy mismatch. Neither state authorizes repair or execution.
The engine receipt is a required preflight input and is embedded in the
`McpTrustGradeRefreshPreflightV3` receipt. Its digest, current reproducibility,
and exact source binding therefore flow into candidate and operator-package
evidence instead of remaining a standalone observation. The receipt binds the
complete frozen lock digest and its PyPI-only source
policy. Lock admission also requires exactly one editable `mcp-trust` root, the
committed `[engine]` requirement, and the matching optional-dependency and
`requires-dist` edges; an orphaned `mcp-audits` lock record cannot qualify a
stale installed engine. The receipt also binds the exact `mcp-audits==2.7.0`
sdist and universal-wheel hashes, project
Python pin and executable, `uv` version and executable digest, and every required
scanner module to its independently resolved relative origin and exact owning
distribution RECORD hash. The installed distribution name, version, metadata
version, `uv` installer marker, and RECORD path/digest are also bound. It contains
no host path.

Then stop unless the preflight receipt says `status: READY` and
`safe_to_execute_catalog: true`. Missing image tags, missing immutable IDs,
missing deterministic build source, remote Docker authority, missing engine
runtime, required scanner module files not owned and hash-bound by the installed
`mcp-audits` distribution record, or incomplete sandbox controls are terminal
preflight blockers. Do
not pull, rebuild, retag, or substitute an image without explicit approval.
Blocked catalog rows remain excluded; do not widen execution to make the
preflight green.

Candidate creation does not trust either receipt self-digest alone. Before any
Docker preflight it revalidates the exact network/filesystem/resource/secret
policies, all ten sandbox controls, every nested verified build qualification
and image ID, the qualification receipt and tracked-input source bindings, the
embedded engine materialization receipt against current installed bytes, and
the exact locked/runtime tool set. Candidate verification requires the current
repository root, recomputes each static image qualification from current
tracked bytes, and requires the receipt's complete source binding to equal the
current worktree binding. A re-digested alteration or missing current-source
evidence is a terminal source-evidence failure.

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

For the first one-target execution, use the separate receipt-only command. The
database, preflight, output directory, image qualifications, and exact target
must already exist and be reviewed. The output directory must be owned by the
operator and have no group or world permissions. Do not use this command to
build a refresh candidate:

```bash
mkdir -m 700 ./dist/target-scans

"$PYTHON" scripts/refresh_candidate.py target-receipt \
  --slug mcp-reference-time \
  --db ./registry.db \
  --seed ./src/mcp_trust/catalog/seed_servers.json \
  --masked-grades ./masked-grades.json \
  --policy ./src/mcp_trust/catalog/refresh_policy.json \
  --qualification-receipt ./dist/grade-refresh/preflight.json \
  --repo-root "$PWD" \
  --out ./dist/target-scans/mcp-reference-time-<timestamp>.json
```

The target command validates all five image qualifications but inspects and
executes only the selected target image. It opens the supplied registry
immutable and query-only, writes one exclusive `0400` receipt, and never calls
the registry scan writer. Refusal, timeout, privacy failure, source/DB/image
drift, missing runtime readback, or uncertain container cleanup writes no
artifact and no fresh grade. The receipt remains local review evidence only;
repeatability, the other 17 scannable rows, candidate readiness, public
freshness, publication, deployment, and scheduler state remain unproved.

After the 120-second host-capacity gate expires, the current-admission verifier
must continue to fail closed. To check only the immutable creation-time history,
without Docker, MCP execution, registry access, or renewed admission, use:

```bash
"$PYTHON" scripts/refresh_candidate.py verify-target-history \
  ./dist/target-scans/mcp-reference-time-<timestamp>.json \
  --qualification-receipt ./dist/grade-refresh/preflight.json
```

`VALID_AT_CREATION_CURRENTLY_EXPIRED` means the artifact and its bound preflight
remain internally consistent and the scan timestamp fell inside the original
capacity window. It is historical integrity evidence only. It does not make the
preflight current, authorize another scan, access or validate current registry
bytes, authenticate the artifact writer, or support candidate, publication,
deployment, freshness, safety, repeatability, scheduler, egress, endorsement, or
other-target claims. Current execution admission still requires the existing
freshness-sensitive verifier and a fresh separately authorized capacity gate.

## 4. Candidate creation and verification

```bash
"$PYTHON" scripts/refresh_candidate.py create \
  --db ./registry.db \
  --out-dir ./dist/refresh-candidates \
  --policy ./src/mcp_trust/catalog/refresh_policy.json \
  --qualification-receipt ./dist/grade-refresh/preflight.json

"$PYTHON" scripts/refresh_candidate.py verify \
  ./dist/refresh-candidates/<candidate>
```

Candidate creation loads the source-bound policy before Docker preflight. Only
`scannable` rows enter preflight or the scanner. A `blocked` row is emitted as
`blocked-policy`, exposes no fresh grade, and preserves any prior timestamp only
as historical context. The accepted 13-row blocked disposition is a controlled
catalog outcome, so it does not by itself make an otherwise complete candidate
partial; any unexpected failure or timeout does. The current policy derives
the exact 18 scannable rows as the complement of the 13-entry union of masked,
unsupported, credential-dependent, and backing-service-dependent rows.

The candidate is local and immutable. Its manifest binds the exact READY
preflight receipt, source and policy digests, tool versions, image build
provenance, and execution-time image IDs. Every successful scan receipt also
self-binds its target, source revision/tree, policy and preflight digests,
immutable image ID, configured launch controls, and 90-second timeout contract.
For a local Docker scan, the source contract also pre-creates a unique
scan-owned container, binds the connector launch to `docker start` of its
immutable ID, removes only that ID, and requires a second bound-daemon query
proving the container absent before accepting scan evidence. Pre-creation means
an outer-deadline worker cannot create a replacement after cleanup. A timeout
emits no receipt or fresh grade; it records
`CONTAINER_ABSENCE_VERIFIED_AFTER_TIMEOUT` only after that readback and otherwise
records `UNKNOWN`. A successful local receipt requires live, privacy-minimized
process readback: PID 1 must match the digest-bound MCP server command. Qualified
npm console scripts use the fixed `/usr/local/bin/node` interpreter and absolute
`/opt/npm/node_modules/.bin/<command>` path; qualified Python console scripts use
the fixed `/opt/venv` interpreter and script path. Image qualification rejects
an npm binding unless the source package, exact locked version, unique `bin`
provider, JavaScript target, and Dockerfile symlink assertion all agree. The process identity,
immutable image, environment names, `/proc` capability state, shared
network/mount namespaces and cgroup must agree with daemon configuration and
the exact locked profile. A same-namespace helper performs the behavioral
root/tmpfs write probes. Environment values are never emitted; this does not
prove that untrusted server code never retained a value. The receipt also binds
the 90-second connector limit, 95-second repository outer deadline, and
5-second runtime-probe deadline. The sandbox profile binds the fixed non-shell
`python` attestor command; its absence fails closed. Missing or contradictory evidence emits no
fresh grade. This source contract is not runtime qualification: actual
enforcement remains `UNKNOWN` until an approved controlled execution captures
and reviews that receipt. The claim does not cover local artifact replay,
Docker, VM, or kernel compromise or an actual egress attempt. Creation or
verification does not approve, publish, deploy, or schedule it.

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

uv run --frozen --extra dev python scripts/grade_refresh.py verify-package \
  --package ./dist/grade-refresh/operator-package \
  --candidate ./dist/refresh-candidates/<candidate> \
  --repeat-candidate ./dist/refresh-candidates/<repeat-candidate> \
  --preflight ./dist/grade-refresh/preflight.json \
  --repeatability ./dist/grade-refresh/fixture-repeatability.json \
  --triage ./dist/grade-refresh/triage.json \
  --task-id <codex-task-id>
```

The builder stages into a task-owned sibling directory, writes the immutable
`OPERATOR_PACKAGE.json` last, independently verifies every receipt and child
file, then uses platform no-replace rename semantics and parent-directory fsync
to finalize a previously absent output without clobbering a concurrent path.
Receipt self-digests are insufficient: READY/BLOCKED preflight coherence,
fixture repeatability semantics, catalog denominator, non-mutation authority,
exact stub-only claim ceiling, 24-hour/future-skew freshness, clean current Git
revision/tree, and freshly recomputed seed, masking, policy, inventory, and
execution-boundary digests are checked independently. A `READY` receipt must
also bind all five qualified image IDs, verified build qualifications, every
required network/filesystem/resource control, and matching locked/runtime tool
versions. Both `package` and `verify-package` re-run the current read-only
preflight before accepting a `READY` receipt; that operation requires separate
authority to inspect the approved Docker/Colima qualification and disabled
scheduler state, but it never starts an MCP server or mutates the scheduler. A
`BLOCKED` receipt may be packaged for review only when its sorted engine reason
codes agree with the embedded engine receipt. Missing or invalid engine evidence
must say so explicitly; present evidence must have exact schema, self-digest,
READY/source semantics, and current installed-byte reproduction before an image
reconstruction gate can be emitted. A blocked receipt cannot claim the
image-provenance completed control. The V3 manifest binds
the preflight, repeatability, optional triage, source revision/tree, catalog
input digests, inventory digest, denominator, counts, execution boundary,
candidate manifests, rollback lineage, privacy decision, and four
content-file digests. Its V2 lineage also projects the exact engine receipt,
lock binding, installed distribution binding and RECORD digest, and Python, uv,
and mcp-audits versions without retaining host paths. Missing engine evidence is
rendered as `UNKNOWN`, never as a safe binding. The human review and rollback
procedure carry the same projection. Its timestamp is derived from the latest
input receipt,
so identical inputs and task identity reproduce byte-identical packages.
`verify-package` must be run from the original receipt and candidate inputs;
package self-digests alone are insufficient.

Review Critical, High, Medium, then Low. The triage normalizes the two
independently verified controlled candidates while excluding receipt IDs and
timestamps; every grade/evidence inconsistency, upgrade, large change, new
mask, provenance gap, or policy change requires disposition.
Omitting the repeat candidate is a blocking High finding and can never produce
the `controlled-sandbox-candidate-repeat` completed control. Presence alone is
not qualification: both candidates must independently verify as publication-ready,
their manifest bindings must match, and their normalized controlled results must
repeat consistently before that completed control is emitted. The ordinary
triage command therefore requires `--repeat-candidate`; an early operator state
package without candidates remains review-only and explicitly incomplete.
The candidate and repeat candidate must resolve to different paths; reusing the
same directory through a symlink or other path alias is rejected as non-independent.

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

For an exact 18-fresh/13-policy-blocked candidate, create a V3 boundary proposal
instead of changing the V38 admission constants. Human acceptance binds the
proposal receipt, policy digest, and all thirteen repeated blocked projections.
The accepted result remains `NO_GO`: it records the reviewed boundary but grants
no execution, publication, deployment, or scheduler authority.

After the reviewed V131 policy change, an exact 20-fresh/11-policy-blocked
candidate uses the additive V4 boundary lineage. V3 remains valid for historical
18/13 artifacts. V4 binds all eleven repeated blocked projections and retains the
same `NO_GO` claim ceiling and separate publication, deployment, and scheduler
gates.

The V132 hermetic-browser change moves only Chrome DevTools and Playwright to
the executable set after exact-image browser initialization and tool enumeration.
Its 22/9 boundary is not represented by V3 or V4 and must not reuse either
acceptance lineage. Until an additive successor lineage is implemented and
accepted, review stops at controlled target evidence with publication,
deployment, and scheduler actions prohibited.

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

## 7. Build the local-only publication package

After an operator has supplied an exact, receipt-bound
`McpTrustPublicationApprovalV1`, verify it and build twice from the same frozen
inputs:

```bash
uv run --frozen python scripts/build_publication_package.py \
  --verify-approval ./dist/publication-approval.json \
  --candidate ./dist/site-candidates/<name>
uv run --frozen python scripts/build_publication_package.py --build \
  --candidate ./dist/site-candidates/<name> \
  --approval ./dist/publication-approval.json \
  --out ./dist/publication-packages/first
uv run --frozen python scripts/build_publication_package.py --build \
  --candidate ./dist/site-candidates/<name> \
  --approval ./dist/publication-approval.json \
  --out ./dist/publication-packages/repeat
```

Require byte-identical trees, then run `--verify-package` on each. The builder
copies the immutable site candidate under its original directory name and adds
a sibling `PUBLICATION_PACKAGE.json`; it does not rewrite the candidate or call
a provider. Package readiness is content review only.

## 8. Deployment gate

Stop. Publication, Vercel deployment, scheduler enablement, and outreach require
separate explicit approval. Use the package's `HumanGateResumeCapsuleV1.json`
for the chat gate. Re-read the live public route separately; local equivalence
does not prove production uptake.

The static lane accepts only `McpTrustProductionDeployAuthorizationV4`. Bind
the exact package and content-approval paths and receipts, provider
prepublication receipt, operator statement digest, retained rollback artifact,
source/output, and Vercel/Node/Python/verifier digests. Revalidate before and
after live TTY confirmation. V3 and `publication_allowed` or
`deployment_allowed` self-assertions are not substitutes.

After any provider call, keep adoption and freshness `UNKNOWN` until a
`McpTrustProductionPublicationReceiptV1` verifies matching provider/source
identity, provider artifact digest, and the receipt-bound exact all-route
readback. Route counts or sentinel matches alone are insufficient. If the
observation crosses `earliest_stale_after`, classify it `STALE`.

## 9. Rollback preparation

Before any future publication retain the exact prior deployment identifier,
source revision, site artifact digest, snapshot digest, masking digest, and
readback receipt. The operator package contains the rollback sequence. It does
not authorize provider mutation.
