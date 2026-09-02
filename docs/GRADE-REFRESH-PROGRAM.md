# MCP Trust grade-refresh program

This program creates local review evidence only. It cannot publish grades,
deploy, change a scheduler, use live credentials, contact backing services, or
authorize third-party execution. A public danger grade is an automated,
point-in-time capability-risk signal—not an endorsement, certification, or
claim that a server is benign or malicious.

## Findings

### Critical

- Public API/VM masking previously depended on the caller passing an in-memory
  set. Public-readonly startup now requires `MCP_TRUST_MASKED_GRADES`, and VM
  bundles remove masked scan rows and bind the masking file. Runtime adoption
  remains UNKNOWN until a separately authorized deployment and live readback.
- Five executable catalog images now have digest-pinned bases, complete npm or
  Python locks, reproducible offline bundles, and source-bound two-build
  qualification receipts. `basic-memory` additionally binds its source-only
  `pybars3`/`PyMeta3` inputs and build tools by digest; package build code ran
  twice only in separate network-none, read-only-root, capability-dropped,
  resource-limited containers and produced byte-identical wheels.

### High

- Production source and deployment revisions are not exposed by the current
  public route. The live page can be read, but exact source/deploy binding is
  UNKNOWN until a future release identity is published and read back.
- Historical refresh evidence used mutable image tags. The new preflight binds
  tags to immutable local image IDs before execution; a real candidate must
  still consume a fresh `READY` receipt before this control is proven end to
  end.
- The three ignored historical cohort recipes were recovered byte-for-byte and
  moved into tracked source. Their original SHA-256 values are
  `a6e71b03a909647ed059229c1e7cc8d2f9ecb1fb7b71937a1f32ea31bc29238b`
  (live batch),
  `79c39f13a7982712e2b5029aa5005019ee0eda6a4555321d5be1168652644fca`
  (batch 3), and
  `8e9c820beba2599a2c9f029ec26d208e4262cf11126bfc40070a2a3b009ab5e0`
  (batch 4). Filenames, timestamps, receipts, and catalog commits corroborate
  their intended cohorts, but do not bind them to the original image bytes.
  They are reconstruction inputs, not recovered image provenance.
- The five admitted recipes now use immutable base digests and complete
  transitive npm/Python locks. Registry preparation disables package lifecycle
  code; lock-only rematerialization reproduced every normalized offline bundle
  byte-for-byte. Network-none, no-cache BuildKit runs with timestamp rewriting
  then produced identical OCI image IDs twice. The receipts expire after 24
  hours; an expired receipt returns the cohort to `UNKNOWN`.
- Current public grades were scanned on 2026-07-04 with MCPAudit 2.4.0, while
  the frozen lock resolves MCPAudit 2.7.0. Candidate drift and engine behavior
  remain UNKNOWN until all 18 policy-eligible entries are safely rescanned and
  all 13 excluded entries retain their reviewed fail-closed dispositions.
- A READY preflight now consumes and embeds the independently reproducible
  engine-materialization receipt. Candidate creation and verification revalidate
  that receipt against current installed distribution bytes, closing the former
  standalone-receipt provenance seam without installing or executing anything.

### Medium

- The host LaunchAgent is persistently disabled and unloaded, but a dormant
  installed plist remains and differs from the repository template. It was not
  changed. Scheduler definition drift requires review before any future load;
  scheduler enablement remains outside this program's authority.
- Freshness has three distinct meanings: 24-hour candidate/review evidence,
  90-day public grade validity, and 30/180-day corpus aging bands. Public grade
  validity is computed by one fail-closed authority: exactly day 90 is `FRESH`,
  later is `STALE`, missing/malformed/future time is `UNKNOWN`, and no scan is
  `NOT_APPLICABLE`. Static output is historical-only and carries an immutable
  validity boundary; it never claims a request-time transition. A future policy
  change requires review.
- Several seed references are unversioned even though their executable packages
  are baked at versions declared in image build files. Image ID, build
  qualification receipt, dependency-lock digests, catalog digest, and source
  digest are therefore required together; a seed digest alone is insufficient
  provenance.
- Prior scan receipts do not contain the new policy digest. Initial comparisons
  must report `baseline_policy_digest_unknown` and require operator review.

### Low

- Historical launch/handoff documents contain obsolete catalog denominators.
  Treat them as historical evidence; the reviewed denominator is the strict
  31-entry policy and seed pairing.
- Snapshot signing remains intentionally inactive. Structural and content
  binding do not prove publisher identity or rollback resistance.

## Signal model

Every reviewed result keeps four separate fields:

1. **Danger grade / score** — technical capability danger under the committed
   grading rules.
2. **Transparency** — annotation coverage, never folded into danger.
3. **Evidence quality** — `complete`, `partial`, `fixture-only`, or `UNKNOWN`
   based on provenance, receipt, repeatability, and sandbox evidence.
4. **Endorsement** — always `false` for automated grades.

Missing or contradictory evidence cannot be converted into a better grade.
Masked results withhold grade, risk, findings, history, and receipt references;
the mask is itself review evidence, not a safety statement.

## Catalog execution inventory

`src/mcp_trust/catalog/refresh_policy.json` is paired with the 31-row seed and
`masked-grades.json`. `scripts/grade_refresh.py inventory` expands every row
across these independent axes:

- scannable or blocked;
- intentionally masked;
- unsupported upstream;
- credential-dependent;
- backing-service-dependent;
- unsafe to execute unsandboxed.

All 31 entries launch local processes and are unsafe unsandboxed. Seven require
credentials; the only admitted mode is non-functional dummy values inside a
network-off sandbox. Ten depend on external or local backing services; a tool
surface observed without that service does not prove functional behavior.
Eight are upstream-archived/unsupported and eight are intentionally masked.
Build-source paths exist for every entry. All 31 entries map to five qualified
images. The current policy derives 13 blocked entries as the exact union of the
masked, unsupported, credential-dependent, and backing-service-dependent
categories; the remaining 18 are scannable.
Candidate execution derives its scan set from this exact source-bound policy:
blocked rows never enter Docker preflight or scanner invocation and cannot
retain a fresh-looking grade.

Two controlled candidates may be supplied to triage. Their review projection
compares grade, transparency, normalized risk/findings/evidence, sandbox
receipt data, masked proof state, and blocked/failure classification while
excluding run IDs and timestamps. Any inconsistent slug is a High finding;
either partial candidate remains a Critical publication block.

## Threat model and controls

| Threat | Required control | Failure state |
|---|---|---|
| Untrusted process execution | Docker by immutable image ID; never host passthrough | `BLOCKED` |
| Image provenance or tag retargeting | Tag, image ID, repository digests, platform, Dockerfile/source digests, two-build qualification receipt | `UNKNOWN` or `BLOCKED` |
| Dependency drift | Immutable base digests, complete npm/Python dependency locks, tool versions, and source-build receipts where wheel-only resolution is impossible | `BLOCKED` |
| Egress and callbacks | `--network none`; remote transports are a separate approval lane | `BLOCKED` |
| Secret theft | no live secrets; dummy values only with network off; values never recorded | `BLOCKED` |
| Filesystem escape | read-only root, bounded tmpfs, no host mounts, non-root user | `BLOCKED` |
| CPU/memory/PID exhaustion | explicit CPU, memory and PID ceilings; pre-created uniquely owned Docker container; connector launch bound to its immutable ID; repository outer deadline; removal and post-cleanup daemon absence readback | `BLOCKED` |
| Result/receipt spoofing | canonical JSON digests, exact candidate manifest, receipt/DB identity checks | `UNKNOWN` |
| Grade manipulation | source/rule/policy digests, separate axes, review triage | review required |
| Compromised upstream | reviewed image/source bytes; no live substitution | `BLOCKED` |
| Publication mistake | candidate/publication/deployment/scheduler authority all separate | `WAITING` |

Deterministic reconstruction has two distinct network lanes. Dependency
preparation may use only the explicitly approved registry clients/endpoints,
must disable package lifecycle code except for an explicit source-build lane,
normalize fetch-time-only npm cache metadata, and produce content-addressed,
source-bound locks or vendored inputs. Source-build package code must run only
with network `none`, no secrets, a read-only root, bounded task-owned writes,
and explicit CPU, memory, PID, and time controls; repeat outputs must match.
Lock-only rematerialization must reproduce the tracked bundle digests. The two
qualification builds themselves run with build network `none`; their
Dockerfiles must use immutable `FROM ...@sha256:` references, must not invoke
OS package managers, dynamic package installs, `npx`, `uvx`, `curl`, or `wget`,
and must consume the committed manager-specific locks. The preflight rejects a
digest mentioned only in a comment, an untracked lock or receipt, unequal build
image IDs, or a target tag whose live image ID differs from the qualification.
Before any Docker, BuildKit, package-manager, network, or output-path operation,
the shared dependency boundary rejects unsafe cohort components, absolute or
traversing paths, symlinked inputs, mutable or descriptor-mismatched base
images, external `COPY --from` sources, non-exact dependency specifications,
and lock sources outside the approved npm/PyPI endpoints. A locally built
dependency-preparation tag is a staging name only: it is inspected immediately
and every subsequent container executes its immutable `sha256:` image ID.
The candidate producer and verifier share one strict READY-preflight validator.
It rejects self-redigested sandbox-policy/control changes, nested qualification
state or image-ID changes, unbound qualification inputs, and locked/runtime
engine drift before Docker preflight or candidate acceptance. The verifier also
requires an explicit current repository root, recomputes static image
qualification projections from the current tracked inputs, and compares the
receipt's full source binding with a fresh current-worktree binding.

Each successful local scan must also carry a privacy-minimized
`McpTrustSandboxRuntimeReadbackV2` inside its execution binding. The collector
observes the exact pre-created container while PID 1 is the digest-bound MCP
server command, a source-qualified `/opt/venv` Python console-script form, or
the fixed `/usr/local/bin/node` interpreter with the image-qualified absolute
`/opt/npm/node_modules/.bin/<command>` npm console-script path,
whose package, exact lock version, unique `bin` provider, JavaScript target, and
Dockerfile symlink assertion must agree during image qualification,
reads PID 1 status and environment names, proves the helper
shares its network/mount namespaces and cgroup, and compares daemon
configuration with `/proc`, mount, interface, and cgroup observations. The
helper performs only the behavioral root/tmpfs write probes. Network-none,
read-only root, dropped capabilities, no-new-privileges, non-root identity, no
bind mounts, bounded tmpfs, memory, CPU, PID, exact image/config names plus the
Docker-managed `HOSTNAME` name, and command bindings must match the exact
configured profile. Environment values are never
emitted. Missing or contradictory readback refuses a fresh grade and remains
`UNKNOWN`. The receipt is not signed and does not prove protection from an
artifact-replay-capable local writer. Each qualified purpose-built image also
binds the fixed non-shell `python` attestor command; an image without that
capability fails closed and cannot return scan evidence. The generic
`DockerSandbox` image default is not runtime-qualified by this source contract.

Docker is the current baseline, not proof against a kernel/runtime compromise.
If the threat model requires stronger isolation, use a verified microVM/gVisor
boundary and requalify the same controls before execution.

## Target-scoped controlled receipt

`McpTrustTargetScanArtifactV2` is a separate, receipt-only path for the first
controlled server scan. It does not add a selector or partial mode to the
corpus-wide candidate builder. Before inspecting the one target image, it
validates and reproduces the complete five-image `READY` qualification against
the exact 31-row policy boundary (18 scannable, 13 blocked). Only one exact
policy-scannable local target then reaches Docker and `MCPAuditEngine`.

The source registry is never initialized, copied, seeded, vacuumed, or written.
It is held as an owner-private regular file, opened with SQLite
`mode=ro&immutable=1` and `query_only`, and bound by stable descriptor identity,
pre/post SHA-256, exact reviewed target identity, and absent WAL, SHM, and journal
sidecars. A successful artifact embeds the existing V2 scan receipt, exact
source/tree/policy/preflight/engine/image/runtime/cleanup bindings, explicit
no-publication authority, and a recursive privacy decision. Missing evidence,
timeout, drift, cleanup ambiguity, privacy failure, or a non-`mcpaudit` result
writes no artifact and no grade.

Finalization accepts only a previously absent file in an existing owner-private
directory. It uses a retained directory descriptor, exclusive no-follow
temporary file, file and directory fsync, platform atomic no-replace rename,
mode `0400`, and independent final readback. The verifier also requires current
clean source, reviewed inputs, complete preflight qualifications, and the same
read-only registry row. Receipt verification is not repeatability, candidate
readiness, publication, deployment, production freshness, safety, or
endorsement evidence.

The separate `McpTrustTargetScanHistoricalVerificationV1` projection can
recheck an immutable artifact and its exact bound preflight after the short
host-capacity window expires. It checks self-digests, duplicated source,
catalog, engine, image, receipt, and creation-time timestamp bindings only. It
does not inspect current Docker or registry state, authenticate the artifact
writer, renew the preflight, or grant current execution admission. Its maximum
claim is `VALID_AT_CREATION_CURRENTLY_EXPIRED` historical integrity for that one
local target receipt.

## Grade-diff triage

Review is mandatory for:

- every grade improvement;
- a movement of two or more letter bands;
- every masked result or masking change;
- failed, missing, or UNKNOWN scan evidence;
- inconsistent repeated fixtures or scans;
- missing comparable surface/source/image/receipt provenance;
- engine, grading, masking, evidence, or refresh-policy changes.

The triage receipt is severity-first and sets `publication_allowed: false`.
Human review is evidence for a later approval gate; it is not publication
authority by itself.

The tracked `refresh_disposition_policy.json` and `publication-review` command
form the next fail-closed review layer. They require exactly one disposition for
every masked slug, independently recompute triage, verify both masked controlled
projections, and preserve the historical policy baseline as `UNKNOWN`. The
current policy additionally requires both the bundled exact V38 proposal receipt
and the independently receipt-bound V38 acceptance artifact. It rejects V20/V33
acceptance transfer and proves that every disposition and V37 forward source,
policy, masking, candidate, tool, and image binding is unchanged. The resulting
packet
contains no masked grade, risk, or finding detail and always returns `NO_GO`;
immutable site and rollback binding, production binding, and explicit publication
authority remain separate gates. The evidence-source revision remains distinct
from the later clean committed implementation binding. Dormant scheduler-
definition drift is quarantined behind reconciliation and separate activation
approval instead of being normalized away by the disabled and unloaded state.

The `build_site_candidate.py` layer consumes the exact `RefreshCandidateV2`, accepted V38
review receipt, and acceptance artifact, then renders with a deterministic
candidate timestamp into a
fresh temporary directory. Its canonical content manifest is independently
verified before and after atomic finalization and binds the clean committed
builder revision plus complete Git-tree digest. A missing prior artifact remains
`UNKNOWN` rollback lineage; the current accepted-source review always yields
`publication_allowed: false` and `deployment_allowed: false`. Deployment
deployment authorization rejects raw, pending, accepted-review-only, tampered, or
rollback-unbound site trees.

The local publication-admission state machine is deliberately split:

1. `REVIEW_ONLY_ACCEPTED_FOR_SOURCE_REVIEW` — immutable V2 site candidate;
2. `PUBLICATION_CONTENT_APPROVED_LOCAL_ONLY` — strict, receipt-bound operator
   content approval with no mutation authority;
3. `PUBLICATION_PACKAGE_READY_FOR_DEPLOY_REVIEW` — deterministic copy-only local
   package with no mutation authority;
4. a separate short-lived `McpTrustProductionDeployAuthorizationV4`, binding
   the exact package, content approval, provider/operator receipts, rollback
   artifact, source/output, and tool digests (not implied by 1–3);
5. a separate `McpTrustProductionPublicationReceiptV1` bound to provider/source
   identity, provider artifact digest, and the exact all-route readback receipt.

The approval expires at the earliest candidate, provider, rollback, or explicit
operator TTL boundary. Its verifier rejects stale or UNKNOWN unmasked evidence,
unresolved triage, source/repeatability drift, missing provenance, privacy leaks,
symlinks, duplicate or extra keys, and authority self-assertion. Re-reading the
package repeats those checks, so expired or drifted inputs fail before any
future provider mutation boundary.

## Freshness and safe failure

- A candidate and its individual scans must be within the configured 24-hour
  candidate evidence budget. That budget is separate from the 90-day public
  validity horizon.
- A failed/UNKNOWN scan has no fresh grade and is excluded from candidate static
  output. The previous grade may be shown only as historical context with its
  original timestamp and never as current.
- A stale candidate cannot be approved or built for publication.
- Public pages must expose the last-scan time, immutable validity boundary, and
  static-historical disclosure. Rebuilding without a new scan cannot extend
  that boundary.
- A failed refresh leaves production unchanged but does not make production
  fresh. Production freshness remains `UNKNOWN` or `STALE` from live readback.

## Verification claim boundaries

- Repeated StubEngine fixtures prove deterministic in-process normalization.
- A benign controlled container fixture proves the Docker command boundary only.
- A real controlled catalog scan proves only that exact target under the exact
  bound image and controls.
- A local candidate build proves no deployment or production freshness.
- Only separate publication authorization plus the candidate-receipt-bound
  exact all-route readback can prove that approved bytes reached the public
  origin. A sentinel-only readback proves route shape and disclosure text, not
  candidate adoption. Provider deployment identity and scheduler state still
  require their own independent readbacks.
- Provider exit zero is never freshness evidence. Missing provider artifact,
  source identity, or exact readback evidence remains `UNKNOWN`; an observation
  after the candidate boundary is `STALE`.
