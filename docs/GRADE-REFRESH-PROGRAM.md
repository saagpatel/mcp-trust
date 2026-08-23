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
- Four executable catalog images now have digest-pinned bases, complete npm or
  Python locks, reproducible offline bundles, and source-bound two-build
  qualification receipts. `basic-memory` remains `UNKNOWN` and blocked: its
  pinned `pybars3` dependency is source-only and package build-code execution
  has not been sandbox-qualified. No substitute package or image is admitted.

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
- The four admitted recipes now use immutable base digests and complete
  transitive npm/Python locks. Registry preparation disables package lifecycle
  code; lock-only rematerialization reproduced every normalized offline bundle
  byte-for-byte. Network-none, no-cache BuildKit runs with timestamp rewriting
  then produced identical OCI image IDs twice. The receipts expire after 24
  hours; an expired receipt returns the cohort to `UNKNOWN`.
- Current public grades were scanned on 2026-07-04 with MCPAudit 2.4.0, while
  the frozen lock resolves MCPAudit 2.7.0. Candidate drift and engine behavior
  remain UNKNOWN until the 30 qualified entries are safely rescanned;
  `basic-memory` must remain separately UNKNOWN until its sandbox image is
  qualified.
- The legacy VM bundle gate is weaker than full refresh-candidate verification.
  Masking is now fail-closed, but future VM publication must additionally
  require current candidate, provenance, freshness, and receipt verification.

### Medium

- The host LaunchAgent is persistently disabled and unloaded, but a dormant
  installed plist remains and differs from the repository template. It was not
  changed. Scheduler definition drift requires review before any future load;
  scheduler enablement remains outside this program's authority.
- Freshness has three existing meanings: 24-hour candidate eligibility,
  90-day public grade staleness, and 30/180-day corpus aging bands. This program
  uses 24 hours for candidate/review evidence and requires public output to show
  point-in-time scan age. A future policy change requires review.
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
Build-source paths exist for every entry. Thirty entries map to four qualified
images; `basic-memory` is the single blocked and build-unqualified entry.
Candidate execution derives its scan set from this exact source-bound policy:
blocked rows never enter Docker preflight or scanner invocation and cannot
retain a fresh-looking grade.

## Threat model and controls

| Threat | Required control | Failure state |
|---|---|---|
| Untrusted process execution | Docker by immutable image ID; never host passthrough | `BLOCKED` |
| Image provenance or tag retargeting | Tag, image ID, repository digests, platform, Dockerfile/source digests, two-build qualification receipt | `UNKNOWN` or `BLOCKED` |
| Dependency drift | Immutable base digests, complete OS/npm/Python dependency locks, and tool versions in receipt; no dynamic package execution | `BLOCKED` |
| Egress and callbacks | `--network none`; remote transports are a separate approval lane | `BLOCKED` |
| Secret theft | no live secrets; dummy values only with network off; values never recorded | `BLOCKED` |
| Filesystem escape | read-only root, bounded tmpfs, no host mounts, non-root user | `BLOCKED` |
| CPU/memory/PID exhaustion | explicit CPU, memory, PID and scan timeout ceilings | `BLOCKED` |
| Result/receipt spoofing | canonical JSON digests, exact candidate manifest, receipt/DB identity checks | `UNKNOWN` |
| Grade manipulation | source/rule/policy digests, separate axes, review triage | review required |
| Compromised upstream | reviewed image/source bytes; no live substitution | `BLOCKED` |
| Publication mistake | candidate/publication/deployment/scheduler authority all separate | `WAITING` |

Deterministic reconstruction has two distinct network lanes. Dependency
preparation may use only the explicitly approved registry clients/endpoints,
must disable package lifecycle code, normalize fetch-time-only npm cache
metadata, and produce content-addressed, source-bound locks or vendored inputs.
Lock-only rematerialization must reproduce the tracked bundle digests. The two
qualification builds themselves run with build network `none`; their
Dockerfiles must use immutable `FROM ...@sha256:` references, must not invoke
OS package managers, dynamic package installs, `npx`, `uvx`, `curl`, or `wget`,
and must consume the committed manager-specific locks. The preflight rejects a
digest mentioned only in a comment, an untracked lock or receipt, unequal build
image IDs, or a target tag whose live image ID differs from the qualification.

Docker is the current baseline, not proof against a kernel/runtime compromise.
If the threat model requires stronger isolation, use a verified microVM/gVisor
boundary and requalify the same controls before execution.

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

## Freshness and safe failure

- A candidate and its individual scans must be less than 24 hours old.
- A failed/UNKNOWN scan has no fresh grade and is excluded from candidate static
  output. The previous grade may be shown only as historical context with its
  original timestamp and never as current.
- A stale candidate cannot be approved or built for publication.
- Public pages must expose the last-scan time and static-refresh disclosure.
- A failed refresh leaves production unchanged but does not make production
  fresh. Production freshness remains `UNKNOWN` or `STALE` from live readback.

## Verification claim boundaries

- Repeated StubEngine fixtures prove deterministic in-process normalization.
- A benign controlled container fixture proves the Docker command boundary only.
- A real controlled catalog scan proves only that exact target under the exact
  bound image and controls.
- A local candidate build proves no deployment or production freshness.
- Only separate publication authorization plus live route readback can bind the
public artifact; scheduler state still requires its own readback.
