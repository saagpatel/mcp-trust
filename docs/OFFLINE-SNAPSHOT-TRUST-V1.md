# Offline Snapshot Trust V1

This contract lets an offline consumer verify that exact catalog snapshot bytes
were authorized by a consumer-pinned MCP Trust publisher root, are within a
bounded validity window, and do not move backward from the consumer's last
accepted publication.

It is an admission layer around the existing schema-v2 validator. It does not
scan a server, contact a network endpoint, attest a running server, approve a
refresh candidate, publish a package, or deploy the site.

## Current activation state

The verifier, deterministic fixtures, and negative tests are implemented. No
production trust root, private key, signed production statement, publication
counter, or checkpoint location has been selected. The packaged
`catalog_snapshot.json` therefore continues to receive structural schema-v2
admission only unless a consumer separately supplies and pins the v1 trust
inputs described here.

Activating production signing requires an operator decision on all of these:

- the exact publisher ID and initial root bytes;
- snapshot-key and recovery-key custodians;
- signature thresholds and key-overlap windows;
- the first accepted publication ID;
- maximum statement lifetime and clock skew;
- how the root SHA-256 pin reaches consumers independently of the snapshot;
- who owns durable checkpoint storage and atomic checkpoint advancement.

Test-only Ed25519 private seeds exist only inside `tests/test_snapshot_trust.py`.
They are deliberately obvious deterministic fixtures and must never be copied
into a release, approval, candidate, deploy bundle, environment, secret store,
or production signer.

## What V1 proves

For a `VERIFIED` result, V1 proves all of the following about the exact bytes
read during that verification call:

- the statement names the publisher ID in the pinned root;
- the configured threshold of authorized Ed25519 snapshot keys signed the
  canonical statement;
- the statement binds the snapshot byte length and SHA-256 digest;
- the snapshot passed the existing fail-closed schema-v2 catalog validator;
- verification occurred no earlier than the allowed clock-skew window and
  before the statement expiry;
- the statement lifetime is no longer than the root policy permits;
- the publication ID is at or above the root floor and is monotonic relative to
  the supplied checkpoint;
- a newer publication links to the exact prior publication, snapshot digest,
  and statement digest recorded in that checkpoint.

V1 does not prove that a scan was correct, a server is safe, the publisher is a
particular legal organization, a key was held in hardware, a package came from
PyPI, a deployment is current, or a running server matches the snapshot. The
publisher identity is only as strong as the independent review and pinning of
the root bytes.

Statement freshness is publication freshness, not scan freshness. A publisher
can sign a snapshot containing old scan records; consumers must still evaluate
each record's `scanned_at`, `scan_age_days`, and stale policy. Time enforcement
also assumes the consumer's local clock has not been rolled backward.

## Threat model and claim ceiling

V1 detects snapshot or statement modification, unknown or unauthorized
signers, insufficient signature threshold, expired or future-dated statements,
overlong validity, publication rollback, same-ID equivocation, broken
publication chains, and unauthorized root rotation.

Rollback resistance is stateful. A caller that discards, rewinds, or permits an
attacker to replace its checkpoint has discarded the evidence needed to detect
rollback. On first use, the caller must compare the exact trust-root bytes to an
independently obtained SHA-256 pin; accepting a root delivered beside the
snapshot is trust-on-first-use and does not establish publisher identity.
The byte-level snapshot and root-update verifiers therefore return
`TRUST_ROOT_DIGEST_REQUIRED` when the expected root digest is omitted.

The stable-path helpers reject symlinks, non-regular inputs, oversized files,
and files that change while being read. They do not claim adversarial isolation
from another process with the same user permissions after verification. A
consumer should use the verified in-memory bytes or an atomically admitted copy,
not re-open an untrusted path and assume it is unchanged.

Every verification failure returns:

```json
{
  "schema": "mcp-trust-snapshot-verification.v1",
  "status": "UNKNOWN",
  "reason_codes": ["SORTED_MACHINE_CODE"]
}
```

An `UNKNOWN` result contains no catalog rows, slugs, findings, or grades.

## Authority separation

The intended production roles are separate:

1. `refresh candidate create` gathers evidence but has no approval, signing,
   publication, deployment, or scheduling authority.
2. `refresh candidate verify` checks candidate structure and reviewed-input
   binding but grants no authority.
3. `refresh candidate approve` records a short-lived, digest-bound local staging
   decision but holds no signing key and grants no deployment authority.
4. A snapshot signer receives only the exact approved snapshot digest and signs
   the detached statement outside the refresh and deploy processes.
5. An offline consumer pins the root, verifies the statement, and advances its
   own checkpoint only after `VERIFIED`.
6. Recovery custodians can authorize a root update but cannot satisfy the normal
   snapshot threshold unless separately listed in the snapshot role.
7. Package publication and Vercel/VM deployment remain their existing operator
   lanes. A signature does not grant either capability.

The existing `MANIFEST.sha256` in refresh candidates and SHA-256 fields in VM
deploy bundles remain content-integrity indexes. They are not external trust
roots and do not identify a publisher by themselves.

## Root contract

The consumer-pinned root uses schema `mcp-trust-snapshot-root.v1`. It contains:

- `root_version`: a positive monotonic integer;
- `publisher.id` and `publisher.name`;
- `minimum_publication_id`: the first publication a new consumer may admit;
- bounded statement lifetime and clock skew in seconds;
- independent `snapshot_threshold` and `recovery_threshold` values;
- Ed25519 public keys whose `key_id` is
  `sha256:<sha256-of-32-raw-public-key-bytes>`;
- exactly one role per key, either `snapshot` or `recovery`;
- inclusive publication-ID bounds for each key.

Multiple snapshot keys with overlapping bounds support planned rotation. The
verifier counts unique authorized signatures only; duplicate, unknown,
out-of-window, wrong-role, or invalid signatures never satisfy a threshold.

## Snapshot statement contract

Schema `mcp-trust-snapshot-statement.v1` has a `signed` object and detached
signature list. The signed object binds:

- publisher and root version;
- positive monotonic publication ID;
- timezone-aware UTC `issued_at` and `expires_at` values;
- media type `application/vnd.mcp-trust.catalog+json` and snapshot schema 2;
- exact snapshot byte length and SHA-256;
- either `previous: null` for the root's first publication, or the prior
  checkpoint's publication ID, snapshot SHA-256, and statement SHA-256.

Signatures cover the UTF-8 bytes returned by
`mcp_trust.catalog.snapshot_trust.canonical_signed_bytes(signed)`: JSON object
keys sorted lexicographically, no insignificant whitespace, UTF-8 characters
preserved, and no non-finite numbers. The admitted v1 signed schemas use no
floating-point fields.

The checkpoint's `statement_sha256` is the SHA-256 of those canonical signed
bytes. It identifies the authenticated statement payload, not the detached
envelope's whitespace or signature-list serialization.

## Checkpoint and rollback contract

Schema `mcp-trust-snapshot-checkpoint.v1` binds the publisher, root version and
root SHA-256, accepted publication ID, snapshot SHA-256, and statement SHA-256.

- An exact replay of the current checkpoint is idempotent.
- A lower publication ID returns `UNKNOWN` with `PUBLICATION_ROLLBACK`.
- Reusing the same publication ID with different bytes returns `UNKNOWN` with
  `PUBLICATION_ID_CONFLICT`.
- A newer publication must link to the exact checkpoint or returns `UNKNOWN`
  with `PUBLICATION_CHAIN_MISMATCH`.
- First use must match the root's publication floor and have no predecessor.

The verifier is read-only. Its `VERIFIED` response includes `next_checkpoint`;
the consumer owns review, durable storage, permissions, and atomic replacement.
A long-running consumer should require its served snapshot to equal the current
checkpoint. A newly verified but unpersisted publication is not rollback-safe.

## Offline consumer commands

Verify a snapshot with an independent root digest pin:

```bash
mcp-trust verify-snapshot ./catalog_snapshot.json \
  --statement ./catalog_snapshot.statement.json \
  --trust-root ./catalog_snapshot.root.json \
  --trust-root-sha256 <independently-obtained-64-hex-digest> \
  --checkpoint ./catalog_snapshot.checkpoint.json
```

Omit `--checkpoint` only for the root's first publication. Exit zero means the
result is `VERIFIED`; exit one means `UNKNOWN`. The command performs no network
access and writes no checkpoint.

Python consumers that need catalog rows should read the snapshot bytes once,
call `verify_snapshot` on those bytes, require `status == "VERIFIED"`, and then
parse that same in-memory value. `verify_snapshot_paths` is a summary-only
stable-path helper; re-opening its source path would create a new observation.
Never parse or serve grades from a failed result.

## Recovery root update

Schema `mcp-trust-snapshot-root-update.v1` binds the exact prior root version
and SHA-256 plus a complete next root, its own issue/expiry window, and the
current root's lifetime policy. It must meet the current root's recovery
threshold. The next root must retain the same publisher ID, increment the root
version by exactly one, and may not lower the checkpoint's accepted publication
floor.

Verify a proposed rotation offline:

```bash
mcp-trust verify-root-update ./catalog_snapshot.root.json \
  --update ./catalog_snapshot.root-update.json \
  --checkpoint ./catalog_snapshot.checkpoint.json \
  --current-root-sha256 <independently-obtained-64-hex-digest>
```

A `VERIFIED` response returns a normalized `new_root` object, the exact UTF-8
artifact as `new_root_json`, and a `next_checkpoint` rebound to that artifact's
SHA-256. Persist the UTF-8 bytes of `new_root_json` verbatim before using the
returned checkpoint; `canonical_root_bytes(new_root)` reproduces the same bytes
for Python consumers. The command does not replace either file. Snapshot-role
keys cannot authorize this transition.

## Publication and deployment boundary

No existing command signs snapshots. That omission is deliberate until the
operator selects production custody and root policy. A future signing adapter
must receive only approved digest-bound input, must not inherit candidate scan,
approval, package, Vercel, VM, or schedule authority, and must emit a detached
statement that this verifier accepts.

The Vercel static deploy authorization remains a deploy authorization, not a
snapshot signature. The VM deploy bundle manifest remains a transfer manifest,
not a publisher identity. Running-server enumeration and attestation remain
out of scope.
