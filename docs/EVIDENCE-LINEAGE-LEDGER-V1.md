# MCP Evidence Lineage Ledger v1

`EvidenceLineageLedger` is a metadata-only contract for four corpus decisions:
admit, refresh, publish, and withdraw. It binds one exact subject version to
source and scan digests, portable receipt references, freshness, rights
evidence, public projections, predecessor/successor links, and a retention
tombstone.

It is not a second catalog, a scan runner, a legal-opinion engine, or publication
authority. The packaged catalog and reviewed corpus records remain the product
surfaces. A ledger is decision evidence for those surfaces. No function in this
contract launches a process, contacts a registry, reads ambient credentials,
publishes a record, removes a projection, or changes deployment state.

## Contract

The canonical model is
`src/mcp_trust/corpus/lineage.py::EvidenceLineageLedger` with schema identifier
`mcp-trust-evidence-lineage-ledger.v1`. Models are frozen and reject unknown
fields. References must be relative repository/public artifact references or
credential-free HTTPS URLs. Absolute local paths, query strings, parent
traversal, raw payload fields, and undeclared extensions fail validation.

Each record contains:

- `subject`: name, package identity, exact version, and source reference;
- `source`: origin, canonical artifact digest, observation time, and evidence
  reference;
- `rights`: `documented`, `unknown`, or `restricted`, with complete factual
  evidence required for any non-unknown state;
- `scan`: engine/version, canonical scan artifact digest, execution mode,
  sandbox/network evidence, and time interval;
- `receipts`: digest-bound, portable scan-receipt references only;
- `freshness`: named policy and explicit expiry;
- `publication`: draft/published/withdrawn state and the exact public
  projections that still exist;
- `lineage`: predecessor and optional derived-successor links plus explicit supersession;
- `quality`: sorted stable reason codes for unresolved evidence;
- `retention`: source policy pointer and withdrawal tombstone state.

The ledger requires unique sorted record IDs, closed predecessor references,
stable package identity across a lineage chain, no branching, and an acyclic
successor graph. A later record can point at an immutable predecessor without
rewriting it; an optional declared successor must agree with that derived link.
Withdrawal is valid only after every projection is removed and a tombstone is
retained.

## Decision semantics

`assess_lineage()` requires an explicit timezone-aware observation time. It does
not consult the clock or any ambient system. Consumers must require the exact
safe status for their decision; a zero-test run or a valid model is not itself
authorization.

| Decision | Safe status | Fail-closed behavior |
|---|---|---|
| admit | `ALLOWED` | stale, missing, masked, or mismatched evidence is `UNKNOWN` or `BLOCKED` |
| refresh | `NOT_REQUIRED` | any evidence gap becomes `REQUIRED` |
| publish | `ALLOWED` | unknown rights are `UNKNOWN`; restricted rights or version conflicts are `BLOCKED` |
| withdraw | `COMPLETE` or `NOT_REQUIRED` | an unsafe published record becomes `REQUIRED` |

Stable reasons include `EVIDENCE_EXPIRED`, `RECEIPT_MISSING`,
`RIGHTS_UNKNOWN`, `RIGHTS_RESTRICTED`, `SANDBOX_NETWORK_UNKNOWN`,
`SCAN_ARTIFACT_DIGEST_UNKNOWN`, `SUBJECT_VERSION_UNKNOWN`,
`SUBJECT_VERSION_MISMATCH`, and
`PUBLICATION_WITHDRAWN`. Unknown or expired evidence never becomes current by
default.

## Read-only assessment

The CLI reads one ledger and emits canonical assessment JSON to stdout. It exits
zero only when every record has the safe status for the requested decision.
Unreadable, malformed, or schema-invalid ledgers return a content-free
`UNKNOWN` error envelope; rejected values are never copied into CLI output.

```bash
uv run --frozen python scripts/assess_evidence_lineage.py \
  tests/fixtures/evidence-lineage-pilot-v1.json \
  --decision publish \
  --now 2026-08-05T12:00:00Z \
  --pretty
```

The committed three-record pilot is bound to the first three rows of
`src/mcp_trust/catalog_snapshot.json` by canonical row digest. It deliberately
does not infer package versions, scan artifact digests, receipt files, network isolation, or rights
from the packaged projection. At the pilot observation time, all three records
therefore require refresh and withdrawal review, and publication remains
`UNKNOWN`. This is a decision-gap receipt, not a migration or an instruction to
remove currently served data.

## Adoption and rollback

Adoption into candidate promotion or catalog publication requires a separate
consumer change and owner approval. Until then, the module, read-only CLI, and
pilot fixture are source capability only. They do not prove installed use,
runtime enforcement, catalog migration, publication, withdrawal, scheduler
execution, or production behavior.

Rollback is a normal source revert. No database migration, external state,
service configuration, deployment, scheduler, or public catalog record is
changed by this contract.
