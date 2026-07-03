# Near-Next Corpus Candidate Review

This note records the source-mapping review for the two deferred candidates
called out after the first two-entry public catalog integration. It is not a
promotion artifact and does not assign public catalog meaning.

Source inputs:

- Reviewed temp corpus records:
  `tmp/live-batch-published-review-20260702.json`
- Temp evidence receipts:
  `tmp/live-batch-receipts-20260702-evidence/`
- Public npm metadata read with `npm view <package>@<version> --json`
- Npm tarballs captured with `npm pack <package>@<version>`
- Registry-derived source repositories cloned read-only for tag/path
  comparison

Registry and package metadata remain discovery/provenance signals only. Tool
surface truth still comes from controlled MCPAudit scan evidence.

## Recommendation

Both candidates are promotion-ready from a source-mapping perspective, pending
separate public-catalog integration approval. Keep them deferred until that
approval is given. Neither package version declares repository or homepage
metadata in npm, so the review relies on exact package tarballs plus
Registry-derived source repository tags/paths rather than npm repository fields.

Build reproducibility was not proven in this pass: the review did not install
dependencies or rebuild package artifacts. It confirmed package identity,
version tags/paths, selected file hashes, and tool-name/source correspondence.

## Candidate Findings

| Record ID | Package | Registry-derived source | Scan result | Tool evidence | Source-mapping decision |
| --- | --- | --- | --- | --- | --- |
| `com-pulsemcp-image-diff-0-1-3` | `@pulsemcp/image-diff-mcp-server@0.1.3` | `https://github.com/pulsemcp/mcp-servers` | `C`, low transparency, danger score `4.14` | 1 tool, schema hash present, no annotations | Source mapping confirmed to monorepo tag/path; defer only until integration approval. |
| `com-seanwinslow-intent-engineering-0-2-0` | `@swins/intent-engineering-mcp@0.2.0` | `https://github.com/seanwinslow28/sw-mcp-intent-engineering` | `C`, low transparency, danger score `3.54` | 3 tools, schema hashes present, no annotations | Source mapping confirmed to repo tag; defer only until integration approval. |

## Provenance Review

`com-pulsemcp-image-diff-0-1-3`:

- Npm tarball: `pulsemcp-image-diff-mcp-server-0.1.3.tgz`
- Local tarball SHA-256:
  `f78201f3782964e27590ada95c512c1d84c4969ed4c5e653f1b3d5e0e80b9576`
- Npm dist integrity:
  `sha512-BRD6cwCeXbrdgiZep4QgOfupETpACnNhBsrKYJmeN7Y/Hxfh1eMjLWo+yBcScxN1Z5UgREmhqLxnDsrpD7W1CQ==`
- Registry-derived repo:
  `https://github.com/pulsemcp/mcp-servers`
- Exact source tag:
  `@pulsemcp/image-diff-mcp-server@0.1.3`
- Tag commit:
  `2933cf865b956a33e6d8201a55a9cb47a66ab260`
- Source path:
  `productionized/image-diff/local/package.json`
- The tarball `package.json` and tagged source-path `package.json` have
  matching SHA-256:
  `cfaa2be59f97911e4482ed8005defc39e90f89245a084f65bd68e6c667cc030b`
- Tool-name correspondence was present in the tagged source and tarball:
  `get_diff_of_images`
- Bin metadata has a packaging wrinkle: `npm view` reports
  `image-diff-mcp-server`, matching the temp scan source spec, while the packed
  `package.json` reports `@pulsemcp/image-diff-mcp-server`. Preserve the
  receipt-backed source spec unless a fresh approved scan says otherwise.

`com-seanwinslow-intent-engineering-0-2-0`:

- Npm tarball: `swins-intent-engineering-mcp-0.2.0.tgz`
- Local tarball SHA-256:
  `8f345d3d69a3e5a421c895ee1455000077c3688902ea06f822f753d8029706b4`
- Npm dist integrity:
  `sha512-T16xkDdxKfeMLBowY9Yvx+V+FEEAX9tLeukGcZ7rUKtOGhtzI07LekM/hHrORhpkR+v4wa6yZdBSYQyru4JT3Q==`
- Registry-derived repo:
  `https://github.com/seanwinslow28/sw-mcp-intent-engineering`
- Exact source tag: `v0.2.0`
- Tag commit:
  `0810449212c7d0c73351e09210302ffc8466a21c`
- The tarball and tagged source have matching package metadata, README, and
  license hashes:
  - `package.json` SHA-256:
    `4f1788852bf1c1b17111311fe71eaaeb05a6718418a3922f6e19aff61e0a70f1`
  - `README.md` SHA-256:
    `600761b9a11444aae3e3104df1c133e21629f9792e58807d9a96f82bf7385880`
  - `LICENSE` SHA-256:
    `f161aef239d8756bb988338963bdb5af82e6893395be99a09a75ac4a71c41739`
- Tool-name correspondence was present in the tagged source and tarball:
  `audit_intent_spec`, `generate_intent_spec_scaffold`,
  `assess_retrofit_level`

## Evidence Notes

`com-pulsemcp-image-diff-0-1-3`:

- Receipt:
  `tmp/live-batch-receipts-20260702-evidence/com-pulsemcp-image-diff-0-1-3-2ff3df25582e4c189a0800e00e6d868e.json`
- Tool observed: `get_diff_of_images`
- Schema hash algorithm: `sha256`
- Sandbox: Docker image `mcp-trust-live-batch:20260628`, runtime network
  disabled
- npm/package metadata for `@pulsemcp/image-diff-mcp-server@0.1.3`:
  exact version, MIT license, no deprecation flag, no repository, no homepage,
  bin `image-diff-mcp-server` via npm metadata and
  `@pulsemcp/image-diff-mcp-server` in the packed tarball

`com-seanwinslow-intent-engineering-0-2-0`:

- Receipt:
  `tmp/live-batch-receipts-20260702-evidence/com-seanwinslow-intent-engineering-0-2-0-e8b2775ce90446779950c3803ca93134.json`
- Tools observed: `audit_intent_spec`, `generate_intent_spec_scaffold`,
  `assess_retrofit_level`
- Schema hash algorithm: `sha256`
- Sandbox: Docker image `mcp-trust-live-batch:20260628`, runtime network
  disabled
- npm metadata for `@swins/intent-engineering-mcp@0.2.0`: exact version, MIT
  license, no deprecation flag, no repository, no homepage, bin
  `intent-engineering-mcp`

## Promotion Preconditions

Before either candidate is integrated into the public catalog:

- Confirm explicit public-catalog integration approval for these record IDs.
- Preserve the existing caveat that automated scan output is not an
  endorsement.
- Keep danger grade and transparency separate.
- Reuse the isolated temp evidence only if the receipt, package version, and
  source mapping still match.
- Regenerate public catalog records only after explicit integration approval.
