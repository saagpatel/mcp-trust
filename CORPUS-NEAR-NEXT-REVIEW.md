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

Registry and package metadata remain discovery/provenance signals only. Tool
surface truth still comes from controlled MCPAudit scan evidence.

## Recommendation

Keep both candidates deferred. They are reasonable near-next promotion
candidates after manual source mapping, but neither package version declares a
repository or homepage in npm metadata. The Registry-derived repository URL
therefore needs human confirmation against the package tarball/source tree
before either entry is promoted into the public catalog.

## Candidate Findings

| Record ID | Package | Registry-derived source | Scan result | Tool evidence | Source-mapping decision |
| --- | --- | --- | --- | --- | --- |
| `com-pulsemcp-image-diff-0-1-3` | `@pulsemcp/image-diff-mcp-server@0.1.3` | `https://github.com/pulsemcp/mcp-servers` | `C`, low transparency, danger score `4.14` | 1 tool, schema hash present, no annotations | Defer until the monorepo path and package provenance are confirmed. |
| `com-seanwinslow-intent-engineering-0-2-0` | `@swins/intent-engineering-mcp@0.2.0` | `https://github.com/seanwinslow28/sw-mcp-intent-engineering` | `C`, low transparency, danger score `3.54` | 3 tools, schema hashes present, no annotations | Defer until npm package provenance is tied to the Registry-derived repository. |

## Evidence Notes

`com-pulsemcp-image-diff-0-1-3`:

- Receipt:
  `tmp/live-batch-receipts-20260702-evidence/com-pulsemcp-image-diff-0-1-3-2ff3df25582e4c189a0800e00e6d868e.json`
- Tool observed: `get_diff_of_images`
- Schema hash algorithm: `sha256`
- Sandbox: Docker image `mcp-trust-live-batch:20260628`, runtime network
  disabled
- npm metadata for `@pulsemcp/image-diff-mcp-server@0.1.3`:
  exact version, MIT license, no deprecation flag, no repository, no homepage,
  bin `image-diff-mcp-server`

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

- Confirm the npm tarball corresponds to the Registry-derived source repository
  and, for monorepos, the exact package path.
- Preserve the existing caveat that automated scan output is not an
  endorsement.
- Keep danger grade and transparency separate.
- Reuse the isolated temp evidence only if the receipt, package version, and
  source mapping still match.
- Regenerate public catalog records only after explicit integration approval.

