# Deferred Corpus Candidate Review

This note records the source/provenance review for the four remaining
Registry-derived candidates from the first approved no-auth sandboxed live-scan
batch. It is not a promotion artifact, does not add catalog entries, and does
not assign new public meaning.

Source inputs:

- Temp reviewed corpus records:
  `tmp/live-batch-published-review-20260703-near-next.json`
- Temp evidence receipts:
  `tmp/live-batch-receipts-20260702-evidence/`
- Public package metadata read with `npm view`, `npm pack`, and `pip download`
- Registry-derived source repositories cloned read-only into ignored scratch
  space for tag/path comparison

Registry and package metadata remain discovery/provenance signals only. Tool
surface truth still comes from controlled MCPAudit scan evidence.

## Recommendation

Keep all four candidates deferred from the public catalog for now.

`ai.adeu/adeu` and `ai.ravenmcp/raven-mcp` have exact package versions, exact
source tags, and package/source metadata matches. They are not blocked on source
identity, but their observed tool surfaces carry enough public-rating risk that
promotion should require an explicit "publish F/low-transparency first-pass
evidence" decision.

`com.kage-core/kage` and `com.kogcat/kogcat-mcp` should remain blocked pending a
stronger source/provenance review. Kage's npm package does not declare
repository/homepage metadata, the registry-derived repo did not expose an exact
`2.3.0` tag during this pass, and the default-branch package metadata was already
at `3.2.0`. Kogcat's wheel metadata does not declare a project URL, and the
registry-derived repo did not expose an exact `0.46.2` tag.

Build reproducibility was not proven in this pass. The review confirmed package
identity, selected metadata hashes, source-tag/path availability where present,
and tool-name/source correspondence. It did not install dependencies, rebuild
artifacts, or run new MCP scans.

## Candidate Findings

| Record ID | Package | Registry-derived source | Scan result | Tool evidence | Decision |
| --- | --- | --- | --- | --- | --- |
| `ai-adeu-adeu-1-7-1` | `@adeu/mcp-server@1.7.1` | `https://github.com/dealfluence/adeu` | `F`, low transparency | 9 tools, schema hashes present, no annotations | Source mapping confirmed, but defer until explicit approval to publish F/low-transparency document/email/cloud tool evidence. |
| `ai-ravenmcp-raven-mcp-1-3-3` | `raven-mcp@1.3.3` | `https://github.com/rhinocap/raven-mcp` | `F`, low transparency | 27 tools, schema hashes present, no annotations | Source mapping confirmed, but defer until explicit approval to publish F/low-transparency broad design/content/service tool evidence. |
| `com-kage-core-kage-2-3-0` | `@kage-core/kage-graph-mcp@2.3.0` | `https://github.com/kage-core/Kage` | `F`, low transparency | 66 tools, schema hashes present, no annotations | Keep blocked: package lacks npm source metadata and no exact source tag was found. |
| `com-kogcat-kogcat-mcp-0-46-2` | `kogcat-mcp==0.46.2` | `https://github.com/KogCat/cc-kogcat` | `F`, low transparency | 9 tools, schema hashes present, no annotations | Keep blocked: wheel lacks source URL/project metadata and no exact source tag was found. |

## Provenance Review

`ai-adeu-adeu-1-7-1`:

- Npm tarball: `adeu-mcp-server-1.7.1.tgz`
- Local tarball SHA-256:
  `1922ced9e74734a27a9a380ef2e37debe7c63ebdb5ce1f8378f5fa80d24ae2b7`
- Npm dist integrity:
  `sha512-3uq9uUKCrK9iv2s4OIRvX7GpXBrq9PAHePwmHjUhuWXRdj2DQBeiGAonSvhUj3CLBOWe3cbU+zlrLHSS82E+wg==`
- Package metadata declares repository
  `https://github.com/dealfluence/adeu.git`, directory
  `node/packages/mcp-server`.
- Exact source tag: `v1.7.1`
- Tag commit:
  `5b41cca9c83b1a3231f2564ef1ff02f750f7bb3c`
- The tarball `package.json` and tagged source-path `package.json` have
  matching SHA-256:
  `a2868ca3a7941849ebd63611a753cd08111f678ceadb0fa384e53ad967856e21`
- Tool-name correspondence was present in tagged source:
  `read_docx`, `process_document_batch`, `accept_all_changes`,
  `diff_docx_files`, `finalize_document`, `login_to_adeu_cloud`,
  `logout_of_adeu_cloud`, `search_and_fetch_emails`, `create_email_draft`.

`ai-ravenmcp-raven-mcp-1-3-3`:

- Npm tarball: `raven-mcp-1.3.3.tgz`
- Local tarball SHA-256:
  `6b7bc76ae397888edf949a59924f14a2aa7f4d785c89df9c02310dd8c57a4ab3`
- Npm dist integrity:
  `sha512-4xE9o6nHo034MWBdkshGSmWCRTO0BV9Oq/hjHVqXGEU3+3Sf9FVMIfK7HoexRxO/PSsSc5XGMFCt45neRRlrJA==`
- Package metadata declares repository
  `https://github.com/rhinocap/raven-mcp`.
- Exact source tag: `v1.3.3`
- Tag commit:
  `2b2bc1a503037210afc82ab2aa8088fbfebd18c6`
- The tarball `package.json` and tagged source `package.json` have matching
  SHA-256:
  `504e9bbdc738c9ca2d2eb86eea1bfcef36da8db96f703f2800f7bef13f32ce00`
- Tool-name correspondence was present in tagged source for the observed
  readback surface, including `get_principles`, `get_pattern`,
  `search_knowledge`, `evaluate_design`, `raven_reflect`, and
  `raven_register`.

`com-kage-core-kage-2-3-0`:

- Npm tarball: `kage-core-kage-graph-mcp-2.3.0.tgz`
- Local tarball SHA-256:
  `6da871ac9ddb215a0eacee566790ab34fcca6bcbf4321de3ebdf62d5dec56c1c`
- Npm dist integrity:
  `sha512-lOMSDkFN13POwr2reT1/ujP1GP6FpvfVa9pwhArdmIGN8Ybr7P/BUlMSiaGt0wxWcGqA0tPpDrYUjTUM2XGSxw==`
- Npm package metadata does not declare repository, homepage, or bugs fields.
- No exact `2.3.0` / `v2.3.0` tag was found in the registry-derived repo during
  this pass.
- The registry-derived repo default branch was at commit
  `775de95a025fc7869d5f08a100e44456ae960655`; its `mcp/package.json` reported
  version `3.2.0`, not `2.3.0`.
- Tool-name correspondence exists on the default branch for many `kage_*` tools,
  but that is not enough to bind the scanned package artifact to source.

`com-kogcat-kogcat-mcp-0-46-2`:

- PyPI wheel: `kogcat_mcp-0.46.2-py3-none-any.whl`
- Local wheel SHA-256:
  `79a55f69514bb8b7dcc61f7a97ffd0d120c34f72ab0e39b0a5ba6308a2d6a092`
- Wheel metadata SHA-256:
  `dd3a64816a3c3902db08f740efc94dffd1a0b7afb53ee1deb7db10f31baebabe`
- Wheel metadata reports name `kogcat-mcp`, version `0.46.2`, license
  `FSL-1.1-MIT`, and no home-page or project URL.
- No exact `0.46.2` / `v0.46.2` tag was found in the registry-derived repo
  during this pass.
- The registry-derived repo default branch was at commit
  `f44bcb257a2aee8adf346c8aee0ee740d6322d80`; its `kogcat/pyproject.toml`
  reports version `0.46.2`.
- Tool-name correspondence exists on the default branch for the observed
  knowledge and memory tools, but source binding remains weaker than the
  tag-backed npm candidates.

## Evidence Notes

All four receipts are temp evidence from the approved no-auth sandboxed live
batch:

- DB: `tmp/registry-live-batch-20260628.db`
- Receipts: `tmp/live-batch-receipts-20260702-evidence/`
- Approval ref: `first-live-corpus-batch-20260628-evidence-rerun`
- Sandbox image: `mcp-trust-live-batch:20260628`
- Runtime network: disabled

The receipts include tool names/counts, per-tool schema hashes, prompt/resource
counts, and annotation coverage. They do not include raw input schemas.

## Promotion Preconditions

Before any of these candidates is integrated into the public catalog:

- Confirm explicit public-catalog integration approval for the exact record IDs.
- For Adeu and Raven, explicitly approve publishing first-pass `F` /
  low-transparency evidence despite source mapping being confirmed.
- For Kage, require exact source/version binding or an explicit caveat that npm
  package source metadata is absent and the registry-derived source cannot be
  tag-matched.
- For Kogcat, require exact source/version binding or an explicit caveat that
  wheel metadata omits source/project URLs and the registry-derived source
  cannot be tag-matched.
- Preserve the caveat that automated scan output is not an endorsement.
- Keep danger grade and transparency separate.
- Reuse isolated temp evidence only if the receipt, package version, and source
  mapping still match.
