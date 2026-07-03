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

`com.kage-core/kage` and `com.kogcat/kogcat-mcp` now have stronger source
matching than the initial review found, but they should still remain blocked
pending an explicit provenance caveat decision. Kage has an untagged release
commit for `2.3.0` whose `mcp/package.json` and `mcp/README.md` match the npm
tarball hashes, but the npm package still lacks repository/homepage metadata and
the source repo has no exact version tag. Kogcat's default branch package files
match the wheel runtime files byte-for-byte, but the wheel metadata still omits
source/project URLs and the source repo has no exact version tag.

Build reproducibility was not proven in this pass. The review confirmed package
identity, selected metadata hashes, source-tag/path availability where present,
and tool-name/source correspondence. It did not install dependencies, rebuild
artifacts, or run new MCP scans.

## Candidate Findings

| Record ID | Package | Registry-derived source | Scan result | Tool evidence | Decision |
| --- | --- | --- | --- | --- | --- |
| `ai-adeu-adeu-1-7-1` | `@adeu/mcp-server@1.7.1` | `https://github.com/dealfluence/adeu` | `F`, low transparency | 9 tools, schema hashes present, no annotations | Source mapping confirmed, but defer until explicit approval to publish F/low-transparency document/email/cloud tool evidence. |
| `ai-ravenmcp-raven-mcp-1-3-3` | `raven-mcp@1.3.3` | `https://github.com/rhinocap/raven-mcp` | `F`, low transparency | 27 tools, schema hashes present, no annotations | Source mapping confirmed, but defer until explicit approval to publish F/low-transparency broad design/content/service tool evidence. |
| `com-kage-core-kage-2-3-0` | `@kage-core/kage-graph-mcp@2.3.0` | `https://github.com/kage-core/Kage` | `F`, low transparency | 66 tools, schema hashes present, no annotations | Source match strengthened to an untagged release commit, but keep blocked pending explicit no-tag/no-package-source caveat approval. |
| `com-kogcat-kogcat-mcp-0-46-2` | `kogcat-mcp==0.46.2` | `https://github.com/KogCat/cc-kogcat` | `F`, low transparency | 9 tools, schema hashes present, no annotations | Source match strengthened by byte-for-byte wheel/runtime file hashes, but keep blocked pending explicit no-tag/no-wheel-source caveat approval. |

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
- Source history contains an untagged release commit:
  `d6580fbf04193dbf424882f54038c4401a33ec5f`, dated
  `2026-06-13 14:48:37 +0530`, with subject
  `Release 2.3.0: contradiction detection, docs search, +3 platforms, layered memory`.
- At that commit, `mcp/package.json` reports package
  `@kage-core/kage-graph-mcp`, version `2.3.0`, license `GPL-3.0-only`, and no
  repository/homepage fields.
- The npm tarball and untagged release commit have matching hashes for selected
  source-package files:
  - `package.json` SHA-256:
    `5e39ea231be155802b106dbdfc878fef28779b28e79c043a73efd69068dc1cf5`
  - `README.md` SHA-256:
    `5c852f608754e299c2cff74495862f1ce4775d0bda5776d7ce4f070f4e4a6494`
- Tool-name correspondence exists for many `kage_*` tools, but the npm package
  still needs a public caveat because the source binding is untagged and not
  package-declared.

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
  `f44bcb257a2aee8adf346c8aee0ee740d6322d80`, dated
  `2026-06-24 20:02:57 +0800`, with subject `release v0.46.6`; its
  `kogcat/pyproject.toml` still reports version `0.46.2`.
- Every runtime file included in the wheel matches the corresponding file under
  `kogcat/scripts/` at that default-branch commit, including:
  - `mcp_server.py` SHA-256:
    `d14677deb43522fe070dc64a4d5ba0d2531707bd2572d01b8e0e538059a60503`
  - `om_mcp/tools.py` SHA-256:
    `92e3b02c27892d80d1c8a7edbd1c702ae038f37ea2e0ee410165bd0c1befe256`
  - `om_supervisor.py` SHA-256:
    `9c9cbe6736b44d98b251aa7f6d57d0719f449f908146ae49e10140019229047b`
- Tool-name correspondence exists on the default branch for the observed
  knowledge and memory tools, but the wheel still needs a public caveat because
  the source binding is untagged and not package-declared.

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
- For Kage, explicitly approve a no-tag/no-package-source caveat if relying on
  the untagged release commit and matching package-file hashes.
- For Kogcat, explicitly approve a no-tag/no-wheel-source caveat if relying on
  default-branch runtime-file hash matches.
- Preserve the caveat that automated scan output is not an endorsement.
- Keep danger grade and transparency separate.
- Reuse isolated temp evidence only if the receipt, package version, and source
  mapping still match.
