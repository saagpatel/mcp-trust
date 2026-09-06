# V132 hermetic-browser policy boundary

This review changes only the execution disposition of the two browser-backed
Batch 4 entries. The image now includes one digest-pinned Playwright browser
runtime and launches it headlessly with an isolated profile inside the existing
network-none, non-root, read-only-root sandbox. Chrome DevTools usage statistics
and CrUX lookup are disabled. This does not claim browser safety, endorsement,
external-network behavior, publication readiness, deployment, or production
freshness.

| Entry | Before | After | Controlled evidence |
| --- | --- | --- | --- |
| `io-github-chromedevtools-chrome-devtools-mcp-1-5-0` | blocked and masked | scannable and unmasked | The real stdio server initialized and enumerated 29 tools while its browser ran from the exact image path; all locked runtime controls and post-run container absence were verified. |
| `io-github-microsoft-playwright-mcp-0-0-77` | blocked and masked | scannable and unmasked | The real stdio server initialized and enumerated 23 tools while its browser ran from the exact image path; all locked runtime controls and post-run container absence were verified. |

The reviewed denominator remains 31. The resulting policy is 22 scannable and
9 blocked, with 4 intentionally masked entries and 8 backing-service-dependent
entries. All local process entries still require a qualified pinned sandbox
image with network disabled.

The npm package and browser image are independently immutable, but their
Chromium revisions differ: `@playwright/mcp` 0.0.77 carries Playwright Core's
revision 1229 expectation, while the pinned arm64 runtime supplies revision
1234 (`Chromium 151.0.7922.34`). Successful controlled execution is evidence for
this exact combination only; the mismatch remains an explicit compatibility
caveat and must not be generalized to other versions.

## V5 disposition and acceptance boundary

`McpTrustGradeRefreshDispositionPolicyV5` is additive. It accepts only the
exact 31-row V132 projection of 22 fresh and 9 policy-blocked entries; the V3
18/13 and V4 20/11 contracts remain valid historical lineages and cannot accept
this projection. Proposal review must independently reproduce two complete
candidates, exact triage, and all nine blocked projections.

Direct acceptance emits `McpTrustAcceptedDispositionArtifactV4` with
`ACCEPTED_EXACT_V132_BOUNDARY`, binds the proposal and policy receipts plus the
SHA-256 of the current authorization statement, and records
`transfer_from_v131: false`. The accepted forward state is
`OPERATOR_ACCEPTED_EXACT_V132_BOUNDARY_LOCAL_REVIEW_ONLY`; the nine entries
remain `ACCEPTED_EXACT_V132_RETAIN_BLOCKED` and still require a separate policy
change and fresh controlled evidence before execution.

The accepted decision remains `NO_GO`. It grants no site-candidate,
publication, deployment, provider, credential, external-write, or scheduler
authority. Existing site and publication admission stay V38-only and must fail
closed on V5 input.
