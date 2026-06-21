# Real Catalog And Sandbox Decision Pack

This is the catalog and sandbox launch package for replacing demo data with real
public MCP servers. The approved reference set is now copied into
`src/mcp_trust/catalog/seed_servers.json`. Real scans, broader seed changes, and
grading-band changes remain approval-gated because they affect the public trust
surface.

## Verified Local State

- The current seed catalog contains the seven official reference server entries
  from Candidate Set A.
- API scan triggering is token-gated for the real `mcpaudit` engine with
  `MCP_TRUST_SCAN_TOKEN`, and public read-only deployments can disable scan
  triggering entirely with `MCP_TRUST_PUBLIC_READONLY=1`.
- Scan runs can write durable JSON receipts with `MCP_TRUST_RECEIPTS_DIR`.
- Local stub-backed verification is green.
- One real sandboxed smoke scan has run against `mcp-reference-time` using
  `MCP_TRUST_SANDBOX=docker`, `MCP_TRUST_SANDBOX_NETWORK=none`, and the
  `mcp-trust-scan:reference-2026-06-19` image. It persisted grade `A`,
  transparency `high`, and a JSON receipt in an ephemeral `/tmp` smoke DB.
- The full seven-server reference corpus has now run against local
  `./registry.db` with durable receipts under `./receipts/`.
- Current grade distribution is A=1, B=2, C=1, D=1, F=2. Transparency
  distribution is high=3, low=4.
- The project `.venv` has `mcp-audits 2.1.0`; adapter unit tests pass there.
- Docker/Colima were repaired locally by clearing a stale broken Colima disk
  entry and recreating the Colima VM profile. Docker is reachable through the
  `colima` context.
- Direct `curl` to `registry.modelcontextprotocol.io` was blocked by the local
  egress policy, so this package uses web-visible primary sources and should be
  refreshed from the official registry API once egress is allowed.

## Source Priority

Use this sourcing order for v1:

1. Official MCP Registry metadata:
   https://modelcontextprotocol.io/registry/about
2. Official reference servers maintained by the MCP steering group:
   https://github.com/modelcontextprotocol/servers
3. Vendor-owned public servers with clear ownership and current docs.
4. Community servers only after provenance, maintenance, license, and install
   instructions are verified.

The official registry is in preview, but it is still the best metadata source
because it standardizes package location, execution instructions, and env var
names.

## Candidate Set A: Calibration-First Reference Servers

These are the safest first corpus for sandbox validation and grade distribution
inspection. They are real public packages, but the upstream repo says reference
servers are educational examples, not production-ready endorsements. Treat them
as calibration inputs, not the whole public launch catalog.

The package-manager docs usually launch these via `npx` or `uvx`. For network-off
scan execution, use the direct package binaries preinstalled by `Dockerfile.scan`
instead.

| Slug | Name | Source spec candidate | Env keys | Why include | Scan notes |
|---|---|---|---|---|---|
| `mcp-reference-everything` | MCP Reference Everything | `kind=npm`, `reference=@modelcontextprotocol/server-everything`, `command=mcp-server-everything`, `args=[]` | none | Broad reference/test server with prompts, resources, and tools. | High-capability calibration target. |
| `mcp-reference-fetch` | MCP Reference Fetch | `kind=pypi`, `reference=mcp-server-fetch`, `command=mcp-server-fetch`, `args=[]` | none | Web fetch and HTML-to-Markdown conversion. | Network-off scans validate launch and tool enumeration only. |
| `mcp-reference-filesystem` | MCP Reference Filesystem | `kind=npm`, `reference=@modelcontextprotocol/server-filesystem`, `command=mcp-server-filesystem`, `args=["/scan"]` | none | Filesystem read/write and directory controls. | Use Docker tmpfs scratch only; no host mounts. |
| `mcp-reference-git` | MCP Reference Git | `kind=pypi`, `reference=mcp-server-git`, `command=mcp-server-git`, `args=["--repository", "/fixtures/repo"]` | none | Git repository read/search/manipulation tools. | Use the read-only fixture repo baked into `Dockerfile.scan`. |
| `mcp-reference-memory` | MCP Reference Memory | `kind=npm`, `reference=@modelcontextprotocol/server-memory`, `command=mcp-server-memory`, `args=[]` | `MEMORY_FILE_PATH` optional | Knowledge graph memory server. | Optional memory file should live under Docker tmpfs if enabled later. |
| `mcp-reference-sequential-thinking` | MCP Reference Sequential Thinking | `kind=npm`, `reference=@modelcontextprotocol/server-sequential-thinking`, `command=mcp-server-sequential-thinking`, `args=[]` | `DISABLE_THOUGHT_LOGGING` optional | Low I/O reasoning tool and useful low-risk anchor. | Candidate for expected low danger, transparency permitting. |
| `mcp-reference-time` | MCP Reference Time | `kind=pypi`, `reference=mcp-server-time`, `command=mcp-server-time`, `args=[]` | `LOCAL_TIMEZONE` optional | Time and timezone conversion. | Candidate for first one-server sandbox smoke scan. |

Primary sources:

- Official server inventory and reference warning:
  https://github.com/modelcontextprotocol/servers
- Everything install docs:
  https://github.com/modelcontextprotocol/servers/tree/main/src/everything
- Fetch install docs:
  https://github.com/modelcontextprotocol/servers/tree/main/src/fetch
- Filesystem install docs:
  https://github.com/modelcontextprotocol/servers/tree/main/src/filesystem
- Git install docs:
  https://github.com/modelcontextprotocol/servers/tree/main/src/git
- Memory install docs:
  https://github.com/modelcontextprotocol/servers/tree/main/src/memory
- Sequential Thinking install docs:
  https://github.com/modelcontextprotocol/servers/tree/main/src/sequentialthinking
- Time package and install docs:
  https://pypi.org/project/mcp-server-time/

## Candidate Set B: Public Catalog Candidates, Not First Scan Batch

These are useful public catalog candidates, but they need extra policy work
before scanning or public grading.

| Slug | Name | Proposed source | Env/auth | Status |
|---|---|---|---|---|
| `brave-search` | Brave Search MCP Server | `kind=npm`, `reference=@brave/brave-search-mcp-server`, `command=npx`, `args=["-y", "@brave/brave-search-mcp-server", "--transport", "stdio"]` | `BRAVE_API_KEY` | Vendor-owned and public. Do not scan until API-key handling and no-network behavior are decided. |
| `github-remote` | GitHub Remote MCP Server | `kind=remote`, `reference=https://api.githubcopilot.com/mcp/` | OAuth/Copilot | Vendor-hosted remote MCP endpoint. Current scan adapter may not handle OAuth; catalog entry may be useful later, but automated grading is blocked. |
| `slack-mcp` | Slack MCP Server | remote/vendor app flow | OAuth/scopes | Public vendor docs exist, but scanning requires OAuth app flow and workspace scopes; defer. |

Primary sources:

- Brave Search MCP Server:
  https://github.com/brave/brave-search-mcp-server
- GitHub remote MCP Server guide:
  https://github.blog/ai-and-ml/generative-ai/a-practical-guide-on-how-to-use-the-github-mcp-server/
- Slack MCP Server guide:
  https://slack.com/help/articles/48855576908307-Guide-to-Model-Context-Protocol-in-Slack

## Exclusions For First Public Seed

Do not seed archived `@modelcontextprotocol` integration packages such as the
old Brave Search, GitHub, GitLab, Google Drive, or Slack packages from the
archived reference list. The current official server repo marks those old
reference integrations as archived or replaced.

## Sandbox Decision Package

Recommended first decision: approve a network-off Docker scan profile for the
seven reference servers.

Required controls:

- `MCP_TRUST_ENGINE=mcpaudit`
- `MCP_TRUST_SANDBOX=docker`
- `MCP_TRUST_SANDBOX_NETWORK=none`
- purpose-built `MCP_TRUST_SANDBOX_IMAGE`
- no host mounts
- read-only root filesystem
- tmpfs scratch only
- non-root user if the image supports it
- memory, CPU, and PID limits
- no secrets in the scan environment
- disposable fixture paths only: the Docker tmpfs workdir `/scan`, plus the
  read-only `/fixtures/repo` from the scan image

Why a purpose-built image is required:

- The current Docker sandbox defaults to no network.
- `npx -y` and `uvx` normally fetch packages at launch.
- `Dockerfile.scan` preinstalls the reference packages and exposes direct
  binaries so scan-time execution can stay network-off.

Decision options:

1. Approve network-off Docker for the seven reference servers only.
2. Approve a separate network-enabled fetch-only exception for
   `mcp-reference-fetch`.
3. Defer credentialed/vendor servers until OAuth/API-key scan policy exists.

Recommended answer: approve option 1 now, defer options 2 and 3.

## Reference Corpus Result

| Slug | Grade | Transparency | Composite | Notes |
|---|---:|---|---:|---|
| `mcp-reference-time` | A | high | 1.0 | Low-risk anchor behaved as expected. |
| `mcp-reference-fetch` | B | low | 3.5 | Network-capable, scanned network-off. |
| `mcp-reference-git` | B | high | 3.8 | Fixture repo only. |
| `mcp-reference-memory` | C | low | 5.3 | Low transparency caveat applies. |
| `mcp-reference-filesystem` | D | high | 7.7 | Controlled `/scan` root only. |
| `mcp-reference-everything` | F | low | 8.0 | Broad reference/test surface. |
| `mcp-reference-sequential-thinking` | F | low | 8.6 | Calibration warning: low-I/O reasoning server is heavily penalized by low transparency/default-inferred capabilities. |

Interpretation: the corpus is useful enough to prove the scan/receipt loop, but
it is not evidence that the registry should market grades as broad trust
judgments. Current public wording keeps this as **danger grade + transparency**
and adds stronger automated-scan / low-transparency caveats. No grading-band
change has been made.

## Approval Gates Before Broader Seed Mutation

Before broadening `seed_servers.json` beyond the current reference set, the
operator should approve:

- final candidate slugs and display names
- source specs and env key names
- sandbox image approach
- fixture directories and fixture repo contents
- whether Fetch is scanned network-off, with controlled egress, or deferred
- whether the public seed can include reference servers despite upstream
  "reference, not production-ready" caveats

## Prepared Safe Artifacts

These files are safe prep work and do not run scans by themselves:

- `Dockerfile.scan` pins and preinstalls the seven reference packages.
- `scripts/reference_scan_plan.py` is the shared candidate source for launch
  planning scripts.
- `scripts/plan_reference_scans.py` prints the proposed env, seed-source
  previews, and scan commands without launching them.

## Approval-Gated Next Slice

After operator approval:

1. Run the deployed API/web/badge smoke against persistent SQLite.
2. Confirm public `POST /servers/<slug>/scan` returns 403 in read-only mode.
3. Choose the first non-reference no-auth public/vendor candidates only after
   the deployed read-only loop is green.

Done for this package means a reviewer can approve or reject the first real
scan batch without rediscovering candidate provenance, sandbox constraints, or
remaining public-launch blockers.
