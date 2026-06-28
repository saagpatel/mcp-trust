# MCP Trust Registry

[![CI](https://github.com/saagpatel/mcp-trust/actions/workflows/ci.yml/badge.svg)](https://github.com/saagpatel/mcp-trust/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)

> Check before you connect. A neutral, public danger grade for the MCP servers
> your AI agents rely on.

**Live:** [mcp-trust.vercel.app](https://mcp-trust.vercel.app)

> **Not yet published to PyPI.** Install from source using the Quickstart below.

Connecting an MCP server hands it influence over what your agent does. Tool
poisoning, prompt injection, over-broad permissions, and rug-pull tool
mutations are documented attack classes -- and today there's no quick way to vet
a server before you wire it in. **MCP Trust Registry** scans public MCP servers
and gives each one a single readable danger grade (A-F), a separate
transparency signal, and the findings behind them.

Think OSV.dev / Socket.dev / haveibeenpwned, scoped to MCP servers.

## Prerequisites

- Python >= 3.11
- [`uv`](https://docs.astral.sh/uv/) (used for dependency management and running the project)

## How it works

```
register a server  ->  scan via engine  ->  derive grade  ->  persist  ->  serve at a stable URL
```

The registry does **not** reimplement vulnerability detection. It orchestrates a
pluggable scan engine -- the shipping backend wraps the public
[`mcp-audits`](https://pypi.org/project/mcp-audits/) (>=2.1) package -- and owns the
catalog, the public trust-grade normalization, persistence, and the lookup API.

## Quickstart

```bash
git clone https://github.com/saagpatel/mcp-trust.git && cd mcp-trust
uv pip install -e ".[dev]"      # core + dev deps (runs on the built-in StubEngine)
mcp-trust seed                  # load the seed catalog
mcp-trust scan mcp-reference-time   # scan a catalog server, print its grade
mcp-trust check mcp-reference-time  # look up the latest stored grade
mcp-trust serve                 # serve the API on http://127.0.0.1:8000
```

For real scanning install the engine extra and select it:

```bash
uv pip install -e ".[dev,engine]"
MCP_TRUST_ENGINE=mcpaudit mcp-trust scan mcp-reference-time
```

Scanning launches the server's process. For **untrusted** servers, isolate
execution in a locked-down container (no network, read-only fs, dropped caps,
resource limits):

```bash
MCP_TRUST_ENGINE=mcpaudit MCP_TRUST_SANDBOX=docker mcp-trust scan mcp-reference-time
```

The default is no sandbox (safe only for servers you trust).

## API

| Method | Path | Purpose |
|---|---|---|
| `GET`  | `/` | **web** -- public catalog page (grade + transparency per server) |
| `GET`  | `/ui/servers/{slug}` | **web** -- server detail page + README badge-embed snippet |
| `GET`  | `/healthz` | liveness |
| `GET`  | `/servers` | catalog + latest grade per server (JSON) |
| `GET`  | `/servers/{slug}` | full latest scan record + metadata (JSON) |
| `POST` | `/servers/{slug}/scan` | operator scan trigger; public deployments disable this route |
| `GET`  | `/servers/{slug}/badge.json` | shields.io-compatible README badge |

Every server has two orthogonal signals: a **danger grade** (A-F) and a
**transparency level** (high/medium/low, from annotation coverage). Automated
grades are not endorsements, certifications, or claims that a server is
malicious. A low grade on a low-transparency server means "cannot verify safe,"
not "known dangerous."

HTTP scan triggering is fail-closed by default. Public deployments should set
`MCP_TRUST_PUBLIC_READONLY=1`, which makes `POST /servers/{slug}/scan` return
403 before any engine can run. Operator scans should normally run through the
CLI against the persistent registry DB, not through public traffic.

For local API demos with the deterministic `StubEngine`, set
`MCP_TRUST_ALLOW_UNAUTHENTICATED_STUB_SCANS=1`. Do **not** set that in public.
Token-gated API scan triggering is still available for private operator surfaces
by setting `MCP_TRUST_SCAN_TOKEN` and passing it as `Authorization: Bearer
<token>` or `X-MCP-Trust-Scan-Token`.

Set `MCP_TRUST_RECEIPTS_DIR=/data/mcp-trust/receipts` during real scan runs to
archive a JSON receipt for each scan and store its portable artifact filename in
`report_ref`.

## Status

**Live** at [mcp-trust.vercel.app](https://mcp-trust.vercel.app) as a statically
generated catalog, regenerated from the local registry. The seven official
reference MCP servers carry real `mcp-audits` grades from network-off Docker
sandbox scans (distribution A/B/B/C/D/F/F). Every grade is labeled by
provenance, so demo/stub data can never read as a real scan, and an unscanned
server never shows a letter grade.

The static front door is the low-ops launch path (see
[`DEPLOY-VERCEL.md`](DEPLOY-VERCEL.md)); a weekly `launchd` job under
[`deploy/launchd/`](deploy/launchd/) re-scans, rebuilds, and optionally
redeploys (deploy is opt-in). The live FastAPI service + VM path remains
documented in [`DEPLOY-VM.md`](DEPLOY-VM.md) as an alternative. See
[`SPEC.md`](SPEC.md) for the full contract and [`LAUNCH-GATE.md`](LAUNCH-GATE.md)
for launch history.

## Contributing

`uv.lock` is intentionally committed to the repository to ensure reproducible
installs across environments. When adding or updating dependencies, commit the
updated `uv.lock` alongside your `pyproject.toml` changes.

## License

MIT
