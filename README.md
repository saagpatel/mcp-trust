# MCP Trust Registry

<!-- mcp-name: io.github.saagpatel/mcp-trust -->

[![CI](https://github.com/saagpatel/mcp-trust/actions/workflows/ci.yml/badge.svg)](https://github.com/saagpatel/mcp-trust/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)

> Check before you connect. A neutral, public danger grade for the MCP servers
> your AI agents rely on.

**Live:** [mcp-trust.vercel.app](https://mcp-trust.vercel.app)

> **Not yet published to PyPI.** Install from source using the Quickstart below.

## Use as an MCP server

`mcp-trust` runs as a read-only MCP server so an agent can check a server's
danger grade *before connecting* — it serves a baked snapshot of real scan
grades with explicit per-record provenance, so no database or network is needed.

```bash
mcp-trust mcp-serve          # from a source/dev install (works today)
uvx mcp-trust mcp-serve      # once published to PyPI
```

| Tool | Description |
|---|---|
| `list_servers` | Every graded MCP server with its A-F grade, transparency, and danger score. |
| `check_server` | Full grade, risk dimensions, and findings for one server by slug. |
| `get_methodology` | How the A-F grade and transparency axis are computed, plus the honesty model. |

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

## Manual refresh candidates

Create a review candidate without mutating the canonical registry, baked
snapshot, static site, schedule, or deployment:

```bash
uv run --frozen --extra engine python scripts/refresh_candidate.py create \
  --db ./registry.db \
  --out-dir ./dist/refresh-candidates
```

The command refuses local-process scans unless Docker and every catalog-pinned
image are already available locally. Those sources run through the existing
network-off, read-only, capability-dropped, resource-bounded sandbox. Remote
endpoints are probed over their live network transport without a local process
sandbox and are labeled accordingly. The immutable bundle contains receipts,
catalog identity, scan times and ages, masked/failed/unknown evidence states,
attributed scan drift, an honest static snapshot, and a content-bound manifest.

Candidate creation has no publication or deployment authority. A structurally
valid candidate must first pass `verify`, then receive a separate digest-bound,
short-lived `approve` receipt before `publish` may stage it in a local output
directory. That publication step still does not deploy the public site.

## Status

**Live** at [mcp-trust.vercel.app](https://mcp-trust.vercel.app) as a statically
generated catalog, regenerated from the local registry. The bundled catalog
snapshot contains 23 visible real `mcp-audits` grades; eight reviewed entries
are withheld by `masked-grades.json` and are absent from the public snapshot.
The bundled snapshot labels the visible local-process grades' network and
sandbox provenance as unknown; only a receipt-verified refresh candidate may
claim network-off execution. Every grade is labeled by provenance, so
demo/stub data can never read as a real scan, and an unscanned server never
shows a letter grade. The current production deployment is the 31-server
static catalog; grades are static since 2026-07-11, when the weekly re-scan
lane was disabled and its deploy authority removed (see
`docs/CAPABILITY-RULING-2026-07-10.md`).

The static front door is the low-ops launch path (see
[`DEPLOY-VERCEL.md`](DEPLOY-VERCEL.md)); a weekly `launchd` job under
[`deploy/launchd/`](deploy/launchd/) remains installed but disabled. Its
compatibility entrypoint can create a local review candidate only; it cannot
publish or deploy. The live FastAPI service + VM path remains
documented in [`DEPLOY-VM.md`](DEPLOY-VM.md) as an alternative. See
[`SPEC.md`](SPEC.md) for the full contract and [`LAUNCH-GATE.md`](LAUNCH-GATE.md)
for launch history.

## Contributing

`uv.lock` is intentionally committed to the repository to ensure reproducible
installs across environments. When adding or updating dependencies, commit the
updated `uv.lock` alongside your `pyproject.toml` changes.

## License

MIT
