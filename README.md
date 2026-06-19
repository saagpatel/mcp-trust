# MCP Trust Registry

> Check before you connect. A neutral, public trust grade for the MCP servers
> your AI agents rely on.

Connecting an MCP server hands it influence over what your agent does. Tool
poisoning, prompt injection, over-broad permissions, and rug-pull tool
mutations are documented attack classes — and today there's no quick way to vet
a server before you wire it in. **MCP Trust Registry** scans public MCP servers
and gives each one a single readable grade (A–F) plus the findings behind it.

Think OSV.dev / Socket.dev / haveibeenpwned, scoped to MCP servers.

## How it works

```
register a server  →  scan via engine  →  derive grade  →  persist  →  serve at a stable URL
```

The registry does **not** reimplement vulnerability detection. It orchestrates a
pluggable scan engine — the shipping backend wraps the public
[`mcp-audits`](https://pypi.org/project/mcp-audits/) package — and owns the
catalog, the public trust-grade normalization, persistence, and the lookup API.

## Quickstart

```bash
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
| `GET`  | `/` | **web** — public catalog page (grade + transparency per server) |
| `GET`  | `/ui/servers/{slug}` | **web** — server detail page + README badge-embed snippet |
| `GET`  | `/healthz` | liveness |
| `GET`  | `/servers` | catalog + latest grade per server (JSON) |
| `GET`  | `/servers/{slug}` | full latest scan record + metadata (JSON) |
| `POST` | `/servers/{slug}/scan` | operator scan trigger; real-engine deployments require `MCP_TRUST_SCAN_TOKEN` |
| `GET`  | `/servers/{slug}/badge.json` | shields.io-compatible README badge |

Every server has two orthogonal signals: a **danger grade** (A–F) and a
**transparency level** (high/medium/low, from annotation coverage). A low grade on
a low-transparency server means "cannot verify safe," not "known dangerous."

When the API is configured with the real `mcpaudit` engine, `POST
/servers/{slug}/scan` is protected by `MCP_TRUST_SCAN_TOKEN`; pass it as
`Authorization: Bearer <token>` or `X-MCP-Trust-Scan-Token`. Without that token,
the endpoint refuses the request before launching any scan work.

## Status

MVP. Built and tested end-to-end through the deterministic StubEngine path:
catalog → scan → danger grade + transparency → persist → serve, plus the public
web catalog/detail pages and the README badge-embed loop. The bundled seed
catalog now uses official reference MCP servers for launch calibration. The live
`mcp-audits` adapter is implemented behind an optional extra, with real-server
integration tests gated because they launch MCP server processes. See
[`SPEC.md`](SPEC.md) for the full contract and [`LAUNCH.md`](LAUNCH.md) for the
remaining public-launch gates.

## License

MIT
