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
mcp-trust scan acme-search      # scan a catalog server, print its grade
mcp-trust check acme-search     # look up the latest stored grade
mcp-trust serve                 # serve the API on http://127.0.0.1:8000
```

For real scanning install the engine extra and select it:

```bash
uv pip install -e ".[dev,engine]"
MCP_TRUST_ENGINE=mcpaudit mcp-trust scan acme-search
```

## API

| Method | Path | Purpose |
|---|---|---|
| `GET`  | `/healthz` | liveness |
| `GET`  | `/servers` | catalog + latest grade per server |
| `GET`  | `/servers/{slug}` | full latest scan record + metadata |
| `POST` | `/servers/{slug}/scan` | scan now, persist, return record |
| `GET`  | `/servers/{slug}/badge.json` | shields.io-compatible README badge |

## Status

MVP scaffold. The StubEngine path (catalog → scan → grade → persist → serve) is
built and tested end-to-end. The `mcp-audits` real-scan adapter is built but
integration-gated. See [`SPEC.md`](SPEC.md) for the full contract and roadmap.

## License

MIT
