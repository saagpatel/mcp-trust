# MCP Census

`mcp-trust census` writes a local, one-page report on the official MCP Registry:

```bash
mcp-trust census                 # writes tmp/census/index.html and tmp/census/data/
mcp-trust census --out DIR
```

- **Source:** only the registry's public REST API (`/v0.1/servers?version=latest`),
  paged with its cursor. No server is contacted.
- **Figures:** server and publisher counts, namespace kinds, how many servers
  each publisher lists, the publishers with the most listings, package
  registries, package and remote transports, the declared server.json schema
  version, the deprecated HTTP+SSE transport, and aggregates of the bundled
  Trust Before Connect cards (verdicts and calibrated grades).
- **Data:** every figure links to its CSV in `data/`, beside `servers.csv` (one
  row per server) and `census.json` (the whole summary).
- **Wording:** counts only. Listing SSE, for example, is reported without
  judgement, since many servers keep it alongside Streamable HTTP for older
  clients. The card section reports aggregates, never server names.
- **Versions:** registry entries do not declare an MCP protocol version, so the
  census reports the server.json schema version each entry declares.
- **Local only:** the report is written under `tmp/` (git-ignored) and is not
  published. If the page cap (`--max-pages`, default 1000) is reached, the page
  says the counts are a lower bound.
