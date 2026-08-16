# MCP Config Portability Studio

The portability studio is a local-only compatibility lab. It expresses MCP
connection intent once, renders staged host documents for Codex, Claude Code,
Claude Desktop, and VS Code, and reports every semantic change the adapters can
observe.

Generated configuration is **host-format compatibility evidence only**. It is
not proof that a server starts, connects, authenticates, exposes the expected
tools or resources, is trusted by the host, is adopted by a user, or is safe to
run.

## Research basis

Research was refreshed on **2026-08-11** from official primary sources. A host
format without a published version is pinned as `current` plus this as-of date;
that is intentionally weaker than a versioned standard.

| Surface | Pinned format or version | Official source |
|---|---|---|
| MCP protocol | `2026-07-28` current revision | [MCP versioning](https://modelcontextprotocol.io/docs/2026-07-28/learn/versioning) |
| MCP standard transports | stdio and Streamable HTTP in `2026-07-28` | [MCP transports](https://modelcontextprotocol.io/specification/2026-07-28/basic/transports) |
| MCP Registry metadata | preview `server.json` schema `2025-12-11` | [Publishing remote servers](https://modelcontextprotocol.io/registry/remote-servers) |
| Codex | `config.toml`, current as of 2026-08-11; no published format version | [OpenAI MCP configuration](https://learn.chatgpt.com/docs/extend/mcp?surface=cli), [OpenAI config reference](https://learn.chatgpt.com/docs/config-file/config-reference) |
| Claude Code | project `.mcp.json`, current docs through the v2.1.221 behavior notes | [Claude Code MCP](https://code.claude.com/docs/en/mcp) |
| Claude Desktop | `claude_desktop_config.json` local developer format; no published format version | [Connect to local MCP servers](https://modelcontextprotocol.io/docs/2026-07-28/develop/connect-local-servers), [Anthropic remote connector boundary](https://support.anthropic.com/en/articles/11503834-building-custom-connectors-via-remote-mcp-servers) |
| VS Code | `mcp.json`, current as of 2026-08-11; no published format version | [VS Code MCP configuration reference](https://code.visualstudio.com/docs/agents/reference/mcp-configuration) |

The MCP protocol defines wire behavior, not a universal client configuration
file. The Registry `server.json` schema is server publication metadata, remains
preview, and is not treated as a host configuration format.

### Standard requirements

- The current MCP revision uses date-based version identifiers and names stdio
  and Streamable HTTP as the standard connection transports.
- Registry remote metadata uses `remotes[].type = "streamable-http"`; SSE is
  deprecated. Registry header entries describe required inputs rather than
  publishing their secret values.
- Codex supports command/URL transports, working directory, environment-name
  forwarding, environment-backed HTTP headers, enablement, startup/tool
  timeouts, required startup, OAuth scopes, and tool allow/deny lists.
- Claude Code project configuration uses `mcpServers`, accepts `http` as the
  Streamable HTTP host spelling, supports environment expansion and per-server
  tool timeout milliseconds, and keeps project approval/disable state in
  settings outside `.mcp.json`.
- Claude Desktop's developer JSON documentation establishes local stdio
  `mcpServers`. Remote servers are added through Connectors, not by writing a
  remote entry into `claude_desktop_config.json`.
- VS Code uses `servers`, optional `inputs`, and optional `sandbox`; enablement
  is stored separately from `mcp.json`.

### Design inferences

- The neutral model is a versioned union of documented host capabilities, not
  a claim that the hosts share a schema.
- Seconds are the neutral timeout unit. Claude Code tool timeouts transform to
  milliseconds; Codex retains seconds. The neutral schema rejects positive
  values below one millisecond so an integer-millisecond host cannot silently
  round them to zero. It also rejects non-finite values and values above the
  largest exact JSON integer in milliseconds.
- OAuth, tool, and resource scope collections are semantic sets. Input order
  and duplicates are normalized deterministically; round-trip widening is
  decided from actual set changes, including the unrestricted meaning of an
  empty allowlist.
- A disabled server is omitted for hosts whose rendered document cannot carry
  enablement. This is reported as `dropped` and avoids silently widening a
  disabled intent into an enabled connection.
- A missing tool/resource restriction is `widened`, not merely `unsupported`,
  when the rendered host can expose a broader capability set.
- Undocumented fields and unsupported host defaults stay `UNKNOWN`. The studio
  never converts absence of documentation into a clean compatibility claim.

### Local fixture behavior

The fixtures under `tests/fixtures/portability/` are synthetic. Their commands
are never launched, their `.invalid` URLs are never contacted, and their
placeholders contain no usable credentials. They demonstrate deterministic
format conversion only.

## Neutral schema

`mcp-config-intent.v1` covers:

- stdio command, arguments, and working directory;
- Streamable HTTP URL and placeholder-backed headers;
- environment target names plus environment, prompt, or unknown value sources;
- none, bearer, OAuth, header, and unknown authentication requirements;
- enablement, tool/resource allow and deny scope, startup/tool timeout, and
  required-startup policy;
- source host, source format, source as-of date, documentation URL, and named
  unknown semantics.

Literal secret fields do not exist. Bearer tokens, headers, and environment
values are references only. Suspected secret-bearing command arguments are
rejected in neutral input and redacted during host inspection. URLs with
embedded credentials or secret-like query parameter names are rejected.
Validation diagnostics retain safe field locations and constraint messages but
discard rejected input values. Bearer requirements on stdio transports are
reported as unsupported rather than silently omitted. Timeout values have a
one-millisecond minimum. Every explicit input file is limited to 1 MiB before
parsing; oversized content is rejected without echoing it into diagnostics.

Export the exact JSON Schema with:

```bash
uv run --frozen --extra dev mcp-trust portability schema
```

## Capability matrix

| Semantic | Codex | Claude Code | Claude Desktop developer JSON | VS Code |
|---|---|---|---|---|
| Local stdio | Preserved | Preserved | Preserved | Preserved |
| Streamable HTTP | Preserved | `http` spelling transformation | Unsupported; use Connectors | `http` spelling transformation |
| Arguments | Preserved | Preserved | Preserved | Preserved |
| Working directory | Preserved | Unsupported | Unsupported | Preserved |
| Environment key/reference | `env_vars`, no values | `${ENV}` | Placeholder spelling is `UNKNOWN` | `${env:ENV}` or `inputs` |
| Header reference | `env_http_headers` | `${ENV}` | Remote unsupported | `${env:ENV}` or `inputs` |
| Bearer auth reference | Preserved for HTTP | Placeholder-backed header | Remote unsupported | Placeholder-backed header |
| OAuth scopes | Preserved | Preserved | Remote unsupported | Host discovery default; no client ID invented |
| Enabled/disabled in document | Preserved | Stored elsewhere; disabled omitted | Stored elsewhere; disabled omitted | Stored separately; disabled omitted |
| Tool allow/deny | Preserved | Widened | Widened | Widened |
| Resource allow/deny | Widened | Widened | Widened | Widened |
| Startup timeout | Preserved | Unsupported per server | Unsupported | Unsupported |
| Tool timeout | Preserved | Seconds to milliseconds | Unsupported | Unsupported |
| Required startup | Preserved | Unsupported | Unsupported | Unsupported |

## Portability report

Every operation can produce `mcp-config-portability-report.v1`. Changes use
exact states:

- `preserved`: same semantic is represented;
- `transformed`: represented with a documented conversion;
- `dropped`: intentionally omitted;
- `unsupported`: host document cannot express it;
- `defaulted`: host absence required an explicit assumption;
- `widened`: the target may expose broader behavior or scope;
- `UNKNOWN`: current documentation or discarded input cannot support a stronger
  claim.

Reports are stably sorted and include counts for every state, including zero.

## Five-minute demo

The demo writes only to a fresh temporary directory. Staging filenames are
deliberately different from real host configuration filenames.

```bash
demo_dir="$(mktemp -d)"
fixture="tests/fixtures/portability/local-stdio.json"

uv run --frozen --extra dev mcp-trust portability validate "$fixture"

uv run --frozen --extra dev mcp-trust portability render "$fixture" \
  --host codex \
  --output "$demo_dir/codex.generated.toml" \
  --report "$demo_dir/codex.report.json"

uv run --frozen --extra dev mcp-trust portability round-trip "$fixture" \
  --host vscode \
  --output "$demo_dir/vscode.round-trip-report.json"
```

Repeat `render` or `round-trip` with `claude-code`, `claude-desktop`, or
`vscode`. The studio refuses well-known real host configuration filenames,
refuses to overwrite an existing destination, and never creates missing parent
directories.

## Threat boundary

- No real host config discovery: every input path is explicit.
- No install or mutation: generated documents are staging artifacts only. The
  CLI never invokes Codex, Claude, VS Code, an MCP server, or an installer.
- No network: adapters parse and render in memory; tests replace socket creation
  with a hard failure.
- No credential acquisition: no `.env`, keychain, OAuth store, browser profile,
  cookie, or host credential store is read.
- No secret-value output from modeled secret surfaces: environment values,
  bearer tokens, and headers become references. Literal host values in those
  fields are discarded before neutral output.
- No arbitrary-output claim: a malicious input can disguise sensitive text in
  an ordinary non-secret field such as a server name or command. The studio
  blocks common secret-smuggling shapes, but callers must still provide a
  reviewed explicit input. This limitation is `UNKNOWN`, not proof of content
  classification.
- No runtime or adoption proof: parsing and round-trip comparison do not start a
  process, open a connection, authenticate, discover tools/resources, exercise
  host approval, or prove a human used the result.

If an adapter reports `widened`, `unsupported`, `dropped`, or `UNKNOWN`, treat
the result as review-required rather than installation-ready.
