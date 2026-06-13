# AGENTS.md — MCP Trust Registry

## Project Summary
MCP Trust Registry is a neutral public trust registry for MCP servers. Its product
loop is "check before you connect": register public MCP servers, scan them with a
pluggable engine, normalize the results into an A-F danger grade plus transparency
signal, persist the record, and serve it through a public API, web catalog, and
README badge endpoint.

This repo is not trying to win by being another scanner. The scanner is a
replaceable backend; the durable layer is the public catalog, stable lookup API,
trust-grade normalization, and author badge distribution loop. The current real
engine adapter wraps `mcp-audits`, while the default `StubEngine` keeps the full
system testable without launching untrusted code.

## Current State
The MVP is built and tested end to end: seed catalog, scan, grade, persist,
serve JSON and web views, and emit shields.io-compatible badge JSON. The repo is
currently private/pre-launch. Public launch is gated by replacing demo seed data
with real public MCP servers, validating sandboxed real-engine scans, deploying
the FastAPI app with persistent SQLite storage, and smoke-testing the badge loop
against the public base URL.

## Stack
- Python 3.11+
- FastAPI and Uvicorn for the API/web surface
- Typer for the CLI
- Pydantic domain models
- SQLite persistence
- Pytest and Ruff for local verification
- Optional `mcp-audits` engine extra for real MCP-server scanning

## How To Run
Install and run the deterministic local path:

```bash
uv venv .venv
. .venv/bin/activate
uv pip install -e ".[dev]"
python -m pytest -q
ruff check src tests
mcp-trust seed
mcp-trust scan acme-search
mcp-trust check acme-search
mcp-trust serve
```

Run the real engine only when the target server is trusted or sandboxed:

```bash
uv pip install -e ".[dev,engine]"
MCP_TRUST_ENGINE=mcpaudit mcp-trust scan acme-search
MCP_TRUST_ENGINE=mcpaudit MCP_TRUST_SANDBOX=docker mcp-trust scan acme-search
```

Use `LAUNCH.md` as the public-launch runbook. Use `SPEC.md` as the product and
module-boundary contract.

## Known Risks
- Real scans launch server processes. Never scan untrusted servers without an
  isolation decision; prefer `MCP_TRUST_SANDBOX=docker` and a purpose-built
  image for public catalog scans.
- The current seed catalog includes demo targets. Public grades are not
  meaningful until the catalog is replaced with real public MCP servers and
  grading bands are recalibrated against that distribution.
- Low-transparency servers can look risky because annotations are missing; keep
  danger grade and transparency as separate signals instead of collapsing them
  into one overconfident verdict.
- Public launch is a one-way trust event. Do not make the repository public or
  send author-badge outreach until the live catalog, sandbox path, deployment,
  and smoke tests are green.

## Next Recommended Move
Replace the demo seed catalog with 10-20 real public MCP servers, run sandboxed
`mcp-audits` scans, inspect the resulting grade distribution, recalibrate bands
if needed, and then deploy the API with persistent SQLite storage for a live
badge-loop smoke test.

## Agent Operating Notes
- Keep `core/` and `engine/base.py` contracts stable unless the spec is updated
  first.
- Do not put secrets or environment values in server source specs; `env_keys`
  are names only.
- Prefer adding tests beside the module being changed.
- Treat scanner behavior, grading changes, and public-launch steps as
  high-trust-surface changes that require explicit verification.
