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
currently private/pre-launch. The seed catalog now contains official reference
MCP servers for launch calibration. Public launch is gated by validating
sandboxed real-engine scans, inspecting the grade distribution, deciding whether
to broaden beyond reference servers, deploying the FastAPI app with persistent
SQLite storage, and smoke-testing the badge loop against the public base URL.

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
mcp-trust scan mcp-reference-time
mcp-trust check mcp-reference-time
mcp-trust serve
```

Run the real engine only when the target server is trusted or sandboxed:

```bash
uv pip install -e ".[dev,engine]"
MCP_TRUST_ENGINE=mcpaudit mcp-trust scan mcp-reference-time
MCP_TRUST_ENGINE=mcpaudit MCP_TRUST_SANDBOX=docker mcp-trust scan mcp-reference-time
```

Use `LAUNCH.md` as the public-launch runbook. Use `SPEC.md` as the product and
module-boundary contract.

## Known Risks
- Real scans launch server processes. Never scan untrusted servers without an
  isolation decision; prefer `MCP_TRUST_SANDBOX=docker` and a purpose-built
  image for public catalog scans.
- API scan triggering with the real `mcpaudit` engine is operator-gated by
  `MCP_TRUST_SCAN_TOKEN`; public callers must not be able to launch scans.
- The current seed catalog contains official reference servers. Public grades
  are not meaningful until real sandbox scans run and grading bands are checked
  against that distribution.
- Low-transparency servers can look risky because annotations are missing; keep
  danger grade and transparency as separate signals instead of collapsing them
  into one overconfident verdict.
- Public launch is a one-way trust event. Do not make the repository public or
  send author-badge outreach until the live catalog, sandbox path, deployment,
  and smoke tests are green.

## Review guidelines

Focus Codex review on public trust claims, grade/risk masking, API and badge
behavior, scan sandbox boundaries, provenance and source binding, launch-gate
evidence, corpus refresh scripts, executable runbooks, and spec drift. Treat
any path that can launch scans, publish grades, or expose public JSON as
security-sensitive.

For docs-only PRs, comment only when the docs overstate scan safety, sandbox
use, provenance, launch readiness, grade meaning, or evidence that is missing
from the reviewed tree.

## Next Recommended Move
Start Docker/Colima, build `Dockerfile.scan`, run one sandboxed `mcp-audits`
smoke scan against `mcp-reference-time`, then run the full reference corpus,
inspect the resulting grade distribution, recalibrate bands if needed, and
deploy the API with persistent SQLite storage for a live badge-loop smoke test.

## Agent Operating Notes
- Keep `core/` and `engine/base.py` contracts stable unless the spec is updated
  first.
- Do not put secrets or environment values in server source specs; `env_keys`
  are names only.
- Prefer adding tests beside the module being changed.
- Treat scanner behavior, grading changes, and public-launch steps as
  high-trust-surface changes that require explicit verification.
