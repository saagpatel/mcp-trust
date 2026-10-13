# MCP Trust Registry

## Purpose

MCP Trust Registry is a neutral public trust registry for MCP servers. Its
product loop is "check before you connect": register public MCP servers, scan
them with a pluggable engine, normalize results into an A-F danger grade plus a
transparency signal, persist the record, and serve it through a public API, web
catalog, and README badge endpoint.

The scanner is a replaceable backend. The durable product is the public catalog,
stable lookup API, trust-grade normalization, and author badge distribution
loop. The real engine adapter wraps `mcp-audits`; `StubEngine` keeps the system
testable without launching untrusted code.

## Layout

- `src/mcp_trust/api/`: FastAPI service and public API projection.
- `src/mcp_trust/core/`: domain models, grading, governance, and provenance.
- `src/mcp_trust/engine/`: scan engine contract, stub, and optional real adapter.
- `src/mcp_trust/store/`: SQLite schema and repositories.
- `src/mcp_trust/site/`: static site and badge generation.
- `scripts/`, `deploy/`, `docker/`, `docs/`: operator tooling, deployment
  assets, scan environments, and product/runbook documentation.
- `contracts/web-release-readback-v1/`: additive readback schemas and policy.

`SPEC.md` is the product and module-boundary contract. `LAUNCH.md` and the
operator runbook describe separately authorized operator workflows.

## Setup

Use Python 3.12 or newer. `.python-version` pins Python 3.15.0, and `uv.lock`
locks the project and development dependencies. Install the pinned uv version
(`0.13.0`) and run:

```bash
make setup
```

This installs the core and development dependencies. It does not install the
optional `mcp-audits` engine extra or enable real-server/Docker scans.

## Checks

Run the aggregate local gate with:

```bash
make check
```

It checks the lockfile, Ruff lint and formatting, Pyright, deterministic pytest
coverage, and package builds. Opt-in integration and Docker tests remain off.
See the README Quickstart and local development instructions for focused test
commands and a stub-only preview.

## Boundaries

- Keep `core/` and `engine/base.py` contracts stable unless the spec is updated
  first.
- Do not put secrets or environment values in server source specs; `env_keys`
  are names only.
- Treat scanner behavior, grading changes, and public-launch steps as
  high-trust-surface changes requiring explicit verification.
- Real scans launch server processes. Never scan untrusted servers without an
  isolation decision; prefer `MCP_TRUST_SANDBOX=docker` and a purpose-built image
  for public catalog scans.
- API scan triggering with the real `mcpaudit` engine is operator-gated by
  `MCP_TRUST_SCAN_TOKEN`; public callers must not be able to launch scans.
- The seed catalog contains official reference MCP servers. Public grades are
  not meaningful until real sandbox scans run and grading bands are checked
  against that distribution.
- Low-transparency servers can look risky because annotations are missing. Keep
  danger grade and transparency as separate signals instead of collapsing them
  into one verdict.
- Missing sandbox image, network mode, receipt, source binding, or scan
  provenance is unknown, not proof of safety, isolation, hosted execution, or
  unsandboxed execution. Preserve that uncertainty in wording.
- Demo or stub provenance must win over remote-source wording. Remote entries
  with a local launch command must retain local-launch and sandbox context.
- The repository is public. Treat committed code and issue/PR text as public.
  Check visibility before prose characterizes an unreported third-party finding;
  verdict data is published deliberately, while editorial prose is separate.
  Do not send author-badge outreach until live catalog, sandbox path, deployment,
  and smoke tests are green.
- Do not infer production or external-service readiness from local/cloud checks.

## Delivery

Review public trust claims, grade/risk masking, API and badge behavior, scan
sandbox boundaries, provenance and source binding, launch-gate evidence, corpus
refresh scripts, executable runbooks, and spec drift. Treat any path that can
launch scans, publish grades, or expose public JSON as security-sensitive.

For masking, provenance, and public-output changes, trace claims through API
JSON, web detail pages, static site generation, badge payloads, README snippets,
launch bundles, catalog snapshots, receipts, and generated docs. Operator-masked
metadata must stay neutral before a first scan; scan-specific grade, risk,
finding, and report references are withheld only when a scan exists.

For docs-only changes, comment only when docs overstate scan safety, sandbox
use, provenance, launch readiness, grade meaning, or evidence absent from the
reviewed tree.

The reference verifier in `contracts/web-release-readback-v1/` is limited to
explicit-target GET/HEAD readback with no credentials, proxy environment,
deployment, alias, DNS, promotion, or output-file capability. Consumer-specific
release and denied-mutation checks remain local until receipt parity is
demonstrated. `deploy/web-release-readback.json` is the product self-adoption
profile; keep it wired into `deploy/smoke-readonly.sh` ahead of, and additive to,
health, API, badge, portable-reference, and denied scan-POST assertions.

### Cursor Cloud

`.cursor/environment.json` installs the pinned uv and Python versions and runs
`make check` after setup. Cloud validation is local and deterministic. It needs
no credentials, Docker, or network access to MCP servers. The optional
`mcp-audits` extra and Docker sandbox scans are operator-gated workflows and are
not part of environment initialization.
