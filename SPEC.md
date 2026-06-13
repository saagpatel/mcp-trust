# MCP Trust Registry — MVP Spec

**Working title.** Check name collisions before any public launch.

## One-liner
A neutral, public trust registry for MCP servers. Before a developer runs
`<agent> mcp add some-random-server`, they can check its trust grade — like
OSV.dev / Socket.dev / haveibeenpwned, but for the MCP servers your AI agents
connect to.

## Why this and not "a scanner"
Scanners are commoditizing fast (Snyk-acquired Invariant `mcp-scan`, Cisco MCP
Scanner, GitHub secret-scanning MCP, Proximity). The unsaturated, defensible
layer is the **neutral public data network**: a comprehensive, continuously
re-scanned catalog of community MCP servers with a single readable trust grade,
queryable for free at install time. The scanning is a solved input (we wrap the
public `mcp-audits` engine); the catalog, the normalization into a public grade,
and the install-time check are the product.

## The one loop that must work (MVP definition of done)
```
register a public MCP server  →  scan it via the engine  →  derive a trust grade
        →  persist a ScanRecord  →  serve grade + findings at a stable URL/API
```
Everything else (web UI polish, badges, monitoring, auth) is downstream of this
loop working end-to-end.

## Architecture boundaries (owned by lead; do not cross)
- **`core/`** — domain models (`models.py`) + trust grading (`grading.py`).
  Registry IP. Engine-agnostic. *Frozen contract* — implementers import, never edit.
- **`engine/base.py`** — `ScanEngine` Protocol + `EngineResult`. *Frozen contract.*
- The registry NEVER implements detection. It maps an `EngineResult` →
  `ScanRecord` and persists/serves it.

## Modules to implement
| Module | Owns | Depends on (read-only) |
|---|---|---|
| `engine/stub.py` | `StubEngine` — deterministic `EngineResult` from a source spec; lets the whole system run without `mcp-audits`. | `engine/base.py`, `core/models.py` |
| `engine/mcpaudit.py` | `MCPAuditEngine` — adapter wrapping public `mcp-audits`; maps its `ServerAudit`/`RiskScore` → `EngineResult`. Import of `mcp_audit` is lazy/optional; raise `ScanError` if unavailable. | `engine/base.py`, `core/models.py` |
| `store/db.py` | SQLite schema + connection factory (servers, scans tables). | `core/models.py` |
| `store/repository.py` | `ServerRepository` (add/get/list) + `ScanRepository` (record latest scan, get latest by slug). | `store/db.py`, `core/models.py` |
| `api/app.py` | FastAPI app + routes (below). Dependency-injects repositories + an engine. | `store/`, `core/`, `engine/` |
| `cli/main.py` | Typer app: `scan`, `check`, `serve`, `seed`. | all of the above |
| `catalog/seed.py` + `seed_servers.json` | Seed list of ~8–12 well-known *public* MCP servers (name, source spec, homepage). No private servers. | `core/models.py` |

## Grading — calibration & roadmap
The public A–F grade is derived only via `core.grading.grade(risk)`. It does NOT
use the engine's raw `composite` (a capability-breadth SUM that mis-orders —
proven by a 2026-06-13 corpus scan where an unannotated no-op server out-scored
real filesystem/SQL servers). Instead it uses `core.grading.danger_score()`: a
danger-weighted aggregate (shell-execution dominant; destructive/exfiltration
down-weighted as spec-default noise) banded A–F, plus a critical-finding cap.

**Known limitation → v2 (transparency axis).** A fully *unannotated* server is
indistinguishable from a capable one on every dimension, so it is still
over-graded. The real fix is a second axis — **transparency** (annotation
coverage, available from the engine's `annotation_coverage`) — surfaced as a
separate caveat, not folded into the danger grade. Until then, a poor grade on
an unannotated server means "cannot verify safe," not "known dangerous."

## Data model (already defined in `core/models.py` — do not redefine)
- `ServerSource{ kind, reference, command?, args[], env_keys[] }` — `env_keys` are NAMES only, never values.
- `Server{ slug, name, description, source, homepage?, added_at }`
- `RiskSummary{ composite, file_access, network_access, shell_execution, destructive, exfiltration, findings_by_severity }` (all 0–10)
- `Finding{ rule_id, title, severity, category, detail }`
- `ScanRecord{ id, server_slug, engine_name, engine_version, grade, risk, findings[], scanned_at, report_ref? }`
- `TrustGrade` ∈ {A,B,C,D,F,unscanned}; derived only via `core.grading.grade(risk)`.

## API surface (MVP)
- `GET  /healthz` → `{"status":"ok"}`
- `GET  /servers` → `[{slug, name, grade, composite, scanned_at}]` (catalog + latest grade)
- `GET  /servers/{slug}` → full latest `ScanRecord` + `Server` metadata; 404 if unknown.
- `POST /servers/{slug}/scan` → run engine for that server, persist, return the new `ScanRecord`.
- `GET  /servers/{slug}/badge.json` → shields.io-compatible `{schemaVersion, label, message, color}` for a README badge.

## CLI surface (MVP)
- `mcp-trust seed` — load the seed catalog into the DB.
- `mcp-trust scan <slug>` — scan a catalog server, print grade + top findings, persist.
- `mcp-trust check <slug>` — print the latest stored grade (no scan).
- `mcp-trust serve [--host --port]` — run the API (uvicorn).

## Storage
SQLite (matches the substrate's house style). Two tables: `servers` (slug PK,
JSON source) and `scans` (id PK, server_slug FK, JSON risk/findings, grade,
scanned_at). "Latest scan per server" = most recent `scanned_at`.

## Engine default
The API and CLI default to `StubEngine` so the system runs out of the box.
Selecting `MCPAuditEngine` is config-gated (`MCP_TRUST_ENGINE=mcpaudit` env or a
`--engine` flag). The stub path is fully built + tested; the real-scan path is
built but integration-gated (requires `pip install 'mcp-trust[engine]'` and a
launchable server).

## Tests (each module ships its own)
- `test_grading.py` (lead — done): grade bands + critical cap.
- `test_stub_engine.py`: stub returns deterministic, valid `EngineResult`.
- `test_store.py`: round-trip a server + scan; latest-scan resolution.
- `test_api.py`: FastAPI `TestClient` — healthz, list, get-404, scan persists, badge shape.
- `test_cli.py`: Typer `CliRunner` — seed → scan → check happy path.

## Explicitly out of MVP scope (named, not silently cut)
Auth/accounts, hosted multi-tenant dashboard, continuous monitoring/cron,
submission moderation queue, the public marketing site, the verification-badge
program for server authors, sandboxed execution hardening of the real engine
path. These are the post-MVP roadmap, not part of the one loop.
