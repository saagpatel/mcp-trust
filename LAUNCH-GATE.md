# Launch Gate

Current decision: **NO-GO for public launch**.

## Verified State

- MVP application path is green through the deterministic StubEngine.
- The bundled seed catalog now contains seven official reference MCP servers,
  not demo/example placeholder targets.
- The seed catalog is mechanically checked against
  `scripts/reference_scan_plan.py`.
- CLI scans persist computed transparency.
- Real-engine API scan triggering is token-gated with `MCP_TRUST_SCAN_TOKEN`.
- The repo `.venv` has `mcp-audits 2.1.0`; adapter unit tests pass.
- No real MCP server scans were completed in this lane.

## Blocking Items

- Docker runtime is not available locally. The Docker CLI exists, but the daemon
  is not reachable.
- Colima is installed but failed to start while preparing its VM image cache.
- `Dockerfile.scan` has not been built.
- No sandboxed smoke scan has been run against `mcp-reference-time`.
- No full reference corpus scan or grade-distribution review has happened.
- No deployment or public badge-loop smoke has happened.

## Go Criteria

1. Docker/Colima is healthy.
2. `Dockerfile.scan` builds as `mcp-trust-scan:reference-2026-06-19`.
3. One network-off Docker scan against `mcp-reference-time` succeeds and
   persists a record.
4. The full seven-server reference corpus runs in the Docker sandbox.
5. Grade distribution is inspected before any grading-band change.
6. API/web/badge smoke passes against a deployed app with persistent SQLite.
7. Public visibility and outreach remain held until all prior checks are green.

## Next Command Lane

```bash
colima start
docker build -f Dockerfile.scan -t mcp-trust-scan:reference-2026-06-19 .
python scripts/plan_reference_scans.py
export MCP_TRUST_DB=./registry.db
export MCP_TRUST_ENGINE=mcpaudit
export MCP_TRUST_SANDBOX=docker
export MCP_TRUST_SANDBOX_NETWORK=none
export MCP_TRUST_SANDBOX_IMAGE=mcp-trust-scan:reference-2026-06-19
.venv/bin/mcp-trust seed
.venv/bin/mcp-trust scan mcp-reference-time
```
