# Launch Gate

Current decision: **NO-GO for public launch**.

## Verified State

- MVP application path is green through the deterministic StubEngine.
- The bundled seed catalog replaced demo/example placeholder targets with
  official reference MCP servers, approved archived official calibration
  entries, and the first two reviewed Registry-derived no-auth sandboxed corpus
  entries.
- The seed catalog is mechanically checked against
  `scripts/reference_scan_plan.py`.
- CLI scans persist computed transparency.
- HTTP scan triggering is fail-closed by default unless local stub API demos opt
  in with `MCP_TRUST_ALLOW_UNAUTHENTICATED_STUB_SCANS=1`.
- Public deployments can set `MCP_TRUST_PUBLIC_READONLY=1` to reject scan
  triggers before any engine can run.
- API scans can archive JSON receipts when `MCP_TRUST_RECEIPTS_DIR` is set and
  persist the portable receipt filename in `report_ref`.
- The repo `.venv` has `mcp-audits 2.1.0`; adapter unit tests pass.

## Local Launch Evidence

- Docker/Colima were repaired locally by clearing a stale broken Colima disk
  entry and recreating the Colima VM profile.
- `Dockerfile.scan` built locally as `mcp-trust-scan:reference-2026-06-19`.
- One network-off Docker smoke scan ran against `mcp-reference-time` using an
  ephemeral `/tmp` registry DB and receipt directory.
- The smoke scan persisted grade `A`, transparency `high`, `mcpaudit` engine
  version `2.1.0`, and a JSON receipt with sandbox metadata.
- The full seven-server reference corpus ran in the Docker sandbox against
  local `./registry.db` with receipts under `./receipts/`.
- The latest public scan rows have portable filename-only `report_ref` values
  with matching JSON receipt artifacts.
- Current grade distribution is A=1, B=2, C=1, D=1, F=2. Transparency
  distribution is high=3, low=4.
- The distribution exposes a calibration/wording risk: the low-I/O
  `mcp-reference-sequential-thinking` server grades `F` because low
  transparency/default-inferred capabilities inflate risk.
- Public wording now presents the A-F signal as a **danger grade** plus a
  separate transparency signal. No grading-band change has been made.
- Local public-read-only API/web/badge smoke passed against `./registry.db` with
  `MCP_TRUST_PUBLIC_READONLY=1`.
- A deploy-style rehearsal copied `registry.db` and `receipts/` to a temporary
  data root, produced SQLite + receipt backups, served the copied DB in
  read-only mode, and passed the same smoke script with filename-only
  `report_ref` values in public JSON.
- `scripts/validate_launch_state.py --db ./registry.db --receipts-dir ./receipts`
  passes on the local launch DB: 7 seeded servers, 7 latest `mcpaudit` scans,
  7 matching receipt artifacts, no stub latest rows.
- `scripts/build_deploy_bundle.py` builds a sanitized transfer artifact with a
  pruned latest-scan DB, only referenced receipts, and a hashed manifest.
- A GCE VM rehearsal is running as `mcp-trust-v1` in `saagars-project`
  (`us-west1-b`, external IP `8.229.92.116`) with the sanitized bundle
  installed under `/data/mcp-trust/`.
- VM-side validation passes: 7 seeded servers, 7 latest `mcpaudit` scans,
  7 matching receipts, no stub latest rows.
- VM services are active: `mcp-trust.service`, `caddy`, and
  `mcp-trust-backup.timer`.
- First VM backup exists under `/data/mcp-trust/backups/`: SQLite DB backup and
  receipt tarball.
- First VM backup has been copied off-box to local ignored
  `dist/vm-backups/`: `registry-20260620T075144Z.db` and
  `receipts-20260620T075144Z.tar.gz`.
- Read-only smoke passes on the VM against both `http://127.0.0.1` and
  `http://8.229.92.116`; `POST /servers/<slug>/scan` returns 403.
- VM/VPS deployment package is prepared in `DEPLOY-VM.md` and `deploy/`
  templates: systemd service, Caddy reverse proxy, env example, backup timer,
  and read-only smoke script.

## Blocking Items

- Pick and point the final public domain at `8.229.92.116`.
- Replace the rehearsal `:80` Caddy config with the final domain config and
  confirm HTTPS certificate issuance.
- Run the public read-only smoke against the final HTTPS base URL from outside
  the VM. Current Codex egress policy blocks direct curl to the raw IP.
- No final-domain public badge-loop smoke has happened.

## Go Criteria

1. API/web/badge smoke passes against a deployed app with persistent SQLite.
2. `POST /servers/<slug>/scan` returns 403 on the public deployment.
3. Public visibility and outreach remain held until all prior checks are green.

## Local Read-Only Smoke

Passed against `./registry.db` on localhost with `MCP_TRUST_PUBLIC_READONLY=1`:

- `GET /healthz` returned `{"status":"ok"}`.
- `GET /servers` returned all seven scanned reference servers.
- `GET /` rendered the danger catalog copy.
- `GET /ui/servers/mcp-reference-sequential-thinking` rendered low-transparency
  and automated-danger-grade caveats.
- `GET /servers/mcp-reference-sequential-thinking/badge.json` returned an F/red
  shields.io endpoint payload.
- `POST /servers/mcp-reference-time/scan` returned 403 before any engine could
  run.

## Current Reference Corpus Result

| Slug | Grade | Transparency | Composite | Receipt |
|---|---:|---|---:|---|
| `mcp-reference-time` | A | high | 1.0 | yes |
| `mcp-reference-fetch` | B | low | 3.5 | yes |
| `mcp-reference-git` | B | high | 3.8 | yes |
| `mcp-reference-memory` | C | low | 5.3 | yes |
| `mcp-reference-filesystem` | D | high | 7.7 | yes |
| `mcp-reference-everything` | F | low | 8.0 | yes |
| `mcp-reference-sequential-thinking` | F | low | 8.6 | yes |

## Next Command Lane

```bash
python scripts/validate_launch_state.py \
  --db ./registry.db \
  --receipts-dir ./receipts
```
