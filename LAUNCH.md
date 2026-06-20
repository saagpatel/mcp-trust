# LAUNCH.md — v1 Launch Runbook

The single checklist to take MCP Trust Registry from a private repo to a live v1.
Run top to bottom. Each step has exact commands. Set these once:

```bash
export REPO="<owner>/mcp-trust"     # e.g. your-org/mcp-trust
export BASE_URL="https://<your-host>"   # public URL once deployed
```

---

## 0. Pre-flight — prove it's green

```bash
uv venv .venv && . .venv/bin/activate
uv pip install -e ".[dev]"
python -m pytest -q          # expect: all pass; real-server integration stays skipped unless opted in
ruff check src tests         # expect: All checks passed!
```

Optional, with the real engine:

```bash
uv pip install -e ".[dev,engine]"
MCP_TRUST_RUN_INTEGRATION=1 python -m pytest tests/test_mcpaudit_adapter.py -q
```

---

## 1. Scan the real seed catalog + calibrate bands  ⟵ do this BEFORE going public

The grade is only meaningful against a real distribution.

Use [`LAUNCH-CATALOG.md`](LAUNCH-CATALOG.md) for the current candidate list,
source evidence, sandbox decision package, and approval gates before broadening
the seed catalog, running real scans, or changing grading bands.

1. Review `src/mcp_trust/catalog/seed_servers.json` — it currently contains the
   approved official reference server calibration set. Keep `env_keys` to NAMES
   only.
2. Load + scan with the real engine in a sandbox (see step 2 for the image):

   ```bash
   export MCP_TRUST_DB=./registry.db
   export MCP_TRUST_RECEIPTS_DIR=./receipts
   mcp-trust seed
   MCP_TRUST_ENGINE=mcpaudit MCP_TRUST_SANDBOX=docker mcp-trust scan <slug>   # per approved server
   ```
3. Validate the DB + receipt bundle before copying or serving it:

   ```bash
   python scripts/validate_launch_state.py \
     --db ./registry.db \
     --receipts-dir ./receipts
   ```

4. Calibrate the bands against the observed distribution. Re-run the corpus
   helper, then tune `_DIM_WEIGHTS` / `_BANDS` in `src/mcp_trust/core/grading.py`
   so grades spread (don't let every capable server pile into one grade):

   ```bash
   PYTHONPATH=src python scripts/corpus_scan.py > corpus.json   # inspect distribution
   ```

   Re-run `pytest tests/test_grading.py` after any threshold change.

---

## 2. Sandbox image for untrusted scanning

The default scan path launches the server process. For untrusted servers,
`MCP_TRUST_SANDBOX=docker` isolates it (no network, read-only fs, dropped caps).
Caveat: `--network none` blocks launch-time package fetch (`npx -y` / `uvx`), so
bake the runtime (and ideally each server) into a purpose-built image.

The repo includes `Dockerfile.scan` for the approval-gated reference corpus and
`scripts/plan_reference_scans.py` for a dry-run plan that prints env and scan
commands without launching servers.

```bash
python scripts/plan_reference_scans.py
docker build -f Dockerfile.scan -t mcp-trust-scan:reference-2026-06-19 .
export MCP_TRUST_SANDBOX=docker
export MCP_TRUST_SANDBOX_NETWORK=none
export MCP_TRUST_SANDBOX_IMAGE=mcp-trust-scan:reference-2026-06-19
# Use MCP_TRUST_SANDBOX_NETWORK=bridge ONLY for servers you must fetch at launch.
```

Start the Docker daemon before running the integration-gated container path.

---

## 3. Deploy the API

Recommended v1 host: a small controlled VM/VPS. Keep the public app read-only
and run real scans as operator CLI commands against the same persistent SQLite
DB. Public traffic must never launch an MCP server.

Use [`DEPLOY-VM.md`](DEPLOY-VM.md) and the templates in [`deploy/`](deploy/) for
the systemd service, Caddy reverse proxy, backup timer, and read-only smoke
script.

```bash
# VM public read-only app behind Caddy/nginx:
MCP_TRUST_DB=/data/mcp-trust/registry.db \
MCP_TRUST_ENGINE=mcpaudit \
MCP_TRUST_PUBLIC_READONLY=1 \
  uvicorn mcp_trust.api.app:app --host 127.0.0.1 --port 8000
```

Recommended VM layout:

```text
/opt/mcp-trust/app
/data/mcp-trust/registry.db
/data/mcp-trust/receipts/
/data/mcp-trust/backups/
/var/log/mcp-trust/
```

Operator scan shell on the VM:

```bash
export MCP_TRUST_DB=/data/mcp-trust/registry.db
export MCP_TRUST_RECEIPTS_DIR=/data/mcp-trust/receipts
export MCP_TRUST_ENGINE=mcpaudit
export MCP_TRUST_SANDBOX=docker
export MCP_TRUST_SANDBOX_NETWORK=none
export MCP_TRUST_SANDBOX_IMAGE=mcp-trust-scan:reference-2026-06-19
mcp-trust scan <slug>
```

Do not set `MCP_TRUST_ALLOW_UNAUTHENTICATED_STUB_SCANS` in public. That flag is
only for local API demos/tests. `MCP_TRUST_PUBLIC_READONLY=1` makes
`POST /servers/{slug}/scan` return 403 before any engine can run.

If a private operator API is added later, gate it with `MCP_TRUST_SCAN_TOKEN` and
keep it off the public route. v1 should prefer SSH + CLI for scan operations.

---

## 4. Smoke test live

```bash
curl -s "$BASE_URL/healthz"                         # {"status":"ok"}
curl -s "$BASE_URL/servers" | head                  # catalog JSON
open "$BASE_URL/"                                    # web catalog page
open "$BASE_URL/ui/servers/<slug>"                   # detail + badge embed
curl -s "$BASE_URL/servers/<slug>/badge.json"       # shields endpoint shape
curl -i -X POST "$BASE_URL/servers/<slug>/scan"     # expect 403 public read-only
test -f /data/mcp-trust/receipts/<receipt>.json     # receipt exists for scanned rows
```

---

## 5. Go public (when ready)

One-way door — the code is already scrubbed (generic names, no secrets/paths).

```bash
gh repo edit "$REPO" --visibility public --accept-visibility-change-consequences
```

---

## 6. Author-badge outreach — the growth loop

Each detail page ships a copy-paste README badge snippet (absolute URL). This is
the distribution engine — prioritize it.

1. Pick 10–20 well-known public MCP servers already in the catalog.
2. Send each author their grade + transparency + the badge snippet from
   `"$BASE_URL/ui/servers/<slug>"`.
3. Offer to re-scan on request. Every embedded badge is a backlink + reach.

CI gate to hand teams (non-zero exit on no record):

```bash
mcp-trust check <slug> --db /data/registry.db || echo "no trust record"
```

---

## 7. Watch these (leading indicators, before any paid layer)

- servers scanned (catalog breadth)
- lookups / day (demand)
- **badges embedded** (the loop is catching)
- authors onboarded
- grade-regression events (the hook for future monitoring)
- receipt views / day (whether evidence is being inspected)

---

## Roadmap (post-v1, named — not silently cut)

- Two-axis polish: surface annotation-coverage trend over time.
- Continuous monitoring + alerting on grade regressions.
- Private/fleet scanning for orgs; enterprise policy enforcement.
- Stronger isolation (gVisor / microVMs) beyond the Docker baseline.
- Purpose-built per-server sandbox images so `--network none` scans run clean.
