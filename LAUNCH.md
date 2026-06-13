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
python -m pytest -q          # expect: all pass, 2 opt-in skips
ruff check src tests         # expect: All checks passed!
```

Optional, with the real engine:

```bash
uv pip install -e ".[dev,engine]"
MCP_TRUST_RUN_INTEGRATION=1 python -m pytest tests/test_mcpaudit_adapter.py -q
```

---

## 1. Seed the real catalog + calibrate bands  ⟵ do this BEFORE going public

The grade is only meaningful against a real distribution.

1. Edit `src/mcp_trust/catalog/seed_servers.json` — replace the generic demo
   entries with real, public MCP servers (slug, name, source `{kind, reference,
   args, env_keys}`, homepage). Keep `env_keys` to NAMES only.
2. Load + scan with the real engine in a sandbox (see step 3 for the image):

   ```bash
   export MCP_TRUST_DB=./registry.db
   mcp-trust seed
   MCP_TRUST_ENGINE=mcpaudit MCP_TRUST_SANDBOX=docker mcp-trust scan <slug>   # per server
   ```
3. Calibrate the bands against the observed distribution. Re-run the corpus
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

```dockerfile
# Dockerfile.scan — runtime for sandboxed scans
FROM node:22-slim
RUN apt-get update && apt-get install -y --no-install-recommends python3 pipx \
    && rm -rf /var/lib/apt/lists/* && pipx install uv
# Optionally pre-install servers here so they run with --network none.
```

```bash
docker build -f Dockerfile.scan -t mcp-trust-scan .
export MCP_TRUST_SANDBOX=docker
export MCP_TRUST_SANDBOX_IMAGE=mcp-trust-scan
# Use MCP_TRUST_SANDBOX_NETWORK=bridge ONLY for servers you must fetch at launch.
```

Start the Docker daemon before running the integration-gated container path.

---

## 3. Deploy the API

Standard FastAPI app (`mcp_trust.api.app:app`).

```bash
# Local / VM:
MCP_TRUST_DB=/data/registry.db MCP_TRUST_ENGINE=mcpaudit \
  uvicorn mcp_trust.api.app:app --host 0.0.0.0 --port 8000
```

For a managed host (Fly.io / Railway / Render / Cloud Run): containerize with a
production server, mount a persistent volume for the SQLite DB, and set env:
`MCP_TRUST_DB`, `MCP_TRUST_ENGINE=mcpaudit`, `MCP_TRUST_SANDBOX=docker`,
`MCP_TRUST_SANDBOX_IMAGE`. Confirm `BASE_URL` resolves to the deployed app.

---

## 4. Smoke test live

```bash
curl -s "$BASE_URL/healthz"                         # {"status":"ok"}
curl -s "$BASE_URL/servers" | head                  # catalog JSON
open "$BASE_URL/"                                    # web catalog page
open "$BASE_URL/ui/servers/<slug>"                   # detail + badge embed
curl -s "$BASE_URL/servers/<slug>/badge.json"       # shields endpoint shape
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

---

## Roadmap (post-v1, named — not silently cut)

- Two-axis polish: surface annotation-coverage trend over time.
- Continuous monitoring + alerting on grade regressions.
- Private/fleet scanning for orgs; enterprise policy enforcement.
- Stronger isolation (gVisor / microVMs) beyond the Docker baseline.
- Purpose-built per-server sandbox images so `--network none` scans run clean.
