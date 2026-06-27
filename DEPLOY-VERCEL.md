# Deploy: static catalog → Vercel

Low-ops launch path: render the catalog to static HTML/JSON **locally**, then
deploy the rendered output to Vercel. This is the alternative to the always-on
VM service documented in `DEPLOY-VM.md`.

## Why build locally (not on Vercel)

The site is generated from `registry.db`, which holds scan data and is **never
committed** (`.gitignore`). So Vercel cannot build from a fresh `git clone`.
Instead, the build runs where the data lives (your machine or a scheduled job),
and only the **public-safe rendered output** (`site/`) is uploaded. The raw scan
database and receipts stay local. Freshness comes from re-running the build on a
schedule (see `Scheduled freshness`), not from Vercel's Git integration.

## Prerequisites

- The Vercel CLI is installed and you are logged in (`vercel login`).
- A Vercel project exists (or accept the prompts on first `vercel` run).
- A domain you control, to set `--base-url` (badge embeds resolve against it).

## 1. Build the static site from real data

`DOMAIN` must be the final public URL so README badge-embed snippets point at the
live host. The build is read-only against `registry.db`; it never scans.

```bash
DOMAIN="https://<your-domain>"
uv run python scripts/build_site.py \
  --db ./registry.db \
  --out site \
  --base-url "$DOMAIN"
# Expect: "Built static site for 7 server(s) (7 scanned) ... VERIFY OK"
```

Ship the deploy config with the rendered output so headers/CSP/clean-URLs apply:

```bash
cp deploy/vercel.json site/vercel.json
```

## 2. Preview deploy (no production traffic)

```bash
vercel deploy site                 # prints a preview URL
```

Open the preview URL and confirm, on the real grades:

- Catalog (`/`) lists all 7 servers with A–F grades and **no `DEMO DATA` banner**
  (real scans → no demo label).
- A detail page (`/ui/servers/mcp-reference-filesystem`) renders the grade,
  transparency, findings, and the badge-embed snippet.
- `/servers/mcp-reference-time/badge.json` returns a shields.io endpoint payload
  (`"message": "A"`, no `(demo)` suffix).
- An unknown path (e.g. `/nope`) serves the 404 page.

## 3. Production deploy (operator action — public)

```bash
vercel deploy site --prod          # promotes to the production domain
```

Then point your domain at the Vercel project (Vercel dashboard → Domains) and
re-run the badge check against the production URL.

## 4. Scheduled freshness

Re-render and redeploy on a cadence so grades stay current. A scheduled job runs:

```bash
# scan the reference corpus (network-off Docker sandbox) → rebuild → redeploy
# (engine env from LAUNCH-GATE.md "Next Command Lane")
uv run python scripts/build_site.py --db ./registry.db --out site --base-url "$DOMAIN"
cp deploy/vercel.json site/vercel.json
vercel deploy site --prod
```

A `launchd` wrapper for this is the next slice (see the session CONTINUE).

## Safety notes

- `registry.db` and `receipts/` are **never** uploaded — only `site/`.
- The static site is read-only; there is no scan-trigger endpoint to protect
  (unlike the VM service). Re-scans happen locally, behind the sandbox.
- Grades are honest by construction: stub/demo data carries a loud banner and
  `(demo)`-suffixed badges; only real `mcpaudit` scans render bare grades.
