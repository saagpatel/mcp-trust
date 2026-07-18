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
- A final public URL for `--base-url` (currently
  `https://mcp-trust.vercel.app`) so badge embeds resolve against the live host.

## 1. Build the static site from real data

`DOMAIN` must be the final public URL so README badge-embed snippets point at the
live host. The build is read-only against `registry.db`; it never scans.

```bash
DOMAIN="https://mcp-trust.vercel.app"
uv run python scripts/build_site.py \
  --db ./registry.db \
  --out site \
  --base-url "$DOMAIN"
# Expect the current seeded/scanned count, for example:
# "Built static site for 19 server(s) (19 scanned) ... VERIFY OK"
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

- Catalog (`/`) lists all seeded servers with A–F grades and **no `DEMO DATA` banner**
  (real scans → no demo label).
- A detail page (`/ui/servers/mcp-reference-filesystem`) renders the grade,
  transparency, findings, and the badge-embed snippet.
- `/servers/mcp-reference-time/badge.json` returns a shields.io endpoint payload
  (`"message": "A"`, no `(demo)` suffix).
- An unknown path (e.g. `/nope`) serves the 404 page.

## 3. Production deploy (operator action — public)

Production deployment is available only through
`scripts/deploy_production.sh`. Direct production CLI calls and
`MCP_TRUST_AUTO_DEPLOY` are unsupported.

The operator must create a mode-`0600`, non-symlinked, short-lived JSON approval
using schema `McpTrustProductionDeployAuthorizationV1`. It binds its own exact
absolute path plus repository root, `main` branch, full commit SHA, production
URL, the repository-pinned Vercel project and organization IDs, canonical
GitHub origin, absolute Vercel executable path and SHA-256, an exact
deterministic digest of every file in `site/`, receipt ID, issuance time, and
expiry no more than 15 minutes later. Symlinks and special files in `site/` are
rejected. The ignored output digest, provider link, approval, and tool bytes are
revalidated after confirmation and immediately before the provider call.
The manual entrypoint separately requires those exact values and requires the
operator to type `DEPLOY_MCP_TRUST_PRODUCTION` at a live interactive TTY after
the approval validates; the confirmation cannot be supplied by argument or
environment.

Before provider credentials are considered, the entrypoint rejects scheduler
context, detached or feature branches, a dirty or untracked worktree, HEAD/SHA
mismatch, a non-`origin/main` upstream, any ahead/behind state, a commit absent
from that upstream, a substituted target, a copied/mismatched/stale approval,
and an unapproved deployment executable. `VERCEL_TOKEN` is required only after
all local gates pass.

These controls provide strong same-user accident resistance and auditable
manual intent. They are not represented as adversarial isolation from another
process already running as the same macOS user; such a process can scrub
environment markers and allocate a pseudo-terminal.

Then point your domain at the Vercel project (Vercel dashboard → Domains) and
re-run the badge check against the production URL.

## 4. Scheduled freshness

`scripts/refresh_and_publish.sh` is now a compatibility wrapper that creates an
immutable refresh candidate only. It scans an isolated SQLite copy in the
network-off Docker sandbox for local-process sources. Remote sources use their
live network transport without a local process sandbox and may make outbound
connections; their receipts and public records label that mode explicitly. The
wrapper fails closed on unavailable required images, missing receipts/evidence,
or partial scans. It does not mutate `registry.db`, rebuild the canonical site,
publish, or deploy. The installer writes a weekly definition and leaves it
unloaded and persistently disabled:

```bash
bash deploy/launchd/install.sh            # Sunday 19:00 definition; remains disabled
bash deploy/launchd/uninstall.sh          # remove the job
```

Do not enable or start the job as an installation test. A future enablement
requires a separate operator decision plus Docker/image, template parity,
focused-test, and ownership evidence. Re-scanning a version-pinned image is
deterministic; to catch upstream drift, periodically rebuild `Dockerfile.scan`
with current server versions.

Manual candidate publication is a separate local staging action:

```bash
uv run --frozen python scripts/refresh_candidate.py verify <candidate>
uv run --frozen python scripts/refresh_candidate.py approve <candidate> \
  --approval <approval.json> --actor <operator> --reason <reason> \
  --target <local-staging-dir> --confirm-manifest-sha256 <verified-digest>
uv run --frozen python scripts/refresh_candidate.py publish <candidate> \
  --approval <approval.json> --destination <local-staging-dir>
```

The approval is short-lived and bound to the exact manifest and local target.
This staging step grants no Vercel or public-deployment authority.

## Safety notes

- `registry.db` and `receipts/` are **never** uploaded — only `site/`.
- launchd and the refresh script never hold production deployment authority.
- The static site is read-only; there is no scan-trigger endpoint to protect
  (unlike the VM service). Local-process re-scans happen behind the sandbox;
  remote-source re-scans use live network transport and are labeled accordingly.
- Grades are honest by construction: stub/demo data carries a loud banner and
  `(demo)`-suffixed badges; only real `mcpaudit` scans render bare grades.
