# MCP Trust VM Deployment Package

This is the v1 deployment lane: one controlled VM/VPS, a read-only public app,
operator-run Docker scans, persistent SQLite, durable receipts, and nightly
backups.

Public traffic must never launch an MCP server. The public service runs with
`MCP_TRUST_PUBLIC_READONLY=1`.

## Target Layout

```text
/opt/mcp-trust/app
/etc/mcp-trust/mcp-trust.env
/data/mcp-trust/registry.db
/data/mcp-trust/receipts/
/data/mcp-trust/backups/
/var/log/mcp-trust/
```

## VM Baseline

Use a small Ubuntu VM with Docker, Caddy, Git, `uv`, and SQLite:

```bash
sudo apt-get update
sudo apt-get install -y ca-certificates curl git sqlite3 caddy

curl -LsSf https://astral.sh/uv/install.sh | sh

sudo install -d -m 0755 /opt/mcp-trust /etc/mcp-trust /data/mcp-trust/receipts /data/mcp-trust/backups /var/log/mcp-trust
sudo useradd --system --home /opt/mcp-trust --shell /usr/sbin/nologin mcp-trust || true
sudo chown -R mcp-trust:mcp-trust /opt/mcp-trust /data/mcp-trust /var/log/mcp-trust
```

Install Docker Engine using Docker's official Ubuntu instructions, then confirm:

```bash
docker info
```

## App Install

Clone or copy the repo into `/opt/mcp-trust/app`, then install into a venv:

```bash
cd /opt/mcp-trust/app
uv venv .venv
. .venv/bin/activate
uv pip install -e ".[engine]"
```

Copy the env file and keep it secret-owned:

```bash
sudo cp deploy/mcp-trust.env.example /etc/mcp-trust/mcp-trust.env
sudo chown root:mcp-trust /etc/mcp-trust/mcp-trust.env
sudo chmod 0640 /etc/mcp-trust/mcp-trust.env
```

Required public env:

```bash
MCP_TRUST_DB=/data/mcp-trust/registry.db
MCP_TRUST_ENGINE=mcpaudit
MCP_TRUST_PUBLIC_READONLY=1
```

Do not set `MCP_TRUST_ALLOW_UNAUTHENTICATED_STUB_SCANS` on the VM.

## Seed Data And Receipts

Build a sanitized transfer bundle from the workstation after scans pass:

```bash
python scripts/build_deploy_bundle.py \
  --db ./registry.db \
  --receipts-dir ./receipts
```

Upload the resulting `dist/mcp-trust-deploy-bundle-*.tar.gz` to the VM, extract
it, and copy its contents into `/data/mcp-trust/`:

```bash
tar -xzf mcp-trust-deploy-bundle-*.tar.gz
sudo install -m 0644 mcp-trust-deploy-bundle-*/registry.db /data/mcp-trust/registry.db
sudo rsync -a --delete mcp-trust-deploy-bundle-*/receipts/ /data/mcp-trust/receipts/
sudo chown -R mcp-trust:mcp-trust /data/mcp-trust
```

The bundle DB contains only latest scan rows, so historical local rehearsal rows
and absolute local receipt paths are not copied to the VM.

For a fresh VM rehearsal that scans directly on the VM, use the operator shell:

```bash
cd /opt/mcp-trust/app
export MCP_TRUST_DB=/data/mcp-trust/registry.db
export MCP_TRUST_RECEIPTS_DIR=/data/mcp-trust/receipts
export MCP_TRUST_ENGINE=mcpaudit
export MCP_TRUST_SANDBOX=docker
export MCP_TRUST_SANDBOX_NETWORK=none
export MCP_TRUST_SANDBOX_IMAGE=mcp-trust-scan:reference-2026-06-19

.venv/bin/mcp-trust seed
docker build -f Dockerfile.scan -t mcp-trust-scan:reference-2026-06-19 .
.venv/bin/mcp-trust scan mcp-reference-time
python scripts/validate_launch_state.py \
  --db /data/mcp-trust/registry.db \
  --receipts-dir /data/mcp-trust/receipts
```

Run additional approved scans only after the candidate/source/sandbox decision
is recorded in `LAUNCH-CATALOG.md`.

## Systemd Service

Install and start the read-only API service:

```bash
sudo cp deploy/mcp-trust.service /etc/systemd/system/mcp-trust.service
sudo systemctl daemon-reload
sudo systemctl enable --now mcp-trust.service
sudo systemctl status mcp-trust.service
```

The service binds to `127.0.0.1:8000`. It should not be reachable directly from
the public internet.

## Caddy Reverse Proxy

Edit `deploy/Caddyfile` and replace:

- `admin@example.com`
- `mcptrust.example.com`

Then install it:

```bash
sudo cp deploy/Caddyfile /etc/caddy/Caddyfile
sudo caddy validate --config /etc/caddy/Caddyfile
sudo systemctl reload caddy
```

## Nightly Backups

Install the backup units:

```bash
sudo cp deploy/mcp-trust-backup.service /etc/systemd/system/mcp-trust-backup.service
sudo cp deploy/mcp-trust-backup.timer /etc/systemd/system/mcp-trust-backup.timer
sudo systemctl daemon-reload
sudo systemctl enable --now mcp-trust-backup.timer
sudo systemctl start mcp-trust-backup.service
sudo systemctl status mcp-trust-backup.service
```

The backup script writes:

```text
/data/mcp-trust/backups/registry-<timestamp>.db
/data/mcp-trust/backups/receipts-<timestamp>.tar.gz
```

After the first backup, copy at least one DB backup and one receipt tarball
off-box.

## Read-Only Smoke

Run this from the VM or your workstation after DNS/HTTPS is live:

```bash
BASE_URL=https://mcptrust.example.com SLUG=mcp-reference-time ./deploy/smoke-readonly.sh
```

Before the smoke, run the offline state verifier on the VM:

```bash
python scripts/validate_launch_state.py \
  --db /data/mcp-trust/registry.db \
  --receipts-dir /data/mcp-trust/receipts
```

Manual checks:

```bash
curl -s "$BASE_URL/healthz"
curl -s "$BASE_URL/servers" | head
open "$BASE_URL/"
open "$BASE_URL/ui/servers/mcp-reference-time"
curl -s "$BASE_URL/servers/mcp-reference-time/badge.json"
curl -i -X POST "$BASE_URL/servers/mcp-reference-time/scan"
```

Expected `POST /scan` result: `403 Forbidden`.

## Rollback

Use the last known-good git checkout plus the last known-good DB backup:

```bash
sudo systemctl stop mcp-trust.service
sudo cp /data/mcp-trust/backups/registry-<timestamp>.db /data/mcp-trust/registry.db
sudo chown mcp-trust:mcp-trust /data/mcp-trust/registry.db
cd /opt/mcp-trust/app
git checkout <known-good-ref>
. .venv/bin/activate
uv pip install -e ".[engine]"
sudo systemctl start mcp-trust.service
```

Then rerun the read-only smoke.

## Launch Gate

Do not make the repo/site public until:

- `systemctl status mcp-trust.service` is healthy.
- Caddy serves HTTPS for the final domain.
- `deploy/smoke-readonly.sh` passes against the public base URL.
- `POST /servers/<slug>/scan` returns 403 publicly.
- At least one backup has been created and copied off-box.
- `LAUNCH-GATE.md` is updated with deployed evidence.
