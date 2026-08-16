# MCP Trust Registry

<!-- mcp-name: io.github.saagpatel/mcp-trust -->

[![CI](https://github.com/saagpatel/mcp-trust/actions/workflows/ci.yml/badge.svg)](https://github.com/saagpatel/mcp-trust/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)

> Check before you connect. A neutral, public danger grade for the MCP servers
> your AI agents rely on.

**Live:** [mcp-trust.vercel.app](https://mcp-trust.vercel.app)

> **Not yet published to PyPI.** Install from source using the Quickstart below.

## Use as an MCP server

`mcp-trust` runs as a read-only MCP server so an agent can check a server's
danger grade *before connecting* — it serves a baked snapshot of real scan
grades with explicit per-record provenance, so no database or network is needed.

```bash
mcp-trust mcp-serve          # from a source/dev install (works today)
uvx mcp-trust mcp-serve      # once published to PyPI
```

| Tool | Description |
|---|---|
| `list_servers` | Every graded MCP server with its A-F grade, transparency, and danger score. |
| `check_server` | Full grade, risk dimensions, and findings for one server by slug. |
| `get_methodology` | How the A-F grade and transparency axis are computed, plus the honesty model. |

The MCP runtime admits the packaged catalog only after deterministic schema-v2
validation, including duplicate-key rejection, required field/type checks, unique
slugs and source coordinates, supported enums, sandbox/scan-mode agreement, and
timezone-aware scan timestamps. Admission also binds grade to danger score,
transparency to annotation coverage, and critical findings to the grade cap.
Raw JSON is limited to 1 MiB, with deterministic server, finding, tool, and
public-string ceilings. Schema v2 preserves additive unknown fields; missing or
invalid required fields and unknown schema versions fail closed.

If catalog admission fails, `list_servers` and `check_server` serve zero records
and return `mcp-trust-mcp-error.v1` with status `UNKNOWN`, error code
`CATALOG_SNAPSHOT_INVALID`, sorted reason codes, and `server_count_served: 0`.
`get_methodology` remains available. This boundary checks internal consistency;
it does not prove snapshot authenticity, authorship, immutability, or freshness.

Offline consumers can add those missing publication checks with
`mcp-trust verify-snapshot`: a detached Ed25519 statement binds the exact
snapshot bytes, publisher ID, bounded issue/expiry window, monotonic publication
ID, and prior consumer checkpoint. The consumer must independently pin the
trust-root SHA-256 and preserve the returned checkpoint for rollback resistance.
Invalid, expired, unknown-signer, forked, or rolled-back inputs return only
`UNKNOWN` reason codes and no grades. See
[`docs/OFFLINE-SNAPSHOT-TRUST-V1.md`](docs/OFFLINE-SNAPSHOT-TRUST-V1.md).
Statement freshness proves recent publication authorization, not a recent scan;
the per-record scan timestamp and 90-day stale policy remain separate checks.

No production trust root, signing key, statement, or checkpoint ships today, so
the built-in MCP snapshot remains structural-only unless a consumer separately
supplies and pins those inputs. Test fixture keys are not publication keys.

Connecting an MCP server hands it influence over what your agent does. Tool
poisoning, prompt injection, over-broad permissions, and rug-pull tool
mutations are documented attack classes -- and today there's no quick way to vet
a server before you wire it in. **MCP Trust Registry** scans public MCP servers
and gives each one a single readable danger grade (A-F), a separate
transparency signal, and the findings behind them.

Think OSV.dev / Socket.dev / haveibeenpwned, scoped to MCP servers.

## Prerequisites

- Python >= 3.11
- [`uv`](https://docs.astral.sh/uv/) (used for dependency management and running the project)

## MCP config portability studio

Render one versioned, secret-placeholder-only MCP connection intent into staged
Codex, Claude Code, Claude Desktop, or VS Code configuration and receive an
explicit semantic loss/widening report:

```bash
uv run --frozen --extra dev mcp-trust portability validate \
  tests/fixtures/portability/local-stdio.json
uv run --frozen --extra dev mcp-trust portability round-trip \
  tests/fixtures/portability/local-stdio.json --host codex
```

The studio is local-only. It never discovers or edits a real host config,
launches an MCP server, contacts a URL, or emits modeled secret values. Generated
configuration proves only documented host-format compatibility, not a runtime
connection or adoption. See
[`docs/MCP-CONFIG-PORTABILITY-STUDIO.md`](docs/MCP-CONFIG-PORTABILITY-STUDIO.md).

## How it works

```
register a server  ->  scan via engine  ->  derive grade  ->  persist  ->  serve at a stable URL
```

The registry does **not** reimplement vulnerability detection. It orchestrates a
pluggable scan engine -- the shipping backend wraps the public
[`mcp-audits`](https://pypi.org/project/mcp-audits/) (>=2.1) package -- and owns the
catalog, the public trust-grade normalization, persistence, and the lookup API.

## Quickstart

```bash
git clone https://github.com/saagpatel/mcp-trust.git && cd mcp-trust
uv pip install -e ".[dev]"      # core + dev deps (runs on the built-in StubEngine)
mcp-trust seed                  # load the seed catalog
mcp-trust scan mcp-reference-time   # scan a catalog server, print its grade
mcp-trust check mcp-reference-time  # look up the latest stored grade
mcp-trust serve                 # serve the API on http://127.0.0.1:8000
```

For real scanning install the engine extra and select it:

```bash
uv pip install -e ".[dev,engine]"
MCP_TRUST_ENGINE=mcpaudit mcp-trust scan mcp-reference-time
```

Scanning launches the server's process. For **untrusted** servers, isolate
execution in a locked-down container (no network, read-only fs, dropped caps,
resource limits):

```bash
MCP_TRUST_ENGINE=mcpaudit MCP_TRUST_SANDBOX=docker mcp-trust scan mcp-reference-time
```

The default is no sandbox (safe only for servers you trust).

## API

| Method | Path | Purpose |
|---|---|---|
| `GET`  | `/` | **web** -- public catalog page (grade + transparency per server) |
| `GET`  | `/ui/servers/{slug}` | **web** -- server detail page + README badge-embed snippet |
| `GET`  | `/healthz` | liveness |
| `GET`  | `/servers` | catalog + latest grade, provenance, and staleness per server (JSON) |
| `GET`  | `/servers/{slug}` | full latest scan record + provenance/staleness and metadata (JSON) |
| `POST` | `/servers/{slug}/scan` | operator scan trigger; public deployments disable this route |
| `GET`  | `/servers/{slug}/badge.json` | shields.io-compatible README badge |

Every server has two orthogonal signals: a **danger grade** (A-F) and a
**transparency level** (high/medium/low, from annotation coverage). Automated
grades are not endorsements, certifications, or claims that a server is
malicious. A low grade on a low-transparency server means "cannot verify safe,"
not "known dangerous."

HTTP scan triggering is fail-closed by default. Public deployments should set
`MCP_TRUST_PUBLIC_READONLY=1`, which makes `POST /servers/{slug}/scan` return
403 before any engine can run. Operator scans should normally run through the
CLI against the persistent registry DB, not through public traffic.

For local API demos with the deterministic `StubEngine`, set
`MCP_TRUST_ALLOW_UNAUTHENTICATED_STUB_SCANS=1`. Do **not** set that in public.
Token-gated API scan triggering is still available for private operator surfaces
by setting `MCP_TRUST_SCAN_TOKEN` and passing it as `Authorization: Bearer
<token>` or `X-MCP-Trust-Scan-Token`.

If the newest stored scan row is unreadable, API, web, static, badge, and
snapshot projections fail closed to `UNKNOWN`; they never resurrect an older
grade. Stored source/risk/finding/evidence JSON has a 1 MiB per-field admission
ceiling, with bounded finding/tool collections and content-free diagnostics.
An unreadable older row leaves a readable latest grade intact but makes scan
history and grade-change claims explicitly `UNKNOWN`. Snapshot construction
stops until unreadable history is repaired or dispositioned.

Set `MCP_TRUST_RECEIPTS_DIR=/data/mcp-trust/receipts` during real scan runs to
archive a JSON receipt for each scan and store its portable artifact filename in
`report_ref`.

## Remote authorization metadata preflight

Remote Registry candidates can be checked for discoverable MCP authorization
metadata without contacting the MCP endpoint or handling credentials. First
build a candidate manifest from a previously saved official Registry response,
then select one exact `stable_id`:

```bash
uv run python scripts/plan_registry_corpus.py \
  --input path/to/saved-registry-response.json > /tmp/registry-candidates.json

uv run mcp-trust auth-posture com.example/remote@1.0.0 \
  --manifest /tmp/registry-candidates.json \
  --pretty
```

If a public `WWW-Authenticate: Bearer` challenge has already been obtained by a
separate operator workflow, pass its value with `--www-authenticate`. Otherwise
the command tries the MCP-required protected-resource well-known paths, followed
by RFC 8414 and OpenID Connect authorization-server discovery in specification
order.

The command emits `McpAuthorizationPostureV1` JSON. Exit 0 and
`state=metadata-ready` mean only that at least one authorization server exposes
the endpoints and PKCE `S256` metadata needed for policy review. They do **not**
prove authorization, credential availability, runtime security, scan
eligibility, or a trust grade. Unknown or invalid evidence exits 1 and stays
blocked; an invalid local manifest binding exits 2.

The network boundary is deliberately narrow: HTTPS metadata GETs only, no
ambient proxies, redirects, credentials, endpoint session, or writes. DNS is
resolved once per request; every answer must be globally routable, and the
connection is pinned to an accepted address while TLS validation and SNI remain
bound to the original hostname. Response bodies are size-bounded, validated,
and represented in output only by byte count and SHA-256. Successful metadata
responses must also carry a valid HTTP `Date`; declared cache freshness is
honored up to a 24-hour policy cap, while missing, future-dated, or stale source
evidence remains unknown. The implementation is based on the
[MCP authorization specification](https://modelcontextprotocol.io/specification/2025-11-25/basic/authorization),
[RFC 9728](https://www.rfc-editor.org/rfc/rfc9728.html),
[RFC 8414](https://www.rfc-editor.org/rfc/rfc8414.html), and
[OpenID Connect Discovery](https://openid.net/specs/openid-connect-discovery-1_0.html).

## Reusable web release readback

This repository owns the language-neutral `WebReleaseReadbackV1` contract and
its standard-library reference verifier. A consumer supplies an explicit HTTPS
origin plus a versioned route-sentinel manifest:

```bash
python scripts/web_release_readback.py \
  --manifest path/to/release-routes.json \
  --target-url https://preview.example.com \
  --pretty
```

The command emits one structured receipt to stdout and exits nonzero when any
status, required or forbidden sentinel, exact body, digest, body bound, timeout,
or redirect assertion fails. It implements only GET and HEAD, ignores ambient
proxies, accepts no credentials, and has no deployment, alias, DNS, promotion,
or rollback capability. The schemas, deterministic artifact manifest, versioning
policy, and rollback boundary live under
`contracts/web-release-readback-v1/`.

The owner repository also consumes the contract through
`deploy/web-release-readback.json`. `deploy/smoke-readonly.sh` emits the shared
route receipt before running the registry-specific health, API, badge, portable
receipt-reference, and denied scan-POST assertions. This self-adoption is a
release readback check only; it neither deploys nor changes an alias.

This generic receipt is additive. Product-specific API, badge, privacy, release
lineage, and denied-mutation checks remain owned by each consumer until proven
receipt parity justifies removing only their duplicated HTTP assertion plumbing.

## Evidence lineage decisions

`EvidenceLineageLedgerV1` is a metadata-only, fail-closed contract for MCP
corpus admit, refresh, publish, and withdraw decisions. It binds exact identity,
digests, portable receipt references, freshness, rights evidence, public
projections, supersession, and retention without storing raw logs or secrets.
The read-only assessor requires an explicit observation time and emits stable
reason codes; only an explicit `ALLOWED` status can authorize admit or publish.

See [`docs/EVIDENCE-LINEAGE-LEDGER-V1.md`](docs/EVIDENCE-LINEAGE-LEDGER-V1.md)
for the schema, decision semantics, three-record packaged-catalog pilot, claim
ceiling, and rollback boundary. This source capability does not itself migrate
the catalog, publish or withdraw records, run scans, or change deployment state.

## Manual refresh candidates

Create a review candidate without mutating the canonical registry, baked
snapshot, static site, schedule, or deployment:

```bash
uv run --frozen --extra engine python scripts/refresh_candidate.py create \
  --db ./registry.db \
  --out-dir ./dist/refresh-candidates
```

The command refuses local-process scans unless Docker and every catalog-pinned
image are already available locally. Those sources run through the existing
network-off, read-only, capability-dropped, resource-bounded sandbox. Remote
endpoints are probed over their live network transport without a local process
sandbox and are labeled accordingly. The immutable bundle contains receipts,
catalog identity, scan times and ages, masked/failed/unknown evidence states,
attributed scan drift, an honest static snapshot, and a content-bound manifest.

Candidate creation has no publication or deployment authority. A structurally
valid candidate must first pass `verify`, then receive a separate digest-bound,
short-lived `approve` receipt before `publish` may stage it in a local output
directory. `verify` exits successfully only for a current, complete,
reviewed-input-bound candidate that is eligible for publication. Eligibility
never grants approval, publication, deployment, or scheduling authority.

Snapshot signing is a separate authority after candidate approval/staging. The
refresh process never receives a signing or recovery key, and its SHA-256
manifest is not a publisher identity. Production signing remains disabled until
an operator chooses the root, custody, thresholds, publication counter, and
checkpoint owner described in the offline trust contract.

## Status

**Live** at [mcp-trust.vercel.app](https://mcp-trust.vercel.app) as a statically
generated catalog, regenerated from the local registry. The bundled catalog
snapshot contains 23 visible real `mcp-audits` grades; eight reviewed entries
are withheld by `masked-grades.json` and are absent from the public snapshot.
The bundled snapshot labels the visible local-process grades' network and
sandbox provenance as unknown; only a receipt-verified refresh candidate may
claim network-off execution. Every grade is labeled by provenance, so
demo/stub data can never read as a real scan, and an unscanned server never
shows a letter grade. The current production deployment is the 31-server
static catalog; grades are static since 2026-07-11, when the weekly re-scan
lane was disabled and its deploy authority removed (see
`docs/CAPABILITY-RULING-2026-07-10.md`).

The static front door is the low-ops launch path (see
[`DEPLOY-VERCEL.md`](DEPLOY-VERCEL.md)); a weekly `launchd` job under
[`deploy/launchd/`](deploy/launchd/) remains installed but disabled. Its
compatibility entrypoint can create a local review candidate only; it cannot
publish or deploy. The live FastAPI service + VM path remains
documented in [`DEPLOY-VM.md`](DEPLOY-VM.md) as an alternative. See
[`SPEC.md`](SPEC.md) for the full contract and [`LAUNCH-GATE.md`](LAUNCH-GATE.md)
for launch history. The deployed catalog reports scan timestamps as its
freshness authority; static HTML does not claim to attest machine-local
scheduler state.

## Contributing

`uv.lock` is intentionally committed to the repository to ensure reproducible
installs across environments. When adding or updating dependencies, commit the
updated `uv.lock` alongside your `pyproject.toml` changes.

## License

MIT
