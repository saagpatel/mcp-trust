"""MCP Census: a local, one-page report on the official MCP Registry.

Reads only the registry's public REST API (``/v0.1/servers``, latest versions),
paged with its cursor. Servers are never contacted. Every figure is written as
a CSV beside a self-contained ``index.html``, plus the per-server rows and a
JSON summary, so each number links to the data behind it.

Wording stays neutral: listing a deprecated transport is reported as a count,
never as a judgement of any publisher, and the catalog-card section reports
only aggregates.
"""

from __future__ import annotations

import csv
import io
import json
import re
import urllib.error
import urllib.request
from collections import Counter
from collections.abc import Callable, Iterable
from dataclasses import dataclass, field
from datetime import UTC, datetime
from html import escape
from pathlib import Path
from typing import Any
from urllib.parse import quote, urlsplit

REGISTRY_URL = "https://registry.modelcontextprotocol.io"
PAGE_LIMIT = 100
MAX_PAGES = 1000
MAX_PAGE_BYTES = 8 * 1024 * 1024
FETCH_TIMEOUT = 30.0
USER_AGENT = "mcp-trust-census (+https://github.com/saagpatel/mcp-trust)"
_OFFICIAL = "io.modelcontextprotocol.registry/official"
_SCHEMA_DATE = re.compile(r"/schemas/(\d{4}-\d{2}-\d{2})/")

Fetch = Callable[[str], Any]


class CensusError(RuntimeError):
    """The registry could not be read; no report is written."""


def registry_fetcher(registry_url: str = REGISTRY_URL) -> Fetch:
    """Bounded HTTPS JSON reads from the registry host only, no redirects elsewhere."""
    host = urlsplit(registry_url).hostname

    class _SameHost(urllib.request.HTTPRedirectHandler):
        def redirect_request(
            self, req: Any, fp: Any, code: int, msg: str, hdrs: Any, newurl: str
        ) -> Any:
            if urlsplit(newurl).scheme != "https" or urlsplit(newurl).hostname != host:
                raise CensusError("registry redirected off its host")
            return super().redirect_request(req, fp, code, msg, hdrs, newurl)

    opener = urllib.request.build_opener(_SameHost())

    def fetch(url: str) -> Any:
        parts = urlsplit(url)
        if parts.scheme != "https" or parts.hostname != host:
            raise CensusError("refusing a URL outside the registry host")
        request = urllib.request.Request(
            url, headers={"User-Agent": USER_AGENT, "Accept": "application/json"}
        )
        try:
            with opener.open(request, timeout=FETCH_TIMEOUT) as response:
                raw = response.read(MAX_PAGE_BYTES + 1)
        except (urllib.error.URLError, TimeoutError, OSError) as exc:
            raise CensusError(f"registry read failed ({type(exc).__name__})") from None
        if len(raw) > MAX_PAGE_BYTES:
            raise CensusError("a registry page exceeded the size cap")
        try:
            return json.loads(raw.decode("utf-8"))
        except (UnicodeDecodeError, ValueError):
            raise CensusError("a registry page was not JSON") from None

    return fetch


def fetch_latest(
    fetch: Fetch, registry_url: str = REGISTRY_URL, max_pages: int = MAX_PAGES
) -> tuple[list[dict[str, Any]], int, bool]:
    """All latest-version entries; returns (entries, pages read, truncated at max_pages)."""
    entries: list[dict[str, Any]] = []
    cursor: str | None = None
    for page in range(1, max_pages + 1):
        url = f"{registry_url.rstrip('/')}/v0.1/servers?limit={PAGE_LIMIT}&version=latest"
        if cursor:
            url += f"&cursor={quote(cursor, safe='')}"
        payload = fetch(url)
        if not isinstance(payload, dict) or not isinstance(payload.get("servers"), list):
            raise CensusError("unexpected registry page shape")
        entries.extend(e for e in payload["servers"] if isinstance(e, dict))
        metadata = payload.get("metadata")
        cursor = metadata.get("nextCursor") if isinstance(metadata, dict) else None
        if not isinstance(cursor, str) or not cursor:
            return entries, page, False
    return entries, max_pages, True


def _dict(value: object) -> dict[str, Any]:
    return value if isinstance(value, dict) else {}


def _list(value: object) -> list[Any]:
    return value if isinstance(value, list) else []


def _str(value: object) -> str | None:
    return value if isinstance(value, str) and value else None


@dataclass(frozen=True)
class Row:
    """One registry server, reduced to the fields the census counts."""

    name: str
    publisher: str
    namespace_kind: str
    status: str
    schema_version: str
    registry_types: tuple[str, ...]
    package_transports: tuple[str, ...]
    remote_transports: tuple[str, ...]

    @property
    def offers_sse(self) -> bool:
        return "sse" in self.remote_transports or "sse" in self.package_transports

    @property
    def remote_sse_only(self) -> bool:
        return bool(self.remote_transports) and set(self.remote_transports) == {"sse"}


def to_row(entry: dict[str, Any]) -> Row | None:
    server = _dict(entry.get("server")) or entry
    name = _str(server.get("name"))
    if name is None:
        return None
    namespace = name.split("/", 1)[0].lower()
    if namespace.startswith("io.github."):
        kind, publisher = "GitHub account", namespace.removeprefix("io.github.")
    else:
        kind, publisher = "domain", ".".join(reversed(namespace.split(".")))
    schema = _str(server.get("$schema")) or ""
    dated = _SCHEMA_DATE.search(schema)
    version = dated.group(1) if dated else ("other" if schema else "not declared")
    packages = [_dict(p) for p in _list(server.get("packages"))]
    remotes = [_dict(r) for r in _list(server.get("remotes"))]
    status = _str(_dict(_dict(entry.get("_meta")).get(_OFFICIAL)).get("status")) or "unknown"
    return Row(
        name=name,
        publisher=publisher,
        namespace_kind=kind,
        status=status,
        schema_version=version,
        registry_types=tuple(sorted({_str(p.get("registryType")) or "other" for p in packages})),
        package_transports=tuple(
            sorted({_str(_dict(p.get("transport")).get("type")) or "unspecified" for p in packages})
        ),
        remote_transports=tuple(sorted({_str(r.get("type")) or "unspecified" for r in remotes})),
    )


@dataclass
class Figure:
    """A titled table; written to data/<key>.csv and linked from the page."""

    key: str
    title: str
    note: str
    columns: tuple[str, ...]
    rows: list[tuple[object, ...]] = field(default_factory=list)


def _share(count: int, total: int) -> str:
    return f"{100 * count / total:.1f}%" if total else "0.0%"


def _counted(key: str, title: str, note: str, counter: Counter[str], total: int) -> Figure:
    rows: list[tuple[object, ...]] = [
        (label, count, _share(count, total)) for label, count in counter.most_common()
    ]
    return Figure(key, title, note, ("value", "servers", "share"), rows)


def build_figures(rows: list[Row], cards: list[dict[str, Any]]) -> list[Figure]:
    total = len(rows)
    publishers = Counter(r.publisher for r in rows)
    with_packages = sum(1 for r in rows if r.registry_types)
    with_remotes = sum(1 for r in rows if r.remote_transports)
    both = sum(1 for r in rows if r.registry_types and r.remote_transports)
    remote_rows = [r for r in rows if r.remote_transports]
    overview = Figure(
        "overview",
        "Overview",
        "Latest version of every server listed in the official MCP Registry.",
        ("measure", "count"),
        [
            ("servers listed", total),
            ("distinct publishers", len(publishers)),
            ("offer a package", with_packages),
            ("offer a remote endpoint", with_remotes),
            ("offer both", both),
        ],
    )
    sizes = Counter(
        "1 server"
        if n == 1
        else "2-5 servers"
        if n <= 5
        else "6-20 servers"
        if n <= 20
        else "21+ servers"
        for n in publishers.values()
    )
    publisher_sizes = Figure(
        "publisher-sizes",
        "How many servers each publisher lists",
        "Publishers grouped by how many servers they list.",
        ("group", "publishers", "share of publishers"),
        [
            (g, sizes[g], _share(sizes[g], len(publishers)))
            for g in ("1 server", "2-5 servers", "6-20 servers", "21+ servers")
        ],
    )
    top = Figure(
        "top-publishers",
        "Publishers with the most listed servers",
        "The ten namespaces with the most entries; a count of listings, not a ranking of quality.",
        ("publisher", "servers"),
        [(name, count) for name, count in publishers.most_common(10)],
    )
    namespaces = _counted(
        "namespace-kinds",
        "Namespace kinds",
        "Registry names are either a verified GitHub account (io.github.*) or a verified domain.",
        Counter(r.namespace_kind for r in rows),
        total,
    )
    statuses = _counted(
        "status",
        "Registry status",
        "Status the registry reports for the latest version.",
        Counter(r.status for r in rows),
        total,
    )
    registries = _counted(
        "package-registries",
        "Package registries",
        "Where packaged servers are published; a server can list several.",
        Counter(t for r in rows for t in r.registry_types),
        with_packages,
    )
    package_transports = _counted(
        "package-transports",
        "Package transports",
        "Transport declared for each packaged server; a server can declare several.",
        Counter(t for r in rows for t in r.package_transports),
        with_packages,
    )
    remote_transports = _counted(
        "remote-transports",
        "Remote endpoint transports",
        "Transport of each remote endpoint; a server can list several.",
        Counter(t for r in rows for t in r.remote_transports),
        with_remotes,
    )
    schemas = _counted(
        "schema-versions",
        "Declared server.json schema version",
        "The server.json schema each entry declares. Registry entries do not declare an MCP "
        "protocol "
        "version, so this is the closest declared version in the registry data.",
        Counter(r.schema_version for r in rows),
        total,
    )
    sse = Figure(
        "http-sse",
        "Deprecated HTTP+SSE transport",
        "The 2025-03-26 MCP spec replaced HTTP+SSE with Streamable HTTP. Many servers keep SSE "
        "for older clients alongside Streamable HTTP; these are counts only.",
        ("measure", "servers", "share"),
        [
            (
                "list SSE anywhere",
                sum(r.offers_sse for r in rows),
                _share(sum(r.offers_sse for r in rows), total),
            ),
            (
                "remote endpoints are SSE only",
                sum(r.remote_sse_only for r in remote_rows),
                _share(sum(r.remote_sse_only for r in remote_rows), len(remote_rows)),
            ),
            (
                "remote endpoints include Streamable HTTP",
                sum("streamable-http" in r.remote_transports for r in remote_rows),
                _share(
                    sum("streamable-http" in r.remote_transports for r in remote_rows),
                    len(remote_rows),
                ),
            ),
        ],
    )
    figures = [overview, statuses, namespaces, publisher_sizes, top, registries, package_transports]
    figures += [remote_transports, schemas, sse]
    figures += card_figures(cards)
    return figures


def card_figures(cards: list[dict[str, Any]]) -> list[Figure]:
    """Aggregates of the bundled trust cards; names are deliberately left out."""
    verdicts = Counter(str(c.get("verdict")) for c in cards)
    grades = Counter(str(c.get("grade")) for c in cards)
    total = len(cards)
    return [
        Figure(
            "card-verdicts",
            "Trust Before Connect cards: verdicts",
            "Verdicts from the bundled, demo-labelled catalog cards (sandboxed runs of "
            "credential-free "
            "registry servers). A small, non-random sample.",
            ("verdict", "cards", "share"),
            [(v, n, _share(n, total)) for v, n in verdicts.most_common()],
        ),
        Figure(
            "card-grades",
            "Trust Before Connect cards: calibrated grades",
            "Registry grades under the calibrated rubric in docs/trust-card-import.md "
            "(observed behaviour only).",
            ("grade", "cards", "share"),
            [(g, grades[g], _share(grades[g], total)) for g in sorted(grades)],
        ),
    ]


def _csv(columns: Iterable[str], rows: Iterable[Iterable[object]]) -> str:
    buffer = io.StringIO()
    writer = csv.writer(buffer, lineterminator="\n")
    writer.writerow(list(columns))
    writer.writerows([list(r) for r in rows])
    return buffer.getvalue()


_CSS = """
:root{--bg:#fbfaf7;--fg:#1d1d1b;--muted:#6b6a65;--line:#e4e1d8;--card:#fff;--accent:#3d5a99}
@media (prefers-color-scheme:dark){:root{--bg:#161614;--fg:#ecebe6;--muted:#a3a19a;
--line:#2e2d29;--card:#1e1d1a;--accent:#8fa8e6}}
*{box-sizing:border-box}body{margin:0;background:var(--bg);color:var(--fg);
font:15px/1.55 system-ui,sans-serif}
main{max-width:920px;margin:0 auto;padding:32px 16px 64px}h1{font-size:24px;margin:0 0 4px}
h2{font-size:16px;margin:32px 0 6px}.note{color:var(--muted);font-size:13px;margin:0 0 8px}
.wrap{overflow-x:auto}table{width:100%;border-collapse:collapse;background:var(--card);
border:1px solid var(--line)}
td,th{text-align:left;padding:6px 10px;border-top:1px solid var(--line);overflow-wrap:anywhere}
th{color:var(--muted);font-size:13px}a{color:var(--accent)}
"""


def render_html(figures: list[Figure], meta: dict[str, Any]) -> str:
    parts = [
        "<!doctype html><html lang=en><head><meta charset=utf-8>",
        '<meta name=viewport content="width=device-width,initial-scale=1">',
        f"<title>MCP Census</title><style>{_CSS}</style></head><body><main>",
        "<h1>MCP Census</h1>",
        f"<p class=note>The official MCP Registry as read from its public REST API on "
        f"{escape(str(meta['generated_at']))}: {escape(str(meta['entries']))} latest entries over "
        f"{escape(str(meta['pages']))} pages"
        + (" (stopped at the page cap; counts are a lower bound)" if meta["truncated"] else "")
        + ". No server was contacted. Every table links to its data; "
        '<a href="data/servers.csv">per-server rows</a> and '
        '<a href="data/census.json">the full summary</a> are also available. '
        "Local report, not published.</p>",
    ]
    for figure in figures:
        parts.append(f'<h2 id="{escape(figure.key)}">{escape(figure.title)}</h2>')
        parts.append(
            f"<p class=note>{escape(figure.note)} "
            f'<a href="data/{escape(figure.key)}.csv">Download CSV</a></p>'
        )
        parts.append(
            "<div class=wrap><table><tr>"
            + "".join(f"<th>{escape(c)}</th>" for c in figure.columns)
            + "</tr>"
        )
        for row in figure.rows:
            parts.append("<tr>" + "".join(f"<td>{escape(str(v))}</td>" for v in row) + "</tr>")
        parts.append("</table></div>")
    parts.append("</main></body></html>")
    return "\n".join(parts)


def write_report(out: Path, rows: list[Row], figures: list[Figure], meta: dict[str, Any]) -> None:
    data = out / "data"
    data.mkdir(parents=True, exist_ok=True)
    for figure in figures:
        (data / f"{figure.key}.csv").write_text(_csv(figure.columns, figure.rows), encoding="utf-8")
    (data / "servers.csv").write_text(
        _csv(
            (
                "name",
                "publisher",
                "namespace_kind",
                "status",
                "schema_version",
                "registry_types",
                "package_transports",
                "remote_transports",
            ),
            (
                (
                    r.name,
                    r.publisher,
                    r.namespace_kind,
                    r.status,
                    r.schema_version,
                    " ".join(r.registry_types),
                    " ".join(r.package_transports),
                    " ".join(r.remote_transports),
                )
                for r in rows
            ),
        ),
        encoding="utf-8",
    )
    summary = {
        **meta,
        "figures": {
            f.key: {"title": f.title, "columns": f.columns, "rows": f.rows} for f in figures
        },
    }
    (data / "census.json").write_text(
        json.dumps(summary, indent=2, default=str) + "\n", encoding="utf-8"
    )
    (out / "index.html").write_text(render_html(figures, meta), encoding="utf-8")


def bundled_card_summaries(card_dir: Path) -> list[dict[str, Any]]:
    """Verdict and calibrated grade of each bundled card; no names leave this function."""
    from mcp_trust.catalog.trust_card import card_to_result, load_card  # noqa: PLC0415
    from mcp_trust.core import grading  # noqa: PLC0415

    summaries = []
    for path in sorted(card_dir.glob("*.card.json")):
        card = load_card(path)
        summaries.append(
            {"verdict": card["verdict"], "grade": grading.grade(card_to_result(card).risk).value}
        )
    return summaries


def run_census(
    out: Path,
    fetch: Fetch,
    card_dir: Path,
    registry_url: str = REGISTRY_URL,
    max_pages: int = MAX_PAGES,
) -> dict[str, Any]:
    entries, pages, truncated = fetch_latest(fetch, registry_url, max_pages)
    rows = [row for row in (to_row(e) for e in entries) if row is not None]
    meta = {
        "generated_at": datetime.now(tz=UTC).strftime("%Y-%m-%d %H:%M UTC"),
        "registry": registry_url,
        "entries": len(rows),
        "pages": pages,
        "truncated": truncated,
    }
    figures = build_figures(rows, bundled_card_summaries(card_dir))
    write_report(out, rows, figures, meta)
    return {**meta, "figures": {f.key: f.rows for f in figures}}
