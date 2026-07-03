"""Pure-presentation layer for the MCP Trust Registry web UI.

No DB access, no FastAPI imports. All text interpolated into HTML is escaped
via ``html.escape``. No external CSS, JS, or fonts — inline styles only.

Row shape used by :func:`render_catalog`:

.. code-block:: python

    {
        "slug": str,           # URL-safe identifier
        "name": str,           # Display name
        "grade": str,          # TrustGrade value or "unscanned"
        "transparency": str,   # TransparencyLevel value or ""
        "composite": float | None,
        "scanned_at": str,     # ISO datetime or ""
    }
"""

from __future__ import annotations

import logging
from datetime import datetime
from html import escape

from mcp_trust.core import grading
from mcp_trust.core.governance import DISPUTE_SLA_DAYS, DISPUTE_URL, STALE_AFTER_DAYS, is_stale
from mcp_trust.core.models import ScanRecord, Server, SourceKind

_log = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Grade → visual colour (matches badge.json route)
# ---------------------------------------------------------------------------

_GRADE_CSS: dict[str, str] = {
    "A": "#2da44e",  # brightgreen
    "B": "#4CAF50",  # green
    "C": "#e6a817",  # amber / yellow
    "D": "#f08030",  # orange
    "F": "#d1242f",  # red
    "unscanned": "#8b949e",  # grey
}

_TRANSPARENCY_CSS: dict[str, str] = {
    "high": "#2da44e",
    "medium": "#e6a817",
    "low": "#f08030",
    "": "#8b949e",
}

# ---------------------------------------------------------------------------
# Shared page skeleton
# ---------------------------------------------------------------------------

_PAGE_STYLE = """
  *, *::before, *::after { box-sizing: border-box; margin: 0; padding: 0; }
  body {
    font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto,
                 Helvetica, Arial, sans-serif;
    background: #f6f8fa;
    color: #24292f;
    line-height: 1.5;
  }
  a { color: #0969da; text-decoration: none; }
  a:hover { text-decoration: underline; }

  .site-header {
    background: #fff;
    border-bottom: 1px solid #d0d7de;
    padding: 0.75rem 1.5rem;
    display: flex;
    align-items: center;
    gap: 0.75rem;
  }
  .site-header .logo { font-size: 1.1rem; font-weight: 700; color: #24292f; }
  .site-header .tagline {
    font-size: 0.85rem;
    color: #57606a;
    border-left: 1px solid #d0d7de;
    padding-left: 0.75rem;
  }

  main { max-width: 1040px; margin: 2rem auto; padding: 0 1.25rem; }

  .page-title { font-size: 1.4rem; font-weight: 600; margin-bottom: 0.25rem; }
  .page-subtitle { color: #57606a; font-size: 0.9rem; margin-bottom: 1.5rem; }

  table {
    width: 100%;
    border-collapse: collapse;
    background: #fff;
    border: 1px solid #d0d7de;
    border-radius: 6px;
    overflow: hidden;
    font-size: 0.9rem;
  }
  thead { background: #f6f8fa; }
  th {
    text-align: left;
    padding: 0.55rem 0.9rem;
    font-weight: 600;
    color: #57606a;
    font-size: 0.8rem;
    text-transform: uppercase;
    letter-spacing: 0.03em;
    border-bottom: 1px solid #d0d7de;
  }
  td { padding: 0.6rem 0.9rem; border-bottom: 1px solid #eaeef2; vertical-align: middle; }
  tr:last-child td { border-bottom: none; }
  tr:hover td { background: #f6f8fa; }

  .pill {
    display: inline-block;
    padding: 0.15rem 0.55rem;
    border-radius: 20px;
    font-size: 0.78rem;
    font-weight: 700;
    color: #fff;
    letter-spacing: 0.03em;
  }
  .chip {
    display: inline-block;
    padding: 0.1rem 0.45rem;
    border-radius: 4px;
    font-size: 0.75rem;
    font-weight: 500;
    color: #fff;
    opacity: 0.9;
  }

  /* Detail page */
  .card {
    background: #fff;
    border: 1px solid #d0d7de;
    border-radius: 6px;
    padding: 1.5rem;
    margin-bottom: 1.25rem;
  }
  .grade-hero {
    display: flex;
    align-items: center;
    gap: 1.25rem;
    margin-bottom: 1rem;
  }
  .grade-big {
    font-size: 3.5rem;
    font-weight: 800;
    line-height: 1;
    color: #fff;
    width: 5rem;
    height: 5rem;
    border-radius: 12px;
    display: flex;
    align-items: center;
    justify-content: center;
  }
  .meta-row { display: flex; gap: 1.5rem; flex-wrap: wrap; margin-top: 0.5rem; }
  .meta-item { font-size: 0.875rem; }
  .meta-label { color: #57606a; font-size: 0.78rem; text-transform: uppercase;
                letter-spacing: 0.04em; margin-bottom: 0.15rem; font-weight: 600; }

  .badge-box {
    background: #f6f8fa;
    border: 1px solid #d0d7de;
    border-radius: 6px;
    padding: 1rem 1.25rem;
    margin-bottom: 1.25rem;
  }
  .badge-box h3 { font-size: 0.95rem; font-weight: 600; margin-bottom: 0.5rem; }
  .badge-box pre {
    font-size: 0.8rem;
    overflow-x: auto;
    white-space: pre-wrap;
    word-break: break-all;
    background: #fff;
    border: 1px solid #d0d7de;
    border-radius: 4px;
    padding: 0.6rem 0.75rem;
    margin-top: 0.4rem;
  }

  .not-found-box {
    text-align: center;
    padding: 4rem 1rem;
    color: #57606a;
  }
  .not-found-box .code { font-size: 4rem; font-weight: 800; color: #d0d7de; }
  .not-found-box .msg { font-size: 1.1rem; margin-top: 0.5rem; }
  .not-found-box .back { margin-top: 1.25rem; display: block; }
"""


def _header() -> str:
    return (
        '<header class="site-header">'
        '<span class="logo">MCP Trust Registry</span>'
        '<span class="tagline">Check before you connect</span>'
        '<nav style="margin-left:auto;font-size:0.85rem;display:flex;gap:1rem">'
        '<a href="/ui/methodology">Methodology</a>'
        '<a href="/ui/dispute">Dispute a grade</a>'
        "</nav>"
        "</header>"
    )


def _banner(text: str) -> str:
    """Render a prominent, full-width warning strip below the header.

    Used to label the page's data provenance (e.g. demo/stub data) so a reader
    can never mistake a synthetic grade for a real scan. *text* is treated as
    untrusted and escaped.
    """
    return (
        '<div role="alert" style="background:#fff3cd;border-bottom:2px solid #e0a800;'
        "color:#664d03;padding:0.65rem 1.5rem;font-size:0.85rem;text-align:center;"
        f'font-weight:500">{escape(text)}</div>'
    )


def _page(title: str, body: str, *, banner: str | None = None) -> str:
    escaped_title = escape(title)
    banner_html = _banner(banner) if banner else ""
    return (
        "<!doctype html>"
        '<html lang="en">'
        "<head>"
        '<meta charset="utf-8">'
        '<meta name="viewport" content="width=device-width, initial-scale=1">'
        f"<title>{escaped_title}</title>"
        f"<style>{_PAGE_STYLE}</style>"
        "</head>"
        "<body>"
        f"{_header()}"
        f"{banner_html}"
        f"{body}"
        "</body>"
        "</html>"
    )


# ---------------------------------------------------------------------------
# Grade + transparency helpers
# ---------------------------------------------------------------------------


def _grade_pill(grade: str, *, stale: bool = False) -> str:
    """Grade pill. A stale grade greys out and is labelled — it must never
    read as a current verdict (governance staleness policy)."""
    color = _GRADE_CSS["unscanned"] if stale else _GRADE_CSS.get(grade, _GRADE_CSS["unscanned"])
    label = f"{grade.upper()} (stale)" if stale else grade.upper()
    return f'<span class="pill" style="background:{escape(color)}">{escape(label)}</span>'


def _transparency_chip(level: str) -> str:
    if not level:
        return '<span class="chip" style="background:#8b949e">—</span>'
    color = _TRANSPARENCY_CSS.get(level.lower(), _TRANSPARENCY_CSS[""])
    return f'<span class="chip" style="background:{escape(color)}">{escape(level)}</span>'


def _provenance_card(server: Server, record: ScanRecord | None) -> str:
    """Provenance & dispute card: how this entry got listed, exactly what was
    scanned, and the standing dispute path for the graded party."""
    source = server.source
    kind = source.kind
    ref = escape(str(source.reference))

    items: list[str] = [
        "<li><strong>Listing basis:</strong> operator-listed from a public catalog. "
        "This entry was not submitted by its vendor.</li>"
    ]
    if record is None:
        items.append(
            f"<li><strong>Scan target:</strong> the {escape(str(kind))} artifact "
            f"<code>{ref}</code>. Not yet scanned.</li>"
        )
    elif kind is SourceKind.REMOTE:
        items.append(
            f"<li><strong>Scan target:</strong> a hosted endpoint (<code>{ref}</code>).</li>"
        )
    else:
        items.append(
            f"<li><strong>Scan target:</strong> the published {escape(str(kind))} "
            f"artifact <code>{ref}</code>, installed and scanned locally inside a "
            "network-isolated sandbox. No vendor-hosted infrastructure was "
            "contacted.</li>"
        )
    if source.env_keys:
        keys = ", ".join(f"<code>{escape(key)}</code>" for key in source.env_keys)
        items.append(
            "<li><strong>Credentials:</strong> this server declares required "
            f"environment variables ({keys}). Scans never use real credentials; at "
            "most inert placeholder values are injected inside the sandbox.</li>"
        )
    else:
        items.append("<li><strong>Credentials:</strong> none declared, none used.</li>")
    items.append(
        "<li><strong>Dispute:</strong> vendor or maintainer of this server? "
        '<a href="/ui/dispute">Dispute this grade</a> — first response within '
        f"{DISPUTE_SLA_DAYS} days.</li>"
    )

    return (
        '<div class="card">'
        '<h2 style="font-size:1rem;font-weight:600;margin-bottom:0.75rem">'
        "Provenance &amp; dispute</h2>"
        '<ul style="font-size:0.875rem;padding-left:1.1rem;display:grid;gap:0.4rem">'
        + "".join(items)
        + "</ul></div>"
    )


# ---------------------------------------------------------------------------
# Public render functions
# ---------------------------------------------------------------------------


def render_catalog(
    rows: list[dict],
    *,
    banner: str | None = None,
    now: datetime | None = None,
) -> str:
    """Render the full catalog HTML page.

    Parameters
    ----------
    rows:
        List of dicts with keys:

        - ``slug`` (str) — URL-safe server identifier
        - ``name`` (str) — display name
        - ``grade`` (str) — TrustGrade value or ``"unscanned"``
        - ``transparency`` (str) — TransparencyLevel value or ``""``
        - ``composite`` (float | None) — danger score 0–10
        - ``scanned_at`` (str) — ISO datetime string or ``""``
    """
    if not rows:
        table_body = (
            '<tr><td colspan="6" style="text-align:center;color:#57606a;padding:2rem">'
            "No servers in the registry yet."
            "</td></tr>"
        )
    else:
        parts: list[str] = []
        for row in rows:
            slug = escape(str(row.get("slug", "")))
            name = escape(str(row.get("name", "")))
            grade = str(row.get("grade", "unscanned"))
            transparency = str(row.get("transparency", ""))
            composite = row.get("composite")
            scanned_at_raw = str(row.get("scanned_at", "") or "")
            scanned_at = escape(scanned_at_raw)

            stale = False
            if now is not None and scanned_at_raw and grade != "unscanned":
                try:
                    stale = is_stale(datetime.fromisoformat(scanned_at_raw), now)
                except ValueError:
                    # Renders as not-stale rather than crashing the catalog,
                    # but never silently: staleness is a trust surface.
                    _log.warning(
                        "unparseable scanned_at %r for %s; staleness unknown",
                        scanned_at_raw,
                        slug,
                    )

            composite_str = f"{composite:.1f}" if composite is not None else "—"
            scanned_str = scanned_at[:19].replace("T", " ") if scanned_at else "—"
            if stale:
                scanned_str += " (stale)"

            parts.append(
                "<tr>"
                f'<td><a href="/ui/servers/{slug}">{name}</a>'
                f'<br><small style="color:#57606a;font-size:0.78rem">{slug}</small></td>'
                f"<td>{_grade_pill(grade, stale=stale)}</td>"
                f"<td>{_transparency_chip(transparency)}</td>"
                f'<td style="font-variant-numeric:tabular-nums">{escape(composite_str)}</td>'
                f'<td style="font-size:0.82rem;color:#57606a">{escape(scanned_str)}</td>'
                f'<td><a href="/ui/servers/{slug}">Details →</a></td>'
                "</tr>"
            )
        table_body = "".join(parts)

    body = (
        "<main>"
        '<h1 class="page-title">MCP Server Danger Catalog</h1>'
        '<p class="page-subtitle">'
        "Each server gets an A–F danger grade plus a separate transparency signal. "
        "Grades come from automated scans and mean check before you connect, not endorsement."
        "</p>"
        "<table>"
        "<thead><tr>"
        "<th>Server</th><th>Danger grade</th><th>Transparency</th>"
        "<th>Danger score</th><th>Last scanned</th><th></th>"
        "</tr></thead>"
        f"<tbody>{table_body}</tbody>"
        "</table>"
        "</main>"
    )
    return _page("MCP Trust Registry — Catalog", body, banner=banner)


def render_detail(
    server: Server,
    record: ScanRecord | None,
    *,
    base_url: str,
    banner: str | None = None,
    now: datetime | None = None,
) -> str:
    """Render the detail page for one server.

    Parameters
    ----------
    server:
        A ``Server`` domain object (``slug``, ``name``, ``description``,
        ``source``, ``homepage``).
    record:
        The latest ``ScanRecord`` for this server, or ``None`` if unscanned.
    base_url:
        Absolute base URL of the deployment, e.g. ``"https://mcptrust.dev"``.
        Used to build the shields.io badge embed snippet. Must NOT end with ``/``.
    """
    # --- Extract server fields ---
    name = escape(str(server.name))
    description = escape(str(server.description or ""))
    homepage = server.homepage
    source = server.source

    # --- Grade / transparency ---
    if record is not None:
        grade = str(record.grade)
        transparency = str(record.transparency)
        composite_val = record.risk.composite
        scanned_at_raw = str(record.scanned_at)
        engine_name = escape(str(record.engine_name))
        engine_version = escape(str(record.engine_version))
        findings = list(record.findings)
    else:
        grade = "unscanned"
        transparency = ""
        composite_val = None
        scanned_at_raw = ""
        engine_name = "—"
        engine_version = "—"
        findings = []

    stale = record is not None and now is not None and is_stale(record.scanned_at, now)

    grade_color = (
        _GRADE_CSS["unscanned"] if stale else _GRADE_CSS.get(grade, _GRADE_CSS["unscanned"])
    )
    composite_str = f"{composite_val:.1f}" if composite_val is not None else "—"
    scanned_str = scanned_at_raw[:19].replace("T", " ") if scanned_at_raw else "Never"
    if stale:
        scanned_str += " (stale)"

    stale_chip = (
        '<span class="chip" style="background:#8b949e">stale — pending re-scan</span>'
        if stale
        else ""
    )

    # --- Hero card ---
    hero = (
        '<div class="card">'
        '<div class="grade-hero">'
        f'<div class="grade-big" style="background:{escape(grade_color)}">'
        f"{escape(grade.upper())}</div>"
        "<div>"
        f'<h1 style="font-size:1.5rem;font-weight:700">{name}</h1>'
        f'<p style="color:#57606a;margin-top:0.2rem">{description}</p>'
        '<div class="meta-row" style="margin-top:0.6rem">'
        f"{_transparency_chip(transparency)}"
        '<span class="chip" style="background:#57606a">automated scan</span>'
        f"{stale_chip}"
        "</div>"
        "</div>"
        "</div>"
        '<div class="meta-row">'
        '<div class="meta-item">'
        '<div class="meta-label">Danger score</div>'
        f"<div>{escape(composite_str)} / 10</div>"
        "</div>"
        '<div class="meta-item">'
        '<div class="meta-label">Transparency</div>'
        f"<div>{_transparency_chip(transparency)}</div>"
        "</div>"
        '<div class="meta-item">'
        '<div class="meta-label">Last scanned</div>'
        f"<div>{escape(scanned_str)}</div>"
        "</div>"
        '<div class="meta-item">'
        '<div class="meta-label">Engine</div>'
        f"<div>{engine_name} {engine_version}</div>"
        "</div>"
    )

    if source is not None:
        kind_str = escape(str(getattr(source, "kind", "—")))
        ref_str = escape(str(getattr(source, "reference", "—")))
        hero += (
            '<div class="meta-item">'
            '<div class="meta-label">Source</div>'
            f"<div>{kind_str}: {ref_str}</div>"
            "</div>"
        )

    if homepage:
        hp = str(homepage)
        hp_esc = escape(hp)
        # Only http(s) homepages become clickable links. A non-web scheme such as
        # ``javascript:`` would survive html.escape() untouched and execute on
        # click, so render it as inert escaped text instead — never an href.
        scheme = hp.split(":", 1)[0].lower() if ":" in hp else ""
        link = (
            f'<a href="{hp_esc}" rel="noopener noreferrer">{hp_esc}</a>'
            if scheme in ("http", "https")
            else hp_esc
        )
        hero += (
            f'<div class="meta-item"><div class="meta-label">Homepage</div><div>{link}</div></div>'
        )

    hero += "</div>"  # close meta-row

    scan_basis = ""
    if record is not None and source is not None:
        scan_basis = (
            f" It reflects the {escape(str(source.kind))} artifact "
            f"<code>{escape(str(source.reference))}</code> as scanned on "
            f"{escape(scanned_str)} and may not describe later releases."
        )
    hero += (
        '<p style="margin-top:1rem;font-size:0.85rem;color:#57606a;'
        'border-left:3px solid #57606a;padding-left:0.75rem">'
        "<strong>Automated danger grade:</strong> an automated opinion derived from "
        'the disclosed checks on the <a href="/ui/methodology">methodology page</a> — '
        "not a statement of fact about the vendor, and not an endorsement, "
        "certification, or claim that the server is malicious."
        f"{scan_basis}"
        "</p>"
    )

    # Low transparency is a caveat, NOT a danger verdict — state it plainly.
    if transparency == "low":
        hero += (
            '<p style="margin-top:1rem;font-size:0.85rem;color:#57606a;'
            'border-left:3px solid #f08030;padding-left:0.75rem">'
            "<strong>Low transparency:</strong> this server declares few or no tool "
            "behavior annotations, so the danger score is inferred from defaults. "
            "Treat as <em>cannot verify safe</em> — not necessarily dangerous."
            "</p>"
        )

    if stale:
        hero += (
            '<p style="margin-top:1rem;font-size:0.85rem;color:#57606a;'
            'border-left:3px solid #8b949e;padding-left:0.75rem">'
            f"<strong>Stale grade:</strong> this scan is more than {STALE_AFTER_DAYS} "
            "days old and the grade is pending re-scan. The server may have changed "
            "since; treat the grade as historical, not current."
            "</p>"
        )

    hero += "</div>"  # close card

    # --- Badge embed box ---
    badge_url = f"{base_url}/servers/{server.slug}/badge.json"
    detail_url = f"{base_url}/ui/servers/{server.slug}"
    badge_md = f"[![MCP Trust](https://img.shields.io/endpoint?url={badge_url})]({detail_url})"
    badge_box = (
        '<div class="badge-box">'
        "<h3>Add this badge to your README</h3>"
        '<p style="font-size:0.85rem;color:#57606a">'
        "Copy the Markdown below only if you want to link readers to the latest "
        "danger grade and scan caveats:"
        "</p>"
        f"<pre>{escape(badge_md)}</pre>"
        '<img src="'
        f"https://img.shields.io/endpoint?url={escape(badge_url)}"
        '" alt="MCP Trust badge" style="margin-top:0.75rem;display:block">'
        "</div>"
    )

    # --- Findings table ---
    if findings:
        finding_rows: list[str] = []
        for f in findings:
            sev = escape(str(f.severity))
            rule = escape(str(f.rule_id))
            title_f = escape(str(f.title))
            category = escape(str(f.category))
            detail = escape(str(getattr(f, "detail", "") or ""))
            finding_rows.append(
                "<tr>"
                f"<td>{sev}</td>"
                f"<td><code>{rule}</code></td>"
                f"<td>{title_f}</td>"
                f"<td>{category}</td>"
                f'<td style="font-size:0.82rem;color:#57606a">{detail}</td>'
                "</tr>"
            )
        findings_table = (
            "<table>"
            "<thead><tr>"
            "<th>Severity</th><th>Rule</th><th>Title</th><th>Category</th><th>Detail</th>"
            "</tr></thead>"
            f"<tbody>{''.join(finding_rows)}</tbody>"
            "</table>"
        )
    else:
        findings_table = '<p style="color:#57606a;font-size:0.9rem">No findings on record.</p>'

    findings_section = (
        '<div class="card">'
        '<h2 style="font-size:1rem;font-weight:600;margin-bottom:0.75rem">Findings</h2>'
        f"{findings_table}"
        "</div>"
    )

    # --- Provenance & dispute card ---
    provenance_card = _provenance_card(server, record)

    # --- Back link ---
    back = '<p><a href="/">← Back to catalog</a></p>'

    body = (
        f"<main>{back}<div style='margin-top:1rem'>{hero}</div>"
        f"{provenance_card}{badge_box}{findings_section}</main>"
    )
    return _page(f"MCP Trust — {server.name}", body, banner=banner)


def render_not_found(slug: str) -> str:
    """Render a minimal 404 page for an unknown server slug."""
    escaped = escape(slug)
    body = (
        "<main>"
        '<div class="not-found-box">'
        '<div class="code">404</div>'
        f'<div class="msg">Server <strong>{escaped}</strong> not found in the registry.</div>'
        '<a class="back" href="/">← Return to catalog</a>'
        "</div>"
        "</main>"
    )
    return _page("MCP Trust — Not Found", body)


def render_methodology() -> str:
    """Render the public grading-methodology page.

    Built from :func:`mcp_trust.core.grading.methodology` so the published
    description can never drift from the code that actually grades.
    """
    method = grading.methodology()

    weight_rows = "".join(
        f"<tr><td><code>{escape(dim)}</code></td>"
        f'<td style="font-variant-numeric:tabular-nums">{weight:.1f}</td></tr>'
        for dim, weight in method["dimension_weights"].items()
    )
    band_rows = "".join(
        f"<tr><td>{_grade_pill(grade_value)}</td>"
        f'<td style="font-variant-numeric:tabular-nums">≤ {upper:.1f}</td></tr>'
        for upper, grade_value in method["bands"]
    )
    band_rows += f"<tr><td>{_grade_pill('F')}</td><td>above the D band</td></tr>"

    body = (
        "<main>"
        '<p><a href="/">← Back to catalog</a></p>'
        '<h1 class="page-title" style="margin-top:1rem">Grading methodology</h1>'
        '<p class="page-subtitle">'
        "Every grade on this site is an automated, dated, reproducible "
        "<strong>opinion</strong> derived from the disclosed checks below — not a "
        "statement of fact about a vendor, and never a claim that a server is "
        "malicious.</p>"
        '<div class="card">'
        '<h2 style="font-size:1rem;font-weight:600;margin-bottom:0.75rem">What is scanned</h2>'
        '<p style="font-size:0.875rem">'
        "The published package artifact (npm, PyPI, or equivalent) is installed and "
        "launched locally inside a network-isolated sandbox, and its declared MCP "
        "surface (tools, prompts, resources, annotations) is read back. No "
        "vendor-hosted infrastructure is contacted. Scans never use real "
        "credentials; where a server requires environment variables, at most inert "
        "placeholder values are injected inside the sandbox. Each detail page "
        "shows the engine name, engine version, artifact reference, and scan "
        "date, so any published grade can be independently re-derived against "
        "the same artifact version.</p>"
        "</div>"
        '<div class="card">'
        '<h2 style="font-size:1rem;font-weight:600;margin-bottom:0.75rem">Danger score</h2>'
        '<p style="font-size:0.875rem;margin-bottom:0.75rem">'
        "The engine reports risk per capability dimension (0–10). The registry "
        "aggregates them with danger weights — emphasizing the dimensions that "
        f"separate real risk. Calibrated {escape(method['calibrated'])}.</p>"
        "<table><thead><tr><th>Dimension</th><th>Weight</th></tr></thead>"
        f"<tbody>{weight_rows}</tbody></table>"
        "</div>"
        '<div class="card">'
        '<h2 style="font-size:1rem;font-weight:600;margin-bottom:0.75rem">Grade bands</h2>'
        "<table><thead><tr><th>Grade</th><th>Danger score</th></tr></thead>"
        f"<tbody>{band_rows}</tbody></table>"
        '<p style="font-size:0.875rem;margin-top:0.75rem">'
        "<strong>Critical cap:</strong> any CRITICAL finding caps the grade at "
        f"{escape(method['critical_cap'])} regardless of score — a single "
        "tool-poisoning or rug-pull vector is disqualifying on its own.</p>"
        "</div>"
        '<div class="card">'
        '<h2 style="font-size:1rem;font-weight:600;margin-bottom:0.75rem">'
        "Transparency — and what a low grade does NOT mean</h2>"
        '<p style="font-size:0.875rem">'
        "Transparency is a separate axis: the fraction of a server's tools that "
        "declare behavior annotations "
        f"(high ≥ {method['transparency_high']:.0%}, "
        f"medium ≥ {method['transparency_medium']:.0%}). "
        "A fully unannotated server is indistinguishable from a maximally capable "
        "one, so its danger score is inferred from spec-defaults. "
        "<strong>A failing grade on a low-transparency server means "
        "<em>cannot verify it is safe</em> — not <em>known dangerous</em>.</strong> "
        "That caveat is stated on every affected page.</p>"
        "</div>"
        '<div class="card">'
        '<h2 style="font-size:1rem;font-weight:600;margin-bottom:0.75rem">Grade freshness</h2>'
        '<p style="font-size:0.875rem">'
        f"A grade older than {STALE_AFTER_DAYS} days is marked <em>stale</em> on "
        "its page and badge, greys out, and is treated as historical until "
        "re-scanned. Vendors ship fixes; a grade never outlives its evidence "
        "silently.</p>"
        "</div>"
        '<div class="card">'
        '<h2 style="font-size:1rem;font-weight:600;margin-bottom:0.75rem">'
        "Disagree with a grade?</h2>"
        '<p style="font-size:0.875rem">'
        'See the <a href="/ui/dispute">dispute &amp; correction policy</a>. '
        'Published corrections live in the <a href="/ui/corrections">corrections '
        "log</a>.</p>"
        "</div>"
        "</main>"
    )
    return _page("MCP Trust — Grading Methodology", body)


def render_dispute() -> str:
    """Render the dispute / right-of-reply policy page."""
    body = (
        "<main>"
        '<p><a href="/">← Back to catalog</a></p>'
        '<h1 class="page-title" style="margin-top:1rem">Dispute a grade</h1>'
        '<p class="page-subtitle">'
        "Vendors and maintainers of any listed server have a standing "
        "right of reply.</p>"
        '<div class="card">'
        '<h2 style="font-size:1rem;font-weight:600;margin-bottom:0.75rem">How to dispute</h2>'
        '<p style="font-size:0.875rem">'
        f'Open a <a href="{escape(DISPUTE_URL)}" rel="noopener noreferrer">grade-dispute '
        "issue</a> naming the server, the grade or finding you dispute, and — if the "
        "server has changed — the release that addresses it.</p>"
        "</div>"
        '<div class="card">'
        '<h2 style="font-size:1rem;font-weight:600;margin-bottom:0.75rem">What happens next</h2>'
        '<ol style="font-size:0.875rem;padding-left:1.1rem;display:grid;gap:0.4rem">'
        f"<li>First response within <strong>{DISPUTE_SLA_DAYS} days</strong>.</li>"
        "<li>The server is re-scanned against its latest release with the current "
        "engine, in the same disclosed sandbox configuration.</li>"
        "<li>If the grade changes, the entry is updated and the change is recorded "
        'in the public <a href="/ui/corrections">corrections log</a>.</li>'
        "<li>If the grade stands, the finding-level evidence is reviewed manually; "
        "the vendor's reply is published alongside the entry either way.</li>"
        "<li>A grade that cannot be reproduced from the disclosed method is "
        "withdrawn, not defended.</li>"
        "</ol>"
        "</div>"
        '<div class="card">'
        '<h2 style="font-size:1rem;font-weight:600;margin-bottom:0.75rem">Scope</h2>'
        '<p style="font-size:0.875rem">'
        "Grades are automated opinions about a specific artifact version at a "
        'specific time (see the <a href="/ui/methodology">methodology</a>). '
        "Disputes about the method itself are welcome through the same channel.</p>"
        "</div>"
        "</main>"
    )
    return _page("MCP Trust — Dispute a Grade", body)


def render_corrections(corrections: list[dict]) -> str:
    """Render the public corrections log.

    Each entry: ``{"date": str, "slug": str, "summary": str, "resolution": str}``.
    """
    if not corrections:
        table = (
            '<p style="color:#57606a;font-size:0.9rem">No corrections recorded yet. '
            "Grade changes that result from disputes or re-scans are logged here "
            "permanently.</p>"
        )
    else:
        rows = "".join(
            "<tr>"
            f"<td>{escape(str(entry.get('date', '')))}</td>"
            f'<td><a href="/ui/servers/{escape(str(entry.get("slug", "")))}">'
            f"{escape(str(entry.get('slug', '')))}</a></td>"
            f"<td>{escape(str(entry.get('summary', '')))}</td>"
            f"<td>{escape(str(entry.get('resolution', '')))}</td>"
            "</tr>"
            for entry in corrections
        )
        table = (
            "<table><thead><tr>"
            "<th>Date</th><th>Server</th><th>Correction</th><th>Resolution</th>"
            f"</tr></thead><tbody>{rows}</tbody></table>"
        )

    body = (
        "<main>"
        '<p><a href="/">← Back to catalog</a></p>'
        '<h1 class="page-title" style="margin-top:1rem">Corrections log</h1>'
        '<p class="page-subtitle">'
        "Every published grade change arising from a dispute, re-scan, or "
        "discovered error — kept public so the registry is held to its own "
        "standard.</p>"
        f'<div class="card">{table}</div>'
        "</main>"
    )
    return _page("MCP Trust — Corrections Log", body)
