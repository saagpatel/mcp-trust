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

from mcp_trust.core.governance import (
    DISPUTE_SLA_DAYS,
    DISPUTE_URL,
    MASKED_SERVER_DESCRIPTION,
    STALE_AFTER_DAYS,
    is_stale,
)
from mcp_trust.core.grading import rubric
from mcp_trust.core.models import ScanRecord, Server, SourceKind
from mcp_trust.core.provenance import ScanProvenance, classify

_log = logging.getLogger(__name__)

# Per-grade dispute / correction channel — single source: core.governance.
_DISPUTE_URL = DISPUTE_URL

# Human-readable labels for the risk dimensions, in display order. Keys match
# both ``RiskSummary`` field names and the ``rubric()`` dimension_weights keys.
_DIMENSION_LABELS: dict[str, str] = {
    "file_access": "File access",
    "network_access": "Network access",
    "shell_execution": "Shell execution",
    "destructive": "Destructive",
    "exfiltration": "Exfiltration",
}

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


def _grade_pill(grade: str, *, stale: bool = False, masked: bool = False) -> str:
    """Grade pill. A stale grade greys out and is labelled — it must never
    read as a current verdict (governance staleness policy). A masked grade
    (operator-withheld pending governance review) shows no letter at all."""
    if masked:
        return f'<span class="pill" style="background:{_GRADE_CSS["unscanned"]}">masked</span>'
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
    provenance = classify(record)

    items: list[str] = [
        "<li><strong>Listing basis:</strong> operator-listed from a public catalog. "
        "This entry was not submitted by its vendor.</li>"
    ]
    if record is None:
        items.append(
            f"<li><strong>Scan target:</strong> the {escape(str(kind))} artifact "
            f"<code>{ref}</code>. Not yet scanned.</li>"
        )
    elif provenance is ScanProvenance.DEMO:
        items.append(
            f"<li><strong>Scan target:</strong> the configured {escape(str(kind))} "
            f"target <code>{ref}</code>. This record is demo data from the local "
            "stub path; no real server artifact or hosted endpoint was launched.</li>"
        )
    elif kind is SourceKind.REMOTE and not source.command:
        items.append(
            f"<li><strong>Scan target:</strong> a hosted endpoint (<code>{ref}</code>).</li>"
        )
    elif record.sandbox_image:
        image = escape(record.sandbox_image)
        if kind is SourceKind.REMOTE and source.command:
            command = escape(source.command)
            items.append(
                f"<li><strong>Scan target:</strong> the configured remote target "
                f"<code>{ref}</code>, launched and scanned locally using command "
                f"<code>{command}</code> and sandbox image <code>{image}</code>. "
                "The public record stores the sandbox image, but not the network "
                "mode, so this page does not claim network isolation for that run.</li>"
            )
        else:
            items.append(
                f"<li><strong>Scan target:</strong> the published {escape(str(kind))} "
                f"artifact <code>{ref}</code>, installed and scanned locally using "
                f"sandbox image <code>{image}</code>. The public record stores the "
                "sandbox image, but not the network mode, so this page does not claim "
                "network isolation for that run.</li>"
            )
    else:
        if kind is SourceKind.REMOTE and source.command:
            command = escape(source.command)
            items.append(
                f"<li><strong>Scan target:</strong> the configured remote target "
                f"<code>{ref}</code>, launched and scanned locally using command "
                f"<code>{command}</code>. No sandbox image is recorded for this "
                "scan, so this page cannot verify sandbox provenance or network "
                "isolation for that run.</li>"
            )
        else:
            items.append(
                f"<li><strong>Scan target:</strong> the published {escape(str(kind))} "
                f"artifact <code>{ref}</code>, scanned locally. No sandbox image is "
                "recorded for this scan, so this page cannot verify sandbox provenance "
                "or network isolation for that run.</li>"
            )
    if source.env_keys:
        keys = ", ".join(f"<code>{escape(key)}</code>" for key in source.env_keys)
        if record is not None and record.sandbox_image:
            credential_note = "at most inert placeholder values are used for scan execution."
        elif provenance is ScanProvenance.DEMO:
            credential_note = "demo records do not use real credentials."
        else:
            credential_note = "no real credentials are disclosed or stored in the registry."
        items.append(
            "<li><strong>Credentials:</strong> this server declares required "
            f"environment variables ({keys}). Scans never use real credentials; "
            f"{credential_note}</li>"
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


def _dimension_breakdown(record: ScanRecord) -> str:
    """Per-dimension danger scores with the rubric weight applied to each.

    Shows the reader the grade is *computed* from disclosed weights, not
    editorial. Weights come from :func:`rubric` so they can never drift from
    the code that grades.
    """
    weights = rubric()["dimension_weights"]
    assert isinstance(weights, dict)  # narrow for type-checkers; rubric() contract
    risk = record.risk
    rows: list[str] = []
    for dim, label in _DIMENSION_LABELS.items():
        raw = float(getattr(risk, dim, 0.0))
        weight = float(weights.get(dim, 0.0))
        rows.append(
            "<tr>"
            f"<td>{escape(label)}</td>"
            f'<td style="font-variant-numeric:tabular-nums">{raw:.1f}</td>'
            f'<td style="font-variant-numeric:tabular-nums;color:#57606a">×{weight:.1f}</td>'
            f'<td style="font-variant-numeric:tabular-nums">{raw * weight:.2f}</td>'
            "</tr>"
        )
    return (
        "<table>"
        "<thead><tr>"
        "<th>Dimension</th><th>Raw (0–10)</th><th>Weight</th><th>Weighted</th>"
        "</tr></thead>"
        f"<tbody>{''.join(rows)}</tbody>"
        "</table>"
    )


def _methodology_floor(
    *,
    grade: str,
    engine_name: str,
    engine_version: str,
    scanned_str: str,
    source_ref: str,
    transparency_level: str,
) -> str:
    """The per-grade transparency + disclaimer floor.

    Turns a bare public letter into a dated, scoped, disclosed-methodology
    opinion: what was scanned, when, by which engine version, what the grade
    does and does NOT claim, and where to dispute it. ``engine_name``,
    ``engine_version``, and ``scanned_str`` arrive pre-escaped from the caller;
    ``grade``, ``source_ref``, and ``transparency_level`` are escaped here.
    """
    grade_up = escape(grade.upper())
    ref = escape(source_ref) if source_ref else "the distributed package"
    # An F/D on a low-transparency server is a "cannot verify" grade by the
    # rubric's own design — say so where the reader sees the letter, not only
    # in the transparency caveat below.
    cannot_verify = transparency_level == "low" and grade.upper() in {"D", "F"}
    unverified_line = (
        "<li>Because this server declares few or no tool-behavior annotations, "
        f"its {grade_up} reflects risk <strong>inferred from spec defaults</strong> — "
        "read it as <em>cannot verify safe</em>, not <em>known dangerous</em>.</li>"
        if cannot_verify
        else ""
    )
    return (
        '<div class="card">'
        '<h2 style="font-size:1rem;font-weight:600;margin-bottom:0.75rem">'
        "How to read this grade</h2>"
        '<ul style="font-size:0.875rem;color:#24292f;line-height:1.7;'
        'padding-left:1.1rem">'
        f"<li><strong>What was scanned:</strong> {ref}, as distributed.</li>"
        f"<li><strong>When:</strong> {scanned_str}.</li>"
        f"<li><strong>By what:</strong> {engine_name} {engine_version}, applied "
        'to the published <a href="/ui/methodology">danger rubric</a> '
        "(weights, bands, and the critical cap are all public).</li>"
        "<li><strong>What the grade means:</strong> this registry's opinion, "
        "computed by the disclosed automated methodology against the artifact "
        "version above, on the scan date above. It measures conformance to the "
        "rubric at scan time.</li>"
        "<li><strong>What it does not claim:</strong> it is not a statement that "
        "the product is malicious, insecure in your deployment, or unfit for use, "
        "and it is not an endorsement or certification.</li>"
        f"{unverified_line}"
        "<li><strong>Disagree?</strong> Grades are re-checkable against the same "
        f'package version, and corrections are welcome: <a href="{_DISPUTE_URL}" '
        'rel="noopener noreferrer">open a dispute</a> — see the '
        '<a href="/ui/dispute">dispute &amp; correction policy</a>.</li>'
        "</ul>"
        "</div>"
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
            masked = bool(row.get("masked", False))
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

            composite_str = (
                "—" if masked else (f"{composite:.1f}" if composite is not None else "—")
            )
            scanned_str = scanned_at[:19].replace("T", " ") if scanned_at else "—"
            if stale and not masked:
                scanned_str += " (stale)"

            parts.append(
                "<tr>"
                f'<td><a href="/ui/servers/{slug}">{name}</a>'
                f'<br><small style="color:#57606a;font-size:0.78rem">{slug}</small></td>'
                f"<td>{_grade_pill(grade, stale=stale, masked=masked)}</td>"
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
    masked: bool = False,
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
    now:
        Timestamp for grade-staleness rendering; ``None`` disables staleness.
    masked:
        Operator-withheld grade (masked-grades list): the letter grade, danger
        score, per-dimension breakdown, and finding detail are withheld pending
        governance review; scan metadata and the dispute path stay disclosed.
    """
    # --- Extract server fields ---
    name = escape(str(server.name))
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
    operator_masked = masked
    masked = operator_masked and record is not None  # nothing to withhold on an unscanned entry
    description_text = (
        MASKED_SERVER_DESCRIPTION if operator_masked else str(server.description or "")
    )
    description = escape(description_text)

    grade_display = "—" if masked else grade.upper()
    grade_color = (
        _GRADE_CSS["unscanned"]
        if stale or masked
        else _GRADE_CSS.get(grade, _GRADE_CSS["unscanned"])
    )
    composite_str = f"{composite_val:.1f}" if composite_val is not None else "—"
    danger_cell = "withheld" if masked else f"{escape(composite_str)} / 10"
    scanned_str = scanned_at_raw[:19].replace("T", " ") if scanned_at_raw else "Never"
    if stale and not masked:
        scanned_str += " (stale)"

    if masked:
        status_chip = (
            '<span class="chip" style="background:#8b949e">'
            "grade withheld — under governance review</span>"
        )
    elif stale:
        status_chip = '<span class="chip" style="background:#8b949e">stale — pending re-scan</span>'
    else:
        status_chip = ""

    # --- Hero card ---
    hero = (
        '<div class="card">'
        '<div class="grade-hero">'
        f'<div class="grade-big" style="background:{escape(grade_color)}">'
        f"{escape(grade_display)}</div>"
        "<div>"
        f'<h1 style="font-size:1.5rem;font-weight:700">{name}</h1>'
        f'<p style="color:#57606a;margin-top:0.2rem">{description}</p>'
        '<div class="meta-row" style="margin-top:0.6rem">'
        f"{_transparency_chip(transparency)}"
        '<span class="chip" style="background:#57606a">automated scan</span>'
        f"{status_chip}"
        "</div>"
        "</div>"
        "</div>"
        '<div class="meta-row">'
        '<div class="meta-item">'
        '<div class="meta-label">Danger score</div>'
        f"<div>{danger_cell}</div>"
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

    hero += (
        '<p style="margin-top:1rem;font-size:0.85rem;color:#57606a;'
        'border-left:3px solid #57606a;padding-left:0.75rem">'
        "<strong>Automated danger grade:</strong> this page reports detected or "
        "inferred risk from a scan. It is not an endorsement, certification, or "
        "claim that the server is malicious."
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

    if masked:
        hero += (
            '<p style="margin-top:1rem;font-size:0.85rem;color:#57606a;'
            'border-left:3px solid #8b949e;padding-left:0.75rem">'
            "<strong>Grade withheld:</strong> this entry's grade is temporarily "
            "withheld while the registry completes provenance verification and "
            "governance review of its published grades. The scan metadata above "
            "stays disclosed, and the dispute channel below remains open; the "
            "grade returns when review completes, with any change recorded in "
            'the <a href="/ui/corrections">corrections log</a>.'
            "</p>"
        )
    elif stale:
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
    # A masked entry must not read as a clean scan: finding detail is withheld
    # explicitly, never rendered as "No findings on record."
    if masked:
        findings_table = (
            '<p style="color:#57606a;font-size:0.9rem">Finding detail is withheld '
            "while this entry's grade is under governance review.</p>"
        )
    elif findings:
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

    # Score breakdown makes the grade legibly computed, not editorial — only
    # when there is a scan on record to break down, and never on a masked
    # entry (the weighted scores ARE the withheld verdict).
    if record is not None and not masked:
        breakdown = (
            '<h2 style="font-size:1rem;font-weight:600;margin:1.25rem 0 0.75rem">'
            "Score breakdown</h2>"
            f"{_dimension_breakdown(record)}"
        )
    else:
        breakdown = ""

    findings_section = (
        '<div class="card">'
        '<h2 style="font-size:1rem;font-weight:600;margin-bottom:0.75rem">Findings</h2>'
        f"{findings_table}"
        f"{breakdown}"
        "</div>"
    )

    # --- Methodology + disclaimer floor (only meaningful with a scan) ---
    floor = (
        _methodology_floor(
            # A masked page must not leak the letter through the floor's
            # cannot-verify line.
            grade="—" if masked else grade,
            engine_name=engine_name,
            engine_version=engine_version,
            scanned_str=escape(scanned_str),
            source_ref=str(getattr(source, "reference", "")) if source is not None else "",
            transparency_level=transparency,
        )
        if record is not None
        else ""
    )

    # --- Provenance & dispute card ---
    provenance_card = _provenance_card(server, record)

    # --- Back link ---
    back = '<p><a href="/">← Back to catalog</a></p>'

    body = (
        f"<main>{back}<div style='margin-top:1rem'>{hero}</div>"
        f"{floor}{provenance_card}{badge_box}{findings_section}</main>"
    )
    return _page(f"MCP Trust — {server.name}", body, banner=banner)


def render_methodology() -> str:
    """Render the public methodology page.

    Single, linkable source of the grading rubric — weights, bands, the
    critical cap, and the transparency axis — rendered from :func:`rubric` so
    the page can never disagree with the code that grades. Every per-grade
    "How to read this grade" block links here.
    """
    spec = rubric()
    weights = spec["dimension_weights"]
    bands = spec["grade_bands"]
    thresholds = spec["transparency_thresholds"]
    assert isinstance(weights, dict) and isinstance(bands, list)  # rubric() contract
    assert isinstance(thresholds, dict)

    weight_rows = "".join(
        "<tr>"
        f"<td>{escape(str(_DIMENSION_LABELS.get(dim, dim)))}</td>"
        f'<td style="font-variant-numeric:tabular-nums">×{float(w):.1f}</td>'
        "</tr>"
        for dim, w in weights.items()
    )

    # Bands are half-open with an inclusive UPPER bound (grading uses
    # ``score <= upper``): the first band is ``score ≤ u0``, each later band is
    # ``prev < score ≤ upper``, and the worst grade is ``score > last``. Render
    # the bounds exactly that way so a boundary value maps to exactly one row.
    band_rows: list[str] = []
    prev: float | None = None
    for upper, grade_value in bands:
        u = float(upper)
        rng = f"≤ {u:.1f}" if prev is None else f"&gt; {prev:.1f}, ≤ {u:.1f}"
        band_rows.append(
            "<tr>"
            f"<td>{escape(str(grade_value))}</td>"
            f'<td style="font-variant-numeric:tabular-nums">{rng}</td>'
            "</tr>"
        )
        prev = u
    band_rows.append(
        "<tr>"
        f"<td>{escape(str(spec['worst_grade']))}</td>"
        f'<td style="font-variant-numeric:tabular-nums">&gt; {prev:.1f}</td>'
        "</tr>"
    )

    high = float(thresholds["high"])
    medium = float(thresholds["medium"])

    body = (
        "<main>"
        '<p><a href="/">← Back to catalog</a></p>'
        '<h1 class="page-title" style="margin-top:1rem">How grades are computed</h1>'
        '<p class="page-subtitle">'
        "Every grade on this registry is produced by the automated rubric below. "
        "It is disclosed in full so a grade can be re-derived and argued with, "
        "not taken on faith."
        "</p>"
        '<div class="card">'
        '<h2 style="font-size:1rem;font-weight:600;margin-bottom:0.5rem">'
        "1. Danger-weighted score</h2>"
        '<p style="font-size:0.875rem;color:#57606a;margin-bottom:0.75rem">'
        "Each risk dimension (0–10) is multiplied by a fixed weight, then summed "
        "and clamped to 0–10. Weights emphasize the dimensions that actually "
        "separate risk (shell execution above all) and down-weight ones that "
        "appear on benign and dangerous servers alike."
        "</p>"
        "<table><thead><tr><th>Dimension</th><th>Weight</th></tr></thead>"
        f"<tbody>{weight_rows}</tbody></table>"
        "</div>"
        '<div class="card">'
        '<h2 style="font-size:1rem;font-weight:600;margin-bottom:0.5rem">'
        "2. Score → letter grade</h2>"
        "<table><thead><tr><th>Grade</th><th>Danger score</th></tr></thead>"
        f"<tbody>{''.join(band_rows)}</tbody></table>"
        '<p style="font-size:0.875rem;color:#57606a;margin-top:0.75rem">'
        "<strong>Critical cap:</strong> any single finding of a disqualifying "
        f"class (e.g. tool-poisoning or rug-pull) caps the grade at "
        f"{escape(str(spec['critical_cap']))} regardless of score."
        "</p>"
        "</div>"
        '<div class="card">'
        '<h2 style="font-size:1rem;font-weight:600;margin-bottom:0.5rem">'
        "3. Transparency (a separate axis)</h2>"
        '<p style="font-size:0.875rem;color:#24292f;line-height:1.7">'
        "Transparency is the fraction of a server's tools that declare behavior "
        "annotations. It is reported <strong>alongside</strong> the danger grade, "
        "never folded into it. "
        f"High ≥ {high:.0%}, medium ≥ {medium:.0%}, otherwise low. "
        "A low-transparency server's danger grade is inferred from spec defaults, "
        "so a low grade there means <em>cannot verify safe</em> — not "
        "<em>known dangerous</em>."
        "</p>"
        "</div>"
        '<div class="card">'
        '<h2 style="font-size:1rem;font-weight:600;margin-bottom:0.5rem">'
        "4. What is scanned</h2>"
        '<p style="font-size:0.875rem;color:#24292f;line-height:1.7">'
        "Published package artifact scans (npm, PyPI, or equivalent) are "
        "installed and launched locally by the scanner, and hosted endpoint "
        "entries are labeled as hosted endpoint scans. The declared MCP surface "
        "(tools, prompts, resources, annotations) is read back. The public report "
        "records the sandbox image when available, but does not expose per-run "
        "network mode. Scans never use real credentials; where a server requires "
        "environment variables, at most inert placeholder values are used."
        "</p>"
        "</div>"
        '<div class="card">'
        '<h2 style="font-size:1rem;font-weight:600;margin-bottom:0.5rem">'
        "5. Grade freshness</h2>"
        '<p style="font-size:0.875rem;color:#24292f;line-height:1.7">'
        f"A grade older than {STALE_AFTER_DAYS} days is marked <em>stale</em> on "
        "its page and badge, greys out, and is treated as historical until "
        "re-scanned. Vendors ship fixes; a grade never outlives its evidence "
        "silently."
        "</p>"
        "</div>"
        '<div class="card">'
        '<h2 style="font-size:1rem;font-weight:600;margin-bottom:0.5rem">'
        "Scope and disputes</h2>"
        '<p style="font-size:0.875rem;color:#24292f;line-height:1.7">'
        "A grade is this registry's opinion, computed by this methodology against "
        "a specific package version on a specific date, both shown on each grade "
        "page. It is not an endorsement, certification, or claim of malice. Grades "
        "are re-checkable against the same package version; corrections are "
        f'welcome at <a href="{_DISPUTE_URL}" rel="noopener noreferrer">the issue '
        'tracker</a> under the <a href="/ui/dispute">dispute &amp; correction '
        "policy</a>, and published grade changes live in the "
        '<a href="/ui/corrections">corrections log</a>.'
        "</p>"
        "</div>"
        "</main>"
    )
    return _page("MCP Trust — Methodology", body)


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
