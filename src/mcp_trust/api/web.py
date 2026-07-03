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

from html import escape

from mcp_trust.core.grading import rubric
from mcp_trust.core.models import ScanRecord, Server

# Public repository issue tracker — the per-grade dispute / correction channel.
_DISPUTE_URL = "https://github.com/saagpatel/mcp-trust/issues"

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


def _grade_pill(grade: str) -> str:
    color = _GRADE_CSS.get(grade, _GRADE_CSS["unscanned"])
    return f'<span class="pill" style="background:{escape(color)}">{escape(grade.upper())}</span>'


def _transparency_chip(level: str) -> str:
    if not level:
        return '<span class="chip" style="background:#8b949e">—</span>'
    color = _TRANSPARENCY_CSS.get(level.lower(), _TRANSPARENCY_CSS[""])
    return f'<span class="chip" style="background:{escape(color)}">{escape(level)}</span>'


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
        'rel="noopener noreferrer">open a dispute</a>.</li>'
        "</ul>"
        "</div>"
    )


# ---------------------------------------------------------------------------
# Public render functions
# ---------------------------------------------------------------------------


def render_catalog(rows: list[dict], *, banner: str | None = None) -> str:
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
            scanned_at = escape(str(row.get("scanned_at", "") or ""))

            composite_str = f"{composite:.1f}" if composite is not None else "—"
            scanned_str = scanned_at[:19].replace("T", " ") if scanned_at else "—"

            parts.append(
                "<tr>"
                f'<td><a href="/ui/servers/{slug}">{name}</a>'
                f'<br><small style="color:#57606a;font-size:0.78rem">{slug}</small></td>'
                f"<td>{_grade_pill(grade)}</td>"
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

    grade_color = _GRADE_CSS.get(grade, _GRADE_CSS["unscanned"])
    composite_str = f"{composite_val:.1f}" if composite_val is not None else "—"
    scanned_str = scanned_at_raw[:19].replace("T", " ") if scanned_at_raw else "Never"

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

    # Score breakdown makes the grade legibly computed, not editorial — only
    # when there is a scan on record to break down.
    if record is not None:
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
            grade=grade,
            engine_name=engine_name,
            engine_version=engine_version,
            scanned_str=escape(scanned_str),
            source_ref=str(getattr(source, "reference", "")) if source is not None else "",
            transparency_level=transparency,
        )
        if record is not None
        else ""
    )

    # --- Back link ---
    back = '<p><a href="/">← Back to catalog</a></p>'

    body = (
        f"<main>{back}<div style='margin-top:1rem'>{hero}</div>"
        f"{floor}{badge_box}{findings_section}</main>"
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

    # Bands are ordered best→worst with an inclusive upper bound; the final
    # grade is everything above the last bound.
    band_rows: list[str] = []
    prev = 0.0
    for upper, grade_value in bands:
        band_rows.append(
            "<tr>"
            f"<td>{escape(str(grade_value))}</td>"
            f'<td style="font-variant-numeric:tabular-nums">{prev:.1f} – {float(upper):.1f}</td>'
            "</tr>"
        )
        prev = float(upper)
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
        "Scope and disputes</h2>"
        '<p style="font-size:0.875rem;color:#24292f;line-height:1.7">'
        "A grade is this registry's opinion, computed by this methodology against "
        "a specific package version on a specific date, both shown on each grade "
        "page. It is not an endorsement, certification, or claim of malice. Grades "
        "are re-checkable against the same package version; corrections are "
        f'welcome at <a href="{_DISPUTE_URL}" rel="noopener noreferrer">the issue '
        "tracker</a>."
        "</p>"
        "</div>"
        "</main>"
    )
    return _page("MCP Trust — Methodology", body)


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
