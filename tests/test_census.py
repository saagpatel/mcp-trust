"""MCP Census: synthetic registry pages only; nothing is fetched."""

from __future__ import annotations

import csv
import json
from pathlib import Path
from typing import Any

import pytest
from typer.testing import CliRunner

from mcp_trust.census import (
    CensusError,
    build_figures,
    fetch_latest,
    registry_fetcher,
    run_census,
    to_row,
)
from mcp_trust.cli.main import app

REGISTRY = "https://registry.example.test"
CARDS = Path(__file__).parents[1] / "src" / "mcp_trust" / "catalog" / "trust_cards"


def entry(
    name: str,
    *,
    status: str = "active",
    schema: str = "2025-12-11",
    packages: list[dict[str, Any]] | None = None,
    remotes: list[dict[str, Any]] | None = None,
) -> dict[str, Any]:
    server: dict[str, Any] = {
        "$schema": f"https://static.modelcontextprotocol.io/schemas/{schema}/server.schema.json",
        "name": name,
        "description": "Synthetic.",
        "version": "1.0.0",
        "packages": packages or [],
        "remotes": remotes or [],
    }
    return {
        "server": server,
        "_meta": {"io.modelcontextprotocol.registry/official": {"status": status}},
    }


def npm(transport: str = "stdio") -> dict[str, Any]:
    return {
        "registryType": "npm",
        "identifier": "x",
        "version": "1.0.0",
        "transport": {"type": transport},
    }


def pypi() -> dict[str, Any]:
    return {
        "registryType": "pypi",
        "identifier": "y",
        "version": "1.0.0",
        "transport": {"type": "stdio"},
    }


ENTRIES = [
    entry("io.github.alice/one", packages=[npm()]),
    entry("io.github.alice/two", packages=[pypi()], schema="2025-09-29"),
    entry("com.example/remote", remotes=[{"type": "streamable-http", "url": "https://a"}]),
    entry("com.example/legacy", remotes=[{"type": "sse", "url": "https://b"}], status="deprecated"),
    entry(
        "io.github.bob/both",
        packages=[npm()],
        remotes=[
            {"type": "sse", "url": "https://c"},
            {"type": "streamable-http", "url": "https://d"},
        ],
    ),
]


class Pages:
    def __init__(self, entries: list[dict[str, Any]], size: int = 2) -> None:
        self.pages = [entries[i : i + size] for i in range(0, len(entries), size)]
        self.urls: list[str] = []

    def __call__(self, url: str) -> Any:
        self.urls.append(url)
        index = len(self.urls) - 1
        payload: dict[str, Any] = {"servers": self.pages[index]}
        if index + 1 < len(self.pages):
            payload["metadata"] = {"nextCursor": f"cursor/{index + 1}"}
        return payload


def figure(figures: list[Any], key: str) -> dict[object, tuple[object, ...]]:
    found = next(f for f in figures if f.key == key)
    return {row[0]: row for row in found.rows}


def test_pages_are_followed_with_the_cursor() -> None:
    fetch = Pages(ENTRIES)
    entries, pages, truncated = fetch_latest(fetch, REGISTRY)
    assert len(entries) == 5 and pages == 3 and not truncated
    assert "version=latest" in fetch.urls[0] and "cursor=cursor%2F1" in fetch.urls[1]


def test_page_cap_marks_the_census_as_a_lower_bound() -> None:
    entries, pages, truncated = fetch_latest(Pages(ENTRIES), REGISTRY, max_pages=2)
    assert len(entries) == 4 and pages == 2 and truncated


def test_rows_classify_publishers_versions_and_transports() -> None:
    row = to_row(ENTRIES[4])
    assert row is not None
    assert (row.publisher, row.namespace_kind) == ("bob", "GitHub account")
    assert row.offers_sse and not row.remote_sse_only
    domain = to_row(ENTRIES[3])
    assert domain is not None and domain.publisher == "example.com" and domain.remote_sse_only
    assert to_row({"server": {"description": "no name"}}) is None


def test_figures_count_correctly() -> None:
    rows = [r for r in (to_row(e) for e in ENTRIES) if r is not None]
    figures = build_figures(rows, [{"verdict": "review", "grade": "C"}])
    overview = figure(figures, "overview")
    assert overview["servers listed"][1] == 5 and overview["distinct publishers"][1] == 3
    assert overview["offer both"][1] == 1
    assert figure(figures, "status")["deprecated"][1] == 1
    assert figure(figures, "schema-versions")["2025-09-29"][1] == 1
    sse = figure(figures, "http-sse")
    assert sse["list SSE anywhere"][1:] == (2, "40.0%")
    assert sse["remote endpoints are SSE only"][1:] == (1, "33.3%")
    assert figure(figures, "card-verdicts")["review"][1] == 1


def test_report_links_every_figure_to_its_data_and_names_no_card(tmp_path: Path) -> None:
    summary = run_census(tmp_path, Pages(ENTRIES), CARDS, REGISTRY)
    page = (tmp_path / "index.html").read_text(encoding="utf-8")
    for key in summary["figures"]:
        csv_path = tmp_path / "data" / f"{key}.csv"
        assert csv_path.is_file() and f'href="data/{key}.csv"' in page
        assert list(csv.reader(csv_path.open(encoding="utf-8")))[0]
    assert (tmp_path / "data" / "servers.csv").is_file()
    assert json.loads((tmp_path / "data" / "census.json").read_text())["entries"] == 5
    for card in CARDS.glob("*.card.json"):
        assert card.name.removesuffix(".card.json") not in page


def test_server_text_is_escaped(tmp_path: Path) -> None:
    hostile = [entry('io.github.x/<script>alert("x")</script>', packages=[npm()])]
    run_census(tmp_path, Pages(hostile), CARDS, REGISTRY)
    page = (tmp_path / "index.html").read_text(encoding="utf-8")
    assert "<script>alert" not in page


def test_fetcher_stays_on_the_registry_host() -> None:
    fetch = registry_fetcher(REGISTRY)
    with pytest.raises(CensusError):
        fetch("https://elsewhere.example.test/v0.1/servers")
    with pytest.raises(CensusError):
        fetch("http://registry.example.test/v0.1/servers")


def test_unexpected_page_shape_is_an_error() -> None:
    with pytest.raises(CensusError):
        fetch_latest(lambda url: {"items": []}, REGISTRY)


def test_cli_reports_a_registry_failure(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    def failing(*args: object, **kwargs: object) -> object:
        raise CensusError("registry read failed (URLError)")

    monkeypatch.setattr("mcp_trust.census.run_census", failing)
    result = CliRunner().invoke(app, ["census", "--out", str(tmp_path / "c")])
    assert result.exit_code == 1 and "registry read failed" in result.output


@pytest.mark.parametrize(
    ("schema", "expected"),
    [
        (
            "https://static.modelcontextprotocol.io/schemas/2025-12-11/server.schema.json",
            "2025-12-11",
        ),
        ("https://static.modelcontextprotocol.io/schemas/server.json", "other"),
        ("", "not declared"),
    ],
)
def test_schema_versions_are_dated_or_labelled(schema: str, expected: str) -> None:
    item = entry("io.github.x/y", packages=[npm()])
    item["server"]["$schema"] = schema
    row = to_row(item)
    assert row is not None and row.schema_version == expected
