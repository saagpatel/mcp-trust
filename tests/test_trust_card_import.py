"""Import of MCPAudit Trust Before Connect cards (experimental).

The nws-weather fixture is a real card and pin produced by `mcp-audit trust`
against a public registry server; every other card here is synthetic.
"""

from __future__ import annotations

import copy
import json
from pathlib import Path
from typing import Any

import pytest
from typer.testing import CliRunner

from mcp_trust.catalog.trust_card import (
    ENGINE_NAME,
    TrustCardError,
    card_to_result,
    card_to_server,
    default_slug,
    load_card,
)
from mcp_trust.cli.main import app
from mcp_trust.core import grading
from mcp_trust.core.models import ScanRecord, Severity, SourceKind, TrustGrade
from mcp_trust.core.provenance import ScanProvenance, classify

FIXTURES = Path(__file__).parent / "fixtures" / "trust_cards"
CARD = FIXTURES / "nws-weather.card.json"
PIN = FIXTURES / "nws-weather.pin.json"
runner = CliRunner()


def real_card() -> dict[str, Any]:
    return json.loads(CARD.read_text(encoding="utf-8"))


def write(tmp_path: Path, card: dict[str, Any], name: str = "card.json") -> Path:
    path = tmp_path / name
    path.write_text(json.dumps(card), encoding="utf-8")
    return path


def synthetic(**changes: Any) -> dict[str, Any]:
    card = copy.deepcopy(real_card())
    card.update(changes)
    return card


# Loading -------------------------------------------------------------------------


@pytest.mark.parametrize(
    "mutate",
    [
        lambda c: c.update(schema="mcp-audit.trust-card/2"),
        lambda c: c.update(verdict="incomplete"),
        lambda c: c["observation"].update(status="failed"),
        lambda c: c.pop("target"),
    ],
)
def test_load_card_refuses_foreign_or_incomplete_cards(tmp_path: Path, mutate: Any) -> None:
    card = real_card()
    mutate(card)
    with pytest.raises(TrustCardError):
        load_card(write(tmp_path, card))


def test_load_card_refuses_non_json(tmp_path: Path) -> None:
    path = tmp_path / "card.json"
    path.write_bytes(b"\xff not json")
    with pytest.raises(TrustCardError):
        load_card(path)


# Mapping -------------------------------------------------------------------------


def test_real_card_maps_to_a_graded_engine_result() -> None:
    card = load_card(CARD)
    result = card_to_result(card, json.loads(PIN.read_text(encoding="utf-8")))
    assert result.engine_name == ENGINE_NAME
    assert result.findings[0].rule_id == "TBC-VERDICT"
    assert result.findings[0].severity == Severity.INFO
    assert {f.rule_id for f in result.findings[1:]} == {"TBC-READONLY-NET"}
    assert result.risk.network_access == 2.0 and result.risk.file_access == 0.0
    assert grading.grade(result.risk) == TrustGrade.A
    assert result.evidence is not None and result.evidence.tool_count == 10
    assert all(t.has_input_schema and t.input_schema_sha256 for t in result.evidence.tools)
    assert result.sandbox_image and result.sandbox_image.startswith("node:")


def test_server_comes_from_the_resolved_target() -> None:
    card = load_card(CARD)
    slug = default_slug(card)
    server = card_to_server(card, slug)
    assert slug == "cyanheads-nws-weather-mcp-server"
    assert server.source.kind == SourceKind.NPM
    assert server.source.reference == "@cyanheads/nws-weather-mcp-server"
    assert server.homepage and server.homepage.startswith("https://github.com/cyanheads/")


def test_env_keys_keep_only_valid_names() -> None:
    card = synthetic()
    card["target"]["package"]["env"] = [{"name": "API_TOKEN"}, {"name": "bad name"}, {"x": 1}]
    assert card_to_server(card, "x").source.env_keys == ["API_TOKEN"]


def test_remote_card_is_marked_outside_only() -> None:
    card = synthetic()
    card["target"] = {
        "server_name": "com.example/remote",
        "remote": {"type": "streamable-http", "url": "https://mcp.example.com/mcp"},
    }
    card["observation"] = {"mode": "outside", "status": "complete", "tools": [], "phases": []}
    card["mismatches"] = []
    server = card_to_server(card, default_slug(card))
    result = card_to_result(card)
    assert server.slug == "example-remote" and server.source.kind == SourceKind.REMOTE
    assert "TBC-OUTSIDE-ONLY" in {f.rule_id for f in result.findings}
    assert result.risk.network_access == 3.0


def test_do_not_install_caps_the_grade() -> None:
    card = synthetic(verdict="do_not_install", headline="Do not install.")
    card["mismatches"] = [
        {
            "severity": "high",
            "rule": "TBC-READONLY-WRITE",
            "tool": "nws_get_forecast",
            "summary": "x",
        }
    ]
    result = card_to_result(card)
    assert result.risk.count(Severity.CRITICAL) == 1
    assert result.risk.file_access == 8.0
    assert grading.grade(result.risk) in {TrustGrade.D, TrustGrade.F}


def test_unprompted_egress_scores_higher_than_tool_egress() -> None:
    card = synthetic()
    card["mismatches"] = [{"severity": "medium", "rule": "TBC-UNPROMPTED-NET", "summary": "x"}]
    assert card_to_result(card).risk.network_access == 6.0


def test_keyword_noise_on_read_only_tools_does_not_raise_danger() -> None:
    card = synthetic()
    for tool in card["observation"]["tools"]:
        tool["inferred"] = ["shell_execution", "exfiltration", "file_write"]
        tool["read_only_hint"] = True
    risk = card_to_result(card).risk
    assert risk.shell_execution == 0.0 and risk.exfiltration == 0.0


def test_imported_verdicts_stay_demo_classified() -> None:
    result = card_to_result(load_card(CARD))
    record = ScanRecord(
        id="a" * 32,
        server_slug="cyanheads-nws-weather-mcp-server",
        engine_name=result.engine_name,
        engine_version=result.engine_version,
        grade=grading.grade(result.risk),
        risk=result.risk,
        findings=result.findings,
        scanned_at="2026-11-08T00:00:00Z",
    )
    assert classify(record) == ScanProvenance.DEMO


# CLI -----------------------------------------------------------------------------


def test_cli_imports_the_card_as_a_catalog_entry(tmp_path: Path) -> None:
    db = str(tmp_path / "registry.db")
    result = runner.invoke(app, ["import-card", str(CARD), "--pin", str(PIN), "--db", db])
    assert result.exit_code == 0, result.output
    assert "as 'cyanheads-nws-weather-mcp-server'" in result.output
    check = runner.invoke(app, ["check", "cyanheads-nws-weather-mcp-server", "--db", db])
    assert check.exit_code == 0 and "Grade: A" in check.output


def test_cli_refuses_a_slug_owned_by_another_server(tmp_path: Path) -> None:
    db = str(tmp_path / "registry.db")
    assert runner.invoke(app, ["import-card", str(CARD), "--db", db]).exit_code == 0
    other = synthetic()
    other["target"]["package"]["identifier"] = "@someone/else"
    result = runner.invoke(app, ["import-card", str(write(tmp_path, other)), "--db", db])
    assert result.exit_code == 1 and "--slug" in result.output


def test_cli_refuses_incomplete_cards(tmp_path: Path) -> None:
    path = write(tmp_path, synthetic(verdict="incomplete"))
    result = runner.invoke(app, ["import-card", str(path), "--db", str(tmp_path / "r.db")])
    assert result.exit_code == 1 and "incomplete" in result.output


# Review fixes ----------------------------------------------------------------------


@pytest.mark.parametrize(
    "mutate",
    [
        lambda c: c.pop("observation"),
        lambda c: c["observation"].pop("status"),
        lambda c: c["observation"].update(status="partial"),
        lambda c: c.pop("verdict"),
        lambda c: c.update(verdict="maybe"),
        lambda c: c["observation"].update(tools="nope"),
        lambda c: c["observation"].update(phases=[1, 2]),
        lambda c: c.update(mismatches={"x": 1}),
        lambda c: c.pop("generated_at"),
        lambda c: c.update(generated_at="2999-01-01T00:00:00Z"),
        lambda c: c.update(generated_at="not a time"),
    ],
)
def test_only_complete_well_formed_cards_load(tmp_path: Path, mutate: Any) -> None:
    card = real_card()
    mutate(card)
    with pytest.raises(TrustCardError):
        load_card(write(tmp_path, card))


def test_pin_must_be_a_trust_pin(tmp_path: Path) -> None:
    db = str(tmp_path / "r.db")
    bad = write(tmp_path, {"schema": "other"}, "pin.json")
    result = runner.invoke(app, ["import-card", str(CARD), "--pin", str(bad), "--db", db])
    assert result.exit_code == 1 and "trust-pin" in result.output


def test_malformed_resources_field_counts_as_zero() -> None:
    card = synthetic()
    card["observation"]["resources"] = ["a", "b"]
    result = card_to_result(card)
    assert result.evidence is not None and result.evidence.resource_count == 0


def test_severity_counts_cover_every_stored_finding() -> None:
    result = card_to_result(load_card(CARD))
    counted = sum(result.risk.findings_by_severity.values())
    assert counted == len(result.findings)


def test_scan_keeps_observation_time_and_older_cards_do_not_supersede(tmp_path: Path) -> None:
    from mcp_trust.store.db import connect, init_schema
    from mcp_trust.store.repository import ScanRepository

    db = str(tmp_path / "r.db")
    assert runner.invoke(app, ["import-card", str(CARD), "--db", db]).exit_code == 0
    older = synthetic(generated_at="2026-01-01T00:00:00Z", verdict="review", headline="older")
    assert (
        runner.invoke(app, ["import-card", str(write(tmp_path, older)), "--db", db]).exit_code == 0
    )
    conn = connect(db)
    init_schema(conn)
    latest = ScanRepository(conn).latest("cyanheads-nws-weather-mcp-server")
    assert latest is not None
    assert latest.scanned_at.isoformat().startswith(real_card()["generated_at"][:19])
    assert latest.findings[0].detail != "older"


def test_same_name_in_another_registry_is_refused(tmp_path: Path) -> None:
    db = str(tmp_path / "r.db")
    assert runner.invoke(app, ["import-card", str(CARD), "--db", db]).exit_code == 0
    pypi = synthetic()
    pypi["target"]["package"]["registry_type"] = "pypi"
    result = runner.invoke(app, ["import-card", str(write(tmp_path, pypi)), "--db", db])
    assert result.exit_code == 1 and "npm" in result.output


def test_real_scan_is_not_superseded_without_replace(tmp_path: Path) -> None:
    from mcp_trust.store.db import connect, init_schema
    from mcp_trust.store.repository import ScanRepository, ServerRepository

    db = str(tmp_path / "r.db")
    card = load_card(CARD)
    conn = connect(db)
    init_schema(conn)
    ServerRepository(conn).upsert(card_to_server(card, "cyanheads-nws-weather-mcp-server"))
    real = ScanRecord(
        id="b" * 32,
        server_slug="cyanheads-nws-weather-mcp-server",
        engine_name="mcpaudit",
        engine_version="3.0.0",
        grade=TrustGrade.B,
        risk=card_to_result(card).risk,
        scanned_at="2026-01-01T00:00:00Z",
    )
    ScanRepository(conn).record(real)
    refused = runner.invoke(app, ["import-card", str(CARD), "--db", db])
    assert refused.exit_code == 1 and "--replace" in refused.output
    replaced = runner.invoke(app, ["import-card", str(CARD), "--db", db, "--replace"])
    assert replaced.exit_code == 0, replaced.output


def test_records_beyond_admission_limits_are_refused_before_any_write(tmp_path: Path) -> None:
    from mcp_trust.store.db import connect, init_schema
    from mcp_trust.store.repository import ServerRepository

    card = synthetic()
    card["mismatches"] = [{"severity": "low", "rule": "TBC-DRIFT", "summary": "x"}] * 1024
    db = str(tmp_path / "r.db")
    result = runner.invoke(app, ["import-card", str(write(tmp_path, card)), "--db", db])
    assert result.exit_code == 1 and "1024" in result.output
    conn = connect(db)
    init_schema(conn)
    assert ServerRepository(conn).get("cyanheads-nws-weather-mcp-server") is None
