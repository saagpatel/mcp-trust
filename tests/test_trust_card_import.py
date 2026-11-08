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
    result = card_to_result(card, json.loads(PIN.read_text(encoding="utf-8")))
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


# Round-two review fixes -----------------------------------------------------------


def real_pin() -> dict[str, Any]:
    return json.loads(PIN.read_text(encoding="utf-8"))


@pytest.mark.parametrize(
    "mutate",
    [
        lambda c: c["observation"].pop("tools"),
        lambda c: c["observation"].pop("phases"),
        lambda c: c.pop("mismatches"),
        lambda c: c["observation"]["tools"][0].update(read_only_hint="yes"),
        lambda c: c["observation"]["tools"][0].update(inferred="file_read"),
        lambda c: c["observation"]["tools"][0].pop("name"),
        lambda c: c["observation"]["phases"][0].update(file_changes="none"),
        lambda c: c["observation"]["phases"][0].update(network="none"),
        lambda c: c["observation"]["phases"][0].update(file_changes=[{"path": "/x"}]),
        lambda c: c["mismatches"].append({"severity": "severe", "rule": "X", "summary": "s"}),
        lambda c: c["target"]["package"].update(identifier=""),
    ],
)
def test_missing_or_malformed_evidence_is_refused(tmp_path: Path, mutate: Any) -> None:
    card = real_card()
    mutate(card)
    with pytest.raises(TrustCardError):
        server = card_to_server(load_card(write(tmp_path, card)), "x")
        assert server  # unreachable when refused


@pytest.mark.parametrize(
    "mutate",
    [
        lambda p: p.update(server_name="io.github.someone/else"),
        lambda p: p.update(version="0.11.0"),
        lambda p: p.update(package="pypi:@cyanheads/nws-weather-mcp-server"),
        lambda p: p.update(created_at="2026-01-01T00:00:00Z"),
        lambda p: p["tools"].pop(),
        lambda p: p["tools"][0].update(input_schema_sha256="not-a-hash"),
    ],
)
def test_pins_from_another_run_are_refused(tmp_path: Path, mutate: Any) -> None:
    from mcp_trust.catalog.trust_card import load_pin

    pin = real_pin()
    mutate(pin)
    with pytest.raises(TrustCardError):
        load_pin(write(tmp_path, pin, "pin.json"), load_card(CARD))


def test_no_pin_means_no_schema_claims() -> None:
    assert card_to_result(load_card(CARD)).evidence is None


def test_oversized_server_fields_are_refused_before_any_write(tmp_path: Path) -> None:
    from mcp_trust.store.db import connect, init_schema
    from mcp_trust.store.repository import ServerRepository

    card = synthetic()
    card["target"]["description"] = "d" * (1_100_000)
    db = str(tmp_path / "r.db")
    result = runner.invoke(app, ["import-card", str(write(tmp_path, card)), "--db", db])
    assert result.exit_code == 1 and "admits" in result.output
    conn = connect(db)
    init_schema(conn)
    assert ServerRepository(conn).get("cyanheads-nws-weather-mcp-server") is None


def test_unreadable_latest_scan_is_an_error_not_a_traceback(tmp_path: Path) -> None:
    from mcp_trust.store.db import connect, init_schema

    db = str(tmp_path / "r.db")
    assert runner.invoke(app, ["import-card", str(CARD), "--db", db]).exit_code == 0
    conn = connect(db)
    init_schema(conn)
    conn.execute("UPDATE scans SET findings_json = 'not json'")
    conn.commit()
    result = runner.invoke(app, ["import-card", str(CARD), "--db", db])
    assert result.exit_code == 1 and "unreadable latest scan" in result.output


def test_scans_without_a_readable_server_row_are_refused(tmp_path: Path) -> None:
    from mcp_trust.store.db import connect, init_schema

    db = str(tmp_path / "r.db")
    assert runner.invoke(app, ["import-card", str(CARD), "--db", db]).exit_code == 0
    conn = connect(db)
    init_schema(conn)
    conn.execute("UPDATE servers SET source_json = 'not json'")
    conn.commit()
    result = runner.invoke(app, ["import-card", str(CARD), "--db", db])
    assert result.exit_code == 1 and "unreadable server row" in result.output


# Round-three review fixes ---------------------------------------------------------


def scored(tools: list[dict[str, Any]], phases: list[dict[str, Any]], mismatches: list[Any]) -> Any:
    card = synthetic()
    card["observation"]["tools"] = tools
    card["observation"]["phases"] = phases
    card["mismatches"] = mismatches
    return card_to_result(card).risk


def tool(name: str = "t", read_only: bool | None = True, **extra: Any) -> dict[str, Any]:
    return {
        "name": name,
        "read_only_hint": read_only,
        "destructive_hint": extra.pop("destructive", None),
        "open_world_hint": None,
        "inferred": extra.pop("inferred", []),
    }


def phase(*changes: dict[str, Any], network: list[Any] | None = None) -> dict[str, Any]:
    return {"name": "startup", "file_changes": list(changes), "network": network or []}


@pytest.mark.parametrize(
    ("tools", "phases", "mismatches", "dimension", "expected"),
    [
        ([tool()], [phase({"path": "/tmp/x", "in_home": False})], [], "file_access", 8.0),
        ([tool()], [phase({"path": "/scratch/x", "in_home": True})], [], "file_access", 3.0),
        (
            [tool()],
            [phase({"path": "/scratch", "in_home": True, "entries_only": True})],
            [],
            "file_access",
            1.0,
        ),
        ([tool("a", None), tool("b", True)], [], [], "file_access", 1.5),
        ([tool()], [phase(network=[{"kind": "dns"}])], [], "network_access", 2.0),
        (
            [tool()],
            [],
            [{"severity": "high", "rule": "TBC-READONLY-NET", "summary": "x"}],
            "network_access",
            8.0,
        ),
        (
            [tool("a", None, inferred=["shell_execution"]), tool("b")],
            [],
            [],
            "shell_execution",
            5.0,
        ),
        ([tool("a", None, destructive=True), tool("b")], [], [], "destructive", 5.0),
    ],
)
def test_documented_calibration(
    tools: Any, phases: Any, mismatches: Any, dimension: str, expected: float
) -> None:
    assert getattr(scored(tools, phases, mismatches), dimension) == expected


def test_injection_caps_the_grade() -> None:
    risk = scored(
        [tool()], [], [{"severity": "high", "rule": "TBC-INJECTION", "summary": "ignore previous"}]
    )
    assert risk.count(Severity.CRITICAL) == 1 and grading.grade(risk) in {
        TrustGrade.D,
        TrustGrade.F,
    }


@pytest.mark.parametrize(
    "mutate",
    [
        lambda c: c["observation"]["tools"][0].pop("inferred"),
        lambda c: c["observation"]["tools"][0].pop("read_only_hint"),
    ],
)
def test_missing_scoring_fields_are_refused(tmp_path: Path, mutate: Any) -> None:
    card = real_card()
    mutate(card)
    with pytest.raises(TrustCardError):
        load_card(write(tmp_path, card))


def test_unreadable_server_row_without_scans_is_left_alone(tmp_path: Path) -> None:
    from mcp_trust.store.db import connect, init_schema

    db = str(tmp_path / "r.db")
    assert runner.invoke(app, ["import-card", str(CARD), "--db", db]).exit_code == 0
    conn = connect(db)
    init_schema(conn)
    conn.execute("DELETE FROM scans")
    conn.execute("UPDATE servers SET source_json = 'not json'")
    conn.commit()
    result = runner.invoke(app, ["import-card", str(CARD), "--db", db])
    assert result.exit_code == 1 and "unreadable server row" in result.output
    row = conn.execute("SELECT source_json FROM servers").fetchone()
    assert row[0] == "not json"


def test_non_regular_files_are_refused(tmp_path: Path) -> None:
    with pytest.raises(TrustCardError):
        load_card(tmp_path)


def test_imports_write_no_receipt(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    receipts = tmp_path / "receipts"
    monkeypatch.setenv("MCP_TRUST_RECEIPTS_DIR", str(receipts))
    db = str(tmp_path / "r.db")
    assert runner.invoke(app, ["import-card", str(CARD), "--db", db]).exit_code == 0
    assert not receipts.exists() or not any(receipts.iterdir())


# Round-four review fixes ----------------------------------------------------------


def remote_card_and_pin(card_url: str, pin_target: str) -> tuple[dict[str, Any], dict[str, Any]]:
    card = synthetic()
    card["target"] = {
        "input": card_url,
        "kind": "url",
        "remote": {"type": "streamable-http", "url": card_url},
    }
    card["observation"]["mode"] = "outside"
    card["observation"]["phases"] = []
    card["mismatches"] = []
    pin = real_pin()
    pin.update(target=pin_target, server_name=None, package=None, version=None)
    return card, pin


def test_remote_pin_must_target_the_same_endpoint(tmp_path: Path) -> None:
    from mcp_trust.catalog.trust_card import load_pin

    card, pin = remote_card_and_pin("https://first.example/mcp", "https://different.example/mcp")
    with pytest.raises(TrustCardError):
        load_pin(write(tmp_path, pin, "pin.json"), load_card(write(tmp_path, card)))
    card, pin = remote_card_and_pin("https://first.example/mcp", "https://first.example/mcp")
    assert load_pin(write(tmp_path, pin, "pin.json"), load_card(write(tmp_path, card)))


def test_reimporting_the_same_card_is_a_no_op(tmp_path: Path) -> None:
    from mcp_trust.store.db import connect, init_schema

    db = str(tmp_path / "r.db")
    assert runner.invoke(app, ["import-card", str(CARD), "--db", db]).exit_code == 0
    again = runner.invoke(app, ["import-card", str(CARD), "--db", db])
    assert again.exit_code == 0 and "already imported" in again.output
    conn = connect(db)
    init_schema(conn)
    assert conn.execute("SELECT COUNT(*) FROM scans").fetchone()[0] == 1


def test_older_card_imports_behind_a_newer_real_scan(tmp_path: Path) -> None:
    from mcp_trust.store.db import connect, init_schema
    from mcp_trust.store.repository import ScanRepository, ServerRepository

    db = str(tmp_path / "r.db")
    card = load_card(CARD)
    conn = connect(db)
    init_schema(conn)
    ServerRepository(conn).upsert(card_to_server(card, "cyanheads-nws-weather-mcp-server"))
    ScanRepository(conn).record(
        ScanRecord(
            id="c" * 32,
            server_slug="cyanheads-nws-weather-mcp-server",
            engine_name="mcpaudit",
            engine_version="3.0.0",
            grade=TrustGrade.B,
            risk=card_to_result(card).risk,
            scanned_at="2099-01-01T00:00:00Z",
        )
    )
    result = runner.invoke(app, ["import-card", str(CARD), "--db", db])
    assert result.exit_code == 0, result.output
    latest = ScanRepository(conn).latest("cyanheads-nws-weather-mcp-server")
    assert latest is not None and latest.engine_name == "mcpaudit"


def test_deeply_nested_json_is_a_clean_error(tmp_path: Path) -> None:
    path = tmp_path / "card.json"
    path.write_text("[" * 200_000, encoding="utf-8")
    with pytest.raises(TrustCardError):
        load_card(path)


# Round-five review fixes ----------------------------------------------------------


def test_adding_a_pin_later_needs_replace_and_supersedes_cleanly(tmp_path: Path) -> None:
    from mcp_trust.store.db import connect, init_schema
    from mcp_trust.store.repository import ScanRepository

    db = str(tmp_path / "r.db")
    assert runner.invoke(app, ["import-card", str(CARD), "--db", db]).exit_code == 0
    refused = runner.invoke(app, ["import-card", str(CARD), "--pin", str(PIN), "--db", db])
    assert refused.exit_code == 1 and "different evidence" in refused.output
    enriched = runner.invoke(
        app, ["import-card", str(CARD), "--pin", str(PIN), "--db", db, "--replace"]
    )
    assert enriched.exit_code == 0, enriched.output
    conn = connect(db)
    init_schema(conn)
    assert conn.execute("SELECT COUNT(*) FROM scans").fetchone()[0] == 1
    latest = ScanRepository(conn).latest("cyanheads-nws-weather-mcp-server")
    assert latest is not None and latest.evidence is not None


def test_truncated_change_lists_score_the_worst_case() -> None:
    card = synthetic()
    card["observation"]["phases"] = [
        {"name": "startup", "file_changes": [], "network": [], "file_changes_truncated": 3}
    ]
    assert card_to_result(card).risk.file_access == 8.0


def test_future_card_time_is_clamped_to_now() -> None:
    from datetime import UTC, datetime

    from mcp_trust.catalog.trust_card import observed_at

    now = datetime(2026, 11, 8, 12, 0, tzinfo=UTC)
    soon = {"generated_at": "2026-11-08T12:03:00Z"}
    assert observed_at(soon, now) == now


def test_pin_hash_with_trailing_newline_is_refused(tmp_path: Path) -> None:
    from mcp_trust.catalog.trust_card import load_pin

    pin = real_pin()
    pin["tools"][0]["input_schema_sha256"] += "\n"
    with pytest.raises(TrustCardError):
        load_pin(write(tmp_path, pin, "pin.json"), load_card(CARD))


def test_import_waits_on_a_concurrent_writer_and_writes_nothing(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    import sqlite3

    from mcp_trust.store.db import connect, init_schema

    db = str(tmp_path / "r.db")
    holder = connect(db)
    init_schema(holder)
    holder.execute("BEGIN IMMEDIATE")

    def quick(path: str) -> sqlite3.Connection:
        conn = sqlite3.connect(str(path), timeout=0.1)
        conn.row_factory = sqlite3.Row
        return conn

    monkeypatch.setattr("mcp_trust.cli.main.connect", quick)
    result = runner.invoke(app, ["import-card", str(CARD), "--db", db])
    assert result.exit_code == 1 and "busy" in result.output
    holder.rollback()
    assert holder.execute("SELECT COUNT(*) FROM servers").fetchone()[0] == 0


# Bundled catalog cards -------------------------------------------------------------

BUNDLED = Path(__file__).parents[1] / "src" / "mcp_trust" / "catalog" / "trust_cards"


def test_bundled_cards_are_complete_named_by_slug_and_pinned() -> None:
    from mcp_trust.catalog.trust_card import load_pin

    cards = sorted(BUNDLED.glob("*.card.json"))
    assert cards, "no bundled cards"
    for path in cards:
        card = load_card(path)
        assert path.name == f"{default_slug(card)}.card.json"
        pin = path.with_name(path.name.removesuffix(".card.json") + ".pin.json")
        assert pin.is_file() and load_pin(pin, card)


def test_import_cards_loads_every_bundled_card_as_demo_data(tmp_path: Path) -> None:
    from mcp_trust.store.db import connect, init_schema
    from mcp_trust.store.repository import ScanRepository

    db = str(tmp_path / "r.db")
    result = runner.invoke(app, ["import-cards", "--db", db])
    assert result.exit_code == 0, result.output
    cards = sorted(BUNDLED.glob("*.card.json"))
    assert f"Imported {len(cards)} of {len(cards)} card(s)." in result.output
    conn = connect(db)
    init_schema(conn)
    scans = ScanRepository(conn)
    for path in cards:
        latest = scans.latest(path.name.removesuffix(".card.json"))
        assert latest is not None and classify(latest) == ScanProvenance.DEMO
    again = runner.invoke(app, ["import-cards", "--db", db])
    assert again.exit_code == 0 and again.output.count("already imported") == len(cards)


def test_import_cards_reports_refusals_and_continues(tmp_path: Path) -> None:
    folder = tmp_path / "cards"
    folder.mkdir()
    (folder / "good.card.json").write_bytes(CARD.read_bytes())
    write(folder, synthetic(verdict="incomplete"), "bad.card.json")
    result = runner.invoke(app, ["import-cards", str(folder), "--db", str(tmp_path / "r.db")])
    assert result.exit_code == 1
    assert "Imported 1 of 2 card(s)." in result.output and "bad.card.json" in result.output


def test_import_cards_needs_cards(tmp_path: Path) -> None:
    result = runner.invoke(app, ["import-cards", str(tmp_path), "--db", str(tmp_path / "r.db")])
    assert result.exit_code == 1 and "no *.card.json" in result.output
