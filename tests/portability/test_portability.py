# ruff: noqa: E501
from __future__ import annotations

import json
import socket
from pathlib import Path

import pytest
from typer.testing import CliRunner

from mcp_trust.cli.main import app
from mcp_trust.portability.errors import PortabilityInputError
from mcp_trust.portability.models import ChangeState
from mcp_trust.portability.service import (
    inspect_host,
    neutral_schema_json,
    parse_neutral,
    render_host,
    round_trip,
    supported_hosts,
)

FIXTURES = Path(__file__).parents[1] / "fixtures" / "portability"
runner = CliRunner()


def read_fixture(name: str) -> str:
    return (FIXTURES / name).read_text(encoding="utf-8")


@pytest.mark.parametrize(
    "name",
    [
        "local-stdio.json",
        "remote-http.json",
        "headers-auth.json",
        "environment-keys.json",
        "disabled-server.json",
        "unsupported-fields.json",
        "multi-server.json",
    ],
)
def test_synthetic_neutral_fixtures_validate(name: str) -> None:
    assert parse_neutral(read_fixture(name)).schema_version == "mcp-config-intent.v1"


def test_malformed_neutral_input_fails_closed() -> None:
    with pytest.raises(PortabilityInputError):
        parse_neutral(read_fixture("malformed.json"))


def test_probable_secret_argument_is_rejected_in_neutral_input() -> None:
    raw = json.loads(read_fixture("local-stdio.json"))
    raw["servers"]["localDemo"]["transport"]["args"] = ["--api-key", "synthetic-secret"]
    with pytest.raises(PortabilityInputError, match="secret-bearing flags"):
        parse_neutral(json.dumps(raw))


@pytest.mark.parametrize("host", supported_hosts())
def test_render_is_deterministic_and_stably_ordered(host: str) -> None:
    intent = parse_neutral(read_fixture("multi-server.json"))
    first = render_host(intent, host)
    second = render_host(intent, host)
    assert first == second
    assert (
        first.document.index("alpha") < first.document.index("zeta")
        if "zeta" in first.document
        else True
    )
    assert first.report.changes == sorted(
        first.report.changes,
        key=lambda item: (item.server, item.path, item.state, item.explanation),
    )


@pytest.mark.parametrize("host", supported_hosts())
def test_one_neutral_fixture_round_trips_with_machine_readable_report(host: str) -> None:
    intent = parse_neutral(read_fixture("local-stdio.json"))
    inspected, report = round_trip(intent, host)
    payload = report.model_dump(mode="json")
    assert inspected.intent.servers
    assert payload["schema_version"] == "mcp-config-portability-report.v1"
    assert payload["host"] == host
    assert payload["claim_ceiling"] == "HOST_FORMAT_COMPATIBILITY_EVIDENCE_ONLY"
    assert sum(payload["summary"].values()) == len(payload["changes"])


def test_codex_preserves_rich_policy_while_other_hosts_report_loss() -> None:
    intent = parse_neutral(read_fixture("local-stdio.json"))
    codex = render_host(intent, "codex").report
    claude = render_host(intent, "claude-code").report
    assert any(
        item.path == "tools.allow" and item.state == ChangeState.PRESERVED for item in codex.changes
    )
    assert any(
        item.path == "tools" and item.state == ChangeState.WIDENED for item in claude.changes
    )
    assert any(
        item.path == "startup.startup_timeout_seconds" and item.state == ChangeState.UNSUPPORTED
        for item in claude.changes
    )


@pytest.mark.parametrize("host", ["claude-code", "claude-desktop", "vscode"])
def test_disabled_servers_are_omitted_instead_of_widened_to_enabled(host: str) -> None:
    result = render_host(parse_neutral(read_fixture("disabled-server.json")), host)
    assert "disabledDemo" not in result.document
    assert any(
        item.path == "enabled" and item.state == ChangeState.DROPPED
        for item in result.report.changes
    )


def test_codex_disabled_server_state_is_preserved() -> None:
    result = render_host(parse_neutral(read_fixture("disabled-server.json")), "codex")
    assert "enabled = false" in result.document


@pytest.mark.parametrize(
    ("host", "document"),
    [
        (
            "codex",
            '[mcp_servers.demo]\nurl="https://safe.example.invalid/mcp"\nhttp_headers={Authorization="Bearer synthetic-secret-value"}\n',
        ),
        (
            "claude-code",
            '{"mcpServers":{"demo":{"type":"http","url":"https://safe.example.invalid/mcp","headers":{"Authorization":"Bearer synthetic-secret-value"}}}}',
        ),
        (
            "claude-desktop",
            '{"mcpServers":{"demo":{"command":"python","args":[],"env":{"API_KEY":"synthetic-secret-value"}}}}',
        ),
        (
            "vscode",
            '{"servers":{"demo":{"type":"http","url":"https://safe.example.invalid/mcp","headers":{"X-Key":"synthetic-secret-value"}}}}',
        ),
    ],
)
def test_inspect_never_copies_literal_secret_values(host: str, document: str) -> None:
    result = inspect_host(document, host)
    emitted = result.intent.model_dump_json() + result.report.model_dump_json()
    assert "synthetic-secret-value" not in emitted
    assert "placeholder" in emitted.lower() or "REDACTED" in emitted


def test_probable_secret_argument_is_redacted_during_inspect() -> None:
    document = json.dumps(
        {
            "mcpServers": {
                "demo": {
                    "type": "stdio",
                    "command": "python",
                    "args": ["server.py", "--token", "synthetic-secret-value"],
                }
            }
        }
    )
    result = inspect_host(document, "claude-code")
    emitted = result.intent.model_dump_json() + result.report.model_dump_json()
    assert "synthetic-secret-value" not in emitted
    assert "REDACTED_SECRET_1" in emitted


def test_duplicate_host_json_keys_fail_closed() -> None:
    document = '{"servers":{"one":{},"one":{}}}'
    with pytest.raises(PortabilityInputError, match="duplicate JSON key"):
        inspect_host(document, "vscode")


@pytest.mark.parametrize(
    ("host", "fixture"),
    [
        ("codex", "codex-defaults.toml"),
        ("claude-code", "claude-code-defaults.json"),
        ("vscode", "vscode-defaults.json"),
    ],
)
def test_host_defaults_are_explicit_in_report(host: str, fixture: str) -> None:
    report = inspect_host(read_fixture(fixture), host).report
    assert any(
        item.path == "enabled" and item.state == ChangeState.DEFAULTED for item in report.changes
    )


@pytest.mark.parametrize("host", supported_hosts())
def test_adapters_make_no_network_calls(monkeypatch: pytest.MonkeyPatch, host: str) -> None:
    def denied(*args: object, **kwargs: object) -> None:
        raise AssertionError(f"network attempted: {args!r} {kwargs!r}")

    monkeypatch.setattr(socket, "socket", denied)
    intent = parse_neutral(read_fixture("local-stdio.json"))
    result = render_host(intent, host)
    inspect_host(result.document, host)


@pytest.mark.parametrize("host", supported_hosts())
def test_pure_adapter_calls_write_no_files(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, host: str
) -> None:
    monkeypatch.chdir(tmp_path)
    before = list(tmp_path.rglob("*"))
    intent = parse_neutral(read_fixture("local-stdio.json"))
    round_trip(intent, host)
    assert list(tmp_path.rglob("*")) == before


def test_cli_writes_only_explicit_destinations(tmp_path: Path) -> None:
    document = tmp_path / "rendered.json"
    report = tmp_path / "report.json"
    result = runner.invoke(
        app,
        [
            "portability",
            "render",
            str(FIXTURES / "local-stdio.json"),
            "--host",
            "vscode",
            "--output",
            str(document),
            "--report",
            str(report),
        ],
    )
    assert result.exit_code == 0, result.output
    assert sorted(path.name for path in tmp_path.iterdir()) == ["rendered.json", "report.json"]


def test_cli_rejects_implicit_parent_creation(tmp_path: Path) -> None:
    result = runner.invoke(
        app,
        [
            "portability",
            "render",
            str(FIXTURES / "local-stdio.json"),
            "--host",
            "vscode",
            "--output",
            str(tmp_path / "missing" / "rendered.json"),
        ],
    )
    assert result.exit_code == 2
    assert not (tmp_path / "missing").exists()


@pytest.mark.parametrize(
    "name", ["config.toml", "claude_desktop_config.json", ".mcp.json", "mcp.json"]
)
def test_cli_refuses_real_host_configuration_filenames(tmp_path: Path, name: str) -> None:
    result = runner.invoke(
        app,
        [
            "portability",
            "render",
            str(FIXTURES / "local-stdio.json"),
            "--host",
            "vscode",
            "--output",
            str(tmp_path / name),
        ],
    )
    assert result.exit_code == 2
    assert not (tmp_path / name).exists()


def test_cli_refuses_to_overwrite_existing_destination(tmp_path: Path) -> None:
    destination = tmp_path / "staged.generated.json"
    destination.write_text("owned", encoding="utf-8")
    result = runner.invoke(
        app,
        [
            "portability",
            "render",
            str(FIXTURES / "local-stdio.json"),
            "--host",
            "vscode",
            "--output",
            str(destination),
        ],
    )
    assert result.exit_code == 2
    assert destination.read_text(encoding="utf-8") == "owned"


def test_schema_export_is_versioned_and_deterministic() -> None:
    first = neutral_schema_json()
    second = neutral_schema_json()
    assert first == second
    schema = json.loads(first)
    assert schema["properties"]["schema_version"]["const"] == "mcp-config-intent.v1"
    assert "servers" in schema["required"]


@pytest.mark.parametrize("command", ["validate", "round-trip"])
def test_cli_machine_readable_commands(command: str) -> None:
    args = ["portability", command, str(FIXTURES / "local-stdio.json")]
    if command == "round-trip":
        args.extend(["--host", "codex"])
    result = runner.invoke(app, args)
    assert result.exit_code == 0, result.output
    assert json.loads(result.output)


def test_cli_schema_command() -> None:
    result = runner.invoke(app, ["portability", "schema"])
    assert result.exit_code == 0, result.output
    assert json.loads(result.output)["title"] == "NeutralConfig"
