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
    _compare,
    canonical_neutral,
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


@pytest.mark.parametrize(
    ("url", "secret_fragments", "safe_diagnostic"),
    [
        (
            "https://alice:correct-horse@example.invalid/mcp",
            ("alice", "correct-horse"),
            "cannot embed credentials",
        ),
        (
            "https://example.invalid/mcp?token=violet-credential",
            ("violet-credential",),
            "cannot carry secret-like query parameters",
        ),
        (
            "https://example.invalid/mcp?safe=1&access_token=orange-credential",
            ("orange-credential",),
            "cannot carry secret-like query parameters",
        ),
        (
            "https://example.invalid/mcp?api%5Fkey=indigo-credential",
            ("indigo-credential",),
            "cannot carry secret-like query parameters",
        ),
        (
            "https://encoded%40user:encoded%3Apassword@example.invalid/mcp",
            ("encoded%40user", "encoded%3Apassword"),
            "cannot embed credentials",
        ),
        (
            "https://example.invalid/mcp?client-secret=silver-credential",
            ("silver-credential",),
            "cannot carry secret-like query parameters",
        ),
        (
            "https://example.invalid/mcp?X-Amz-Signature=gold-credential",
            ("gold-credential",),
            "cannot carry secret-like query parameters",
        ),
    ],
)
def test_neutral_validation_errors_never_echo_secret_bearing_urls(
    url: str, secret_fragments: tuple[str, ...], safe_diagnostic: str
) -> None:
    raw = json.loads(read_fixture("remote-http.json"))
    raw["servers"]["remoteDemo"]["transport"]["url"] = url

    with pytest.raises(PortabilityInputError) as raised:
        parse_neutral(json.dumps(raw))

    message = str(raised.value)
    for secret in secret_fragments:
        assert secret not in message
    assert safe_diagnostic in message
    assert "servers.*.transport" in message
    assert "input_value" not in message
    assert raised.value.__cause__ is None
    assert raised.value.__context__ is None


@pytest.mark.parametrize(
    ("host", "document", "secret_fragments"),
    [
        (
            "codex",
            '[mcp_servers.demo]\nurl = "https://bob:blue-password@example.invalid/mcp"\n',
            ("bob", "blue-password"),
        ),
        (
            "claude-code",
            '{"mcpServers":{"demo":{"type":"http","url":"https://example.invalid/mcp?token=green-credential"}}}',
            ("green-credential",),
        ),
        (
            "vscode",
            '{"servers":{"demo":{"type":"http","url":"https://example.invalid/mcp?API_KEY=red-credential"}}}',
            ("red-credential",),
        ),
    ],
)
def test_host_inspection_validation_errors_never_echo_secret_bearing_urls(
    host: str, document: str, secret_fragments: tuple[str, ...]
) -> None:
    with pytest.raises(PortabilityInputError) as raised:
        inspect_host(document, host)

    message = str(raised.value)
    for secret in secret_fragments:
        assert secret not in message
    assert "url" in message
    assert "input_value" not in message
    assert raised.value.__cause__ is None
    assert raised.value.__context__ is None


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
def test_stdio_bearer_auth_is_explicitly_reported_as_unsupported(host: str) -> None:
    raw = json.loads(read_fixture("local-stdio.json"))
    raw["servers"]["localDemo"]["auth"] = {
        "kind": "bearer",
        "required": True,
        "token": {
            "kind": "environment",
            "key": "PORTABILITY_BEARER_TOKEN",
            "secret": True,
            "required": True,
        },
        "scopes": [],
    }

    result = render_host(parse_neutral(json.dumps(raw)), host)

    assert any(
        item.path == "auth" and item.state == ChangeState.UNSUPPORTED
        for item in result.report.changes
    )
    assert "PORTABILITY_BEARER_TOKEN" not in result.document


@pytest.mark.parametrize("host", ["codex", "claude-code", "vscode"])
def test_remote_bearer_auth_remains_preserved_when_representable(host: str) -> None:
    raw = json.loads(read_fixture("remote-http.json"))
    raw["servers"]["remoteDemo"]["auth"] = {
        "kind": "bearer",
        "required": True,
        "token": {
            "kind": "environment",
            "key": "PORTABILITY_BEARER_TOKEN",
            "secret": True,
            "required": True,
        },
        "scopes": [],
    }

    result = render_host(parse_neutral(json.dumps(raw)), host)

    assert any(
        item.path == "auth" and item.state == ChangeState.PRESERVED
        for item in result.report.changes
    )
    assert "PORTABILITY_BEARER_TOKEN" in result.document


@pytest.mark.parametrize("field", ["startup_timeout_seconds", "tool_timeout_seconds"])
@pytest.mark.parametrize("value", [5e-324, 0.0004, 0.000999999])
def test_sub_millisecond_timeouts_fail_with_a_bounded_validation_result(
    field: str, value: float
) -> None:
    raw = json.loads(read_fixture("local-stdio.json"))
    raw["servers"]["localDemo"]["startup"][field] = value

    with pytest.raises(PortabilityInputError) as raised:
        parse_neutral(json.dumps(raw))

    message = str(raised.value)
    assert field in message
    assert "0.001" in message
    assert "input_value" not in message


def test_one_millisecond_tool_timeout_round_trips_without_zero() -> None:
    raw = json.loads(read_fixture("local-stdio.json"))
    raw["servers"]["localDemo"]["startup"]["tool_timeout_seconds"] = 0.001
    intent = parse_neutral(json.dumps(raw))

    rendered = render_host(intent, "claude-code")
    assert json.loads(rendered.document)["mcpServers"]["localDemo"]["timeout"] == 1

    inspected, report = round_trip(intent, "claude-code")
    assert inspected.intent.servers["localDemo"].startup.tool_timeout_seconds == pytest.approx(
        0.001
    )
    assert report.summary.transformed >= 1


@pytest.mark.parametrize("value", [float("nan"), float("inf"), 1e308])
def test_unrepresentable_timeouts_fail_validation_instead_of_crashing_render(value: float) -> None:
    raw = json.loads(read_fixture("local-stdio.json"))
    raw["servers"]["localDemo"]["startup"]["tool_timeout_seconds"] = value

    with pytest.raises(PortabilityInputError) as raised:
        parse_neutral(json.dumps(raw))

    assert "tool_timeout_seconds" in str(raised.value)
    assert "input_value" not in str(raised.value)


def test_scope_collections_canonicalize_reordering_and_duplicates() -> None:
    first_raw = json.loads(read_fixture("remote-http.json"))
    first_server = first_raw["servers"]["remoteDemo"]
    first_server["tools"] = {
        "allow": ["demo.write", "demo.read", "demo.write"],
        "deny": ["demo.delete", "demo.delete"],
    }
    first_server["auth"]["scopes"] = ["demo.write", "demo.read", "demo.write"]

    second_raw = json.loads(json.dumps(first_raw))
    second_server = second_raw["servers"]["remoteDemo"]
    second_server["tools"] = {
        "allow": ["demo.read", "demo.write"],
        "deny": ["demo.delete"],
    }
    second_server["auth"]["scopes"] = ["demo.read", "demo.write"]

    first = parse_neutral(json.dumps(first_raw))
    second = parse_neutral(json.dumps(second_raw))

    assert first.servers["remoteDemo"].tools.allow == ["demo.read", "demo.write"]
    assert first.servers["remoteDemo"].tools.deny == ["demo.delete"]
    assert first.servers["remoteDemo"].auth.scopes == ["demo.read", "demo.write"]
    assert canonical_neutral(first) == canonical_neutral(second)
    assert render_host(first, "codex") == render_host(second, "codex")


@pytest.mark.parametrize(
    ("path", "before", "after", "expected"),
    [
        ("tools.allow", ["read", "write", "read"], ["write", "read"], ChangeState.PRESERVED),
        ("tools.allow", ["read"], ["read", "write"], ChangeState.WIDENED),
        ("tools.allow", ["read", "write"], ["read"], ChangeState.TRANSFORMED),
        ("tools.allow", ["read"], [], ChangeState.WIDENED),
        ("tools.allow", [], ["read"], ChangeState.TRANSFORMED),
        ("tools.deny", ["write"], [], ChangeState.WIDENED),
        ("tools.deny", [], ["write"], ChangeState.TRANSFORMED),
        ("auth.scopes", ["read"], ["read", "write"], ChangeState.WIDENED),
        ("auth.scopes", ["read", "write"], ["read"], ChangeState.TRANSFORMED),
    ],
)
def test_scope_comparison_distinguishes_equivalence_widening_and_narrowing(
    path: str, before: list[str], after: list[str], expected: ChangeState
) -> None:
    changes = []

    _compare(before, after, server="demo", path=path, changes=changes)

    assert len(changes) == 1
    assert changes[0].state == expected


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


def test_malformed_host_json_does_not_retain_secret_bearing_source() -> None:
    document = (
        '{"servers":{"demo":{"type":"http",'
        '"url":"https://example.invalid/mcp?token=malformed-json-credential",}}}'
    )

    with pytest.raises(PortabilityInputError) as raised:
        inspect_host(document, "vscode")

    assert "malformed-json-credential" not in str(raised.value)
    assert raised.value.__cause__ is None
    assert raised.value.__context__ is None


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


def test_cli_json_output_is_stable_for_semantically_equivalent_scope_sets(tmp_path: Path) -> None:
    raw = json.loads(read_fixture("remote-http.json"))
    raw["servers"]["remoteDemo"]["tools"] = {
        "allow": ["demo.write", "demo.read", "demo.write"],
        "deny": [],
    }
    input_file = tmp_path / "scope-input.json"
    input_file.write_text(json.dumps(raw), encoding="utf-8")

    first = runner.invoke(app, ["portability", "round-trip", str(input_file), "--host", "codex"])
    second = runner.invoke(app, ["portability", "round-trip", str(input_file), "--host", "codex"])

    assert first.exit_code == 0, first.output
    assert second.exit_code == 0, second.output
    assert first.output == second.output
    assert json.loads(first.output)["schema_version"] == "mcp-config-portability-report.v1"


def test_cli_secret_validation_failures_are_redacted_and_stable(tmp_path: Path) -> None:
    neutral = json.loads(read_fixture("remote-http.json"))
    neutral["servers"]["remoteDemo"]["transport"]["url"] = (
        "https://example.invalid/mcp?token=cli-purple-credential"
    )
    neutral_path = tmp_path / "neutral-secret-url.json"
    neutral_path.write_text(json.dumps(neutral), encoding="utf-8")

    host_path = tmp_path / "host-secret-url.json"
    host_path.write_text(
        '{"servers":{"demo":{"type":"http","url":"https://example.invalid/mcp?access_token=cli-yellow-credential"}}}',
        encoding="utf-8",
    )

    command_lines = [
        ["portability", "validate", str(neutral_path)],
        ["portability", "round-trip", str(neutral_path), "--host", "codex"],
        ["portability", "inspect", str(host_path), "--host", "vscode"],
    ]
    for command_line in command_lines:
        first = runner.invoke(app, command_line)
        second = runner.invoke(app, command_line)
        assert first.exit_code == 2
        assert second.exit_code == 2
        assert first.output == second.output
        assert "cli-purple-credential" not in first.output
        assert "cli-yellow-credential" not in first.output
        assert "input_value" not in first.output


def test_cli_rejects_oversized_portability_input_without_echoing_content(tmp_path: Path) -> None:
    secret_marker = "oversized-purple-credential"
    oversized = tmp_path / "oversized.json"
    oversized.write_text(
        '{"padding":"' + secret_marker + ("x" * 1_100_000) + '"}', encoding="utf-8"
    )

    result = runner.invoke(app, ["portability", "validate", str(oversized)])

    assert result.exit_code == 2
    assert "too large" in result.output
    assert secret_marker not in result.output


def test_cli_schema_command() -> None:
    result = runner.invoke(app, ["portability", "schema"])
    assert result.exit_code == 0, result.output
    assert json.loads(result.output)["title"] == "NeutralConfig"
