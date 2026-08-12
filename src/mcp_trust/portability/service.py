"""Public, side-effect-free portability operations."""

from __future__ import annotations

import json
from typing import Any

from pydantic import ValidationError

from mcp_trust.portability.adapters import (
    ClaudeCodeAdapter,
    ClaudeDesktopAdapter,
    CodexAdapter,
    VSCodeAdapter,
)
from mcp_trust.portability.errors import PortabilityInputError, UnsupportedHostError
from mcp_trust.portability.models import (
    ChangeState,
    InspectResult,
    NeutralConfig,
    PortabilityReport,
    RenderResult,
)
from mcp_trust.portability.report import build_report, change

_ADAPTERS = {
    "codex": CodexAdapter(),
    "claude-code": ClaudeCodeAdapter(),
    "claude-desktop": ClaudeDesktopAdapter(),
    "vscode": VSCodeAdapter(),
}


def supported_hosts() -> tuple[str, ...]:
    return tuple(sorted(_ADAPTERS))


def adapter_for(host: str):
    try:
        return _ADAPTERS[host]
    except KeyError as exc:
        raise UnsupportedHostError(
            f"unsupported host {host!r}; choose one of: {', '.join(supported_hosts())}"
        ) from exc


def parse_neutral(document: str) -> NeutralConfig:
    try:
        return NeutralConfig.model_validate_json(document)
    except (ValidationError, ValueError) as exc:
        raise PortabilityInputError(f"invalid neutral intent: {exc}") from exc


def canonical_neutral(intent: NeutralConfig) -> str:
    return (
        json.dumps(intent.model_dump(mode="json"), indent=2, sort_keys=True, ensure_ascii=False)
        + "\n"
    )


def render_host(intent: NeutralConfig, host: str) -> RenderResult:
    return adapter_for(host).render(intent)


def inspect_host(document: str, host: str) -> InspectResult:
    try:
        return adapter_for(host).inspect(document)
    except ValidationError as exc:
        raise PortabilityInputError(f"invalid {host} host configuration: {exc}") from exc


def _semantic_view(intent: NeutralConfig) -> dict[str, Any]:
    result = intent.model_dump(mode="json")
    result.pop("schema_version", None)
    result.pop("mcp_protocol_version", None)
    result.pop("registry_metadata_schema_version", None)
    for server in result["servers"].values():
        server.pop("provenance", None)
        server.pop("unknown_semantics", None)
    return result


def _compare(
    before: object,
    after: object,
    *,
    server: str,
    path: str,
    changes: list,
) -> None:
    if type(before) is not type(after):
        changes.append(
            change(server, path, ChangeState.TRANSFORMED, "Round-trip value type changed.")
        )
        return
    if isinstance(before, dict):
        keys = sorted(set(before) | set(after))
        for key in keys:
            next_path = f"{path}.{key}" if path else key
            if key not in after:
                state = ChangeState.WIDENED if key in {"allow", "deny"} else ChangeState.DROPPED
                changes.append(
                    change(
                        server, next_path, state, "Semantic value was not present after round-trip."
                    )
                )
            elif key not in before:
                changes.append(
                    change(
                        server,
                        next_path,
                        ChangeState.DEFAULTED,
                        "Host inspection introduced a default semantic value.",
                    )
                )
            else:
                _compare(before[key], after[key], server=server, path=next_path, changes=changes)
        return
    if isinstance(before, list):
        if before != after:
            state = (
                ChangeState.WIDENED if path.endswith(("allow", "deny")) else ChangeState.TRANSFORMED
            )
            changes.append(
                change(
                    server, path, state, "Ordered semantic collection changed during round-trip."
                )
            )
        return
    if before != after:
        changes.append(
            change(
                server, path, ChangeState.TRANSFORMED, "Semantic value changed during round-trip."
            )
        )
    else:
        changes.append(
            change(server, path, ChangeState.PRESERVED, "Semantic value survived round-trip.")
        )


def round_trip(intent: NeutralConfig, host: str) -> tuple[InspectResult, PortabilityReport]:
    adapter = adapter_for(host)
    rendered = adapter.render(intent)
    inspected = adapter.inspect(rendered.document)
    changes = [*rendered.report.changes, *inspected.report.changes]
    before = _semantic_view(intent)["servers"]
    after = _semantic_view(inspected.intent)["servers"]
    for server in sorted(set(before) | set(after)):
        if server not in after:
            changes.append(
                change(
                    server,
                    "server",
                    ChangeState.DROPPED,
                    "Server was omitted by the host adapter and did not round-trip.",
                )
            )
        elif server not in before:
            changes.append(
                change(
                    server,
                    "server",
                    ChangeState.DEFAULTED,
                    "Host inspection introduced an unexpected server.",
                )
            )
        else:
            _compare(before[server], after[server], server=server, path="", changes=changes)
    report = build_report(
        operation="round-trip",
        host=host,
        format_version=adapter.format_version,
        changes=changes,
    )
    return inspected, report


def neutral_schema_json() -> str:
    return (
        json.dumps(NeutralConfig.model_json_schema(), indent=2, sort_keys=True, ensure_ascii=False)
        + "\n"
    )
