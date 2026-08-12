# ruff: noqa: E501
"""Adapter protocol and shared conversion helpers."""

from __future__ import annotations

import re
from typing import Protocol

from mcp_trust.portability.models import (
    ChangeState,
    InspectResult,
    RenderResult,
    SemanticChange,
    ValueSource,
)
from mcp_trust.portability.report import change

_ENV_EXPANSION = re.compile(r"^\$\{(?:env:)?([A-Za-z_][A-Za-z0-9_]*)\}$")
_INPUT_EXPANSION = re.compile(r"^\$\{input:([^}]+)\}$")


class HostAdapter(Protocol):
    host: str
    format_version: str

    def render(self, intent: object) -> RenderResult: ...

    def inspect(self, document: str) -> InspectResult: ...


def portable_key(value: str, *, prefix: str = "VALUE") -> str:
    normalized = re.sub(r"[^A-Za-z0-9_]", "_", value).upper().strip("_")
    if not normalized:
        normalized = prefix
    if normalized[0].isdigit():
        normalized = f"{prefix}_{normalized}"
    return normalized[:128]


def source_from_host_value(
    value: object,
    *,
    fallback_key: str,
    server: str,
    path: str,
    changes: list[SemanticChange],
) -> ValueSource:
    """Create a safe reference from a host value without retaining literal content."""
    text = value if isinstance(value, str) else ""
    env_match = _ENV_EXPANSION.fullmatch(text)
    if env_match:
        changes.append(
            change(server, path, ChangeState.PRESERVED, "Environment reference preserved.")
        )
        return ValueSource(kind="environment", key=env_match.group(1))
    input_match = _INPUT_EXPANSION.fullmatch(text)
    if input_match:
        changes.append(
            change(
                server,
                path,
                ChangeState.TRANSFORMED,
                "Host input reference normalized to a prompt placeholder.",
            )
        )
        return ValueSource(kind="prompt", key=portable_key(input_match.group(1), prefix="INPUT"))
    changes.append(
        change(
            server,
            path,
            ChangeState.TRANSFORMED,
            "A host literal was replaced by a placeholder; the original value was not retained.",
        )
    )
    return ValueSource(kind="prompt", key=portable_key(fallback_key))


def note_unknown_fields(
    *,
    server: str,
    raw: dict[str, object],
    known: set[str],
    changes: list[SemanticChange],
) -> list[str]:
    fields = sorted(set(raw) - known)
    for field in fields:
        changes.append(
            change(
                server,
                f"host.{field}",
                ChangeState.UNKNOWN,
                "The host field is not represented by the neutral schema; its value was not retained.",
            )
        )
    return fields
