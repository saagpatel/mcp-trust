"""Deterministic portability report helpers."""

from __future__ import annotations

from collections import Counter

from mcp_trust.portability.models import (
    ChangeState,
    PortabilityReport,
    ReportSummary,
    SemanticChange,
)


def change(server: str, path: str, state: ChangeState, explanation: str) -> SemanticChange:
    return SemanticChange(server=server, path=path, state=state, explanation=explanation)


def build_report(
    *,
    operation: str,
    host: str,
    format_version: str,
    changes: list[SemanticChange],
) -> PortabilityReport:
    ordered = sorted(
        changes, key=lambda item: (item.server, item.path, item.state, item.explanation)
    )
    counts = Counter(item.state.value for item in ordered)
    summary = ReportSummary(
        preserved=counts[ChangeState.PRESERVED.value],
        transformed=counts[ChangeState.TRANSFORMED.value],
        dropped=counts[ChangeState.DROPPED.value],
        unsupported=counts[ChangeState.UNSUPPORTED.value],
        defaulted=counts[ChangeState.DEFAULTED.value],
        widened=counts[ChangeState.WIDENED.value],
        UNKNOWN=counts[ChangeState.UNKNOWN.value],
    )
    return PortabilityReport(
        operation=operation,
        host=host,
        adapter_format_version=format_version,
        changes=ordered,
        summary=summary,
    )
