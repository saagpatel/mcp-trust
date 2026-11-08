"""Import an MCPAudit Trust Before Connect verdict card as a catalog entry.

`mcp-audit trust TARGET` (experimental) resolves a server, runs it in a
sandbox with a network sinkhole, and writes a verdict card
(`schema: mcp-audit.trust-card/1`). This module maps that card onto the
registry's frozen contracts: a ``Server`` from what the card resolved, and an
``EngineResult`` whose findings are the card's mismatches. The grade is then
derived by ``core.grading`` like any other scan; this module never grades.

The card is read as plain JSON so the registry keeps no dependency on the
``mcp_audit`` package. Cards from incomplete observations are refused: the
registry does not grade what was not observed.

Engine name ``mcp-audit-trust`` is not in ``REAL_ENGINE_NAMES``, so imported
verdicts stay demo-classified until that provenance decision is made.
"""

from __future__ import annotations

import hashlib
import json
import re
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from mcp_trust.core.models import (
    Finding,
    RiskSummary,
    ScanEvidence,
    Server,
    ServerSource,
    Severity,
    SourceKind,
    ToolEvidence,
)
from mcp_trust.engine.base import EngineResult

CARD_SCHEMA = "mcp-audit.trust-card/1"
ENGINE_NAME = "mcp-audit-trust"
MAX_CARD_BYTES = 4 * 1024 * 1024

_SEVERITY = {
    "high": Severity.HIGH,
    "medium": Severity.MEDIUM,
    "low": Severity.LOW,
    "info": Severity.INFO,
}
_RULE_CATEGORY = {
    "TBC-RESOLVE": "provenance",
    "TBC-READONLY-WRITE": "file_access",
    "TBC-TRANSIENT-WRITE": "file_access",
    "TBC-WRITE-OUTSIDE-HOME": "file_access",
    "TBC-STARTUP-WRITE": "file_access",
    "TBC-READONLY-NET": "network_access",
    "TBC-UNPROMPTED-NET": "network_access",
    "TBC-LOCAL-CLAIM-NET": "network_access",
    "TBC-INJECTION": "injection",
    "TBC-DRIFT": "drift",
    "TBC-PIN-OTHER-SERVER": "drift",
    "TBC-INSTALL-SCRIPTS": "supply_chain",
}
# Card capability names (inferred per tool) -> registry risk dimensions.
_SLUG_PART = re.compile(r"[^a-z0-9]+")
_ENV_KEY = re.compile(r"^[A-Z_][A-Z0-9_]*$")


class TrustCardError(ValueError):
    """The file is not an importable trust card."""


def _dict(value: object) -> dict[str, Any]:
    return value if isinstance(value, dict) else {}


def _list(value: object) -> list[Any]:
    return value if isinstance(value, list) else []


def _str(value: object) -> str | None:
    return value if isinstance(value, str) and value else None


def load_card(path: Path) -> dict[str, Any]:
    """Read and minimally validate a trust card."""
    try:
        raw = path.read_bytes()
    except OSError as exc:
        raise TrustCardError(f"cannot read card ({type(exc).__name__})") from None
    if len(raw) > MAX_CARD_BYTES:
        raise TrustCardError("card exceeds the 4 MiB import limit")
    try:
        card = json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, ValueError):
        raise TrustCardError("card is not UTF-8 JSON") from None
    if not isinstance(card, dict) or card.get("schema") != CARD_SCHEMA:
        raise TrustCardError(f"not a {CARD_SCHEMA} card")
    if card.get("verdict") == "incomplete" or _dict(card.get("observation")).get("status") in {
        "failed",
        "skipped",
    }:
        raise TrustCardError("card records an incomplete observation; nothing to grade")
    if not _dict(card.get("target")):
        raise TrustCardError("card has no target")
    return card


def default_slug(card: dict[str, Any]) -> str:
    """`io.github.owner/name` -> `owner-name`; `com.example/name` -> `example-name`."""
    target = _dict(card.get("target"))
    package = _dict(target.get("package"))
    name = _str(target.get("server_name")) or _str(package.get("identifier")) or ""
    namespace, _, short = name.rpartition("/")
    owner = namespace.rsplit(".", 1)[-1] if namespace else ""
    slug = _SLUG_PART.sub("-", f"{owner}-{short}".lower()).strip("-")
    if not slug:
        raise TrustCardError("cannot derive a slug; pass one explicitly")
    return slug


def card_to_server(card: dict[str, Any], slug: str, now: datetime | None = None) -> Server:
    target = _dict(card.get("target"))
    package = _dict(target.get("package"))
    remote = _dict(target.get("remote"))
    if package.get("registry_type") in {"npm", "pypi"}:
        kind = SourceKind(package["registry_type"])
        reference = _str(package.get("identifier")) or ""
    elif _str(remote.get("url")):
        kind, reference = SourceKind.REMOTE, str(remote["url"])
    else:
        raise TrustCardError("card names neither an npm/PyPI package nor a remote")
    env_keys = sorted(
        {
            str(var["name"])
            for var in map(_dict, _list(package.get("env")))
            if isinstance(var.get("name"), str) and _ENV_KEY.match(var["name"])
        }
    )
    return Server(
        slug=slug,
        name=_str(target.get("title")) or _str(target.get("server_name")) or reference,
        description=_str(target.get("description")) or "",
        source=ServerSource(kind=kind, reference=reference, env_keys=env_keys),
        homepage=_str(target.get("repository_url")),
        added_at=now or datetime.now(tz=UTC),
    )


def _share(tools: list[dict[str, Any]], test: Any) -> float:
    return sum(1 for tool in tools if test(tool)) / len(tools) if tools else 0.0


def _risk(card: dict[str, Any], findings: list[Finding]) -> RiskSummary:
    """Score dimensions from what the sandbox observed and what tools declared.

    Keyword-inferred capabilities are weak signal (the card itself does not
    raise mismatches on them), so they only count for tools that do not declare
    themselves read-only. Calibration, all on the registry's 0-10 scale:

    - file_access: writes outside home 8, writes in home 3, temporary-entry
      churn 1; tools not declared read-only add up to 3 by share.
    - network_access: unprompted egress (startup or shutdown) 6, egress breaking
      a closed-world declaration 8, egress during read-only calls 2; a remote
      server is a network service by nature, 3.
    - shell_execution and exfiltration: 10 x the share of tools that are not
      declared read-only and whose text suggests the capability.
    - destructive: 10 x the share of tools declaring destructiveHint.
    """
    observation = _dict(card.get("observation"))
    tools = [_dict(t) for t in _list(observation.get("tools"))]
    phases = [_dict(p) for p in _list(observation.get("phases"))]
    rules = {f.rule_id for f in findings}
    changes = [_dict(c) for p in phases for c in _list(p.get("file_changes"))]
    lasting = [c for c in changes if not c.get("entries_only")]
    if any(not c.get("in_home") for c in lasting) or "TBC-READONLY-WRITE" in rules:
        observed_files = 8.0
    elif lasting:
        observed_files = 3.0
    elif changes:
        observed_files = 1.0
    else:
        observed_files = 0.0
    undeclared = _share(tools, lambda t: t.get("read_only_hint") is not True)
    file_access = max(observed_files, round(3.0 * undeclared, 2))
    if any(f.rule_id == "TBC-READONLY-NET" and f.severity == Severity.HIGH for f in findings):
        network_access = 8.0
    elif "TBC-UNPROMPTED-NET" in rules or "TBC-LOCAL-CLAIM-NET" in rules:
        network_access = 6.0
    elif observation.get("mode") == "outside":
        network_access = 3.0
    elif any(_list(p.get("network")) for p in phases):
        network_access = 2.0
    else:
        network_access = 0.0

    def suggests(capability: str) -> Any:
        return lambda t: (
            t.get("read_only_hint") is not True and capability in _list(t.get("inferred"))
        )

    scores = {
        "file_access": file_access,
        "network_access": network_access,
        "shell_execution": round(10.0 * _share(tools, suggests("shell_execution")), 2),
        "destructive": round(10.0 * _share(tools, lambda t: t.get("destructive_hint") is True), 2),
        "exfiltration": round(10.0 * _share(tools, suggests("exfiltration")), 2),
    }
    counts: dict[Severity, int] = {}
    for finding in findings:
        counts[finding.severity] = counts.get(finding.severity, 0) + 1
    annotated = _share(
        tools,
        lambda t: any(
            t.get(k) is not None for k in ("read_only_hint", "destructive_hint", "open_world_hint")
        ),
    )
    return RiskSummary(
        composite=max(scores.values()),
        findings_by_severity=counts,
        annotation_coverage=round(annotated, 4),
        **scores,
    )


def card_to_result(card: dict[str, Any], pin: dict[str, Any] | None = None) -> EngineResult:
    """Map a card onto the engine contract; the registry grades the result."""
    findings = [
        Finding(
            rule_id="TBC-VERDICT",
            title=f"Trust Before Connect verdict: {card.get('verdict')}",
            severity=Severity.INFO,
            category="verdict",
            detail=_str(card.get("headline")) or "",
        )
    ]
    observation = _dict(card.get("observation"))
    if observation.get("mode") == "outside":
        findings.append(
            Finding(
                rule_id="TBC-OUTSIDE-ONLY",
                title="Remote server observed from outside only",
                severity=Severity.INFO,
                category="coverage",
                detail="Its own file writes and outbound connections were not observable.",
            )
        )
    mismatches: list[Finding] = []
    for mismatch in map(_dict, _list(card.get("mismatches"))):
        rule = _str(mismatch.get("rule")) or "TBC-UNKNOWN"
        tool = _str(mismatch.get("tool"))
        mismatches.append(
            Finding(
                rule_id=rule,
                title=(f"{tool}: " if tool else "") + (_str(mismatch.get("summary")) or rule)[:300],
                severity=_SEVERITY.get(str(mismatch.get("severity")), Severity.INFO),
                category=_RULE_CATEGORY.get(rule, "other"),
                detail=_str(mismatch.get("summary")) or "",
            )
        )
    if card.get("verdict") == "do_not_install":
        # The card's own strongest verdict caps the registry grade (critical cap).
        mismatches.append(
            Finding(
                rule_id="TBC-DO-NOT-INSTALL",
                title="Behaviour contradicted the server's own claims",
                severity=Severity.CRITICAL,
                category="verdict",
                detail=_str(card.get("headline")) or "",
            )
        )
    findings.extend(mismatches)
    hashes = {
        str(t.get("name")): _str(t.get("input_schema_sha256"))
        for t in map(_dict, _list((pin or {}).get("tools")))
    }
    tools = [_dict(t) for t in _list(observation.get("tools"))]
    evidence = ScanEvidence(
        tool_count=len(tools),
        tools=[
            ToolEvidence(
                name=str(tool.get("name")),
                has_input_schema=hashes.get(str(tool.get("name"))) is not None,
                input_schema_sha256=hashes.get(str(tool.get("name"))),
                has_annotations=any(
                    tool.get(k) is not None
                    for k in ("read_only_hint", "destructive_hint", "open_world_hint")
                ),
            )
            for tool in tools
        ],
        prompt_count=len(_list(observation.get("prompts"))),
        resource_count=int(observation.get("resources") or 0),
    )
    return EngineResult(
        engine_name=ENGINE_NAME,
        engine_version=_str(card.get("mcp_audit_version")) or "unknown",
        risk=_risk(card, mismatches),
        findings=findings,
        evidence=evidence,
        sandbox_image=_str(observation.get("image")),
    )


def card_digest(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()
