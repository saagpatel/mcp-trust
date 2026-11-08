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
from datetime import UTC, datetime, timedelta
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
from mcp_trust.store.repository import (
    MAX_STORED_FINDINGS,
    MAX_STORED_JSON_BYTES,
    MAX_STORED_TOOLS,
)

CARD_SCHEMA = "mcp-audit.trust-card/1"
PIN_SCHEMA = "mcp-audit.trust-pin/1"
GRADED_VERDICTS = frozenset({"no_mismatches_observed", "review", "do_not_install"})
PIN_RUN_WINDOW = timedelta(minutes=5)
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


def _read_bytes(path: Path, what: str) -> bytes:
    """Read at most MAX_CARD_BYTES + 1 from a regular file; never stream devices."""
    try:
        if not path.is_file():
            raise TrustCardError(f"{what} is not a regular file")
        with path.open("rb") as handle:
            raw = handle.read(MAX_CARD_BYTES + 1)
    except OSError as exc:
        raise TrustCardError(f"cannot read {what} ({type(exc).__name__})") from None
    if len(raw) > MAX_CARD_BYTES:
        raise TrustCardError(f"{what} exceeds the 4 MiB import limit")
    return raw


def _parse_json(raw: bytes, what: str) -> Any:
    try:
        return json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, ValueError, RecursionError):
        raise TrustCardError(f"{what} is not UTF-8 JSON") from None


def _read_json(path: Path, what: str) -> Any:
    return _parse_json(_read_bytes(path, what), what)


def load_card(path: Path) -> dict[str, Any]:
    return load_card_with_digest(path)[0]


def load_card_with_digest(path: Path) -> tuple[dict[str, Any], str]:
    """Read a trust card and refuse anything that is not a complete observation.

    The registry grades only what was observed: the verdict must be one of the
    card's graded verdicts, the observation status must be exactly ``complete``,
    and the evidence collections must have the expected types.
    """
    raw = _read_bytes(path, "card")
    card = _parse_json(raw, "card")
    if not isinstance(card, dict) or card.get("schema") != CARD_SCHEMA:
        raise TrustCardError(f"not a {CARD_SCHEMA} card")
    if card.get("verdict") not in GRADED_VERDICTS:
        raise TrustCardError("card has no graded verdict (incomplete or unknown); nothing to grade")
    observation = card.get("observation")
    if not isinstance(observation, dict) or observation.get("status") != "complete":
        raise TrustCardError("card records an incomplete observation; nothing to grade")
    if observation.get("mode") not in {"container", "outside"}:
        raise TrustCardError("card observation mode is not container or outside")
    if not isinstance(card.get("target"), dict) or not card["target"]:
        raise TrustCardError("card has no target")
    _validate_evidence(card)
    observed_at(card)
    return card, hashlib.sha256(raw).hexdigest()


_HINTS = ("read_only_hint", "destructive_hint", "open_world_hint")
_SHA256 = re.compile(r"^[0-9a-f]{64}$")


def _records(container: dict[str, Any], key: str, where: str) -> list[dict[str, Any]]:
    """A required list of objects; absence or any other shape is malformed evidence."""
    value = container.get(key)
    if not isinstance(value, list) or not all(isinstance(item, dict) for item in value):
        raise TrustCardError(f"card field {where}{key!r} is missing or malformed")
    return value


def _validate_evidence(card: dict[str, Any]) -> None:
    """Every field scoring reads must be present and well-typed; absence is never 'clean'."""
    observation = card["observation"]
    for tool in _records(observation, "tools", "observation."):
        if not isinstance(tool.get("name"), str) or not tool["name"]:
            raise TrustCardError("a tool has no name")
        if any(h not in tool or not isinstance(tool[h], bool | None) for h in _HINTS):
            raise TrustCardError(f"tool {tool['name']!r} has a missing or non-boolean hint")
        inferred = tool.get("inferred")
        if not isinstance(inferred, list) or not all(isinstance(c, str) for c in inferred):
            raise TrustCardError(f"tool {tool['name']!r} has malformed inferred capabilities")
    for phase in _records(observation, "phases", "observation."):
        for change in _records(phase, "file_changes", "phase."):
            if not isinstance(change.get("path"), str) or not isinstance(
                change.get("in_home"), bool
            ):
                raise TrustCardError("a file change is malformed")
            if not isinstance(change.get("entries_only", False), bool):
                raise TrustCardError("a file change is malformed")
        _records(phase, "network", "phase.")
        truncated = phase.get("file_changes_truncated", 0)
        if not isinstance(truncated, int) or isinstance(truncated, bool) or truncated < 0:
            raise TrustCardError("a phase has a malformed file_changes_truncated count")
    for mismatch in _records(card, "mismatches", ""):
        if mismatch.get("severity") not in _SEVERITY or not isinstance(mismatch.get("rule"), str):
            raise TrustCardError("a mismatch has an unknown severity or no rule")
        if not isinstance(mismatch.get("summary"), str):
            raise TrustCardError("a mismatch has no summary")


def load_pin(path: Path, card: dict[str, Any]) -> dict[str, Any]:
    """A pin is used only if it comes from the same run as the card.

    Same server, package and version; created within PIN_RUN_WINDOW of the card;
    the same tool names; and well-formed hashes. Otherwise its hashes would be
    attributed to an observation they did not come from.
    """
    pin = _read_json(path, "pin")
    if not isinstance(pin, dict) or pin.get("schema") != PIN_SCHEMA:
        raise TrustCardError(f"not a {PIN_SCHEMA} pin")
    target = card["target"]
    package = _dict(target.get("package"))
    expected_package = (
        f"{package.get('registry_type')}:{package.get('identifier')}" if package else None
    )
    expected_version = _str(package.get("version")) or _str(target.get("server_version"))
    if (
        pin.get("target") != target.get("input")
        or pin.get("server_name") != target.get("server_name")
        or pin.get("package") != expected_package
        or pin.get("version") != expected_version
    ):
        raise TrustCardError("pin belongs to another target, server, package or version")
    if not _str(pin.get("target")) or not (
        _str(target.get("server_name"))
        or expected_package
        or _str(_dict(target.get("remote")).get("url"))
    ):
        raise TrustCardError("pin identity cannot be established for this card")
    try:
        created = observed_at({"generated_at": pin.get("created_at")})
    except TrustCardError:
        raise TrustCardError("pin has no valid created_at") from None
    if abs((created - observed_at(card)).total_seconds()) > PIN_RUN_WINDOW.total_seconds():
        raise TrustCardError("pin was not produced by the same run as the card")
    tools = _records(pin, "tools", "pin.")
    names = sorted(str(t.get("name")) for t in tools)
    if names != sorted(t["name"] for t in card["observation"]["tools"]):
        raise TrustCardError("pin tool names differ from the card's")
    if not all(_SHA256.fullmatch(str(t.get("input_schema_sha256"))) for t in tools):
        raise TrustCardError("pin has a malformed input-schema hash")
    return pin


def observed_at(card: dict[str, Any], now: datetime | None = None) -> datetime:
    """When the card was generated; imports keep observation time, not import time."""
    raw = card.get("generated_at")
    if not isinstance(raw, str):
        raise TrustCardError("card has no generated_at timestamp")
    try:
        stamp = datetime.fromisoformat(raw.replace("Z", "+00:00"))
    except ValueError:
        raise TrustCardError("card generated_at is not an ISO-8601 timestamp") from None
    if stamp.tzinfo is None:
        raise TrustCardError("card generated_at has no timezone")
    if stamp > (now or datetime.now(tz=UTC)) + timedelta(minutes=5):
        raise TrustCardError("card generated_at is in the future")
    # Never later than now: a future stamp could keep an import ahead of a real scan.
    return min(stamp.astimezone(UTC), now or datetime.now(tz=UTC))


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
        if not reference:
            raise TrustCardError("card names a package with no identifier")
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


# Mismatch rules that mean the server did something it did not announce.
BEHAVIOURAL_CONCERNS = frozenset(
    {"TBC-UNPROMPTED-NET", "TBC-LOCAL-CLAIM-NET", "TBC-WRITE-OUTSIDE-HOME"}
)
# Danger score for one concern (grade C) and for two or more (grade D).
CONCERN_DANGER = {1: 3.6, 2: 7.2}


def _risk(
    card: dict[str, Any], findings: list[Finding], counted: list[Finding] | None = None
) -> RiskSummary:
    """Score only what the sandbox observed; the calibrated rubric is in the docs.

    The registry grade of an imported card reflects observed behaviour. Shell,
    exfiltration and destructive capabilities are never observed by the sandbox,
    so they score 0; declared hints feed the separate transparency axis.

    - Behavioural concerns (unprompted egress, a contradicted local claim, writes
      outside home) are counted: one scores danger 3.6 (C), two or more 7.2 (D),
      carried on file_access (3 for writes outside home) and network_access.
    - With no concern, only expected behaviour remains: lasting writes in home
      file 2, temporary churn 1; a remote observed from outside network 2,
      egress during tool calls 1. That keeps a clean card in A-B.
    - A write during a read-only tool's call or a truncated change list sets
      file_access 8; egress breaking a closed-world declaration sets
      network_access 8. With do_not_install's critical cap, that is F.
    """
    observation = _dict(card.get("observation"))
    tools = [_dict(t) for t in _list(observation.get("tools"))]
    phases = [_dict(p) for p in _list(observation.get("phases"))]
    rules = {f.rule_id for f in findings}
    changes = [_dict(c) for p in phases for c in _list(p.get("file_changes"))]
    lasting = [c for c in changes if not c.get("entries_only")]
    truncated = any(p.get("file_changes_truncated", 0) for p in phases)
    # Behavioural concerns are counted, not summed across dimensions, so one
    # concern always lands in C and two or more in D, whatever else was seen.
    concerns = rules & BEHAVIOURAL_CONCERNS
    if concerns:
        target = CONCERN_DANGER[min(len(concerns), 2)]
        file_access = 3.0 if "TBC-WRITE-OUTSIDE-HOME" in concerns else 0.0
        network_access = round(max(0.0, target - 1.2 * file_access), 2)
    else:
        # No concern: expected behaviour only, which keeps a clean card in A-B.
        if lasting:
            file_access = 2.0
        elif changes:
            file_access = 1.0
        else:
            file_access = 0.0
        if observation.get("mode") == "outside":
            network_access = 2.0
        elif any(_list(p.get("network")) for p in phases):
            network_access = 1.0
        else:
            network_access = 0.0
    # High-severity contradictions observed in behaviour push the grade to F.
    if truncated or "TBC-READONLY-WRITE" in rules:
        file_access = 8.0
    if any(f.rule_id == "TBC-READONLY-NET" and f.severity == Severity.HIGH for f in findings):
        network_access = 8.0
    scores = {
        "file_access": file_access,
        "network_access": network_access,
        "shell_execution": 0.0,
        "destructive": 0.0,
        "exfiltration": 0.0,
    }
    counts: dict[Severity, int] = {}
    # Severity counts cover every stored finding so they agree with the record.
    for finding in counted if counted is not None else findings:
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
    poisoned = [m for m in mismatches if m.rule_id == "TBC-INJECTION"]
    if poisoned:
        # Tool-poisoning text is disqualifying in the registry rubric (critical cap).
        mismatches.append(
            Finding(
                rule_id="TBC-INJECTION-CAP",
                title="Tool text matches prompt-injection patterns",
                severity=Severity.CRITICAL,
                category="injection",
                detail=poisoned[0].detail,
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
    # Without a pin from the same run, schema presence is unknown: store no
    # evidence rather than claim the tools have no input schema.
    evidence = (
        None
        if pin is None
        else ScanEvidence(
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
            resource_count=_count(observation.get("resources")),
        )
    )
    return EngineResult(
        engine_name=ENGINE_NAME,
        engine_version=_str(card.get("mcp_audit_version")) or "unknown",
        risk=_risk(card, mismatches, findings),
        findings=findings,
        evidence=evidence,
        sandbox_image=_str(observation.get("image")),
    )


def _count(value: object) -> int:
    return value if isinstance(value, int) and not isinstance(value, bool) and value >= 0 else 0


def check_admission(result: EngineResult, server: Server) -> None:
    """Refuse a mapped server or scan the repository could not read back, before any write."""
    if len(result.findings) > MAX_STORED_FINDINGS:
        raise TrustCardError(f"card maps to more than {MAX_STORED_FINDINGS} findings")
    if result.evidence is not None and len(result.evidence.tools) > MAX_STORED_TOOLS:
        raise TrustCardError(f"card lists more than {MAX_STORED_TOOLS} tools")
    stored = [
        server.source.model_dump_json(),
        server.name,
        server.description,
        server.homepage or "",
        result.risk.model_dump_json(),
        json.dumps([f.model_dump(mode="json") for f in result.findings]),
        result.evidence.model_dump_json() if result.evidence is not None else "",
    ]
    if any(len(value.encode("utf-8")) > MAX_STORED_JSON_BYTES for value in stored):
        raise TrustCardError("card maps to a record larger than the repository admits")
