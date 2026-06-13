"""Stub scan engine — deterministic, no external dependencies.

Returns stable ``EngineResult`` values derived from a hash of the source
reference. No randomness, no I/O, no time calls — fully deterministic so
the whole system can be tested end-to-end without ``mcp-audits``.
"""

from __future__ import annotations

import hashlib

from mcp_trust.core.models import Finding, RiskSummary, ServerSource, Severity
from mcp_trust.engine.base import EngineResult, ScanEngine


def _hash_int(text: str, salt: str, lo: int = 0, hi: int = 10) -> float:
    """Derive a stable float in [lo, hi] from a SHA-256 of (text + salt)."""
    digest = hashlib.sha256(f"{text}:{salt}".encode()).digest()
    # Take the first 4 bytes as an unsigned int, map to [lo, hi].
    raw = int.from_bytes(digest[:4], "big")
    span = hi - lo
    return lo + (raw % (span * 10)) / 10.0


def _clamp(v: float, lo: float = 0.0, hi: float = 10.0) -> float:
    return max(lo, min(hi, v))


# Severity ladder used for synthesising findings.
_SEVERITIES: list[Severity] = [
    Severity.CRITICAL,
    Severity.HIGH,
    Severity.MEDIUM,
    Severity.LOW,
    Severity.INFO,
]

_FINDING_TEMPLATES: list[tuple[str, str, str]] = [
    ("STUB001", "Broad filesystem read capability detected", "file_access"),
    ("STUB002", "Unrestricted outbound network access", "network_access"),
    ("STUB003", "Shell execution capability present", "shell_execution"),
    ("STUB004", "Destructive tool registered", "destructive"),
    ("STUB005", "Potential data exfiltration vector", "exfiltration"),
    ("STUB006", "Elevated permission scope", "permissions"),
    ("STUB007", "Tool description anomaly detected", "injection"),
]


def _synthesize(reference: str) -> EngineResult:
    """Build a fully deterministic EngineResult from a source reference string."""
    dims = {
        "file_access": _clamp(_hash_int(reference, "file_access")),
        "network_access": _clamp(_hash_int(reference, "network_access")),
        "shell_execution": _clamp(_hash_int(reference, "shell_execution")),
        "destructive": _clamp(_hash_int(reference, "destructive")),
        "exfiltration": _clamp(_hash_int(reference, "exfiltration")),
    }

    # Composite = weighted average of dimensions, capped at 10.
    composite = _clamp(
        
            dims["file_access"] * 0.25
            + dims["network_access"] * 0.20
            + dims["shell_execution"] * 0.25
            + dims["destructive"] * 0.20
            + dims["exfiltration"] * 0.10
        
    )

    # Number of findings: 0–3 determined by hash.
    digest = hashlib.sha256(f"{reference}:count".encode()).digest()
    n_findings = int.from_bytes(digest[:1], "big") % 4  # 0, 1, 2, or 3

    findings: list[Finding] = []
    findings_by_severity: dict[Severity, int] = {}

    for i in range(n_findings):
        # Pick template deterministically.
        t_idx = int.from_bytes(
            hashlib.sha256(f"{reference}:tpl:{i}".encode()).digest()[:1], "big"
        ) % len(_FINDING_TEMPLATES)
        rule_id, title, category = _FINDING_TEMPLATES[t_idx]

        # Pick severity deterministically, biased toward lower severities.
        s_raw = int.from_bytes(hashlib.sha256(f"{reference}:sev:{i}".encode()).digest()[:1], "big")
        # Map 0-255 → 0-4 with weights [1, 2, 3, 5, 5] (CRITICAL least common).
        weights = [1, 2, 3, 5, 5]
        total = sum(weights)
        thresholds = []
        cumulative = 0
        for w in weights:
            cumulative += w
            thresholds.append(int(cumulative * 255 / total))

        sev_idx = next(
            (j for j, t in enumerate(thresholds) if s_raw <= t),
            len(thresholds) - 1,
        )
        severity = _SEVERITIES[sev_idx]

        findings.append(
            Finding(
                rule_id=f"{rule_id}:{i}",
                title=title,
                severity=severity,
                category=category,
                detail=f"Stub finding {i} for reference '{reference}'.",
            )
        )
        findings_by_severity[severity] = findings_by_severity.get(severity, 0) + 1

    risk = RiskSummary(
        composite=composite,
        file_access=dims["file_access"],
        network_access=dims["network_access"],
        shell_execution=dims["shell_execution"],
        destructive=dims["destructive"],
        exfiltration=dims["exfiltration"],
        findings_by_severity=findings_by_severity,
    )

    return EngineResult(
        engine_name="stub",
        engine_version="0.1.0",
        risk=risk,
        findings=findings,
    )


class StubEngine:
    """Deterministic scan engine for testing and demos.

    Produces stable ``EngineResult`` values derived solely from the source
    reference string. Different references yield meaningfully different grades
    so the catalog demo shows variety.
    """

    name: str = "stub"
    version: str = "0.1.0"

    def scan(self, source: ServerSource) -> EngineResult:
        """Return a deterministic result for *source*. Never raises ``ScanError``."""
        return _synthesize(source.reference)


# Satisfy the Protocol at import time (no runtime check needed — just verify shape).
_: ScanEngine = StubEngine()  # type: ignore[assignment]
