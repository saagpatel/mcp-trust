"""Fail-closed host-capacity evidence for controlled local execution.

The receipt is intentionally path-private. It binds the filesystem device that
contains the caller-selected anchor, two exact byte-count observations, and the
fixed operator policy. It never starts Colima, invokes Docker, or grants scan
authority by itself.
"""

from __future__ import annotations

import hashlib
import json
import os
import time
from collections.abc import Callable
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

HOST_CAPACITY_SCHEMA = "McpTrustHostCapacityReceiptV1"
HOST_CAPACITY_MIN_AVAILABLE_BYTES = 5 * 1024**3
HOST_CAPACITY_MIN_INTERVAL_SECONDS = 30
HOST_CAPACITY_MAX_AGE_SECONDS = 120
HOST_CAPACITY_REQUIRED_READINGS = 2
HOST_CAPACITY_CLAIM_CEILING = (
    "Host-filesystem capacity observations only; this receipt does not prove Colima was "
    "stopped, observation authenticity or same-user tamper resistance, Docker or MCP "
    "isolation, scan safety, publication, deployment, scheduler operation, production "
    "freshness, or endorsement."
)
_RECEIPT_KEYS = frozenset(
    {
        "schema",
        "observed_at",
        "status",
        "safe_to_start_runtime",
        "exit_classification",
        "policy",
        "anchor",
        "readings",
        "reasons",
        "authority",
        "claim_ceiling",
        "receipt_digest",
    }
)
_READING_KEYS = frozenset(
    {
        "sequence",
        "observed_at",
        "device_id",
        "total_bytes",
        "available_bytes",
        "used_bytes",
        "capacity_percent",
    }
)
_POLICY = {
    "minimum_available_bytes": HOST_CAPACITY_MIN_AVAILABLE_BYTES,
    "maximum_capacity_percent_exclusive": 100,
    "required_readings": HOST_CAPACITY_REQUIRED_READINGS,
    "minimum_interval_seconds": HOST_CAPACITY_MIN_INTERVAL_SECONDS,
    "maximum_receipt_age_seconds": HOST_CAPACITY_MAX_AGE_SECONDS,
}
_AUTHORITY = {
    "observation_only": True,
    "colima_start_performed": False,
    "docker_invoked": False,
    "mcp_execution": False,
    "database_accessed": False,
    "publication_performed": False,
    "deployment_performed": False,
    "scheduler_change_performed": False,
}


class HostCapacityError(RuntimeError):
    """Host-capacity evidence is missing, invalid, stale, or unsafe."""


@dataclass(frozen=True)
class HostCapacitySample:
    """One exact filesystem-capacity observation."""

    device_id: int
    total_bytes: int
    available_bytes: int


def _canonical_bytes(payload: object) -> bytes:
    return (
        json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode()
        + b"\n"
    )


def _digest(payload: object) -> str:
    return "sha256:" + hashlib.sha256(_canonical_bytes(payload)).hexdigest()


def _utc(value: datetime) -> datetime:
    if value.tzinfo is None:
        raise HostCapacityError("capacity timestamp must be timezone-aware")
    return value.astimezone(UTC)


def read_host_capacity(anchor: Path) -> HostCapacitySample:
    """Read exact bytes from the filesystem containing ``anchor``."""
    try:
        filesystem = os.statvfs(anchor)
        identity = os.stat(anchor, follow_symlinks=True)
    except OSError as exc:
        raise HostCapacityError("host capacity is unreadable") from exc
    fragment_size = filesystem.f_frsize or filesystem.f_bsize
    total = filesystem.f_blocks * fragment_size
    available = filesystem.f_bavail * fragment_size
    sample = HostCapacitySample(
        device_id=identity.st_dev,
        total_bytes=total,
        available_bytes=available,
    )
    _validate_sample(sample)
    return sample


def _validate_sample(sample: HostCapacitySample) -> None:
    if (
        type(sample.device_id) is not int
        or sample.device_id < 0
        or type(sample.total_bytes) is not int
        or sample.total_bytes <= 0
        or type(sample.available_bytes) is not int
        or sample.available_bytes < 0
        or sample.available_bytes > sample.total_bytes
    ):
        raise HostCapacityError("host capacity counters are inconsistent")


def _reading(sample: HostCapacitySample, *, sequence: int, observed_at: datetime) -> dict[str, Any]:
    _validate_sample(sample)
    used = sample.total_bytes - sample.available_bytes
    return {
        "sequence": sequence,
        "observed_at": _utc(observed_at).isoformat(),
        "device_id": sample.device_id,
        "total_bytes": sample.total_bytes,
        "available_bytes": sample.available_bytes,
        "used_bytes": used,
        "capacity_percent": round((used * 100) / sample.total_bytes, 6),
    }


def _reading_reasons(reading: dict[str, Any]) -> list[str]:
    reasons: list[str] = []
    if reading["available_bytes"] < HOST_CAPACITY_MIN_AVAILABLE_BYTES:
        reasons.append("available_bytes_below_5_gib")
    if reading["capacity_percent"] >= 100:
        reasons.append("capacity_not_below_100_percent")
    return reasons


def build_host_capacity_receipt(
    *,
    anchor: Path,
    reader: Callable[[Path], HostCapacitySample] = read_host_capacity,
    clock: Callable[[], datetime] = lambda: datetime.now(tz=UTC),
    sleeper: Callable[[float], None] = time.sleep,
) -> dict[str, Any]:
    """Observe the host twice and return one deterministic, integrity-bound receipt."""
    readings: list[dict[str, Any]] = []
    reasons: list[str] = []
    try:
        first = reader(anchor)
        first_at = _utc(clock())
        first_reading = _reading(first, sequence=1, observed_at=first_at)
        readings.append(first_reading)
        reasons.extend(_reading_reasons(first_reading))
        if not reasons:
            sleeper(HOST_CAPACITY_MIN_INTERVAL_SECONDS)
            second = reader(anchor)
            second_at = _utc(clock())
            second_reading = _reading(second, sequence=2, observed_at=second_at)
            readings.append(second_reading)
            reasons.extend(_reading_reasons(second_reading))
            if second.device_id != first.device_id:
                reasons.append("capacity_anchor_device_changed")
            if second.total_bytes != first.total_bytes:
                reasons.append("capacity_anchor_total_changed")
            if (second_at - first_at).total_seconds() < HOST_CAPACITY_MIN_INTERVAL_SECONDS:
                reasons.append("capacity_readings_too_close")
    except HostCapacityError as exc:
        reasons.append(str(exc).replace(" ", "_"))
    except (OSError, OverflowError, TypeError, ValueError):
        reasons.append("host_capacity_observation_failed")

    ready = len(readings) == HOST_CAPACITY_REQUIRED_READINGS and not reasons
    observed_at = readings[-1]["observed_at"] if readings else _utc(clock()).isoformat()
    anchor_payload = (
        {
            "kind": "host-filesystem-device",
            "device_id": readings[0]["device_id"],
            "total_bytes": readings[0]["total_bytes"],
        }
        if readings
        else {"kind": "host-filesystem-device", "device_id": None, "total_bytes": None}
    )
    payload: dict[str, Any] = {
        "schema": HOST_CAPACITY_SCHEMA,
        "observed_at": observed_at,
        "status": "READY" if ready else "BLOCKED",
        "safe_to_start_runtime": ready,
        "exit_classification": "ready" if ready else "capacity-blocked",
        "policy": dict(_POLICY),
        "anchor": anchor_payload,
        "readings": readings,
        "reasons": sorted(set(reasons)),
        "authority": dict(_AUTHORITY),
        "claim_ceiling": HOST_CAPACITY_CLAIM_CEILING,
    }
    payload["receipt_digest"] = _digest(payload)
    return payload


def validate_host_capacity_receipt(receipt: object) -> dict[str, Any]:
    """Validate exact receipt structure, integrity, arithmetic, and READY semantics."""
    if not isinstance(receipt, dict) or set(receipt) != _RECEIPT_KEYS:
        raise HostCapacityError("host capacity receipt fields are invalid")
    unsigned = dict(receipt)
    claimed = unsigned.pop("receipt_digest", None)
    if receipt.get("schema") != HOST_CAPACITY_SCHEMA or claimed != _digest(unsigned):
        raise HostCapacityError("host capacity receipt integrity is invalid")
    if receipt.get("policy") != _POLICY or receipt.get("authority") != _AUTHORITY:
        raise HostCapacityError("host capacity receipt policy is invalid")
    if receipt.get("claim_ceiling") != HOST_CAPACITY_CLAIM_CEILING:
        raise HostCapacityError("host capacity receipt claim ceiling is invalid")
    anchor = receipt.get("anchor")
    readings = receipt.get("readings")
    if (
        not isinstance(anchor, dict)
        or set(anchor) != {"kind", "device_id", "total_bytes"}
        or anchor.get("kind") != "host-filesystem-device"
        or type(anchor.get("device_id")) is not int
        or int(anchor["device_id"]) < 0
        or type(anchor.get("total_bytes")) is not int
        or int(anchor["total_bytes"]) <= 0
        or not isinstance(readings, list)
        or len(readings) != HOST_CAPACITY_REQUIRED_READINGS
    ):
        raise HostCapacityError("host capacity receipt anchor or readings are invalid")
    parsed_times: list[datetime] = []
    for sequence, reading in enumerate(readings, start=1):
        if not isinstance(reading, dict) or set(reading) != _READING_KEYS:
            raise HostCapacityError("host capacity reading fields are invalid")
        if reading.get("sequence") != sequence:
            raise HostCapacityError("host capacity reading sequence is invalid")
        try:
            observed_at = _utc(datetime.fromisoformat(str(reading.get("observed_at"))))
        except (HostCapacityError, ValueError) as exc:
            raise HostCapacityError("host capacity reading timestamp is invalid") from exc
        parsed_times.append(observed_at)
        sample = HostCapacitySample(
            device_id=reading.get("device_id"),
            total_bytes=reading.get("total_bytes"),
            available_bytes=reading.get("available_bytes"),
        )
        _validate_sample(sample)
        used_bytes = reading.get("used_bytes")
        capacity_percent = reading.get("capacity_percent")
        if type(used_bytes) is not int or type(capacity_percent) not in {int, float}:
            raise HostCapacityError("host capacity reading arithmetic is invalid")
        try:
            expected = _reading(sample, sequence=sequence, observed_at=observed_at)
        except OverflowError as exc:
            raise HostCapacityError("host capacity reading arithmetic is invalid") from exc
        if reading != expected or used_bytes + sample.available_bytes != sample.total_bytes:
            raise HostCapacityError("host capacity reading arithmetic is invalid")
        if _reading_reasons(reading):
            raise HostCapacityError("host capacity reading does not satisfy policy")
        if reading.get("device_id") != anchor.get("device_id") or reading.get(
            "total_bytes"
        ) != anchor.get("total_bytes"):
            raise HostCapacityError("host capacity reading anchor differs")
    if (parsed_times[1] - parsed_times[0]).total_seconds() < HOST_CAPACITY_MIN_INTERVAL_SECONDS:
        raise HostCapacityError("host capacity reading interval is invalid")
    if receipt.get("observed_at") != readings[-1].get("observed_at"):
        raise HostCapacityError("host capacity receipt timestamp differs")
    if (
        receipt.get("status") != "READY"
        or receipt.get("safe_to_start_runtime") is not True
        or receipt.get("exit_classification") != "ready"
        or receipt.get("reasons") != []
    ):
        raise HostCapacityError("host capacity receipt is not READY")
    return receipt


def require_current_host_capacity(
    receipt: object,
    *,
    anchor: Path,
    now: datetime | None = None,
    reader: Callable[[Path], HostCapacitySample] = read_host_capacity,
) -> dict[str, Any]:
    """Require a fresh READY receipt and a matching current safe observation."""
    validated = validate_host_capacity_receipt(receipt)
    current_time = _utc(now or datetime.now(tz=UTC))
    try:
        observed_at = _utc(datetime.fromisoformat(str(validated["observed_at"])))
    except (HostCapacityError, ValueError) as exc:
        raise HostCapacityError("host capacity receipt timestamp is invalid") from exc
    age = (current_time - observed_at).total_seconds()
    if age < 0 or age > HOST_CAPACITY_MAX_AGE_SECONDS:
        raise HostCapacityError("host capacity receipt is stale or future-dated")
    current = reader(anchor)
    current_reading = _reading(current, sequence=1, observed_at=current_time)
    expected_anchor = validated["anchor"]
    if (
        current.device_id != expected_anchor["device_id"]
        or current.total_bytes != expected_anchor["total_bytes"]
    ):
        raise HostCapacityError("host capacity anchor changed")
    if _reading_reasons(current_reading):
        raise HostCapacityError("current host capacity does not satisfy policy")
    return {
        "receipt_digest": validated["receipt_digest"],
        "observed_at": validated["observed_at"],
        "device_id": current.device_id,
        "total_bytes": current.total_bytes,
        "current_available_bytes": current.available_bytes,
        "current_capacity_percent": current_reading["capacity_percent"],
    }
