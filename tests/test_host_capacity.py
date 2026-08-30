"""Fail-closed tests for the host-capacity admission receipt."""

from __future__ import annotations

import copy
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest

from mcp_trust import host_capacity
from mcp_trust.host_capacity import (
    HOST_CAPACITY_MIN_AVAILABLE_BYTES,
    HostCapacityError,
    HostCapacitySample,
    build_host_capacity_receipt,
    require_current_host_capacity,
    validate_host_capacity_receipt,
)
from tests.receipt_fixtures import host_capacity_receipt

NOW = datetime(2026, 8, 30, 20, 0, tzinfo=UTC)
TOTAL_BYTES = 100 * 1024**3
DEVICE_ID = 42


def _redigest(receipt: dict[str, object]) -> None:
    unsigned = dict(receipt)
    unsigned.pop("receipt_digest", None)
    receipt["receipt_digest"] = host_capacity._digest(unsigned)


def test_exact_floor_and_exact_interval_are_ready_and_deterministic() -> None:
    first = host_capacity_receipt(observed_at=NOW)
    second = host_capacity_receipt(observed_at=NOW)

    assert first == second
    assert validate_host_capacity_receipt(first) == first
    assert first["safe_to_start_runtime"] is True
    assert first["readings"][0]["available_bytes"] == HOST_CAPACITY_MIN_AVAILABLE_BYTES


def test_one_byte_below_floor_blocks_without_waiting_or_second_read() -> None:
    calls = {"read": 0, "sleep": 0}

    def reader(_anchor: Path) -> HostCapacitySample:
        calls["read"] += 1
        return HostCapacitySample(
            device_id=DEVICE_ID,
            total_bytes=TOTAL_BYTES,
            available_bytes=HOST_CAPACITY_MIN_AVAILABLE_BYTES - 1,
        )

    receipt = build_host_capacity_receipt(
        anchor=Path("/fixture"),
        reader=reader,
        clock=lambda: NOW,
        sleeper=lambda _seconds: calls.__setitem__("sleep", calls["sleep"] + 1),
    )

    assert receipt["status"] == "BLOCKED"
    assert receipt["reasons"] == ["available_bytes_below_5_gib"]
    assert calls == {"read": 1, "sleep": 0}


def test_readings_less_than_thirty_seconds_apart_are_blocked() -> None:
    times = iter((NOW, NOW + timedelta(seconds=29, milliseconds=999)))
    sample = HostCapacitySample(DEVICE_ID, TOTAL_BYTES, HOST_CAPACITY_MIN_AVAILABLE_BYTES)

    receipt = build_host_capacity_receipt(
        anchor=Path("/fixture"),
        reader=lambda _anchor: sample,
        clock=lambda: next(times),
        sleeper=lambda _seconds: None,
    )

    assert receipt["status"] == "BLOCKED"
    assert receipt["reasons"] == ["capacity_readings_too_close"]


def test_inconsistent_capacity_counters_fail_closed() -> None:
    receipt = build_host_capacity_receipt(
        anchor=Path("/fixture"),
        reader=lambda _anchor: HostCapacitySample(DEVICE_ID, 1, 2),
        clock=lambda: NOW,
        sleeper=lambda _seconds: None,
    )

    assert receipt["status"] == "BLOCKED"
    assert receipt["safe_to_start_runtime"] is False
    assert "host_capacity_counters_are_inconsistent" in receipt["reasons"]


def test_one_hundred_percent_capacity_is_explicitly_blocked() -> None:
    receipt = build_host_capacity_receipt(
        anchor=Path("/fixture"),
        reader=lambda _anchor: HostCapacitySample(DEVICE_ID, TOTAL_BYTES, 0),
        clock=lambda: NOW,
        sleeper=lambda _seconds: None,
    )

    assert receipt["status"] == "BLOCKED"
    assert "capacity_not_below_100_percent" in receipt["reasons"]


@pytest.mark.parametrize(
    "mutation",
    [
        "extra-field",
        "bad-used-type",
        "bad-capacity-percent",
        "changed-anchor",
        "anchor-type-confusion",
        "oversized-counter",
        "changed-policy",
    ],
)
def test_integrity_bound_false_green_mutations_are_rejected(mutation: str) -> None:
    receipt = copy.deepcopy(host_capacity_receipt(observed_at=NOW))
    if mutation == "extra-field":
        receipt["unexpected"] = True
    elif mutation == "bad-used-type":
        receipt["readings"][0]["used_bytes"] = None
        _redigest(receipt)
    elif mutation == "bad-capacity-percent":
        receipt["readings"][0]["capacity_percent"] = 0
        _redigest(receipt)
    elif mutation == "changed-anchor":
        receipt["anchor"]["device_id"] = DEVICE_ID + 1
        _redigest(receipt)
    elif mutation == "anchor-type-confusion":
        receipt = copy.deepcopy(host_capacity_receipt(observed_at=NOW, device_id=1))
        receipt["anchor"]["device_id"] = True
        _redigest(receipt)
    elif mutation == "oversized-counter":
        huge = 10**1_000
        receipt["anchor"]["total_bytes"] = huge
        for reading in receipt["readings"]:
            reading["total_bytes"] = huge
            reading["used_bytes"] = huge - reading["available_bytes"]
        _redigest(receipt)
    else:
        receipt["policy"]["minimum_available_bytes"] = 1
        _redigest(receipt)

    with pytest.raises(HostCapacityError):
        validate_host_capacity_receipt(receipt)


@pytest.mark.parametrize(
    "now",
    [NOW + timedelta(seconds=121), NOW - timedelta(microseconds=1)],
)
def test_stale_or_future_receipt_is_rejected(now: datetime) -> None:
    receipt = host_capacity_receipt(observed_at=NOW)

    with pytest.raises(HostCapacityError, match="stale or future-dated"):
        require_current_host_capacity(
            receipt,
            anchor=Path("/fixture"),
            now=now,
            reader=lambda _anchor: HostCapacitySample(
                DEVICE_ID, TOTAL_BYTES, HOST_CAPACITY_MIN_AVAILABLE_BYTES
            ),
        )


@pytest.mark.parametrize(
    "sample, message",
    [
        (
            HostCapacitySample(DEVICE_ID + 1, TOTAL_BYTES, HOST_CAPACITY_MIN_AVAILABLE_BYTES),
            "anchor changed",
        ),
        (
            HostCapacitySample(
                DEVICE_ID, TOTAL_BYTES, HOST_CAPACITY_MIN_AVAILABLE_BYTES - 1
            ),
            "does not satisfy policy",
        ),
    ],
)
def test_current_device_or_capacity_regression_is_rejected(
    sample: HostCapacitySample,
    message: str,
) -> None:
    receipt = host_capacity_receipt(observed_at=NOW)

    with pytest.raises(HostCapacityError, match=message):
        require_current_host_capacity(
            receipt,
            anchor=Path("/fixture"),
            now=NOW,
            reader=lambda _anchor: sample,
        )
