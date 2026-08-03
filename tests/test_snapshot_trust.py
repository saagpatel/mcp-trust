"""Content-authenticated offline snapshot verification."""

from __future__ import annotations

import base64
import hashlib
import json
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from typer.testing import CliRunner

from mcp_trust.catalog.snapshot_trust import (
    verify_root_update,
    verify_snapshot,
    verify_snapshot_paths,
)
from mcp_trust.cli.main import app

ROOT = Path(__file__).resolve().parents[1]
NOW = datetime(2026, 8, 3, 12, 0, tzinfo=UTC)
PUBLISHER_ID = "io.github.saagpatel/mcp-trust"


def _private(seed_byte: int) -> Ed25519PrivateKey:
    # Deterministic TEST-ONLY fixture material; never a production signing key.
    return Ed25519PrivateKey.from_private_bytes(bytes([seed_byte]) * 32)


def _public_bytes(key: Ed25519PrivateKey) -> bytes:
    return key.public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )


def _key_id(key: Ed25519PrivateKey) -> str:
    return f"sha256:{hashlib.sha256(_public_bytes(key)).hexdigest()}"


def _b64(value: bytes) -> str:
    return base64.urlsafe_b64encode(value).rstrip(b"=").decode("ascii")


def _canonical(value: object) -> bytes:
    return json.dumps(
        value,
        ensure_ascii=False,
        allow_nan=False,
        separators=(",", ":"),
        sort_keys=True,
    ).encode("utf-8")


def _json_bytes(value: object) -> bytes:
    return json.dumps(value, indent=2, sort_keys=True).encode("utf-8") + b"\n"


def _root_digest(root: object) -> str:
    return hashlib.sha256(_json_bytes(root)).hexdigest()


def _statement_digest(statement: dict[str, object]) -> str:
    return hashlib.sha256(_canonical(statement["signed"])).hexdigest()  # type: ignore[arg-type]


def _key(
    private: Ed25519PrivateKey,
    role: str,
    *,
    valid_from: int = 1,
    valid_through: int | None = None,
) -> dict[str, object]:
    return {
        "key_id": _key_id(private),
        "algorithm": "ed25519",
        "public_key": _b64(_public_bytes(private)),
        "roles": [role],
        "valid_from_publication_id": valid_from,
        "valid_through_publication_id": valid_through,
    }


def _root(
    snapshot_keys: list[dict[str, object]],
    recovery_keys: list[dict[str, object]],
    *,
    version: int = 1,
    minimum_publication_id: int = 1,
    snapshot_threshold: int = 1,
    recovery_threshold: int = 1,
) -> dict[str, object]:
    return {
        "schema": "mcp-trust-snapshot-root.v1",
        "root_version": version,
        "publisher": {
            "id": PUBLISHER_ID,
            "name": "MCP Trust Registry",
        },
        "minimum_publication_id": minimum_publication_id,
        "max_snapshot_lifetime_seconds": 86_400,
        "max_clock_skew_seconds": 300,
        "snapshot_threshold": snapshot_threshold,
        "recovery_threshold": recovery_threshold,
        "keys": [*snapshot_keys, *recovery_keys],
    }


def _snapshot_bytes() -> bytes:
    return (ROOT / "src/mcp_trust/catalog_snapshot.json").read_bytes()


def _statement(
    snapshot: bytes,
    private_keys: list[Ed25519PrivateKey],
    *,
    publication_id: int = 1,
    root_version: int = 1,
    issued_at: datetime = NOW - timedelta(minutes=5),
    expires_at: datetime = NOW + timedelta(hours=1),
    previous: dict[str, object] | None = None,
    publisher_id: str = PUBLISHER_ID,
) -> dict[str, object]:
    signed = {
        "publisher_id": publisher_id,
        "root_version": root_version,
        "publication_id": publication_id,
        "issued_at": issued_at.isoformat(),
        "expires_at": expires_at.isoformat(),
        "snapshot": {
            "media_type": "application/vnd.mcp-trust.catalog+json",
            "schema_version": 2,
            "length": len(snapshot),
            "sha256": hashlib.sha256(snapshot).hexdigest(),
        },
        "previous": previous,
    }
    return {
        "schema": "mcp-trust-snapshot-statement.v1",
        "signed": signed,
        "signatures": [
            {
                "key_id": _key_id(private),
                "signature": _b64(private.sign(_canonical(signed))),
            }
            for private in private_keys
        ],
    }


def _checkpoint_previous(checkpoint: dict[str, object]) -> dict[str, object]:
    return {
        "publication_id": checkpoint["publication_id"],
        "snapshot_sha256": checkpoint["snapshot_sha256"],
        "statement_sha256": checkpoint["statement_sha256"],
    }


def _verified_fixture() -> tuple[
    bytes,
    Ed25519PrivateKey,
    Ed25519PrivateKey,
    dict[str, object],
    dict[str, object],
    dict[str, object],
]:
    snapshot = _snapshot_bytes()
    signer = _private(1)
    recovery = _private(2)
    root = _root([_key(signer, "snapshot")], [_key(recovery, "recovery")])
    statement = _statement(snapshot, [signer])
    result = verify_snapshot(
        snapshot,
        _json_bytes(statement),
        _json_bytes(root),
        expected_root_sha256=_root_digest(root),
        now=NOW,
    )
    assert result["status"] == "VERIFIED"
    return snapshot, signer, recovery, root, statement, result["next_checkpoint"]


def test_valid_snapshot_verifies_identity_freshness_and_checkpoint() -> None:
    snapshot, signer, _recovery, root, statement, checkpoint = _verified_fixture()

    result = verify_snapshot(
        snapshot,
        _json_bytes(statement),
        _json_bytes(root),
        expected_root_sha256=_root_digest(root),
        now=NOW,
    )

    assert result == {
        "schema": "mcp-trust-snapshot-verification.v1",
        "status": "VERIFIED",
        "reason_codes": [],
        "publisher_id": PUBLISHER_ID,
        "root_version": 1,
        "publication_id": 1,
        "issued_at": (NOW - timedelta(minutes=5)).isoformat(),
        "expires_at": (NOW + timedelta(hours=1)).isoformat(),
        "snapshot_sha256": hashlib.sha256(snapshot).hexdigest(),
        "statement_sha256": _statement_digest(statement),
        "signer_key_ids": [_key_id(signer)],
        "next_checkpoint": checkpoint,
    }


@pytest.mark.parametrize(
    ("mutation", "reason"),
    [
        ("snapshot", "SNAPSHOT_DIGEST_MISMATCH"),
        ("signature", "SIGNATURE_INVALID"),
        ("expired", "SNAPSHOT_EXPIRED"),
        ("future", "SNAPSHOT_NOT_YET_VALID"),
        ("publisher", "PUBLISHER_ID_MISMATCH"),
        ("root_version", "ROOT_VERSION_MISMATCH"),
    ],
)
def test_invalid_snapshot_returns_unknown_without_catalog_data(
    mutation: str,
    reason: str,
) -> None:
    snapshot = _snapshot_bytes()
    signer = _private(1)
    recovery = _private(2)
    root = _root([_key(signer, "snapshot")], [_key(recovery, "recovery")])
    statement = _statement(snapshot, [signer])
    if mutation == "snapshot":
        snapshot += b" "
    elif mutation == "signature":
        statement["signatures"][0]["signature"] = _b64(bytes(64))  # type: ignore[index]
    elif mutation == "expired":
        statement = _statement(
            snapshot,
            [signer],
            issued_at=NOW - timedelta(hours=2),
            expires_at=NOW,
        )
    elif mutation == "future":
        statement = _statement(
            snapshot,
            [signer],
            issued_at=NOW + timedelta(minutes=6),
            expires_at=NOW + timedelta(hours=1),
        )
    elif mutation == "publisher":
        statement = _statement(snapshot, [signer], publisher_id="attacker.example")
    elif mutation == "root_version":
        statement = _statement(snapshot, [signer], root_version=2)

    result = verify_snapshot(
        snapshot,
        _json_bytes(statement),
        _json_bytes(root),
        expected_root_sha256=_root_digest(root),
        now=NOW,
    )

    assert result["status"] == "UNKNOWN"
    assert reason in result["reason_codes"]
    assert "next_checkpoint" not in result
    assert "servers" not in json.dumps(result)
    assert "grade" not in json.dumps(result)


def test_unknown_signer_is_unknown_even_with_a_valid_known_signature() -> None:
    snapshot = _snapshot_bytes()
    signer = _private(1)
    unknown = _private(9)
    recovery = _private(2)
    root = _root([_key(signer, "snapshot")], [_key(recovery, "recovery")])
    statement = _statement(snapshot, [signer, unknown])

    result = verify_snapshot(
        snapshot,
        _json_bytes(statement),
        _json_bytes(root),
        expected_root_sha256=_root_digest(root),
        now=NOW,
    )

    assert result["status"] == "UNKNOWN"
    assert result["reason_codes"] == ["UNKNOWN_SIGNER"]


def test_threshold_and_publication_key_bounds_are_enforced() -> None:
    snapshot = _snapshot_bytes()
    first = _private(1)
    second = _private(3)
    recovery = _private(2)
    root = _root(
        [
            _key(first, "snapshot", valid_through=1),
            _key(second, "snapshot", valid_from=2),
        ],
        [_key(recovery, "recovery")],
        snapshot_threshold=2,
    )
    statement = _statement(snapshot, [first, second], publication_id=1)

    result = verify_snapshot(
        snapshot,
        _json_bytes(statement),
        _json_bytes(root),
        expected_root_sha256=_root_digest(root),
        now=NOW,
    )

    assert result["status"] == "UNKNOWN"
    assert "SIGNER_NOT_AUTHORIZED" in result["reason_codes"]
    assert "SIGNATURE_THRESHOLD_NOT_MET" in result["reason_codes"]


def test_exact_checkpoint_replay_is_idempotent() -> None:
    snapshot, _signer, _recovery, root, statement, checkpoint = _verified_fixture()

    result = verify_snapshot(
        snapshot,
        _json_bytes(statement),
        _json_bytes(root),
        checkpoint_bytes=_json_bytes(checkpoint),
        expected_root_sha256=_root_digest(root),
        now=NOW,
    )

    assert result["status"] == "VERIFIED"
    assert result["next_checkpoint"] == checkpoint


def test_older_publication_is_rejected_as_rollback() -> None:
    snapshot, signer, _recovery, root, statement, checkpoint = _verified_fixture()
    newer = _statement(
        snapshot,
        [signer],
        publication_id=2,
        previous=_checkpoint_previous(checkpoint),
    )
    newer_result = verify_snapshot(
        snapshot,
        _json_bytes(newer),
        _json_bytes(root),
        checkpoint_bytes=_json_bytes(checkpoint),
        expected_root_sha256=_root_digest(root),
        now=NOW,
    )
    assert newer_result["status"] == "VERIFIED"

    rollback = verify_snapshot(
        snapshot,
        _json_bytes(statement),
        _json_bytes(root),
        checkpoint_bytes=_json_bytes(newer_result["next_checkpoint"]),
        expected_root_sha256=_root_digest(root),
        now=NOW,
    )

    assert rollback["status"] == "UNKNOWN"
    assert rollback["reason_codes"] == ["PUBLICATION_ROLLBACK"]


def test_same_publication_id_with_different_statement_is_unknown() -> None:
    snapshot, signer, _recovery, root, _statement_one, checkpoint = _verified_fixture()
    conflicting = _statement(
        snapshot,
        [signer],
        issued_at=NOW - timedelta(minutes=4),
    )

    result = verify_snapshot(
        snapshot,
        _json_bytes(conflicting),
        _json_bytes(root),
        checkpoint_bytes=_json_bytes(checkpoint),
        expected_root_sha256=_root_digest(root),
        now=NOW,
    )

    assert result["status"] == "UNKNOWN"
    assert result["reason_codes"] == ["PUBLICATION_ID_CONFLICT"]


def test_new_publication_must_chain_to_the_checkpoint() -> None:
    snapshot, signer, _recovery, root, _statement_one, checkpoint = _verified_fixture()
    unchained = _statement(snapshot, [signer], publication_id=2, previous=None)

    result = verify_snapshot(
        snapshot,
        _json_bytes(unchained),
        _json_bytes(root),
        checkpoint_bytes=_json_bytes(checkpoint),
        expected_root_sha256=_root_digest(root),
        now=NOW,
    )

    assert result["status"] == "UNKNOWN"
    assert result["reason_codes"] == ["PUBLICATION_CHAIN_MISMATCH"]


def test_first_use_requires_the_root_publication_floor() -> None:
    snapshot = _snapshot_bytes()
    signer = _private(1)
    recovery = _private(2)
    root = _root(
        [_key(signer, "snapshot", valid_from=7)],
        [_key(recovery, "recovery")],
        minimum_publication_id=7,
    )
    statement = _statement(snapshot, [signer], publication_id=6)

    result = verify_snapshot(
        snapshot,
        _json_bytes(statement),
        _json_bytes(root),
        expected_root_sha256=_root_digest(root),
        now=NOW,
    )

    assert result["status"] == "UNKNOWN"
    assert "PUBLICATION_BELOW_ROOT_FLOOR" in result["reason_codes"]


def _root_update(
    current_root: dict[str, object],
    new_root: dict[str, object],
    signing_keys: list[Ed25519PrivateKey],
    *,
    issued_at: datetime = NOW - timedelta(minutes=5),
    expires_at: datetime = NOW + timedelta(hours=1),
) -> dict[str, object]:
    signed = {
        "publisher_id": PUBLISHER_ID,
        "previous_root_version": current_root["root_version"],
        "previous_root_sha256": hashlib.sha256(_json_bytes(current_root)).hexdigest(),
        "issued_at": issued_at.isoformat(),
        "expires_at": expires_at.isoformat(),
        "new_root": new_root,
    }
    return {
        "schema": "mcp-trust-snapshot-root-update.v1",
        "signed": signed,
        "signatures": [
            {
                "key_id": _key_id(private),
                "signature": _b64(private.sign(_canonical(signed))),
            }
            for private in signing_keys
        ],
    }


def test_recovery_threshold_can_rotate_the_trust_root() -> None:
    _snapshot, _signer, recovery, root, _statement_one, checkpoint = _verified_fixture()
    next_signer = _private(4)
    next_recovery = _private(5)
    new_root = _root(
        [_key(next_signer, "snapshot", valid_from=2)],
        [_key(next_recovery, "recovery")],
        version=2,
        minimum_publication_id=2,
    )
    update = _root_update(root, new_root, [recovery])

    result = verify_root_update(
        _json_bytes(root),
        _json_bytes(update),
        _json_bytes(checkpoint),
        expected_root_sha256=_root_digest(root),
        now=NOW,
    )

    assert result["status"] == "VERIFIED"
    assert result["new_root"] == new_root
    assert result["next_checkpoint"]["root_version"] == 2
    assert result["next_checkpoint"]["root_sha256"] == hashlib.sha256(
        _json_bytes(new_root)
    ).hexdigest()
    assert result["next_checkpoint"]["publication_id"] == 1


def test_root_update_requires_an_explicit_root_digest_pin() -> None:
    _snapshot, _signer, recovery, root, _statement_one, checkpoint = _verified_fixture()
    new_root = _root(
        [_key(_private(4), "snapshot", valid_from=2)],
        [_key(_private(5), "recovery")],
        version=2,
        minimum_publication_id=2,
    )
    update = _root_update(root, new_root, [recovery])

    result = verify_root_update(
        _json_bytes(root),
        _json_bytes(update),
        _json_bytes(checkpoint),
        now=NOW,
    )

    assert result == {
        "schema": "mcp-trust-root-update-verification.v1",
        "status": "UNKNOWN",
        "reason_codes": ["TRUST_ROOT_DIGEST_REQUIRED"],
    }


def test_snapshot_key_cannot_authorize_root_recovery() -> None:
    _snapshot, signer, _recovery, root, _statement_one, checkpoint = _verified_fixture()
    new_root = _root(
        [_key(_private(4), "snapshot", valid_from=2)],
        [_key(_private(5), "recovery")],
        version=2,
        minimum_publication_id=2,
    )
    update = _root_update(root, new_root, [signer])

    result = verify_root_update(
        _json_bytes(root),
        _json_bytes(update),
        _json_bytes(checkpoint),
        expected_root_sha256=_root_digest(root),
        now=NOW,
    )

    assert result["status"] == "UNKNOWN"
    assert "SIGNER_NOT_AUTHORIZED" in result["reason_codes"]
    assert "RECOVERY_THRESHOLD_NOT_MET" in result["reason_codes"]
    assert "new_root" not in result


def test_root_recovery_cannot_lower_the_accepted_publication_floor() -> None:
    _snapshot, _signer, recovery, root, _statement_one, checkpoint = _verified_fixture()
    new_root = _root(
        [_key(_private(4), "snapshot")],
        [_key(_private(5), "recovery")],
        version=2,
        minimum_publication_id=0,
    )
    update = _root_update(root, new_root, [recovery])

    result = verify_root_update(
        _json_bytes(root),
        _json_bytes(update),
        _json_bytes(checkpoint),
        expected_root_sha256=_root_digest(root),
        now=NOW,
    )

    assert result["status"] == "UNKNOWN"
    assert "ROOT_UPDATE_ROLLBACK" in result["reason_codes"]


def test_expired_root_update_is_unknown() -> None:
    _snapshot, _signer, recovery, root, _statement_one, checkpoint = _verified_fixture()
    new_root = _root(
        [_key(_private(4), "snapshot", valid_from=2)],
        [_key(_private(5), "recovery")],
        version=2,
        minimum_publication_id=2,
    )
    update = _root_update(
        root,
        new_root,
        [recovery],
        issued_at=NOW - timedelta(hours=2),
        expires_at=NOW,
    )

    result = verify_root_update(
        _json_bytes(root),
        _json_bytes(update),
        _json_bytes(checkpoint),
        expected_root_sha256=_root_digest(root),
        now=NOW,
    )

    assert result["status"] == "UNKNOWN"
    assert result["reason_codes"] == ["ROOT_UPDATE_EXPIRED"]


def test_duplicate_keys_and_malformed_documents_fail_closed() -> None:
    snapshot, _signer, _recovery, root, statement, _checkpoint = _verified_fixture()
    duplicated = _json_bytes(statement).replace(
        b'"schema": "mcp-trust-snapshot-statement.v1",',
        b'"schema": "mcp-trust-snapshot-statement.v1",\n  "schema": "attacker",',
        1,
    )

    duplicate_result = verify_snapshot(
        snapshot,
        duplicated,
        _json_bytes(root),
        expected_root_sha256=_root_digest(root),
        now=NOW,
    )
    malformed_result = verify_snapshot(
        snapshot,
        b"{",
        _json_bytes(root),
        expected_root_sha256=_root_digest(root),
        now=NOW,
    )

    assert duplicate_result == {
        "schema": "mcp-trust-snapshot-verification.v1",
        "status": "UNKNOWN",
        "reason_codes": ["STATEMENT_INVALID"],
    }
    assert malformed_result == duplicate_result


def test_missing_root_digest_pin_fails_closed() -> None:
    snapshot = _snapshot_bytes()
    signer = _private(1)
    recovery = _private(2)
    root = _root([_key(signer, "snapshot")], [_key(recovery, "recovery")])
    statement = _statement(snapshot, [signer])

    result = verify_snapshot(snapshot, _json_bytes(statement), _json_bytes(root), now=NOW)

    assert result == {
        "schema": "mcp-trust-snapshot-verification.v1",
        "status": "UNKNOWN",
        "reason_codes": ["TRUST_ROOT_DIGEST_REQUIRED"],
    }


def test_mismatched_root_digest_pin_fails_closed() -> None:
    snapshot = _snapshot_bytes()
    signer = _private(1)
    recovery = _private(2)
    root = _root([_key(signer, "snapshot")], [_key(recovery, "recovery")])
    statement = _statement(snapshot, [signer])

    result = verify_snapshot(
        snapshot,
        _json_bytes(statement),
        _json_bytes(root),
        expected_root_sha256="0" * 64,
        now=NOW,
    )

    assert result == {
        "schema": "mcp-trust-snapshot-verification.v1",
        "status": "UNKNOWN",
        "reason_codes": ["TRUST_ROOT_DIGEST_MISMATCH"],
    }


def test_statement_identity_ignores_unsigned_json_serialization() -> None:
    snapshot, signer, _recovery, root, statement, checkpoint = _verified_fixture()
    reformatted = json.dumps(
        statement,
        ensure_ascii=False,
        separators=(",", ":"),
        sort_keys=False,
    ).encode("utf-8")

    reformatted_result = verify_snapshot(
        snapshot,
        reformatted,
        _json_bytes(root),
        expected_root_sha256=_root_digest(root),
        now=NOW,
    )
    assert reformatted_result["status"] == "VERIFIED"
    assert reformatted_result["next_checkpoint"] == checkpoint

    next_statement = _statement(
        snapshot,
        [signer],
        publication_id=2,
        previous=_checkpoint_previous(checkpoint),
    )
    next_result = verify_snapshot(
        snapshot,
        _json_bytes(next_statement),
        _json_bytes(root),
        checkpoint_bytes=_json_bytes(reformatted_result["next_checkpoint"]),
        expected_root_sha256=_root_digest(root),
        now=NOW,
    )

    assert next_result["status"] == "VERIFIED"


def test_runtime_style_verification_requires_checkpoint_to_be_current() -> None:
    snapshot, signer, _recovery, root, _statement_one, checkpoint = _verified_fixture()
    next_statement = _statement(
        snapshot,
        [signer],
        publication_id=2,
        previous=_checkpoint_previous(checkpoint),
    )

    result = verify_snapshot(
        snapshot,
        _json_bytes(next_statement),
        _json_bytes(root),
        checkpoint_bytes=_json_bytes(checkpoint),
        expected_root_sha256=_root_digest(root),
        require_current_checkpoint=True,
        now=NOW,
    )

    assert result["status"] == "UNKNOWN"
    assert result["reason_codes"] == ["CHECKPOINT_ADVANCE_REQUIRED"]


def test_verify_snapshot_cli_is_offline_and_machine_readable(tmp_path: Path) -> None:
    snapshot, signer, _recovery, root, _prior_statement, _checkpoint = _verified_fixture()
    cli_now = datetime.now(tz=UTC)
    statement = _statement(
        snapshot,
        [signer],
        issued_at=cli_now - timedelta(minutes=5),
        expires_at=cli_now + timedelta(hours=1),
    )
    snapshot_path = tmp_path / "catalog.json"
    statement_path = tmp_path / "statement.json"
    root_path = tmp_path / "root.json"
    snapshot_path.write_bytes(snapshot)
    statement_path.write_bytes(_json_bytes(statement))
    root_bytes = _json_bytes(root)
    root_path.write_bytes(root_bytes)

    result = CliRunner().invoke(
        app,
        [
            "verify-snapshot",
            str(snapshot_path),
            "--statement",
            str(statement_path),
            "--trust-root",
            str(root_path),
            "--trust-root-sha256",
            hashlib.sha256(root_bytes).hexdigest(),
        ],
    )

    assert result.exit_code == 0, result.output
    payload = json.loads(result.output)
    assert payload["status"] == "VERIFIED"
    assert payload["publication_id"] == 1
    assert payload["next_checkpoint"]["publisher_id"] == PUBLISHER_ID


def test_verify_snapshot_cli_returns_unknown_without_grades(tmp_path: Path) -> None:
    snapshot, signer, _recovery, root, _prior_statement, _checkpoint = _verified_fixture()
    cli_now = datetime.now(tz=UTC)
    statement = _statement(
        snapshot,
        [signer],
        issued_at=cli_now - timedelta(minutes=5),
        expires_at=cli_now + timedelta(hours=1),
    )
    statement["signatures"][0]["signature"] = _b64(bytes(64))  # type: ignore[index]
    snapshot_path = tmp_path / "catalog.json"
    statement_path = tmp_path / "statement.json"
    root_path = tmp_path / "root.json"
    snapshot_path.write_bytes(snapshot)
    statement_path.write_bytes(_json_bytes(statement))
    root_bytes = _json_bytes(root)
    root_path.write_bytes(root_bytes)

    result = CliRunner().invoke(
        app,
        [
            "verify-snapshot",
            str(snapshot_path),
            "--statement",
            str(statement_path),
            "--trust-root",
            str(root_path),
            "--trust-root-sha256",
            hashlib.sha256(root_bytes).hexdigest(),
        ],
    )

    assert result.exit_code == 1
    payload = json.loads(result.output)
    assert payload["status"] == "UNKNOWN"
    assert "SIGNATURE_INVALID" in payload["reason_codes"]
    assert "grade" not in result.output


def test_path_verifier_rejects_a_symlinked_trust_root(tmp_path: Path) -> None:
    snapshot, _signer, _recovery, root, statement, _checkpoint = _verified_fixture()
    snapshot_path = tmp_path / "catalog.json"
    statement_path = tmp_path / "statement.json"
    real_root_path = tmp_path / "real-root.json"
    linked_root_path = tmp_path / "root.json"
    snapshot_path.write_bytes(snapshot)
    statement_path.write_bytes(_json_bytes(statement))
    root_bytes = _json_bytes(root)
    real_root_path.write_bytes(root_bytes)
    linked_root_path.symlink_to(real_root_path)

    result = verify_snapshot_paths(
        snapshot_path,
        statement_path,
        linked_root_path,
        expected_root_sha256=hashlib.sha256(root_bytes).hexdigest(),
        now=NOW,
    )

    assert result == {
        "schema": "mcp-trust-snapshot-verification.v1",
        "status": "UNKNOWN",
        "reason_codes": ["TRUST_ROOT_RESOURCE_UNREADABLE"],
    }


def test_verify_root_update_cli_uses_recovery_authority(tmp_path: Path) -> None:
    _snapshot, _signer, recovery, root, _statement_one, checkpoint = _verified_fixture()
    new_root = _root(
        [_key(_private(4), "snapshot", valid_from=2)],
        [_key(_private(5), "recovery")],
        version=2,
        minimum_publication_id=2,
    )
    cli_now = datetime.now(tz=UTC)
    update = _root_update(
        root,
        new_root,
        [recovery],
        issued_at=cli_now - timedelta(minutes=5),
        expires_at=cli_now + timedelta(hours=1),
    )
    root_path = tmp_path / "root.json"
    update_path = tmp_path / "update.json"
    checkpoint_path = tmp_path / "checkpoint.json"
    root_bytes = _json_bytes(root)
    root_path.write_bytes(root_bytes)
    update_path.write_bytes(_json_bytes(update))
    checkpoint_path.write_bytes(_json_bytes(checkpoint))

    result = CliRunner().invoke(
        app,
        [
            "verify-root-update",
            str(root_path),
            "--update",
            str(update_path),
            "--checkpoint",
            str(checkpoint_path),
            "--current-root-sha256",
            hashlib.sha256(root_bytes).hexdigest(),
        ],
    )

    assert result.exit_code == 0, result.output
    payload = json.loads(result.output)
    assert payload["status"] == "VERIFIED"
    assert payload["new_root_version"] == 2
    assert payload["next_checkpoint"]["root_version"] == 2
