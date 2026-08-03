"""Offline content authentication for catalog snapshots.

The trust root is consumer-pinned. Snapshot publishers sign detached statements;
the verifier never reads a network resource and never handles private keys.
Rollback resistance depends on the caller preserving the returned checkpoint.
"""

from __future__ import annotations

import base64
import binascii
import hashlib
import json
import math
import os
import re
import stat
import unicodedata
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from mcp_trust.catalog.runtime_snapshot import (
    CatalogSnapshotValidationError,
    parse_catalog_snapshot,
)

ROOT_SCHEMA = "mcp-trust-snapshot-root.v1"
STATEMENT_SCHEMA = "mcp-trust-snapshot-statement.v1"
CHECKPOINT_SCHEMA = "mcp-trust-snapshot-checkpoint.v1"
ROOT_UPDATE_SCHEMA = "mcp-trust-snapshot-root-update.v1"
VERIFICATION_SCHEMA = "mcp-trust-snapshot-verification.v1"
ROOT_UPDATE_VERIFICATION_SCHEMA = "mcp-trust-root-update-verification.v1"

_SNAPSHOT_MEDIA_TYPE = "application/vnd.mcp-trust.catalog+json"
_SNAPSHOT_SCHEMA_VERSION = 2
_ALGORITHM = "ed25519"
_MAX_METADATA_BYTES = 256 * 1024
_MAX_SNAPSHOT_BYTES = 32 * 1024 * 1024
_MAX_JSON_NODES = 10_000
_MAX_JSON_STRING_CHARS = 65_536
_MAX_KEYS = 32
_MAX_SIGNATURES = 32
_MAX_LIFETIME_SECONDS = 31 * 24 * 60 * 60
_MAX_CLOCK_SKEW_SECONDS = 60 * 60
_SHA256 = re.compile(r"^[0-9a-f]{64}$")
_KEY_ID = re.compile(r"^sha256:[0-9a-f]{64}$")
_BASE64URL = re.compile(r"^[A-Za-z0-9_-]+$")
_PUBLISHER_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._/-]{0,254}$")

_ROOT_KEYS = frozenset(
    {
        "schema",
        "root_version",
        "publisher",
        "minimum_publication_id",
        "max_snapshot_lifetime_seconds",
        "max_clock_skew_seconds",
        "snapshot_threshold",
        "recovery_threshold",
        "keys",
    }
)
_ROOT_KEY_KEYS = frozenset(
    {
        "key_id",
        "algorithm",
        "public_key",
        "roles",
        "valid_from_publication_id",
        "valid_through_publication_id",
    }
)
_SIGNED_STATEMENT_KEYS = frozenset(
    {
        "publisher_id",
        "root_version",
        "publication_id",
        "issued_at",
        "expires_at",
        "snapshot",
        "previous",
    }
)
_SNAPSHOT_SUBJECT_KEYS = frozenset(
    {"media_type", "schema_version", "length", "sha256"}
)
_PREVIOUS_KEYS = frozenset(
    {"publication_id", "snapshot_sha256", "statement_sha256"}
)
_CHECKPOINT_KEYS = frozenset(
    {
        "schema",
        "publisher_id",
        "root_version",
        "root_sha256",
        "publication_id",
        "snapshot_sha256",
        "statement_sha256",
    }
)
_ROOT_UPDATE_SIGNED_KEYS = frozenset(
    {
        "publisher_id",
        "previous_root_version",
        "previous_root_sha256",
        "issued_at",
        "expires_at",
        "new_root",
    }
)


class _DuplicateJSONKey(ValueError):
    pass


class _UnsafeJSON(ValueError):
    pass


def _reject_duplicate_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise _DuplicateJSONKey(key)
        result[key] = value
    return result


def _reject_constant(_value: str) -> None:
    raise _UnsafeJSON


def _bounded_int(value: str) -> int:
    if len(value) > 64:
        raise _UnsafeJSON
    return int(value)


def _bounded_float(value: str) -> float:
    if len(value) > 64:
        raise _UnsafeJSON
    parsed = float(value)
    if not math.isfinite(parsed):
        raise _UnsafeJSON
    return parsed


def _values_are_safe(value: Any) -> bool:
    pending = [value]
    visited = 0
    while pending:
        current = pending.pop()
        visited += 1
        if visited > _MAX_JSON_NODES:
            return False
        if isinstance(current, dict):
            pending.extend(current.keys())
            pending.extend(current.values())
        elif isinstance(current, list):
            pending.extend(current)
        elif isinstance(current, str):
            if len(current) > _MAX_JSON_STRING_CHARS or any(
                unicodedata.category(character) in {"Cc", "Cf"}
                for character in current
            ):
                return False
        elif isinstance(current, float) and not math.isfinite(current):
            return False
    return True


def _strict_json(raw: bytes) -> Any:
    if len(raw) > _MAX_METADATA_BYTES:
        raise _UnsafeJSON
    value = json.loads(
        raw.decode("utf-8"),
        object_pairs_hook=_reject_duplicate_keys,
        parse_constant=_reject_constant,
        parse_int=_bounded_int,
        parse_float=_bounded_float,
    )
    if not _values_are_safe(value):
        raise _UnsafeJSON
    return value


def canonical_signed_bytes(value: object) -> bytes:
    """Return the canonical bytes covered by every v1 signature.

    V1 signed objects contain only strings, integers, nulls, lists, and maps;
    floats are not admitted by the schema.
    """
    return json.dumps(
        value,
        ensure_ascii=False,
        allow_nan=False,
        separators=(",", ":"),
        sort_keys=True,
    ).encode("utf-8")


def _sha256(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def _stat_signature(value: os.stat_result) -> tuple[int, ...]:
    return (
        value.st_dev,
        value.st_ino,
        value.st_mode,
        value.st_size,
        value.st_mtime_ns,
        value.st_ctime_ns,
        value.st_uid,
        value.st_gid,
        value.st_nlink,
    )


def _read_stable_file(path: Path, *, limit: int) -> bytes:
    before = path.lstat()
    if path.is_symlink() or not stat.S_ISREG(before.st_mode) or before.st_size > limit:
        raise OSError("unsafe verification input")
    flags = os.O_RDONLY
    if hasattr(os, "O_CLOEXEC"):
        flags |= os.O_CLOEXEC
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    descriptor = os.open(path, flags)
    try:
        opened = os.fstat(descriptor)
        content = bytearray()
        while len(content) <= limit:
            chunk = os.read(descriptor, min(1024 * 1024, limit + 1 - len(content)))
            if not chunk:
                break
            content.extend(chunk)
        after_read = os.fstat(descriptor)
    finally:
        os.close(descriptor)
    after_path = path.lstat()
    if len(content) > limit or len(
        {
            _stat_signature(before),
            _stat_signature(opened),
            _stat_signature(after_read),
            _stat_signature(after_path),
        }
    ) != 1:
        raise OSError("verification input changed during read")
    return bytes(content)


def _is_int(value: object, *, minimum: int = 0) -> bool:
    return type(value) is int and int(value) >= minimum


def _decode_base64url(value: object, *, expected_length: int) -> bytes | None:
    if not isinstance(value, str) or _BASE64URL.fullmatch(value) is None:
        return None
    try:
        decoded = base64.b64decode(
            value + "=" * (-len(value) % 4),
            altchars=b"-_",
            validate=True,
        )
    except (binascii.Error, ValueError):
        return None
    return decoded if len(decoded) == expected_length else None


def _utc_datetime(value: object) -> datetime | None:
    if not isinstance(value, str):
        return None
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None
    if parsed.tzinfo is None or parsed.utcoffset() != UTC.utcoffset(parsed):
        return None
    return parsed.astimezone(UTC)


def _unknown(schema: str, reasons: set[str] | list[str]) -> dict[str, object]:
    return {
        "schema": schema,
        "status": "UNKNOWN",
        "reason_codes": sorted(set(reasons)),
    }


def _validate_root(value: Any) -> tuple[dict[str, Any] | None, dict[str, bytes]]:
    if not isinstance(value, dict) or set(value) != _ROOT_KEYS:
        return None, {}
    publisher = value.get("publisher")
    keys = value.get("keys")
    if (
        value.get("schema") != ROOT_SCHEMA
        or not _is_int(value.get("root_version"), minimum=1)
        or not isinstance(publisher, dict)
        or set(publisher) != {"id", "name"}
        or not isinstance(publisher.get("id"), str)
        or _PUBLISHER_ID.fullmatch(publisher["id"]) is None
        or not isinstance(publisher.get("name"), str)
        or not publisher["name"]
        or not _is_int(value.get("minimum_publication_id"), minimum=1)
        or not _is_int(value.get("max_snapshot_lifetime_seconds"), minimum=1)
        or int(value["max_snapshot_lifetime_seconds"]) > _MAX_LIFETIME_SECONDS
        or not _is_int(value.get("max_clock_skew_seconds"))
        or int(value["max_clock_skew_seconds"]) > _MAX_CLOCK_SKEW_SECONDS
        or not _is_int(value.get("snapshot_threshold"), minimum=1)
        or not _is_int(value.get("recovery_threshold"), minimum=1)
        or not isinstance(keys, list)
        or not 2 <= len(keys) <= _MAX_KEYS
    ):
        return None, {}

    public_keys: dict[str, bytes] = {}
    snapshot_count = 0
    recovery_count = 0
    for key in keys:
        if not isinstance(key, dict) or set(key) != _ROOT_KEY_KEYS:
            return None, {}
        key_id = key.get("key_id")
        roles = key.get("roles")
        public = _decode_base64url(key.get("public_key"), expected_length=32)
        valid_from = key.get("valid_from_publication_id")
        valid_through = key.get("valid_through_publication_id")
        if (
            not isinstance(key_id, str)
            or _KEY_ID.fullmatch(key_id) is None
            or key.get("algorithm") != _ALGORITHM
            or public is None
            or key_id != f"sha256:{_sha256(public)}"
            or not isinstance(roles, list)
            or len(roles) != 1
            or roles[0] not in {"snapshot", "recovery"}
            or not _is_int(valid_from, minimum=1)
            or (
                valid_through is not None
                and (
                    not _is_int(valid_through, minimum=int(valid_from))
                    or int(valid_through) < int(valid_from)
                )
            )
            or key_id in public_keys
        ):
            return None, {}
        public_keys[key_id] = public
        if roles[0] == "snapshot":
            snapshot_count += 1
        else:
            recovery_count += 1
    if (
        int(value["snapshot_threshold"]) > snapshot_count
        or int(value["recovery_threshold"]) > recovery_count
    ):
        return None, {}
    return value, public_keys


def _load_root(raw: bytes) -> tuple[dict[str, Any] | None, dict[str, bytes]]:
    try:
        return _validate_root(_strict_json(raw))
    except (UnicodeError, ValueError, TypeError, MemoryError):
        return None, {}


def _validate_checkpoint(value: Any) -> dict[str, Any] | None:
    if (
        not isinstance(value, dict)
        or set(value) != _CHECKPOINT_KEYS
        or value.get("schema") != CHECKPOINT_SCHEMA
        or not isinstance(value.get("publisher_id"), str)
        or _PUBLISHER_ID.fullmatch(value["publisher_id"]) is None
        or not _is_int(value.get("root_version"), minimum=1)
        or not isinstance(value.get("root_sha256"), str)
        or _SHA256.fullmatch(value["root_sha256"]) is None
        or not _is_int(value.get("publication_id"), minimum=1)
        or not isinstance(value.get("snapshot_sha256"), str)
        or _SHA256.fullmatch(value["snapshot_sha256"]) is None
        or not isinstance(value.get("statement_sha256"), str)
        or _SHA256.fullmatch(value["statement_sha256"]) is None
    ):
        return None
    return value


def _load_checkpoint(raw: bytes | None) -> dict[str, Any] | None:
    if raw is None:
        return None
    try:
        return _validate_checkpoint(_strict_json(raw))
    except (UnicodeError, ValueError, TypeError, MemoryError):
        return None


def _validate_statement(value: Any) -> tuple[dict[str, Any], list[dict[str, Any]]] | None:
    if (
        not isinstance(value, dict)
        or set(value) != {"schema", "signed", "signatures"}
        or value.get("schema") != STATEMENT_SCHEMA
    ):
        return None
    signed = value.get("signed")
    signatures = value.get("signatures")
    if (
        not isinstance(signed, dict)
        or set(signed) != _SIGNED_STATEMENT_KEYS
        or not isinstance(signed.get("publisher_id"), str)
        or _PUBLISHER_ID.fullmatch(signed["publisher_id"]) is None
        or not _is_int(signed.get("root_version"), minimum=1)
        or not _is_int(signed.get("publication_id"), minimum=1)
        or _utc_datetime(signed.get("issued_at")) is None
        or _utc_datetime(signed.get("expires_at")) is None
        or not isinstance(signatures, list)
        or not 1 <= len(signatures) <= _MAX_SIGNATURES
    ):
        return None
    subject = signed.get("snapshot")
    previous = signed.get("previous")
    if (
        not isinstance(subject, dict)
        or set(subject) != _SNAPSHOT_SUBJECT_KEYS
        or subject.get("media_type") != _SNAPSHOT_MEDIA_TYPE
        or subject.get("schema_version") != _SNAPSHOT_SCHEMA_VERSION
        or not _is_int(subject.get("length"))
        or int(subject["length"]) > _MAX_SNAPSHOT_BYTES
        or not isinstance(subject.get("sha256"), str)
        or _SHA256.fullmatch(subject["sha256"]) is None
    ):
        return None
    if previous is not None and (
        not isinstance(previous, dict)
        or set(previous) != _PREVIOUS_KEYS
        or not _is_int(previous.get("publication_id"), minimum=1)
        or not isinstance(previous.get("snapshot_sha256"), str)
        or _SHA256.fullmatch(previous["snapshot_sha256"]) is None
        or not isinstance(previous.get("statement_sha256"), str)
        or _SHA256.fullmatch(previous["statement_sha256"]) is None
    ):
        return None
    for signature in signatures:
        if (
            not isinstance(signature, dict)
            or set(signature) != {"key_id", "signature"}
            or not isinstance(signature.get("key_id"), str)
            or _KEY_ID.fullmatch(signature["key_id"]) is None
            or _decode_base64url(signature.get("signature"), expected_length=64) is None
        ):
            return None
    return signed, signatures


def _key_is_authorized(
    key: dict[str, Any],
    *,
    role: str,
    publication_id: int,
) -> bool:
    valid_through = key["valid_through_publication_id"]
    return bool(
        key["roles"] == [role]
        and int(key["valid_from_publication_id"]) <= publication_id
        and (valid_through is None or publication_id <= int(valid_through))
    )


def _verify_signatures(
    *,
    signed: dict[str, Any],
    signatures: list[dict[str, Any]],
    root: dict[str, Any],
    public_keys: dict[str, bytes],
    role: str,
    publication_id: int,
) -> tuple[list[str], set[str]]:
    reasons: set[str] = set()
    root_keys = {key["key_id"]: key for key in root["keys"]}
    verified: list[str] = []
    seen: set[str] = set()
    signed_bytes = canonical_signed_bytes(signed)
    for signature in signatures:
        key_id = signature["key_id"]
        if key_id in seen:
            reasons.add("SIGNATURE_DUPLICATE")
            continue
        seen.add(key_id)
        key = root_keys.get(key_id)
        public = public_keys.get(key_id)
        if key is None or public is None:
            reasons.add("UNKNOWN_SIGNER")
            continue
        if not _key_is_authorized(key, role=role, publication_id=publication_id):
            reasons.add("SIGNER_NOT_AUTHORIZED")
            continue
        signature_bytes = _decode_base64url(signature["signature"], expected_length=64)
        assert signature_bytes is not None
        try:
            Ed25519PublicKey.from_public_bytes(public).verify(signature_bytes, signed_bytes)
        except (InvalidSignature, ValueError):
            reasons.add("SIGNATURE_INVALID")
            continue
        verified.append(key_id)
    threshold = int(root[f"{role}_threshold"])
    if len(verified) < threshold:
        reasons.add(
            "SIGNATURE_THRESHOLD_NOT_MET"
            if role == "snapshot"
            else "RECOVERY_THRESHOLD_NOT_MET"
        )
    return sorted(verified), reasons


def _checkpoint_matches_root(
    checkpoint: dict[str, Any],
    root: dict[str, Any],
    root_raw: bytes,
) -> bool:
    return bool(
        checkpoint["publisher_id"] == root["publisher"]["id"]
        and checkpoint["root_version"] == root["root_version"]
        and checkpoint["root_sha256"] == _sha256(root_raw)
    )


def verify_snapshot(
    snapshot_bytes: bytes,
    statement_bytes: bytes,
    trust_root_bytes: bytes,
    *,
    checkpoint_bytes: bytes | None = None,
    expected_root_sha256: str | None = None,
    require_current_checkpoint: bool = False,
    now: datetime | None = None,
) -> dict[str, object]:
    """Verify one detached snapshot statement with no network or state writes."""
    if expected_root_sha256 is not None and (
        _SHA256.fullmatch(expected_root_sha256) is None
        or _sha256(trust_root_bytes) != expected_root_sha256
    ):
        return _unknown(VERIFICATION_SCHEMA, {"TRUST_ROOT_DIGEST_MISMATCH"})
    root, public_keys = _load_root(trust_root_bytes)
    if root is None:
        return _unknown(VERIFICATION_SCHEMA, {"TRUST_ROOT_INVALID"})

    checkpoint = _load_checkpoint(checkpoint_bytes)
    if checkpoint_bytes is not None and checkpoint is None:
        return _unknown(VERIFICATION_SCHEMA, {"CHECKPOINT_INVALID"})
    if checkpoint is not None and not _checkpoint_matches_root(
        checkpoint,
        root,
        trust_root_bytes,
    ):
        return _unknown(VERIFICATION_SCHEMA, {"CHECKPOINT_ROOT_MISMATCH"})

    try:
        loaded_statement = _strict_json(statement_bytes)
    except (UnicodeError, ValueError, TypeError, MemoryError):
        return _unknown(VERIFICATION_SCHEMA, {"STATEMENT_INVALID"})
    validated = _validate_statement(loaded_statement)
    if validated is None:
        return _unknown(VERIFICATION_SCHEMA, {"STATEMENT_INVALID"})
    signed, signatures = validated

    reasons: set[str] = set()
    fixed_now = now or datetime.now(tz=UTC)
    if fixed_now.tzinfo is None:
        fixed_now = fixed_now.replace(tzinfo=UTC)
    fixed_now = fixed_now.astimezone(UTC)
    issued_at = _utc_datetime(signed["issued_at"])
    expires_at = _utc_datetime(signed["expires_at"])
    assert issued_at is not None and expires_at is not None
    publisher_id = root["publisher"]["id"]
    publication_id = int(signed["publication_id"])
    statement_sha256 = _sha256(statement_bytes)
    snapshot_sha256 = _sha256(snapshot_bytes)

    if signed["publisher_id"] != publisher_id:
        reasons.add("PUBLISHER_ID_MISMATCH")
    if signed["root_version"] != root["root_version"]:
        reasons.add("ROOT_VERSION_MISMATCH")
    if publication_id < int(root["minimum_publication_id"]):
        reasons.add("PUBLICATION_BELOW_ROOT_FLOOR")
    if len(snapshot_bytes) > _MAX_SNAPSHOT_BYTES:
        reasons.add("SNAPSHOT_STRUCTURAL_INVALID")
    subject = signed["snapshot"]
    if subject["length"] != len(snapshot_bytes) or subject["sha256"] != snapshot_sha256:
        reasons.add("SNAPSHOT_DIGEST_MISMATCH")
    try:
        parse_catalog_snapshot(snapshot_bytes.decode("utf-8"))
    except (CatalogSnapshotValidationError, UnicodeError):
        reasons.add("SNAPSHOT_STRUCTURAL_INVALID")

    max_skew = int(root["max_clock_skew_seconds"])
    lifetime = (expires_at - issued_at).total_seconds()
    if issued_at.timestamp() > fixed_now.timestamp() + max_skew:
        reasons.add("SNAPSHOT_NOT_YET_VALID")
    if fixed_now >= expires_at:
        reasons.add("SNAPSHOT_EXPIRED")
    if lifetime <= 0 or lifetime > int(root["max_snapshot_lifetime_seconds"]):
        reasons.add("SNAPSHOT_LIFETIME_INVALID")

    if checkpoint is None:
        if publication_id != int(root["minimum_publication_id"]):
            reasons.add("FIRST_USE_PUBLICATION_MISMATCH")
        if signed["previous"] is not None:
            reasons.add("PUBLICATION_CHAIN_MISMATCH")
    else:
        checkpoint_publication_id = int(checkpoint["publication_id"])
        if publication_id < checkpoint_publication_id:
            reasons.add("PUBLICATION_ROLLBACK")
        elif publication_id == checkpoint_publication_id:
            if (
                checkpoint["snapshot_sha256"] != snapshot_sha256
                or checkpoint["statement_sha256"] != statement_sha256
            ):
                reasons.add("PUBLICATION_ID_CONFLICT")
        else:
            expected_previous = {
                "publication_id": checkpoint_publication_id,
                "snapshot_sha256": checkpoint["snapshot_sha256"],
                "statement_sha256": checkpoint["statement_sha256"],
            }
            if signed["previous"] != expected_previous:
                reasons.add("PUBLICATION_CHAIN_MISMATCH")
    if require_current_checkpoint:
        if checkpoint is None:
            reasons.add("CHECKPOINT_REQUIRED")
        elif publication_id > int(checkpoint["publication_id"]):
            reasons.add("CHECKPOINT_ADVANCE_REQUIRED")

    signer_key_ids, signature_reasons = _verify_signatures(
        signed=signed,
        signatures=signatures,
        root=root,
        public_keys=public_keys,
        role="snapshot",
        publication_id=publication_id,
    )
    reasons.update(signature_reasons)
    if reasons:
        return _unknown(VERIFICATION_SCHEMA, reasons)

    next_checkpoint = {
        "schema": CHECKPOINT_SCHEMA,
        "publisher_id": publisher_id,
        "root_version": root["root_version"],
        "root_sha256": _sha256(trust_root_bytes),
        "publication_id": publication_id,
        "snapshot_sha256": snapshot_sha256,
        "statement_sha256": statement_sha256,
    }
    return {
        "schema": VERIFICATION_SCHEMA,
        "status": "VERIFIED",
        "reason_codes": [],
        "publisher_id": publisher_id,
        "root_version": root["root_version"],
        "publication_id": publication_id,
        "issued_at": signed["issued_at"],
        "expires_at": signed["expires_at"],
        "snapshot_sha256": snapshot_sha256,
        "statement_sha256": statement_sha256,
        "signer_key_ids": signer_key_ids,
        "next_checkpoint": next_checkpoint,
    }


def verify_snapshot_paths(
    snapshot_path: Path,
    statement_path: Path,
    trust_root_path: Path,
    *,
    expected_root_sha256: str,
    checkpoint_path: Path | None = None,
    require_current_checkpoint: bool = False,
    now: datetime | None = None,
) -> dict[str, object]:
    """Read one stable local view of every input, then verify it offline."""
    inputs: dict[str, bytes] = {}
    for label, path, limit in (
        ("SNAPSHOT", snapshot_path, _MAX_SNAPSHOT_BYTES),
        ("STATEMENT", statement_path, _MAX_METADATA_BYTES),
        ("TRUST_ROOT", trust_root_path, _MAX_METADATA_BYTES),
    ):
        try:
            inputs[label] = _read_stable_file(path, limit=limit)
        except (OSError, MemoryError):
            return _unknown(VERIFICATION_SCHEMA, {f"{label}_RESOURCE_UNREADABLE"})
    checkpoint_bytes: bytes | None = None
    if checkpoint_path is not None:
        try:
            checkpoint_bytes = _read_stable_file(
                checkpoint_path,
                limit=_MAX_METADATA_BYTES,
            )
        except (OSError, MemoryError):
            return _unknown(VERIFICATION_SCHEMA, {"CHECKPOINT_RESOURCE_UNREADABLE"})
    return verify_snapshot(
        inputs["SNAPSHOT"],
        inputs["STATEMENT"],
        inputs["TRUST_ROOT"],
        checkpoint_bytes=checkpoint_bytes,
        expected_root_sha256=expected_root_sha256,
        require_current_checkpoint=require_current_checkpoint,
        now=now,
    )


def _validate_root_update(value: Any) -> tuple[dict[str, Any], list[dict[str, Any]]] | None:
    if (
        not isinstance(value, dict)
        or set(value) != {"schema", "signed", "signatures"}
        or value.get("schema") != ROOT_UPDATE_SCHEMA
    ):
        return None
    signed = value.get("signed")
    signatures = value.get("signatures")
    if (
        not isinstance(signed, dict)
        or set(signed) != _ROOT_UPDATE_SIGNED_KEYS
        or not isinstance(signed.get("publisher_id"), str)
        or _PUBLISHER_ID.fullmatch(signed["publisher_id"]) is None
        or not _is_int(signed.get("previous_root_version"), minimum=1)
        or not isinstance(signed.get("previous_root_sha256"), str)
        or _SHA256.fullmatch(signed["previous_root_sha256"]) is None
        or _utc_datetime(signed.get("issued_at")) is None
        or _utc_datetime(signed.get("expires_at")) is None
        or not isinstance(signatures, list)
        or not 1 <= len(signatures) <= _MAX_SIGNATURES
    ):
        return None
    for signature in signatures:
        if (
            not isinstance(signature, dict)
            or set(signature) != {"key_id", "signature"}
            or not isinstance(signature.get("key_id"), str)
            or _KEY_ID.fullmatch(signature["key_id"]) is None
            or _decode_base64url(signature.get("signature"), expected_length=64) is None
        ):
            return None
    return signed, signatures


def verify_root_update(
    current_root_bytes: bytes,
    update_bytes: bytes,
    checkpoint_bytes: bytes,
    *,
    expected_root_sha256: str | None = None,
    now: datetime | None = None,
) -> dict[str, object]:
    """Verify a recovery-threshold root rotation without writing either root."""
    if expected_root_sha256 is not None and (
        _SHA256.fullmatch(expected_root_sha256) is None
        or _sha256(current_root_bytes) != expected_root_sha256
    ):
        return _unknown(
            ROOT_UPDATE_VERIFICATION_SCHEMA,
            {"TRUST_ROOT_DIGEST_MISMATCH"},
        )
    current_root, public_keys = _load_root(current_root_bytes)
    if current_root is None:
        return _unknown(ROOT_UPDATE_VERIFICATION_SCHEMA, {"TRUST_ROOT_INVALID"})
    checkpoint = _load_checkpoint(checkpoint_bytes)
    if checkpoint is None:
        return _unknown(ROOT_UPDATE_VERIFICATION_SCHEMA, {"CHECKPOINT_INVALID"})
    if not _checkpoint_matches_root(checkpoint, current_root, current_root_bytes):
        return _unknown(ROOT_UPDATE_VERIFICATION_SCHEMA, {"CHECKPOINT_ROOT_MISMATCH"})
    try:
        loaded_update = _strict_json(update_bytes)
    except (UnicodeError, ValueError, TypeError, MemoryError):
        return _unknown(ROOT_UPDATE_VERIFICATION_SCHEMA, {"ROOT_UPDATE_INVALID"})
    validated = _validate_root_update(loaded_update)
    if validated is None:
        return _unknown(ROOT_UPDATE_VERIFICATION_SCHEMA, {"ROOT_UPDATE_INVALID"})
    signed, signatures = validated
    reasons: set[str] = set()
    fixed_now = now or datetime.now(tz=UTC)
    if fixed_now.tzinfo is None:
        fixed_now = fixed_now.replace(tzinfo=UTC)
    fixed_now = fixed_now.astimezone(UTC)
    issued_at = _utc_datetime(signed["issued_at"])
    expires_at = _utc_datetime(signed["expires_at"])
    assert issued_at is not None and expires_at is not None
    max_skew = int(current_root["max_clock_skew_seconds"])
    lifetime = (expires_at - issued_at).total_seconds()
    if issued_at.timestamp() > fixed_now.timestamp() + max_skew:
        reasons.add("ROOT_UPDATE_NOT_YET_VALID")
    if fixed_now >= expires_at:
        reasons.add("ROOT_UPDATE_EXPIRED")
    if lifetime <= 0 or lifetime > int(current_root["max_snapshot_lifetime_seconds"]):
        reasons.add("ROOT_UPDATE_LIFETIME_INVALID")
    new_root_value = signed["new_root"]
    new_root, _new_public_keys = _validate_root(new_root_value)
    if new_root is None:
        reasons.add("ROOT_UPDATE_INVALID")

    publisher_id = current_root["publisher"]["id"]
    if signed["publisher_id"] != publisher_id:
        reasons.add("PUBLISHER_ID_MISMATCH")
    if signed["previous_root_version"] != current_root["root_version"]:
        reasons.add("ROOT_VERSION_MISMATCH")
    if signed["previous_root_sha256"] != _sha256(current_root_bytes):
        reasons.add("ROOT_DIGEST_MISMATCH")
    if isinstance(new_root_value, dict):
        new_minimum = new_root_value.get("minimum_publication_id")
        if not _is_int(new_minimum, minimum=int(checkpoint["publication_id"])):
            reasons.add("ROOT_UPDATE_ROLLBACK")
    if new_root is not None:
        if new_root["publisher"]["id"] != publisher_id:
            reasons.add("PUBLISHER_ID_MISMATCH")
        if new_root["root_version"] != int(current_root["root_version"]) + 1:
            reasons.add("ROOT_VERSION_MISMATCH")

    signer_key_ids, signature_reasons = _verify_signatures(
        signed=signed,
        signatures=signatures,
        root=current_root,
        public_keys=public_keys,
        role="recovery",
        publication_id=int(checkpoint["publication_id"]),
    )
    reasons.update(signature_reasons)
    if reasons or new_root is None:
        return _unknown(ROOT_UPDATE_VERIFICATION_SCHEMA, reasons or {"ROOT_UPDATE_INVALID"})

    new_root_bytes = json.dumps(new_root, indent=2, sort_keys=True).encode("utf-8") + b"\n"
    next_checkpoint = dict(checkpoint)
    next_checkpoint["root_version"] = new_root["root_version"]
    next_checkpoint["root_sha256"] = _sha256(new_root_bytes)
    return {
        "schema": ROOT_UPDATE_VERIFICATION_SCHEMA,
        "status": "VERIFIED",
        "reason_codes": [],
        "publisher_id": publisher_id,
        "previous_root_version": current_root["root_version"],
        "new_root_version": new_root["root_version"],
        "recovery_signer_key_ids": signer_key_ids,
        "new_root": new_root,
        "next_checkpoint": next_checkpoint,
    }


def verify_root_update_paths(
    current_root_path: Path,
    update_path: Path,
    checkpoint_path: Path,
    *,
    expected_root_sha256: str,
    now: datetime | None = None,
) -> dict[str, object]:
    """Read stable local root-update inputs, then apply the recovery policy."""
    inputs: dict[str, bytes] = {}
    for label, path in (
        ("TRUST_ROOT", current_root_path),
        ("ROOT_UPDATE", update_path),
        ("CHECKPOINT", checkpoint_path),
    ):
        try:
            inputs[label] = _read_stable_file(path, limit=_MAX_METADATA_BYTES)
        except (OSError, MemoryError):
            return _unknown(
                ROOT_UPDATE_VERIFICATION_SCHEMA,
                {f"{label}_RESOURCE_UNREADABLE"},
            )
    return verify_root_update(
        inputs["TRUST_ROOT"],
        inputs["ROOT_UPDATE"],
        inputs["CHECKPOINT"],
        expected_root_sha256=expected_root_sha256,
        now=now,
    )
