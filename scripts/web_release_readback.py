#!/usr/bin/env python3
"""Read-only route-sentinel verifier for web release candidates.

The verifier intentionally has a narrow capability surface:

* the target URL and manifest path are mandatory command-line arguments;
* only HTTP GET and HEAD are implemented;
* proxy, credential, deploy, alias, DNS, and promotion inputs do not exist;
* redirects are disabled unless the manifest explicitly permits same-origin
  redirects, and cross-origin redirects are always rejected;
* the only output is a WebReleaseReadbackV1 receipt on stdout.

Consumers keep deployment policy and domain-specific validation in their own
release lanes. This module owns only bounded transport assertions.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import sys
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any
from urllib.error import HTTPError, URLError
from urllib.parse import urljoin, urlsplit
from urllib.request import (
    HTTPRedirectHandler,
    OpenerDirector,
    ProxyHandler,
    Request,
    build_opener,
)

CONTRACT_VERSION = "1.0.0"
MANIFEST_SCHEMA = "WebReleaseSentinelManifestV1"
RECEIPT_SCHEMA = "WebReleaseReadbackV1"
VERIFIER_NAME = "web-release-readback"
SAFE_METHODS = frozenset({"GET", "HEAD"})
DENIED_METHODS = (
    "POST",
    "PUT",
    "PATCH",
    "DELETE",
    "CONNECT",
    "TRACE",
)
MAX_TIMEOUT_SECONDS = 60.0
MAX_BODY_BYTES = 16 * 1024 * 1024
_ID_RE = re.compile(r"^[a-z][a-z0-9-]{0,62}$")
_SHA256_RE = re.compile(r"^[0-9a-f]{64}$")


class ManifestError(ValueError):
    """Raised before any request when the manifest is outside the contract."""


class RedirectPolicyError(RuntimeError):
    """Raised when a response attempts a redirect outside the bounded policy."""


@dataclass(frozen=True)
class Target:
    url: str
    origin: tuple[str, str, int | None]


def _sha256(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def _utc_now() -> datetime:
    return datetime.now(UTC)


def _isoformat_utc(value: datetime) -> str:
    if value.tzinfo is None:
        raise ValueError("receipt clock must include a timezone")
    return value.astimezone(UTC).isoformat(timespec="seconds").replace(
        "+00:00", "Z"
    )


def _origin(url: str) -> tuple[str, str, int | None]:
    parsed = urlsplit(url)
    try:
        port = parsed.port
    except ValueError as exc:
        raise ManifestError("target URL has an invalid port") from exc
    return parsed.scheme.lower(), (parsed.hostname or "").lower(), port


def validate_target_url(raw: str) -> Target:
    if not isinstance(raw, str) or not raw.strip():
        raise ManifestError("target URL must be a non-empty string")
    candidate = raw.strip()
    parsed = urlsplit(candidate)
    if parsed.scheme.lower() not in {"http", "https"}:
        raise ManifestError("target URL must use http or https")
    if not parsed.hostname:
        raise ManifestError("target URL must include a hostname")
    if parsed.username is not None or parsed.password is not None:
        raise ManifestError("target URL must not contain credentials")
    if parsed.path not in {"", "/"} or parsed.query or parsed.fragment:
        raise ManifestError("target URL must be an origin with no path, query, or fragment")
    hostname = parsed.hostname.lower()
    if parsed.scheme.lower() == "http" and hostname not in {
        "localhost",
        "127.0.0.1",
        "::1",
    } and not hostname.endswith(".localhost"):
        raise ManifestError("non-loopback targets must use https")
    origin = _origin(candidate)
    normalized = candidate.rstrip("/")
    return Target(url=normalized, origin=origin)


def _require_mapping(value: object, label: str) -> Mapping[str, Any]:
    if not isinstance(value, Mapping):
        raise ManifestError(f"{label} must be an object")
    return value


def _require_exact_keys(
    value: Mapping[str, Any],
    *,
    label: str,
    required: set[str],
    optional: set[str] = frozenset(),
) -> None:
    missing = sorted(required - set(value))
    extra = sorted(set(value) - required - optional)
    if missing:
        raise ManifestError(f"{label} is missing required keys: {', '.join(missing)}")
    if extra:
        raise ManifestError(f"{label} has unsupported keys: {', '.join(extra)}")


def _positive_number(value: object, label: str, maximum: float) -> float:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise ManifestError(f"{label} must be a number")
    number = float(value)
    if number <= 0 or number > maximum:
        raise ManifestError(f"{label} must be greater than 0 and at most {maximum:g}")
    return number


def _positive_int(value: object, label: str, maximum: int) -> int:
    if isinstance(value, bool) or not isinstance(value, int):
        raise ManifestError(f"{label} must be an integer")
    if value <= 0 or value > maximum:
        raise ManifestError(f"{label} must be greater than 0 and at most {maximum}")
    return value


def _sentinels(value: object, label: str) -> list[str]:
    if not isinstance(value, list):
        raise ManifestError(f"{label} must be an array")
    if len(value) > 64:
        raise ManifestError(f"{label} must contain at most 64 entries")
    result: list[str] = []
    for index, item in enumerate(value):
        if not isinstance(item, str) or not item or len(item) > 4096:
            raise ManifestError(
                f"{label}[{index}] must be a non-empty string up to 4096 characters"
            )
        result.append(item)
    if len(set(result)) != len(result):
        raise ManifestError(f"{label} must not contain duplicates")
    return result


def validate_manifest(value: object) -> dict[str, Any]:
    manifest = _require_mapping(value, "manifest")
    _require_exact_keys(
        manifest,
        label="manifest",
        required={
            "schema",
            "contract_version",
            "name",
            "defaults",
            "denied_methods",
            "routes",
        },
    )
    if manifest["schema"] != MANIFEST_SCHEMA:
        raise ManifestError(f"manifest schema must be {MANIFEST_SCHEMA}")
    if manifest["contract_version"] != CONTRACT_VERSION:
        raise ManifestError(f"contract_version must be {CONTRACT_VERSION}")
    name = manifest["name"]
    if not isinstance(name, str) or _ID_RE.fullmatch(name) is None:
        raise ManifestError("manifest name must match ^[a-z][a-z0-9-]{0,62}$")

    defaults = _require_mapping(manifest["defaults"], "defaults")
    _require_exact_keys(
        defaults,
        label="defaults",
        required={
            "timeout_seconds",
            "max_body_bytes",
            "follow_same_origin_redirects",
        },
    )
    timeout_seconds = _positive_number(
        defaults["timeout_seconds"], "defaults.timeout_seconds", MAX_TIMEOUT_SECONDS
    )
    max_body_bytes = _positive_int(
        defaults["max_body_bytes"], "defaults.max_body_bytes", MAX_BODY_BYTES
    )
    follow_redirects = defaults["follow_same_origin_redirects"]
    if not isinstance(follow_redirects, bool):
        raise ManifestError("defaults.follow_same_origin_redirects must be boolean")

    denied = manifest["denied_methods"]
    if not isinstance(denied, list) or any(not isinstance(item, str) for item in denied):
        raise ManifestError("denied_methods must be an array of strings")
    if len(set(denied)) != len(denied):
        raise ManifestError("denied_methods must not contain duplicates")
    if set(denied) != set(DENIED_METHODS):
        raise ManifestError(
            "denied_methods must contain exactly " + ", ".join(DENIED_METHODS)
        )

    routes = manifest["routes"]
    if not isinstance(routes, list) or not 1 <= len(routes) <= 64:
        raise ManifestError("routes must contain between 1 and 64 entries")
    normalized_routes: list[dict[str, Any]] = []
    route_ids: set[str] = set()
    for index, raw_route in enumerate(routes):
        label = f"routes[{index}]"
        route = _require_mapping(raw_route, label)
        _require_exact_keys(
            route,
            label=label,
            required={"id", "method", "route", "expected_status"},
            optional={
                "timeout_seconds",
                "max_body_bytes",
                "required_sentinels",
                "forbidden_sentinels",
                "exact_body_utf8",
                "body_sha256",
            },
        )
        route_id = route["id"]
        if not isinstance(route_id, str) or _ID_RE.fullmatch(route_id) is None:
            raise ManifestError(f"{label}.id must match ^[a-z][a-z0-9-]{{0,62}}$")
        if route_id in route_ids:
            raise ManifestError(f"duplicate route id: {route_id}")
        route_ids.add(route_id)

        method = route["method"]
        if not isinstance(method, str):
            raise ManifestError(f"{label}.method must be a string")
        method = method.upper()
        if method not in SAFE_METHODS:
            raise ManifestError(
                f"{label}.method {method!r} is denied; only GET and HEAD are implemented"
            )
        route_path = route["route"]
        if (
            not isinstance(route_path, str)
            or not route_path.startswith("/")
            or route_path.startswith("//")
            or "#" in route_path
            or any(character.isspace() for character in route_path)
        ):
            raise ManifestError(
                f"{label}.route must be a root-relative path without whitespace or fragments"
            )
        expected_status = route["expected_status"]
        if (
            isinstance(expected_status, bool)
            or not isinstance(expected_status, int)
            or not 100 <= expected_status <= 599
        ):
            raise ManifestError(f"{label}.expected_status must be an HTTP status integer")

        route_timeout = timeout_seconds
        if "timeout_seconds" in route:
            route_timeout = _positive_number(
                route["timeout_seconds"], f"{label}.timeout_seconds", MAX_TIMEOUT_SECONDS
            )
        route_max_body = max_body_bytes
        if "max_body_bytes" in route:
            route_max_body = _positive_int(
                route["max_body_bytes"], f"{label}.max_body_bytes", MAX_BODY_BYTES
            )
        required_sentinels = _sentinels(
            route.get("required_sentinels", []), f"{label}.required_sentinels"
        )
        forbidden_sentinels = _sentinels(
            route.get("forbidden_sentinels", []), f"{label}.forbidden_sentinels"
        )
        overlap = sorted(set(required_sentinels) & set(forbidden_sentinels))
        if overlap:
            raise ManifestError(
                f"{label} requires and forbids the same sentinel: {overlap[0]!r}"
            )

        exact_body = route.get("exact_body_utf8")
        digest = route.get("body_sha256")
        if exact_body is not None and not isinstance(exact_body, str):
            raise ManifestError(f"{label}.exact_body_utf8 must be a string")
        if digest is not None and (
            not isinstance(digest, str) or _SHA256_RE.fullmatch(digest) is None
        ):
            raise ManifestError(f"{label}.body_sha256 must be a lowercase SHA-256 digest")
        if exact_body is not None and digest is not None:
            raise ManifestError(
                f"{label} may define exact_body_utf8 or body_sha256, not both"
            )
        if method == "HEAD" and (
            required_sentinels
            or forbidden_sentinels
            or exact_body is not None
            or digest is not None
        ):
            raise ManifestError(f"{label} HEAD checks may assert status only")

        normalized: dict[str, Any] = {
            "id": route_id,
            "method": method,
            "route": route_path,
            "expected_status": expected_status,
            "timeout_seconds": route_timeout,
            "max_body_bytes": route_max_body,
            "required_sentinels": required_sentinels,
            "forbidden_sentinels": forbidden_sentinels,
        }
        if exact_body is not None:
            normalized["exact_body_utf8"] = exact_body
        if digest is not None:
            normalized["body_sha256"] = digest
        normalized_routes.append(normalized)

    return {
        "schema": MANIFEST_SCHEMA,
        "contract_version": CONTRACT_VERSION,
        "name": name,
        "defaults": {
            "timeout_seconds": timeout_seconds,
            "max_body_bytes": max_body_bytes,
            "follow_same_origin_redirects": follow_redirects,
        },
        "denied_methods": list(DENIED_METHODS),
        "routes": normalized_routes,
    }


class _BoundedRedirectHandler(HTTPRedirectHandler):
    def __init__(
        self,
        *,
        target_origin: tuple[str, str, int | None],
        follow_same_origin: bool,
    ) -> None:
        super().__init__()
        self._target_origin = target_origin
        self._follow_same_origin = follow_same_origin

    def redirect_request(  # type: ignore[override]
        self,
        req: Request,
        fp: Any,
        code: int,
        msg: str,
        headers: Any,
        newurl: str,
    ) -> Request | None:
        if _origin(newurl) != self._target_origin:
            raise RedirectPolicyError("redirect_cross_origin")
        if not self._follow_same_origin:
            raise RedirectPolicyError("redirect_not_allowed")
        return super().redirect_request(req, fp, code, msg, headers, newurl)


def _opener(target: Target, *, follow_same_origin: bool) -> OpenerDirector:
    # An empty ProxyHandler prevents ambient proxy credentials or routing from
    # becoming an undeclared verifier capability.
    return build_opener(
        ProxyHandler({}),
        _BoundedRedirectHandler(
            target_origin=target.origin,
            follow_same_origin=follow_same_origin,
        ),
    )


def _route_result(
    *,
    route: Mapping[str, Any],
    target: Target,
    opener: OpenerDirector,
) -> dict[str, Any]:
    requested_url = urljoin(f"{target.url}/", route["route"].lstrip("/"))
    result: dict[str, Any] = {
        "id": route["id"],
        "method": route["method"],
        "route": route["route"],
        "requested_url": requested_url,
        "final_url": None,
        "expected_status": route["expected_status"],
        "actual_status": None,
        "body_bytes": None,
        "body_sha256": None,
        "required_sentinels": {
            "expected": list(route["required_sentinels"]),
            "missing": [],
        },
        "forbidden_sentinels": {
            "expected_absent": list(route["forbidden_sentinels"]),
            "present": [],
        },
        "state": "failed",
        "reason_codes": [],
    }
    request = Request(
        requested_url,
        method=route["method"],
        headers={
            "Accept": "*/*",
            "User-Agent": f"{VERIFIER_NAME}/{CONTRACT_VERSION}",
        },
    )
    response: Any
    try:
        response = opener.open(request, timeout=route["timeout_seconds"])
    except HTTPError as exc:
        response = exc
    except RedirectPolicyError as exc:
        result["reason_codes"].append(str(exc))
        return result
    except (URLError, TimeoutError, OSError) as exc:
        result["reason_codes"].append("network_error")
        result["network_error"] = type(exc).__name__
        return result

    try:
        final_url = response.geturl()
        result["final_url"] = final_url
        if _origin(final_url) != target.origin:
            result["reason_codes"].append("redirect_cross_origin")
            return result
        actual_status = int(response.getcode())
        result["actual_status"] = actual_status
        if actual_status != route["expected_status"]:
            result["reason_codes"].append("status_mismatch")

        body = b""
        if route["method"] != "HEAD":
            body = response.read(route["max_body_bytes"] + 1)
            if len(body) > route["max_body_bytes"]:
                result["reason_codes"].append("body_too_large")
                return result
        result["body_bytes"] = len(body)
        result["body_sha256"] = _sha256(body)

        text: str | None = None
        needs_text = bool(
            route["required_sentinels"]
            or route["forbidden_sentinels"]
            or "exact_body_utf8" in route
        )
        if needs_text:
            try:
                text = body.decode("utf-8", errors="strict")
            except UnicodeDecodeError:
                result["reason_codes"].append("body_utf8_invalid")
        if text is not None:
            missing = [item for item in route["required_sentinels"] if item not in text]
            present = [item for item in route["forbidden_sentinels"] if item in text]
            result["required_sentinels"]["missing"] = missing
            result["forbidden_sentinels"]["present"] = present
            if missing:
                result["reason_codes"].append("required_sentinel_missing")
            if present:
                result["reason_codes"].append("forbidden_sentinel_present")
            if "exact_body_utf8" in route and text != route["exact_body_utf8"]:
                result["reason_codes"].append("exact_body_mismatch")
        if "body_sha256" in route and result["body_sha256"] != route["body_sha256"]:
            result["reason_codes"].append("body_digest_mismatch")
    finally:
        response.close()

    if not result["reason_codes"]:
        result["state"] = "passed"
        result["reason_codes"] = ["matched"]
    return result


def verify_release(
    *,
    manifest: Mapping[str, Any],
    manifest_sha256: str,
    target_url: str,
    checked_at: datetime | None = None,
) -> dict[str, Any]:
    normalized = validate_manifest(manifest)
    target = validate_target_url(target_url)
    opener = _opener(
        target,
        follow_same_origin=normalized["defaults"]["follow_same_origin_redirects"],
    )
    results = [
        _route_result(route=route, target=target, opener=opener)
        for route in normalized["routes"]
    ]
    passed = sum(result["state"] == "passed" for result in results)
    total = len(results)
    return {
        "schema": RECEIPT_SCHEMA,
        "contract_version": CONTRACT_VERSION,
        "target_url": target.url,
        "manifest": {
            "name": normalized["name"],
            "sha256": manifest_sha256,
        },
        "checked_at": _isoformat_utc(checked_at or _utc_now()),
        "verifier": {
            "name": VERIFIER_NAME,
            "version": CONTRACT_VERSION,
            "network_methods": sorted(SAFE_METHODS),
            "denied_methods": list(DENIED_METHODS),
            "credentials_supported": False,
            "proxy_environment_used": False,
            "same_origin_redirects_only": True,
            "mutation_capabilities": [],
        },
        "state": "passed" if passed == total else "failed",
        "summary": {"total": total, "passed": passed, "failed": total - passed},
        "routes": results,
    }


def load_manifest(path: Path) -> tuple[dict[str, Any], str]:
    raw = path.read_bytes()
    try:
        parsed = json.loads(raw)
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ManifestError(f"manifest is not valid UTF-8 JSON: {exc}") from exc
    return validate_manifest(parsed), _sha256(raw)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Verify bounded web release sentinels and emit WebReleaseReadbackV1 JSON."
    )
    parser.add_argument("--manifest", required=True, type=Path)
    parser.add_argument("--target-url", required=True)
    parser.add_argument("--pretty", action="store_true")
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        manifest, manifest_sha256 = load_manifest(args.manifest)
        receipt = verify_release(
            manifest=manifest,
            manifest_sha256=manifest_sha256,
            target_url=args.target_url,
        )
    except (ManifestError, OSError) as exc:
        print(f"web-release-readback: {exc}", file=sys.stderr)
        return 2
    indent = 2 if args.pretty else None
    print(json.dumps(receipt, indent=indent, sort_keys=True, ensure_ascii=False))
    return 0 if receipt["state"] == "passed" else 1


if __name__ == "__main__":
    raise SystemExit(main())
