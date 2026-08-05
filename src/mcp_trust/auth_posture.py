"""Fail-closed, credential-free MCP authorization metadata preflight.

The preflight is deliberately narrower than an OAuth client.  It reads only
public discovery metadata for one exact remote endpoint selected from a saved
official-Registry candidate manifest.  It never acquires or sends credentials,
follows redirects, changes a trust grade, or authorizes a scan.
"""

from __future__ import annotations

import hashlib
import http.client
import ipaddress
import json
import os
import re
import socket
import ssl
import stat
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from datetime import UTC, datetime
from email.utils import parsedate_to_datetime
from pathlib import Path
from typing import Any, Protocol
from urllib.parse import unquote, urlsplit, urlunsplit

SCHEMA_VERSION = "McpAuthorizationPostureV1"
CONTRACT_VERSION = "1.0.0"
SPECIFICATION_PROFILE = "mcp-authorization-2025-11-25"
MCP_AUTHORIZATION_URL = (
    "https://modelcontextprotocol.io/specification/2025-11-25/basic/authorization"
)
RFC_9728_URL = "https://datatracker.ietf.org/doc/html/rfc9728"
RFC_8414_URL = "https://datatracker.ietf.org/doc/html/rfc8414"
OIDC_DISCOVERY_URL = "https://openid.net/specs/openid-connect-discovery-1_0.html"

MAX_MANIFEST_BYTES = 2 * 1024 * 1024
MAX_METADATA_BYTES = 64 * 1024
MAX_HEADER_BYTES = 8 * 1024
MAX_TIMEOUT_SECONDS = 10.0
MAX_JSON_DEPTH = 16
MAX_JSON_NODES = 2048
MAX_AUTHORIZATION_SERVERS = 8
MAX_SCOPES = 64
MAX_RESOLVED_ADDRESSES = 16
MAX_RESPONSE_CLOCK_SKEW_SECONDS = 300
MAX_UNDIRECTED_CACHE_AGE_SECONDS = 3600
MAX_ACCEPTED_CACHE_AGE_SECONDS = 86_400
USER_AGENT = f"mcp-trust-auth-posture/{CONTRACT_VERSION}"

_PARAM_RE = re.compile(
    r"(?:^|[,;\s])(?P<name>[A-Za-z][A-Za-z0-9_-]*)\s*=\s*"
    r'(?:"(?P<quoted>[^"\\]*)"|(?P<token>[^,;\s]+))'
)
_BEARER_RE = re.compile(r"(?:^|,)\s*Bearer(?:\s|$)", re.IGNORECASE)


class AuthPostureInputError(ValueError):
    """The operator-supplied binding or endpoint is outside the contract."""


class MetadataDocumentError(ValueError):
    """Untrusted remote metadata failed a stable validation rule."""

    def __init__(self, reason_code: str) -> None:
        super().__init__(reason_code)
        self.reason_code = reason_code


class _DuplicateKeyError(ValueError):
    pass


@dataclass(frozen=True)
class BoundURL:
    """Normalized HTTPS URL and its request authority."""

    url: str
    hostname: str
    port: int
    path: str
    origin: str


@dataclass(frozen=True)
class RegistryBinding:
    """One exact remote endpoint selected from a saved Registry manifest."""

    stable_id: str
    resource_url: str
    manifest_sha256: str
    source_kind: str

    def as_dict(self) -> dict[str, str]:
        return {
            "stable_id": self.stable_id,
            "resource_url": self.resource_url,
            "manifest_sha256": self.manifest_sha256,
            "source_kind": self.source_kind,
        }


@dataclass(frozen=True)
class FetchResponse:
    """Bounded metadata response; arbitrary headers and bodies are not retained."""

    url: str
    status: int | None = None
    content_type: str | None = None
    http_date: str | None = None
    cache_control: str | None = None
    age: str | None = None
    last_modified: str | None = None
    body: bytes | None = None
    reason_code: str | None = None


class MetadataFetcher(Protocol):
    def fetch(
        self,
        url: str,
        *,
        timeout_seconds: float,
        max_body_bytes: int,
    ) -> FetchResponse: ...


Resolver = Callable[..., list[tuple[Any, ...]]]


def _normalized_hostname(hostname: str) -> str:
    try:
        normalized = hostname.rstrip(".").encode("idna").decode("ascii").lower()
    except UnicodeError as exc:
        raise AuthPostureInputError("URL hostname is not valid IDNA") from exc
    if not normalized:
        raise AuthPostureInputError("URL must include a hostname")
    return normalized


def _looks_like_ip_literal(hostname: str) -> bool:
    try:
        ipaddress.ip_address(hostname)
    except ValueError:
        return False
    return True


def _bound_https_url(raw: str, *, label: str) -> BoundURL:
    if not isinstance(raw, str) or not raw or raw != raw.strip():
        raise AuthPostureInputError(f"{label} must be one non-empty URL")
    if len(raw) > 2048 or "\\" in raw or any(ord(character) < 32 for character in raw):
        raise AuthPostureInputError(f"{label} exceeds the URL boundary")
    try:
        parsed = urlsplit(raw)
        raw_hostname = parsed.hostname or ""
    except ValueError as exc:
        raise AuthPostureInputError(f"{label} is not a valid URL") from exc
    if parsed.scheme.lower() != "https":
        raise AuthPostureInputError(f"{label} must use https")
    if parsed.username is not None or parsed.password is not None:
        raise AuthPostureInputError(f"{label} must not contain credentials")
    if parsed.query or parsed.fragment:
        raise AuthPostureInputError(f"{label} must not contain a query or fragment")
    hostname = _normalized_hostname(raw_hostname)
    if hostname == "localhost" or hostname.endswith(".localhost"):
        raise AuthPostureInputError(f"{label} must not target localhost")
    if _looks_like_ip_literal(hostname):
        raise AuthPostureInputError(f"{label} must use a DNS hostname, not an IP literal")
    try:
        parsed_port = parsed.port
    except ValueError as exc:
        raise AuthPostureInputError(f"{label} has an invalid port") from exc
    port = 443 if parsed_port is None else parsed_port
    if port < 1 or port > 65535:
        raise AuthPostureInputError(f"{label} has an invalid port")
    path = parsed.path or "/"
    decoded_path = unquote(path)
    if not path.startswith("/") or "\\" in decoded_path:
        raise AuthPostureInputError(f"{label} has an invalid path")
    if any(ord(character) < 32 for character in decoded_path):
        raise AuthPostureInputError(f"{label} has an invalid path")
    netloc = hostname if port == 443 else f"{hostname}:{port}"
    url = urlunsplit(("https", netloc, path, "", ""))
    origin = f"https://{netloc}"
    return BoundURL(url=url, hostname=hostname, port=port, path=path, origin=origin)


def _safe_input_error(reason_code: str) -> MetadataDocumentError:
    return MetadataDocumentError(reason_code)


def _metadata_url(raw: object, *, label: str) -> BoundURL:
    if not isinstance(raw, str):
        raise _safe_input_error(f"{label}_invalid")
    try:
        return _bound_https_url(raw, label=label)
    except AuthPostureInputError as exc:
        raise _safe_input_error(f"{label}_invalid") from exc


def _https_endpoint(raw: object, *, label: str) -> str:
    """Validate an advertised HTTPS endpoint without fetching or rewriting it."""

    if not isinstance(raw, str) or not raw or raw != raw.strip():
        raise MetadataDocumentError(f"{label}_invalid")
    if len(raw) > 2048 or "\\" in raw or any(ord(character) < 32 for character in raw):
        raise MetadataDocumentError(f"{label}_invalid")
    try:
        parsed = urlsplit(raw)
        hostname = _normalized_hostname(parsed.hostname or "")
        parsed_port = parsed.port
    except (AuthPostureInputError, ValueError) as exc:
        raise MetadataDocumentError(f"{label}_invalid") from exc
    port = 443 if parsed_port is None else parsed_port
    if (
        parsed.scheme.lower() != "https"
        or parsed.username is not None
        or parsed.password is not None
    ):
        raise MetadataDocumentError(f"{label}_invalid")
    if parsed.fragment or port < 1 or port > 65535:
        raise MetadataDocumentError(f"{label}_invalid")
    if (
        hostname == "localhost"
        or hostname.endswith(".localhost")
        or _looks_like_ip_literal(hostname)
    ):
        raise MetadataDocumentError(f"{label}_invalid")
    decoded_path = unquote(parsed.path or "/")
    if "\\" in decoded_path or any(ord(character) < 32 for character in decoded_path):
        raise MetadataDocumentError(f"{label}_invalid")
    return raw


def _read_regular_file(path: Path, *, maximum: int) -> bytes:
    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(path, flags)
    except OSError as exc:
        raise AuthPostureInputError("candidate manifest is not a readable regular file") from exc
    try:
        file_stat = os.fstat(descriptor)
        if not stat.S_ISREG(file_stat.st_mode):
            raise AuthPostureInputError("candidate manifest must be a regular file")
        if file_stat.st_size > maximum:
            raise AuthPostureInputError("candidate manifest exceeds the size limit")
        with os.fdopen(descriptor, "rb", closefd=False) as handle:
            raw = handle.read(maximum + 1)
    finally:
        os.close(descriptor)
    if len(raw) > maximum:
        raise AuthPostureInputError("candidate manifest exceeds the size limit")
    return raw


def load_registry_binding(path: Path, stable_id: str) -> RegistryBinding:
    """Bind one candidate to one exact remote URL without contacting it."""

    if not stable_id or len(stable_id) > 256:
        raise AuthPostureInputError("candidate stable ID is invalid")
    raw = _read_regular_file(path, maximum=MAX_MANIFEST_BYTES)
    try:
        value = json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise AuthPostureInputError("candidate manifest is not valid UTF-8 JSON") from exc
    if not isinstance(value, dict) or value.get("format_version") != 1:
        raise AuthPostureInputError("candidate manifest format_version must be 1")
    source = value.get("source")
    if not isinstance(source, dict) or source.get("kind") != "official-mcp-registry-export":
        raise AuthPostureInputError(
            "candidate manifest must be derived from an official MCP Registry export"
        )
    candidates = value.get("candidates")
    if not isinstance(candidates, list) or len(candidates) > 10_000:
        raise AuthPostureInputError("candidate manifest candidates must be a bounded array")
    matches = [
        candidate
        for candidate in candidates
        if isinstance(candidate, dict) and candidate.get("stable_id") == stable_id
    ]
    if len(matches) != 1:
        raise AuthPostureInputError("candidate stable ID must match exactly one entry")
    remote_refs = matches[0].get("remote_refs")
    if not isinstance(remote_refs, list) or len(remote_refs) != 1:
        raise AuthPostureInputError("candidate must bind exactly one remote endpoint")
    remote = remote_refs[0]
    if not isinstance(remote, dict):
        raise AuthPostureInputError("candidate remote endpoint is invalid")
    resource = _bound_https_url(remote.get("url"), label="candidate resource URL")
    normalized_url = remote.get("normalized_url")
    if normalized_url is not None and normalized_url != resource.url.rstrip("/"):
        raise AuthPostureInputError("candidate normalized URL does not match its remote URL")
    return RegistryBinding(
        stable_id=stable_id,
        resource_url=resource.url,
        manifest_sha256=hashlib.sha256(raw).hexdigest(),
        source_kind="official-mcp-registry-export",
    )


def _bounded_response_header(
    response: http.client.HTTPResponse,
    name: str,
) -> str | None:
    value = response.getheader(name)
    if value is None:
        return None
    if len(value) > 512 or "\r" in value or "\n" in value:
        return None
    if any(ord(character) < 32 and character != "\t" for character in value):
        return None
    return value


class PinnedHTTPSFetcher:
    """Resolve once, reject non-public addresses, then connect to an allowed IP.

    TLS verification and SNI remain bound to the original hostname.  The
    connection never consults proxy environment variables and never follows a
    redirect.
    """

    def __init__(
        self,
        *,
        resolver: Resolver = socket.getaddrinfo,
        ssl_context: ssl.SSLContext | None = None,
    ) -> None:
        self._resolver = resolver
        self._ssl_context = ssl_context or ssl.create_default_context()

    def _addresses(self, target: BoundURL) -> tuple[str, ...] | str:
        try:
            answers = self._resolver(
                target.hostname,
                target.port,
                type=socket.SOCK_STREAM,
            )
        except OSError:
            return "dns_error"
        addresses = sorted(
            {
                str(answer[4][0]).split("%", 1)[0]
                for answer in answers
                if len(answer) >= 5 and isinstance(answer[4], tuple) and answer[4]
            }
        )
        if not addresses or len(addresses) > MAX_RESOLVED_ADDRESSES:
            return "dns_error"
        for address in addresses:
            try:
                parsed = ipaddress.ip_address(address)
            except ValueError:
                return "dns_error"
            if not parsed.is_global:
                return "non_public_address"
        return tuple(addresses)

    def _request(
        self,
        target: BoundURL,
        address: str,
        *,
        timeout_seconds: float,
        max_body_bytes: int,
    ) -> FetchResponse:
        connection = http.client.HTTPSConnection(
            target.hostname,
            target.port,
            timeout=timeout_seconds,
            context=self._ssl_context,
        )

        def _pinned_connection(
            _authority: tuple[str, int],
            timeout: float | None = None,
            source_address: tuple[str, int] | None = None,
        ) -> socket.socket:
            return socket.create_connection(
                (address, target.port),
                timeout=timeout,
                source_address=source_address,
            )

        connection._create_connection = _pinned_connection  # type: ignore[method-assign]
        response: http.client.HTTPResponse | None = None
        try:
            connection.request(
                "GET",
                target.path,
                headers={
                    "Accept": "application/json, application/*+json",
                    "Connection": "close",
                    "User-Agent": USER_AGENT,
                },
            )
            response = connection.getresponse()
            status_code = int(response.status)
            content_type = response.getheader("Content-Type")
            http_date = _bounded_response_header(response, "Date")
            cache_control = _bounded_response_header(response, "Cache-Control")
            age = _bounded_response_header(response, "Age")
            last_modified = _bounded_response_header(response, "Last-Modified")
            if 300 <= status_code <= 399:
                return FetchResponse(
                    url=target.url,
                    status=status_code,
                    content_type=content_type,
                    http_date=http_date,
                    cache_control=cache_control,
                    age=age,
                    last_modified=last_modified,
                    reason_code="redirect_not_allowed",
                )
            body = response.read(max_body_bytes + 1)
            if len(body) > max_body_bytes:
                return FetchResponse(
                    url=target.url,
                    status=status_code,
                    content_type=content_type,
                    http_date=http_date,
                    cache_control=cache_control,
                    age=age,
                    last_modified=last_modified,
                    reason_code="body_too_large",
                )
            return FetchResponse(
                url=target.url,
                status=status_code,
                content_type=content_type,
                http_date=http_date,
                cache_control=cache_control,
                age=age,
                last_modified=last_modified,
                body=body,
            )
        except (OSError, TimeoutError, ssl.SSLError, http.client.HTTPException):
            return FetchResponse(url=target.url, reason_code="network_error")
        finally:
            if response is not None:
                response.close()
            connection.close()

    def fetch(
        self,
        url: str,
        *,
        timeout_seconds: float,
        max_body_bytes: int,
    ) -> FetchResponse:
        target = _bound_https_url(url, label="metadata URL")
        addresses = self._addresses(target)
        if isinstance(addresses, str):
            return FetchResponse(url=target.url, reason_code=addresses)
        last = FetchResponse(url=target.url, reason_code="network_error")
        for address in addresses:
            last = self._request(
                target,
                address,
                timeout_seconds=timeout_seconds,
                max_body_bytes=max_body_bytes,
            )
            if last.reason_code != "network_error":
                return last
        return last


def _unique(values: list[str]) -> list[str]:
    return list(dict.fromkeys(values))


def _challenge_parameter(header: str, name: str) -> str | None:
    try:
        header_bytes = header.encode("utf-8")
    except UnicodeEncodeError as exc:
        raise MetadataDocumentError("challenge_invalid") from exc
    if len(header_bytes) > MAX_HEADER_BYTES or "\r" in header or "\n" in header:
        raise MetadataDocumentError("challenge_invalid")
    if _BEARER_RE.search(header) is None:
        raise MetadataDocumentError("challenge_invalid")
    values = [
        match.group("quoted") or match.group("token") or ""
        for match in _PARAM_RE.finditer(header)
        if match.group("name").casefold() == name.casefold()
    ]
    if len(values) > 1:
        raise MetadataDocumentError("challenge_duplicate_parameter")
    return values[0] if values else None


def _challenge(header: str | None) -> tuple[str | None, list[str]]:
    if header is None:
        return None, []
    metadata_url = _challenge_parameter(header, "resource_metadata")
    scope = _challenge_parameter(header, "scope")
    scopes = [] if scope is None else _unique(scope.split())
    if len(scopes) > MAX_SCOPES:
        raise MetadataDocumentError("challenge_scope_invalid")
    return metadata_url, scopes


def _resource_metadata_candidates(
    resource: BoundURL,
    challenge_url: str | None,
) -> list[tuple[str, str]]:
    if challenge_url is not None:
        metadata = _metadata_url(challenge_url, label="resource_metadata_url")
        if metadata.origin != resource.origin:
            raise MetadataDocumentError("resource_metadata_origin_not_allowed")
        return [(metadata.url, "www-authenticate")]
    candidates: list[tuple[str, str]] = []
    resource_path = resource.path.rstrip("/")
    if resource_path:
        candidates.append(
            (
                f"{resource.origin}/.well-known/oauth-protected-resource{resource_path}",
                "well-known-path",
            )
        )
    candidates.append(
        (f"{resource.origin}/.well-known/oauth-protected-resource", "well-known-root")
    )
    return list(dict.fromkeys(candidates))


def _authorization_metadata_candidates(issuer: BoundURL) -> list[tuple[str, str]]:
    issuer_path = issuer.path.strip("/")
    if not issuer_path:
        return [
            (
                f"{issuer.origin}/.well-known/oauth-authorization-server",
                "rfc8414",
            ),
            (
                f"{issuer.origin}/.well-known/openid-configuration",
                "openid-connect",
            ),
        ]
    return [
        (
            f"{issuer.origin}/.well-known/oauth-authorization-server/{issuer_path}",
            "rfc8414-path-insertion",
        ),
        (
            f"{issuer.origin}/.well-known/openid-configuration/{issuer_path}",
            "openid-connect-path-insertion",
        ),
        (
            f"{issuer.origin}/{issuer_path}/.well-known/openid-configuration",
            "openid-connect-path-append",
        ),
    ]


def _content_type_is_json(value: str | None) -> bool:
    if value is None:
        return False
    media_type = value.split(";", 1)[0].strip().casefold()
    return media_type == "application/json" or (
        media_type.startswith("application/") and media_type.endswith("+json")
    )


def _cache_freshness_seconds(value: str | None) -> int:
    if value is None:
        return MAX_UNDIRECTED_CACHE_AGE_SECONDS
    max_ages: list[int] = []
    for raw_directive in value.split(","):
        name, separator, raw_parameter = raw_directive.strip().partition("=")
        if name.casefold() != "max-age":
            continue
        parameter = raw_parameter.strip()
        if parameter.startswith('"') or parameter.endswith('"'):
            if len(parameter) < 2 or not (parameter.startswith('"') and parameter.endswith('"')):
                raise MetadataDocumentError("cache_control_invalid")
            parameter = parameter[1:-1]
        if separator != "=" or not parameter.isascii() or not parameter.isdigit():
            raise MetadataDocumentError("cache_control_invalid")
        max_ages.append(int(parameter))
    if len(max_ages) > 1:
        raise MetadataDocumentError("cache_control_invalid")
    declared = max_ages[0] if max_ages else MAX_UNDIRECTED_CACHE_AGE_SECONDS
    return min(declared, MAX_ACCEPTED_CACHE_AGE_SECONDS)


def _response_freshness(
    response: FetchResponse,
    observed_at: datetime,
) -> dict[str, Any]:
    if response.http_date is None:
        raise MetadataDocumentError("http_date_missing")
    try:
        source_date = parsedate_to_datetime(response.http_date)
    except (TypeError, ValueError, IndexError, OverflowError) as exc:
        raise MetadataDocumentError("http_date_invalid") from exc
    if source_date.tzinfo is None:
        raise MetadataDocumentError("http_date_invalid")
    source_date = source_date.astimezone(UTC)
    future_seconds = (source_date - observed_at).total_seconds()
    if future_seconds > MAX_RESPONSE_CLOCK_SKEW_SECONDS:
        raise MetadataDocumentError("http_date_future")
    apparent_age = max(0.0, (observed_at - source_date).total_seconds())
    header_age = 0
    if response.age is not None:
        age_value = response.age.strip()
        if not age_value.isascii() or not age_value.isdigit():
            raise MetadataDocumentError("http_age_invalid")
        header_age = int(age_value)
    effective_age = max(apparent_age, float(header_age))
    freshness_seconds = _cache_freshness_seconds(response.cache_control)
    if effective_age > freshness_seconds + MAX_RESPONSE_CLOCK_SKEW_SECONDS:
        raise MetadataDocumentError("metadata_response_stale")
    return {
        "state": "current",
        "http_date": source_date.isoformat(timespec="seconds").replace("+00:00", "Z"),
        "last_modified": response.last_modified,
        "cache_control": response.cache_control,
        "age_header_seconds": header_age if response.age is not None else None,
        "effective_age_seconds": round(effective_age, 3),
        "policy_freshness_seconds": freshness_seconds,
    }


def _reject_duplicate_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise _DuplicateKeyError(key)
        result[key] = value
    return result


def _bounded_json(value: Any, *, depth: int = 0) -> int:
    if depth > MAX_JSON_DEPTH:
        raise MetadataDocumentError("json_too_complex")
    count = 1
    if isinstance(value, dict):
        for key, child in value.items():
            if not isinstance(key, str) or len(key) > 256:
                raise MetadataDocumentError("json_too_complex")
            count += _bounded_json(child, depth=depth + 1)
    elif isinstance(value, list):
        for child in value:
            count += _bounded_json(child, depth=depth + 1)
    if count > MAX_JSON_NODES:
        raise MetadataDocumentError("json_too_complex")
    return count


def _fetch_json(
    fetcher: MetadataFetcher,
    url: str,
    *,
    kind: str,
    timeout_seconds: float,
    observed_at: datetime,
) -> tuple[dict[str, Any] | None, dict[str, Any]]:
    response = fetcher.fetch(
        url,
        timeout_seconds=timeout_seconds,
        max_body_bytes=MAX_METADATA_BYTES,
    )
    attempt: dict[str, Any] = {
        "kind": kind,
        "url": response.url,
        "status": response.status,
        "content_type": response.content_type,
        "body_bytes": None,
        "body_sha256": None,
        "freshness": {"state": "unknown"},
        "state": "unknown",
        "reason_code": response.reason_code,
    }
    if response.reason_code is not None:
        return None, attempt
    if response.status != 200:
        attempt["reason_code"] = (
            "metadata_not_found" if response.status in {404, 410} else "http_status_unexpected"
        )
        return None, attempt
    if not _content_type_is_json(response.content_type):
        attempt["reason_code"] = "content_type_invalid"
        return None, attempt
    try:
        attempt["freshness"] = _response_freshness(response, observed_at)
    except MetadataDocumentError as exc:
        attempt["reason_code"] = exc.reason_code
        return None, attempt
    body = response.body or b""
    attempt["body_bytes"] = len(body)
    attempt["body_sha256"] = hashlib.sha256(body).hexdigest()
    try:
        document = json.loads(
            body.decode("utf-8"),
            object_pairs_hook=_reject_duplicate_keys,
        )
    except _DuplicateKeyError:
        attempt["reason_code"] = "json_duplicate_key"
        return None, attempt
    except (UnicodeDecodeError, json.JSONDecodeError):
        attempt["reason_code"] = "json_invalid"
        return None, attempt
    if not isinstance(document, dict):
        attempt["reason_code"] = "json_not_object"
        return None, attempt
    try:
        _bounded_json(document)
    except MetadataDocumentError as exc:
        attempt["reason_code"] = exc.reason_code
        return None, attempt
    attempt["state"] = "fetched"
    attempt["reason_code"] = "fetched"
    return document, attempt


def _string_list(
    value: object,
    *,
    label: str,
    maximum: int,
    required: bool,
) -> list[str]:
    if value is None and not required:
        return []
    if not isinstance(value, list) or (required and not value) or len(value) > maximum:
        raise MetadataDocumentError(f"{label}_invalid")
    if any(not isinstance(item, str) or not item or len(item) > 512 for item in value):
        raise MetadataDocumentError(f"{label}_invalid")
    if len(set(value)) != len(value):
        raise MetadataDocumentError(f"{label}_invalid")
    return list(value)


def _validate_resource_metadata(
    document: Mapping[str, Any],
    resource: BoundURL,
) -> dict[str, Any]:
    declared_resource = _metadata_url(document.get("resource"), label="resource")
    if declared_resource.url != resource.url:
        raise MetadataDocumentError("resource_mismatch")
    raw_servers = _string_list(
        document.get("authorization_servers"),
        label="authorization_servers",
        maximum=MAX_AUTHORIZATION_SERVERS,
        required=True,
    )
    for value in raw_servers:
        _metadata_url(value, label="authorization_server")
    scopes = _string_list(
        document.get("scopes_supported"),
        label="scopes_supported",
        maximum=MAX_SCOPES,
        required=False,
    )
    return {
        "resource": declared_resource.url,
        # Preserve the exact issuer identifiers for RFC 8414 string comparison.
        "authorization_servers": raw_servers,
        "scopes_supported": scopes,
    }


def _required_endpoint(document: Mapping[str, Any], key: str) -> str:
    return _https_endpoint(document.get(key), label=key)


def _validate_authorization_metadata(
    document: Mapping[str, Any],
    issuer: BoundURL,
    expected_issuer: str,
) -> dict[str, Any]:
    raw_issuer = document.get("issuer")
    if raw_issuer != expected_issuer:
        raise MetadataDocumentError("issuer_mismatch")
    declared_issuer = _metadata_url(raw_issuer, label="issuer")
    if declared_issuer.url != issuer.url:
        raise MetadataDocumentError("issuer_mismatch")
    methods = _string_list(
        document.get("code_challenge_methods_supported"),
        label="code_challenge_methods_supported",
        maximum=16,
        required=True,
    )
    if "S256" not in methods:
        raise MetadataDocumentError("pkce_s256_missing")
    scopes = _string_list(
        document.get("scopes_supported"),
        label="scopes_supported",
        maximum=MAX_SCOPES,
        required=False,
    )
    client_metadata = document.get("client_id_metadata_document_supported")
    if client_metadata is not None and not isinstance(client_metadata, bool):
        raise MetadataDocumentError("client_id_metadata_document_supported_invalid")
    registration_endpoint = document.get("registration_endpoint")
    if registration_endpoint is not None:
        registration_endpoint = _required_endpoint(document, "registration_endpoint")
    return {
        "issuer": expected_issuer,
        "authorization_endpoint": _required_endpoint(document, "authorization_endpoint"),
        "token_endpoint": _required_endpoint(document, "token_endpoint"),
        "code_challenge_methods_supported": methods,
        "scopes_supported": scopes,
        "client_id_metadata_document_supported": client_metadata,
        "registration_endpoint": registration_endpoint,
    }


def _observation_time(value: datetime | None) -> datetime:
    observed = value or datetime.now(UTC)
    if observed.tzinfo is None:
        raise AuthPostureInputError("observed_at must include a timezone")
    return observed.astimezone(UTC)


def _timestamp(value: datetime) -> str:
    return value.isoformat(timespec="seconds").replace("+00:00", "Z")


def _base_result(binding: RegistryBinding, observed_at: datetime) -> dict[str, Any]:
    return {
        "schema_version": SCHEMA_VERSION,
        "contract_version": CONTRACT_VERSION,
        "observed_at": _timestamp(observed_at),
        "specification": {
            "profile": SPECIFICATION_PROFILE,
            "references": [
                MCP_AUTHORIZATION_URL,
                RFC_9728_URL,
                RFC_8414_URL,
                OIDC_DISCOVERY_URL,
            ],
        },
        "binding": binding.as_dict(),
        "state": "unknown",
        "scan_eligibility": "blocked",
        "authorization_required": None,
        "challenge_scopes": [],
        "resource_metadata": None,
        "authorization_servers": [],
        "fetches": [],
        "reason_codes": [],
        "capability_boundary": {
            "network_methods": ["GET"],
            "credentials_supported": False,
            "proxy_environment_used": False,
            "redirects_followed": False,
            "dns_addresses_pinned": True,
            "non_public_addresses_allowed": False,
            "mutation_capabilities": [],
        },
        "claim_ceiling": {
            "authorization_proven": False,
            "credentials_available": False,
            "trust_grade_authority": False,
            "runtime_security_proven": False,
        },
    }


def probe_authorization_posture(
    binding: RegistryBinding,
    *,
    www_authenticate: str | None = None,
    timeout_seconds: float = 5.0,
    fetcher: MetadataFetcher | None = None,
    observed_at: datetime | None = None,
) -> dict[str, Any]:
    """Probe public OAuth discovery metadata for one registry-bound endpoint."""

    if not 0 < timeout_seconds <= MAX_TIMEOUT_SECONDS:
        raise AuthPostureInputError(
            f"timeout_seconds must be greater than 0 and at most {MAX_TIMEOUT_SECONDS:g}"
        )
    resource = _bound_https_url(binding.resource_url, label="candidate resource URL")
    observation_time = _observation_time(observed_at)
    result = _base_result(binding, observation_time)
    transport = fetcher or PinnedHTTPSFetcher()
    try:
        challenge_url, challenge_scopes = _challenge(www_authenticate)
        candidates = _resource_metadata_candidates(resource, challenge_url)
    except MetadataDocumentError as exc:
        result["reason_codes"] = [exc.reason_code]
        return result
    result["authorization_required"] = True if www_authenticate is not None else None
    result["challenge_scopes"] = challenge_scopes

    resource_metadata: dict[str, Any] | None = None
    resource_metadata_url: str | None = None
    resource_discovery: str | None = None
    resource_errors: list[str] = []
    for candidate_url, discovery_kind in candidates:
        document, attempt = _fetch_json(
            transport,
            candidate_url,
            kind=f"resource-metadata:{discovery_kind}",
            timeout_seconds=timeout_seconds,
            observed_at=observation_time,
        )
        result["fetches"].append(attempt)
        if document is None:
            resource_errors.append(str(attempt["reason_code"]))
            continue
        try:
            resource_metadata = _validate_resource_metadata(document, resource)
        except MetadataDocumentError as exc:
            attempt["state"] = "invalid"
            attempt["reason_code"] = exc.reason_code
            resource_errors.append(exc.reason_code)
            continue
        attempt["state"] = "validated"
        attempt["reason_code"] = "resource_metadata_valid"
        resource_metadata_url = candidate_url
        resource_discovery = discovery_kind
        break

    if resource_metadata is None:
        result["reason_codes"] = _unique(resource_errors or ["resource_metadata_unavailable"])
        return result

    result["resource_metadata"] = {
        **resource_metadata,
        "metadata_url": resource_metadata_url,
        "discovery": resource_discovery,
    }
    ready_servers = 0
    server_results: list[dict[str, Any]] = []
    for issuer_value in resource_metadata["authorization_servers"]:
        issuer = _metadata_url(issuer_value, label="authorization_server")
        server_result: dict[str, Any] = {
            "issuer": issuer_value,
            "state": "unknown",
            "metadata_url": None,
            "discovery": None,
            "metadata": None,
            "reason_codes": [],
        }
        errors: list[str] = []
        for candidate_url, discovery_kind in _authorization_metadata_candidates(issuer):
            document, attempt = _fetch_json(
                transport,
                candidate_url,
                kind=f"authorization-server:{discovery_kind}",
                timeout_seconds=timeout_seconds,
                observed_at=observation_time,
            )
            result["fetches"].append(attempt)
            if document is None:
                errors.append(str(attempt["reason_code"]))
                continue
            try:
                metadata = _validate_authorization_metadata(
                    document,
                    issuer,
                    issuer_value,
                )
            except MetadataDocumentError as exc:
                attempt["state"] = "invalid"
                attempt["reason_code"] = exc.reason_code
                errors.append(exc.reason_code)
                continue
            attempt["state"] = "validated"
            attempt["reason_code"] = "authorization_server_metadata_valid"
            server_result.update(
                {
                    "state": "metadata-ready",
                    "metadata_url": candidate_url,
                    "discovery": discovery_kind,
                    "metadata": metadata,
                    "reason_codes": ["metadata_ready"],
                }
            )
            ready_servers += 1
            break
        if server_result["state"] != "metadata-ready":
            server_result["reason_codes"] = _unique(
                errors or ["authorization_server_metadata_unavailable"]
            )
        server_results.append(server_result)

    result["authorization_servers"] = server_results
    if ready_servers:
        result["state"] = "metadata-ready"
        result["scan_eligibility"] = "policy-review-only"
        result["reason_codes"] = ["metadata_ready"]
        if ready_servers != len(server_results):
            result["reason_codes"].append("authorization_server_partial")
    else:
        result["reason_codes"] = ["authorization_server_metadata_unavailable"]
    return result
