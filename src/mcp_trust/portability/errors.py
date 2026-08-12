"""Portability-specific input and host errors with fail-closed diagnostics."""

from __future__ import annotations

import re
from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit

from pydantic import ValidationError

_SENSITIVE_QUERY_NAMES = {
    "access_token",
    "api_key",
    "apikey",
    "auth",
    "authorization",
    "client_secret",
    "code",
    "key",
    "password",
    "passwd",
    "secret",
    "session",
    "sig",
    "signature",
    "token",
}
_URL_RE = re.compile(r"https?://[^\s'\"<>]+", re.IGNORECASE)
_BEARER_RE = re.compile(r"(?i)\bBearer\s+[^\s,;]+")
_SENSITIVE_ASSIGNMENT_RE = re.compile(
    r"(?i)\b(access[-_]?token|api[-_]?key|auth(?:orization)?|client[-_]?secret|key|"
    r"password|passwd|secret|session|sig(?:nature)?|token)\s*([=:])\s*([^\s,&;]+)"
)
_TRAILING_URL_PUNCTUATION = ".,;)]}"
_SAFE_LOCATION_PARTS = {
    "__root__",
    "allow",
    "args",
    "auth",
    "command",
    "cwd",
    "deny",
    "documentation_url",
    "enabled",
    "environment",
    "headers",
    "key",
    "kind",
    "mcp_protocol_version",
    "name",
    "provenance",
    "registry_metadata_schema_version",
    "required",
    "resources",
    "schema_version",
    "scopes",
    "secret",
    "servers",
    "source_as_of",
    "source_format",
    "source_host",
    "startup",
    "startup_timeout_seconds",
    "stdio",
    "streamable-http",
    "token",
    "tool_timeout_seconds",
    "tools",
    "transport",
    "unknown_semantics",
    "url",
    "value_from",
}


def _is_sensitive_query_name(name: str) -> bool:
    normalized = name.lower().replace("-", "_").replace(".", "_")
    return normalized in _SENSITIVE_QUERY_NAMES or normalized.endswith(
        ("_credential", "_key", "_password", "_secret", "_signature", "_token")
    )


def _redact_url(match: re.Match[str]) -> str:
    candidate = match.group(0)
    trailing = ""
    while candidate and candidate[-1] in _TRAILING_URL_PUNCTUATION:
        trailing = candidate[-1] + trailing
        candidate = candidate[:-1]
    try:
        parsed = urlsplit(candidate)
        hostname = parsed.hostname
    except ValueError:
        return "[REDACTED_URL]" + trailing
    if not hostname:
        return "[REDACTED_URL]" + trailing

    rendered_host = f"[{hostname}]" if ":" in hostname else hostname
    try:
        port = parsed.port
    except ValueError:
        port = None
    if port is not None:
        rendered_host = f"{rendered_host}:{port}"
    if parsed.username is not None or parsed.password is not None:
        rendered_host = f"[REDACTED]@{rendered_host}"

    query = parsed.query
    if query:
        items = parse_qsl(query, keep_blank_values=True)
        if any(_is_sensitive_query_name(name) for name, _ in items):
            query = urlencode(
                [
                    (name, "[REDACTED]") if _is_sensitive_query_name(name) else (name, value)
                    for name, value in items
                ],
                doseq=True,
            )
        else:
            query = _SENSITIVE_ASSIGNMENT_RE.sub(r"\1\2[REDACTED]", query)
    return urlunsplit((parsed.scheme, rendered_host, parsed.path, query, "")) + trailing


def safe_error_text(value: object) -> str:
    """Remove credential-bearing URL and assignment values from public diagnostics."""
    text = _URL_RE.sub(_redact_url, str(value))
    text = _BEARER_RE.sub("Bearer [REDACTED]", text)
    return _SENSITIVE_ASSIGNMENT_RE.sub(r"\1\2[REDACTED]", text)


def _safe_location(location: tuple[object, ...]) -> str:
    parts: list[str] = []
    mask_next = False
    for item in location:
        masked_dynamic_part = mask_next
        if mask_next:
            parts.append("*")
            mask_next = False
        elif isinstance(item, int):
            parts.append(f"[{item}]")
        elif str(item) in _SAFE_LOCATION_PARTS:
            parts.append(str(item))
        else:
            parts.append("*")
        if not masked_dynamic_part and str(item) == "servers":
            mask_next = True
    return ".".join(parts) or "document"


class PortabilityError(ValueError):
    """Base error for deterministic, user-fixable portability failures."""

    def __init__(self, message: object) -> None:
        super().__init__(safe_error_text(message))


class PortabilityInputError(PortabilityError):
    """Raised when an explicit input document is malformed or unsafe."""


class UnsupportedHostError(PortabilityError):
    """Raised when a requested adapter is not supported."""


def validation_input_error(error: ValidationError, *, context: str) -> PortabilityInputError:
    """Convert Pydantic errors without retaining inputs, context objects, or unsafe keys."""
    diagnostics = []
    raw_errors = error.errors(
        include_url=False,
        include_context=False,
        include_input=False,
    )
    for item in raw_errors[:8]:
        location = _safe_location(tuple(item.get("loc") or ()))
        message = safe_error_text(item.get("msg") or "value failed validation")
        diagnostics.append(f"{location}: {message}")
    if len(raw_errors) > len(diagnostics):
        omitted = len(raw_errors) - len(diagnostics)
        diagnostics.append(f"{omitted} additional validation errors omitted")
    detail = "; ".join(sorted(diagnostics)) or "document failed validation"
    return PortabilityInputError(f"{context}: {detail}")
