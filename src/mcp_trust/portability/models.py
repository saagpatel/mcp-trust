# ruff: noqa: E501
"""Versioned neutral MCP connection intent and portability report models."""

from __future__ import annotations

import re
from enum import StrEnum
from typing import Annotated, Literal
from urllib.parse import parse_qsl, urlsplit

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

NEUTRAL_SCHEMA_VERSION = "mcp-config-intent.v1"
REPORT_SCHEMA_VERSION = "mcp-config-portability-report.v1"
RESEARCH_AS_OF = "2026-08-11"
MCP_PROTOCOL_VERSION = "2026-07-28"
MCP_REGISTRY_SCHEMA_VERSION = "2025-12-11"
MIN_TIMEOUT_SECONDS = 0.001
MAX_TIMEOUT_MILLISECONDS = (1 << 53) - 1
MAX_TIMEOUT_SECONDS = MAX_TIMEOUT_MILLISECONDS / 1000

_NAME_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$")
_ENV_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*$")
_PLACEHOLDER_RE = re.compile(r"^\$\{env:([A-Za-z_][A-Za-z0-9_]*)\}$")
_SENSITIVE_ASSIGNMENT_RE = re.compile(
    r"(?i)(?:token|secret|password|passwd|api[-_]?key|authorization)\s*[=:]\s*(?!\$\{env:)[^\s]+"
)
_SENSITIVE_FLAG_RE = re.compile(
    r"(?i)^--?(?:api[-_]?key|token|access[-_]?token|secret|password|passwd|authorization)$"
)
_OBVIOUS_SECRET_RE = re.compile(
    r"(?i)(?:\bBearer\s+\S+|\bsk-[A-Za-z0-9_-]{8,}|\bgh[pousr]_[A-Za-z0-9]{8,})"
)
_SENSITIVE_QUERY_NAMES = {
    "token",
    "access_token",
    "api_key",
    "apikey",
    "secret",
    "client_secret",
    "password",
    "passwd",
    "auth",
    "authorization",
    "code",
    "credential",
    "key",
    "session",
    "sig",
    "signature",
}


def _is_sensitive_query_name(name: str) -> bool:
    normalized = name.lower().replace("-", "_").replace(".", "_")
    return normalized in _SENSITIVE_QUERY_NAMES or normalized.endswith(
        ("_credential", "_key", "_password", "_secret", "_signature", "_token")
    )


class StrictModel(BaseModel):
    model_config = ConfigDict(extra="forbid")


class ValueSource(StrictModel):
    """A value reference. Literal secret values are intentionally unrepresentable."""

    kind: Literal["environment", "prompt", "unknown"]
    key: str = Field(min_length=1, max_length=128)
    secret: bool = True
    required: bool = True

    @field_validator("key")
    @classmethod
    def validate_key(cls, value: str) -> str:
        if not _ENV_RE.fullmatch(value):
            raise ValueError("placeholder keys must be portable environment-style names")
        return value


class EnvironmentBinding(StrictModel):
    name: str
    value_from: ValueSource

    @field_validator("name")
    @classmethod
    def validate_name(cls, value: str) -> str:
        if not _ENV_RE.fullmatch(value):
            raise ValueError("environment names must be portable identifiers")
        return value


class HeaderBinding(StrictModel):
    name: str = Field(min_length=1, max_length=256)
    value_from: ValueSource

    @field_validator("name")
    @classmethod
    def validate_name(cls, value: str) -> str:
        if any(char in value for char in "\r\n:"):
            raise ValueError("header names cannot contain separators or newlines")
        return value


class StdioTransport(StrictModel):
    kind: Literal["stdio"] = "stdio"
    command: str = Field(min_length=1, max_length=4096)
    args: list[str] = Field(default_factory=list)
    cwd: str | None = None

    @model_validator(mode="after")
    def reject_secret_arguments(self) -> StdioTransport:
        values = [self.command, *self.args]
        for index, value in enumerate(values):
            if "\x00" in value or "\r" in value or "\n" in value:
                raise ValueError("command and arguments must be single-line strings")
            if _OBVIOUS_SECRET_RE.search(value) or _SENSITIVE_ASSIGNMENT_RE.search(value):
                raise ValueError("command arguments cannot contain probable secret values")
            if index and _SENSITIVE_FLAG_RE.fullmatch(values[index - 1]):
                if not _PLACEHOLDER_RE.fullmatch(value):
                    raise ValueError("values after secret-bearing flags must use ${env:NAME}")
        return self


class HttpTransport(StrictModel):
    kind: Literal["streamable-http"] = "streamable-http"
    url: str = Field(min_length=1, max_length=8192)
    headers: list[HeaderBinding] = Field(default_factory=list)

    @field_validator("url")
    @classmethod
    def validate_url(cls, value: str) -> str:
        parsed = urlsplit(value)
        if parsed.scheme not in {"http", "https"} or not parsed.hostname:
            raise ValueError("remote MCP URLs must use http or https and include a host")
        if parsed.username or parsed.password:
            raise ValueError("remote MCP URLs cannot embed credentials")
        if any(_is_sensitive_query_name(name) for name, _ in parse_qsl(parsed.query)):
            raise ValueError("remote MCP URLs cannot carry secret-like query parameters")
        return value


Transport = Annotated[StdioTransport | HttpTransport, Field(discriminator="kind")]


class AuthRequirement(StrictModel):
    kind: Literal["none", "bearer", "oauth", "headers", "unknown"] = "none"
    required: bool = False
    token: ValueSource | None = None
    scopes: list[str] = Field(default_factory=list)

    @model_validator(mode="after")
    def validate_auth(self) -> AuthRequirement:
        self.scopes = sorted(set(self.scopes))
        if self.kind == "bearer" and self.token is None:
            raise ValueError("bearer auth requires a placeholder token source")
        if self.kind != "bearer" and self.token is not None:
            raise ValueError("token is only valid for bearer auth")
        return self


class ScopePolicy(StrictModel):
    allow: list[str] = Field(default_factory=list)
    deny: list[str] = Field(default_factory=list)

    @model_validator(mode="after")
    def stable_set(self) -> ScopePolicy:
        self.allow = sorted(set(self.allow))
        self.deny = sorted(set(self.deny))
        return self


class StartupPolicy(StrictModel):
    startup_timeout_seconds: float | None = Field(
        default=None,
        ge=MIN_TIMEOUT_SECONDS,
        le=MAX_TIMEOUT_SECONDS,
        allow_inf_nan=False,
    )
    tool_timeout_seconds: float | None = Field(
        default=None,
        ge=MIN_TIMEOUT_SECONDS,
        le=MAX_TIMEOUT_SECONDS,
        allow_inf_nan=False,
    )
    required: bool | None = None


class Provenance(StrictModel):
    source_host: Literal["neutral", "codex", "claude-code", "claude-desktop", "vscode", "unknown"]
    source_format: str = Field(min_length=1, max_length=128)
    source_as_of: str
    documentation_url: str | None = None


class ServerIntent(StrictModel):
    transport: Transport
    environment: list[EnvironmentBinding] = Field(default_factory=list)
    auth: AuthRequirement = Field(default_factory=AuthRequirement)
    enabled: bool = True
    tools: ScopePolicy = Field(default_factory=ScopePolicy)
    resources: ScopePolicy = Field(default_factory=ScopePolicy)
    startup: StartupPolicy = Field(default_factory=StartupPolicy)
    provenance: Provenance
    unknown_semantics: list[str] = Field(default_factory=list)

    @model_validator(mode="after")
    def unique_bindings(self) -> ServerIntent:
        env_names = [item.name for item in self.environment]
        if len(set(env_names)) != len(env_names):
            raise ValueError("environment names must be unique")
        if isinstance(self.transport, HttpTransport):
            header_names = [item.name.lower() for item in self.transport.headers]
            if len(set(header_names)) != len(header_names):
                raise ValueError("header names must be unique ignoring case")
        return self


class NeutralConfig(StrictModel):
    schema_version: Literal["mcp-config-intent.v1"] = NEUTRAL_SCHEMA_VERSION
    mcp_protocol_version: str = MCP_PROTOCOL_VERSION
    registry_metadata_schema_version: str = MCP_REGISTRY_SCHEMA_VERSION
    servers: dict[str, ServerIntent]

    @field_validator("servers")
    @classmethod
    def validate_server_names(cls, value: dict[str, ServerIntent]) -> dict[str, ServerIntent]:
        for name in value:
            if not _NAME_RE.fullmatch(name):
                raise ValueError(
                    "server names must use the portable intersection: letters, numbers, dot, underscore, hyphen"
                )
        return value


class ChangeState(StrEnum):
    PRESERVED = "preserved"
    TRANSFORMED = "transformed"
    DROPPED = "dropped"
    UNSUPPORTED = "unsupported"
    DEFAULTED = "defaulted"
    WIDENED = "widened"
    UNKNOWN = "UNKNOWN"


class SemanticChange(StrictModel):
    server: str
    path: str
    state: ChangeState
    explanation: str


class ReportSummary(StrictModel):
    preserved: int = 0
    transformed: int = 0
    dropped: int = 0
    unsupported: int = 0
    defaulted: int = 0
    widened: int = 0
    UNKNOWN: int = 0


class PortabilityReport(StrictModel):
    schema_version: Literal["mcp-config-portability-report.v1"] = REPORT_SCHEMA_VERSION
    operation: Literal["render", "inspect", "round-trip"]
    host: Literal["codex", "claude-code", "claude-desktop", "vscode"]
    adapter_as_of: str = RESEARCH_AS_OF
    adapter_format_version: str
    changes: list[SemanticChange]
    summary: ReportSummary
    claim_ceiling: Literal["HOST_FORMAT_COMPATIBILITY_EVIDENCE_ONLY"] = (
        "HOST_FORMAT_COMPATIBILITY_EVIDENCE_ONLY"
    )


class RenderResult(StrictModel):
    document: str
    report: PortabilityReport


class InspectResult(StrictModel):
    intent: NeutralConfig
    report: PortabilityReport


def placeholder_text(source: ValueSource) -> str:
    """Return the neutral placeholder spelling used in command arguments."""
    return f"${{env:{source.key}}}"


def redact_host_args(
    values: list[object], *, server: str
) -> tuple[list[str], list[SemanticChange]]:
    """Convert host arguments to strings while removing probable secret values."""
    result: list[str] = []
    changes: list[SemanticChange] = []
    previous_secret_flag = False
    redaction_index = 1
    for raw in values:
        value = str(raw)
        redact = previous_secret_flag or bool(
            _OBVIOUS_SECRET_RE.search(value) or _SENSITIVE_ASSIGNMENT_RE.search(value)
        )
        if redact:
            value = f"${{env:REDACTED_SECRET_{redaction_index}}}"
            redaction_index += 1
            changes.append(
                SemanticChange(
                    server=server,
                    path="transport.args",
                    state=ChangeState.TRANSFORMED,
                    explanation="A probable secret argument value was replaced by an environment placeholder; the original value was not retained.",
                )
            )
        result.append(value)
        previous_secret_flag = bool(_SENSITIVE_FLAG_RE.fullmatch(value))
    return result, changes
