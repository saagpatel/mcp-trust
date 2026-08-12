# ruff: noqa: E501
"""Pure adapters for Claude Code, Claude Desktop, and VS Code JSON formats."""

from __future__ import annotations

import json
import re
from dataclasses import dataclass

from mcp_trust.portability.errors import PortabilityInputError
from mcp_trust.portability.models import (
    AuthRequirement,
    ChangeState,
    EnvironmentBinding,
    HeaderBinding,
    HttpTransport,
    InspectResult,
    NeutralConfig,
    Provenance,
    RenderResult,
    ScopePolicy,
    ServerIntent,
    StartupPolicy,
    StdioTransport,
    ValueSource,
    redact_host_args,
)
from mcp_trust.portability.report import build_report, change

from .base import note_unknown_fields, source_from_host_value

_CLAUDE_DOC = "https://code.claude.com/docs/en/mcp"
_CLAUDE_DESKTOP_DOC = (
    "https://modelcontextprotocol.io/docs/2026-07-28/develop/connect-local-servers"
)
_VSCODE_DOC = "https://code.visualstudio.com/docs/agents/reference/mcp-configuration"
_BEARER_ENV = re.compile(r"^Bearer\s+\$\{(?:env:)?([A-Za-z_][A-Za-z0-9_]*)\}$", re.I)


def _reject_duplicate_pairs(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise PortabilityInputError(f"duplicate JSON key: {key}")
        result[key] = value
    return result


def _load_json(document: str) -> dict[str, object]:
    try:
        parsed = json.loads(document, object_pairs_hook=_reject_duplicate_pairs)
    except (json.JSONDecodeError, UnicodeError) as exc:
        raise PortabilityInputError(f"invalid JSON: {exc}") from exc
    if not isinstance(parsed, dict):
        raise PortabilityInputError("host configuration must be a JSON object")
    return parsed


@dataclass(frozen=True)
class JsonHostProfile:
    host: str
    format_version: str
    docs_url: str
    server_key: str
    supports_remote: bool
    supports_cwd: bool
    supports_tool_timeout: bool
    placeholder_style: str


class _JsonHostAdapter:
    profile: JsonHostProfile

    @property
    def host(self) -> str:
        return self.profile.host

    @property
    def format_version(self) -> str:
        return self.profile.format_version

    def render(self, intent: NeutralConfig) -> RenderResult:
        changes = []
        rendered_servers: dict[str, object] = {}
        vscode_inputs: dict[str, dict[str, object]] = {}
        for name, server in sorted(intent.servers.items()):
            if not server.enabled:
                changes.append(
                    change(
                        name,
                        "enabled",
                        ChangeState.DROPPED,
                        "This host stores enablement outside the rendered server document; the disabled server was omitted to avoid accidental activation.",
                    )
                )
                continue
            raw: dict[str, object] = {}
            if isinstance(server.transport, StdioTransport):
                raw["type"] = "stdio"
                raw["command"] = server.transport.command
                raw["args"] = list(server.transport.args)
                changes.append(
                    change(name, "transport", ChangeState.PRESERVED, "stdio transport preserved.")
                )
                if server.transport.cwd is not None:
                    if self.profile.supports_cwd:
                        raw["cwd"] = server.transport.cwd
                        changes.append(
                            change(
                                name,
                                "transport.cwd",
                                ChangeState.PRESERVED,
                                "Working directory preserved.",
                            )
                        )
                    else:
                        changes.append(
                            change(
                                name,
                                "transport.cwd",
                                ChangeState.UNSUPPORTED,
                                "This host format has no documented per-server working-directory field.",
                            )
                        )
                if server.environment:
                    env: dict[str, str] = {}
                    for binding in sorted(server.environment, key=lambda item: item.name):
                        env[binding.name] = self._render_value_source(
                            binding.value_from,
                            server=name,
                            path=f"environment.{binding.name}",
                            inputs=vscode_inputs,
                            changes=changes,
                        )
                    raw["env"] = env
            else:
                if not self.profile.supports_remote:
                    changes.append(
                        change(
                            name,
                            "transport",
                            ChangeState.UNSUPPORTED,
                            "Claude Desktop developer JSON supports local stdio servers; remote servers must be added through Connectors, so this server was omitted.",
                        )
                    )
                    continue
                raw["type"] = "http"
                raw["url"] = server.transport.url
                changes.append(
                    change(
                        name,
                        "transport",
                        ChangeState.TRANSFORMED,
                        "Neutral streamable-http rendered with this host's documented type=http spelling.",
                    )
                )
                headers: dict[str, str] = {}
                for binding in sorted(server.transport.headers, key=lambda item: item.name.lower()):
                    headers[binding.name] = self._render_value_source(
                        binding.value_from,
                        server=name,
                        path=f"transport.headers.{binding.name}",
                        inputs=vscode_inputs,
                        changes=changes,
                    )
                if server.auth.kind == "bearer" and server.auth.token is not None:
                    token = self._render_value_source(
                        server.auth.token,
                        server=name,
                        path="auth.token",
                        inputs=vscode_inputs,
                        changes=changes,
                    )
                    headers["Authorization"] = f"Bearer {token}"
                    changes.append(
                        change(
                            name,
                            "auth",
                            ChangeState.PRESERVED,
                            "Bearer authentication rendered as a placeholder-backed Authorization header.",
                        )
                    )
                if headers:
                    raw["headers"] = headers

            if server.auth.kind == "oauth":
                if self.host == "claude-code" and isinstance(server.transport, HttpTransport):
                    if server.auth.scopes:
                        raw["oauth"] = {"scopes": " ".join(sorted(server.auth.scopes))}
                    changes.append(
                        change(
                            name,
                            "auth",
                            ChangeState.PRESERVED,
                            "OAuth requirement and pinned scopes preserved.",
                        )
                    )
                elif self.host == "vscode" and isinstance(server.transport, HttpTransport):
                    changes.append(
                        change(
                            name,
                            "auth",
                            ChangeState.DEFAULTED,
                            "VS Code OAuth discovery is host-managed; no client ID was invented.",
                        )
                    )
                else:
                    changes.append(
                        change(
                            name,
                            "auth",
                            ChangeState.UNSUPPORTED,
                            "OAuth is not documented for this host/transport document.",
                        )
                    )
            elif server.auth.kind not in {"none", "bearer", "headers"}:
                changes.append(
                    change(
                        name,
                        "auth",
                        ChangeState.UNKNOWN,
                        "Authentication requirement has no proven host representation.",
                    )
                )

            if server.tools.allow or server.tools.deny:
                changes.append(
                    change(
                        name,
                        "tools",
                        ChangeState.WIDENED,
                        "This server document cannot encode the neutral tool allow/deny policy; exposed tool scope may be broader.",
                    )
                )
            if server.resources.allow or server.resources.deny:
                changes.append(
                    change(
                        name,
                        "resources",
                        ChangeState.WIDENED,
                        "This server document cannot encode the neutral resource allow/deny policy; exposed resource scope may be broader.",
                    )
                )
            if server.startup.tool_timeout_seconds is not None:
                if self.profile.supports_tool_timeout:
                    raw["timeout"] = int(round(server.startup.tool_timeout_seconds * 1000))
                    changes.append(
                        change(
                            name,
                            "startup.tool_timeout_seconds",
                            ChangeState.TRANSFORMED,
                            "Tool timeout converted from seconds to host milliseconds.",
                        )
                    )
                else:
                    changes.append(
                        change(
                            name,
                            "startup.tool_timeout_seconds",
                            ChangeState.UNSUPPORTED,
                            "This host format has no documented per-server tool timeout.",
                        )
                    )
            if server.startup.startup_timeout_seconds is not None:
                changes.append(
                    change(
                        name,
                        "startup.startup_timeout_seconds",
                        ChangeState.UNSUPPORTED,
                        "This host format has no documented per-server startup timeout.",
                    )
                )
            if server.startup.required is not None:
                changes.append(
                    change(
                        name,
                        "startup.required",
                        ChangeState.UNSUPPORTED,
                        "This host format has no documented required-startup flag.",
                    )
                )
            for field in server.unknown_semantics:
                changes.append(
                    change(
                        name,
                        f"unknown_semantics.{field}",
                        ChangeState.DROPPED,
                        "Named unknown host semantic cannot be emitted because its source value was intentionally discarded.",
                    )
                )
            rendered_servers[name] = raw

        root: dict[str, object] = {self.profile.server_key: rendered_servers}
        if self.host == "vscode" and vscode_inputs:
            root["inputs"] = [vscode_inputs[key] for key in sorted(vscode_inputs)]
        document = json.dumps(root, indent=2, sort_keys=True, ensure_ascii=False) + "\n"
        return RenderResult(
            document=document,
            report=build_report(
                operation="render",
                host=self.host,
                format_version=self.format_version,
                changes=changes,
            ),
        )

    def _render_value_source(
        self,
        source: ValueSource,
        *,
        server: str,
        path: str,
        inputs: dict[str, dict[str, object]],
        changes: list,
    ) -> str:
        if self.profile.placeholder_style == "vscode":
            if source.kind == "environment":
                changes.append(
                    change(server, path, ChangeState.PRESERVED, "Environment reference preserved.")
                )
                return f"${{env:{source.key}}}"
            input_id = source.key.lower().replace("_", "-")
            inputs[input_id] = {
                "type": "promptString",
                "id": input_id,
                "description": f"Value for {source.key}",
                "password": bool(source.secret),
            }
            changes.append(
                change(
                    server,
                    path,
                    ChangeState.PRESERVED,
                    "Prompt placeholder rendered as a VS Code input variable.",
                )
            )
            return f"${{input:{input_id}}}"
        if source.kind == "environment":
            changes.append(
                change(server, path, ChangeState.PRESERVED, "Environment reference preserved.")
            )
            return f"${{{source.key}}}"
        if self.host == "claude-code":
            changes.append(
                change(
                    server,
                    path,
                    ChangeState.TRANSFORMED,
                    "Claude Code has no per-field prompt declaration; prompt source transformed to an environment reference.",
                )
            )
            return f"${{{source.key}}}"
        changes.append(
            change(
                server,
                path,
                ChangeState.UNKNOWN,
                "Claude Desktop variable expansion is not established by current official developer-config documentation; a non-secret placeholder spelling was emitted.",
            )
        )
        return f"${{{source.key}}}"

    def inspect(self, document: str) -> InspectResult:
        root = _load_json(document)
        raw_servers = root.get(self.profile.server_key)
        if not isinstance(raw_servers, dict):
            raise PortabilityInputError(
                f"{self.host} input must contain a {self.profile.server_key!r} object"
            )
        changes = []
        top_known = {self.profile.server_key}
        if self.host == "vscode":
            top_known |= {"inputs", "sandbox"}
            if "sandbox" in root:
                changes.append(
                    change(
                        "*",
                        "sandbox",
                        ChangeState.UNKNOWN,
                        "VS Code sandbox policy is outside the neutral connection-intent schema; its value was not retained.",
                    )
                )
        for key in sorted(set(root) - top_known):
            changes.append(
                change(
                    "*",
                    f"host.{key}",
                    ChangeState.UNKNOWN,
                    "Unknown top-level host field was not retained.",
                )
            )

        servers: dict[str, ServerIntent] = {}
        for name, raw_value in sorted(raw_servers.items()):
            if not isinstance(raw_value, dict):
                raise PortabilityInputError(f"{self.host} server {name!r} must be an object")
            raw = dict(raw_value)
            server_type = raw.get("type")
            if server_type is None:
                if "url" in raw:
                    raise PortabilityInputError(
                        f"{self.host} server {name!r} has a url but no type"
                    )
                server_type = "stdio"
                changes.append(
                    change(
                        name,
                        "transport.kind",
                        ChangeState.DEFAULTED,
                        "Missing type defaulted to stdio.",
                    )
                )
            if server_type == "stdio":
                if not isinstance(raw.get("command"), str):
                    raise PortabilityInputError(
                        f"{self.host} stdio server {name!r} requires command"
                    )
                args, redactions = redact_host_args(list(raw.get("args") or []), server=name)
                changes.extend(redactions)
                transport = StdioTransport(
                    command=raw["command"],
                    args=args,
                    cwd=raw.get("cwd") if self.profile.supports_cwd else None,
                )
                changes.append(
                    change(name, "transport", ChangeState.PRESERVED, "stdio transport inspected.")
                )
            elif server_type in {"http", "streamable-http", "sse"}:
                if not isinstance(raw.get("url"), str):
                    raise PortabilityInputError(f"{self.host} remote server {name!r} requires url")
                headers: list[HeaderBinding] = []
                auth = AuthRequirement()
                raw_headers = raw.get("headers") or {}
                if not isinstance(raw_headers, dict):
                    raise PortabilityInputError(
                        f"{self.host} server {name!r} headers must be an object"
                    )
                for header_name, host_value in sorted(raw_headers.items()):
                    bearer = (
                        _BEARER_ENV.fullmatch(host_value) if isinstance(host_value, str) else None
                    )
                    if str(header_name).lower() == "authorization" and bearer:
                        auth = AuthRequirement(
                            kind="bearer",
                            required=True,
                            token=ValueSource(kind="environment", key=bearer.group(1)),
                        )
                        changes.append(
                            change(
                                name,
                                "auth",
                                ChangeState.PRESERVED,
                                "Bearer environment reference inspected without reading a token.",
                            )
                        )
                        continue
                    headers.append(
                        HeaderBinding(
                            name=str(header_name),
                            value_from=source_from_host_value(
                                host_value,
                                fallback_key=f"HEADER_{header_name}",
                                server=name,
                                path=f"transport.headers.{header_name}",
                                changes=changes,
                            ),
                        )
                    )
                if server_type == "sse":
                    changes.append(
                        change(
                            name,
                            "transport.kind",
                            ChangeState.TRANSFORMED,
                            "Deprecated SSE normalized to neutral remote URL semantics; transport behavior will not round-trip exactly.",
                        )
                    )
                else:
                    changes.append(
                        change(
                            name,
                            "transport",
                            ChangeState.TRANSFORMED,
                            "Host HTTP spelling normalized to streamable-http.",
                        )
                    )
                if not self.profile.supports_remote:
                    changes.append(
                        change(
                            name,
                            "transport",
                            ChangeState.UNSUPPORTED,
                            "Remote entries are not supported by Claude Desktop developer JSON.",
                        )
                    )
                transport = HttpTransport(url=raw["url"], headers=headers)
            else:
                raise PortabilityInputError(
                    f"unsupported {self.host} transport type for {name!r}: {server_type!r}"
                )

            environment = []
            raw_env = raw.get("env") or {}
            if not isinstance(raw_env, dict):
                raise PortabilityInputError(f"{self.host} server {name!r} env must be an object")
            for env_name, host_value in sorted(raw_env.items()):
                environment.append(
                    EnvironmentBinding(
                        name=str(env_name),
                        value_from=source_from_host_value(
                            host_value,
                            fallback_key=str(env_name),
                            server=name,
                            path=f"environment.{env_name}",
                            changes=changes,
                        ),
                    )
                )

            if not isinstance(transport, HttpTransport):
                auth = AuthRequirement()
            oauth = raw.get("oauth")
            if isinstance(oauth, dict):
                scopes_value = oauth.get("scopes") or []
                scopes = (
                    scopes_value.split()
                    if isinstance(scopes_value, str)
                    else [str(item) for item in scopes_value]
                    if isinstance(scopes_value, list)
                    else []
                )
                auth = AuthRequirement(kind="oauth", required=True, scopes=sorted(scopes))
                changes.append(
                    change(
                        name,
                        "auth",
                        ChangeState.PRESERVED,
                        "OAuth requirement inspected; credential values are outside this schema.",
                    )
                )

            timeout = raw.get("timeout") if self.profile.supports_tool_timeout else None
            startup = StartupPolicy(
                tool_timeout_seconds=float(timeout) / 1000
                if isinstance(timeout, (int, float))
                else None
            )
            if timeout is not None:
                changes.append(
                    change(
                        name,
                        "startup.tool_timeout_seconds",
                        ChangeState.TRANSFORMED,
                        "Host milliseconds normalized to seconds.",
                    )
                )
            changes.append(
                change(
                    name,
                    "enabled",
                    ChangeState.DEFAULTED,
                    "Enablement is stored outside this host document; enabled=true assumed for a present server.",
                )
            )

            known = {"type", "command", "args", "env", "url", "headers", "oauth"}
            if self.profile.supports_cwd:
                known.add("cwd")
            if self.profile.supports_tool_timeout:
                known.add("timeout")
            unknown = note_unknown_fields(server=name, raw=raw, known=known, changes=changes)
            servers[name] = ServerIntent(
                transport=transport,
                environment=environment,
                auth=auth,
                enabled=True,
                tools=ScopePolicy(),
                resources=ScopePolicy(),
                startup=startup,
                provenance=Provenance(
                    source_host=self.host,
                    source_format=self.format_version,
                    source_as_of="2026-08-11",
                    documentation_url=self.profile.docs_url,
                ),
                unknown_semantics=unknown,
            )
        intent = NeutralConfig(servers=servers)
        return InspectResult(
            intent=intent,
            report=build_report(
                operation="inspect",
                host=self.host,
                format_version=self.format_version,
                changes=changes,
            ),
        )


class ClaudeCodeAdapter(_JsonHostAdapter):
    profile = JsonHostProfile(
        host="claude-code",
        format_version=".mcp.json current format (Claude Code docs through v2.1.221; as of 2026-08-11)",
        docs_url=_CLAUDE_DOC,
        server_key="mcpServers",
        supports_remote=True,
        supports_cwd=False,
        supports_tool_timeout=True,
        placeholder_style="claude",
    )


class ClaudeDesktopAdapter(_JsonHostAdapter):
    profile = JsonHostProfile(
        host="claude-desktop",
        format_version="claude_desktop_config.json local developer format (no published version; as of 2026-08-11)",
        docs_url=_CLAUDE_DESKTOP_DOC,
        server_key="mcpServers",
        supports_remote=False,
        supports_cwd=False,
        supports_tool_timeout=False,
        placeholder_style="claude",
    )


class VSCodeAdapter(_JsonHostAdapter):
    profile = JsonHostProfile(
        host="vscode",
        format_version="mcp.json current format (no published version; VS Code docs as of 2026-08-11)",
        docs_url=_VSCODE_DOC,
        server_key="servers",
        supports_remote=True,
        supports_cwd=True,
        supports_tool_timeout=False,
        placeholder_style="vscode",
    )
