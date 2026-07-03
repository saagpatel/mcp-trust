"""Discovery-only planning from official MCP Registry metadata.

The official Registry is useful as a discovery and staleness feed. It is not a
tool-surface source: real tools, schemas, prompts, resources, and annotations are
runtime-negotiated after connecting to a server. This module therefore produces
candidate manifests only. It never assigns danger grades and never launches or
contacts an MCP server.
"""

from __future__ import annotations

from collections import Counter
from datetime import UTC, datetime
from enum import StrEnum
from typing import Any
from urllib.parse import urlsplit, urlunsplit

FORMAT_VERSION = 1

REGISTRY_DOC_URL = "https://modelcontextprotocol.io/registry/about"
REGISTRY_API_DOC_URL = (
    "https://raw.githubusercontent.com/modelcontextprotocol/registry/main/docs/reference/api/openapi.yaml"
)
REGISTRY_SCHEMA_URL = (
    "https://raw.githubusercontent.com/modelcontextprotocol/registry/main/"
    "docs/reference/server-json/server.schema.json"
)

_ACTIVE_STATUSES = {"active", ""}
_NON_LIVE_STATUSES = {"deprecated", "deleted"}
_EXACT_VERSION_SEPARATORS = ("==", "@")


class CandidateMode(StrEnum):
    """Operator-facing scan lane recommendation for one registry candidate."""

    NO_AUTH_SANDBOXED = "no-auth-sandboxed"
    CREDENTIALED_SANDBOXED = "credentialed-sandboxed"
    NETWORKED_SANDBOXED = "networked-sandboxed"
    REMOTE_NETWORKED = "remote-networked"
    PACKAGE_ONLY = "package-only"


class Freshness(StrEnum):
    """Registry freshness state derived only from metadata timestamps/status."""

    FRESH = "fresh"
    AGING = "aging"
    STALE = "stale"
    UNKNOWN = "unknown"
    DEPRECATED = "deprecated"
    DELETED = "deleted"


def build_registry_candidate_manifest(
    registry_payload: dict[str, Any] | list[Any],
    *,
    generated_at: datetime | None = None,
    first_batch_limit: int = 25,
) -> dict[str, Any]:
    """Build a dry-run candidate manifest from an already-fetched Registry payload.

    ``registry_payload`` may be either the API list response (``{"servers": [...]}``)
    or a plain list of server objects. The function reads only the provided data.
    """
    generated_at = generated_at or datetime.now(tz=UTC)
    servers = _extract_servers(registry_payload)
    candidates = [_candidate_from_server(server, generated_at) for server in servers]
    candidates.sort(key=_candidate_sort_key)

    selected = [
        candidate
        for candidate in candidates
        if candidate["eligible_for_first_live_batch"]
    ][:first_batch_limit]
    selected_ids = {candidate["stable_id"] for candidate in selected}

    for candidate in candidates:
        candidate["selected_for_first_batch"] = candidate["stable_id"] in selected_ids

    return {
        "format_version": FORMAT_VERSION,
        "notice": (
            "Dry-run only. Registry metadata is discovery/staleness input, not a "
            "tool-surface scan. This manifest does not launch servers, contact MCP "
            "endpoints, install packages, authenticate, mutate catalog data, or "
            "assign danger grades."
        ),
        "generated_at": generated_at.isoformat(),
        "source": {
            "kind": "official-mcp-registry-export",
            "input_servers": len(servers),
            "docs": [REGISTRY_DOC_URL, REGISTRY_API_DOC_URL, REGISTRY_SCHEMA_URL],
        },
        "selection_policy": {
            "first_batch_limit": first_batch_limit,
            "first_batch_requires": [
                "registry status is active",
                "registry entry is latest when isLatest metadata is present",
                "no required secret environment variables",
                "a package reference with an exact version",
                "a public repository or source reference",
                "mode is no-auth-sandboxed",
            ],
            "never_infers": [
                "runtime tools",
                "tool input schemas",
                "tool annotations",
                "prompt/resource surfaces",
                "danger grades",
            ],
        },
        "counts": _counts(candidates),
        "candidates": candidates,
    }


def _extract_servers(payload: dict[str, Any] | list[Any]) -> list[dict[str, Any]]:
    if isinstance(payload, list):
        return [_unwrap_server(item) for item in payload if isinstance(item, dict)]
    if isinstance(payload, dict):
        servers = payload.get("servers")
        if isinstance(servers, list):
            return [_unwrap_server(item) for item in servers if isinstance(item, dict)]
        server = payload.get("server")
        if isinstance(server, dict):
            return [_unwrap_server(payload)]
    raise TypeError("registry payload must be a server list or object containing 'servers'")


def _unwrap_server(entry: dict[str, Any]) -> dict[str, Any]:
    """Return a server object with official list-response metadata attached.

    The official API list response wraps each item as ``{"server": {...},
    "_meta": {...}}``. The standalone server schema keeps metadata on the server
    object itself. Support both shapes so saved API responses can be passed
    directly to the dry-run planner.
    """
    server = entry.get("server")
    if not isinstance(server, dict):
        return entry
    merged = dict(server)
    if "_meta" in entry and "_meta" not in merged:
        merged["_meta"] = entry["_meta"]
    return merged


def _candidate_from_server(server: dict[str, Any], generated_at: datetime) -> dict[str, Any]:
    name = _string(server.get("name")) or "unnamed-server"
    version = _string(server.get("version"))
    meta = _official_meta(server)
    status = (_string(meta.get("status")) or _string(server.get("status")) or "unknown").lower()
    is_latest = _bool_or_none(meta.get("isLatest", server.get("isLatest")))
    published_at = _string(meta.get("publishedAt") or server.get("publishedAt"))
    updated_at = _string(meta.get("updatedAt") or server.get("updatedAt"))
    freshness = _freshness(status, updated_at or published_at, generated_at)

    packages = _packages(server)
    remotes = _remotes(server)
    env = _environment_summary(packages, remotes)
    repository = _repository(server.get("repository"))
    package_refs = [_package_ref(package) for package in packages]
    remote_refs = [_remote_ref(remote) for remote in remotes]
    dedupe_keys = _dedupe_keys(name, version, repository, package_refs, remote_refs)
    mode = _recommend_mode(
        status=status,
        is_latest=is_latest,
        packages=packages,
        remotes=remotes,
        secret_keys=env["secret_env_key_names"],
        package_refs=package_refs,
    )
    has_source = bool(repository.get("url"))
    eligible = (
        mode == CandidateMode.NO_AUTH_SANDBOXED
        and status in _ACTIVE_STATUSES
        and is_latest is not False
        and freshness in {Freshness.FRESH, Freshness.AGING, Freshness.UNKNOWN}
        and env["required_secret_keys"] == []
        and env["secret_env_key_names"] == []
        and _has_exact_package_ref(package_refs)
        and has_source
        and remote_refs == []
    )

    reasons = _reasons(
        mode=mode,
        status=status,
        is_latest=is_latest,
        freshness=freshness,
        required_secret_keys=env["required_secret_keys"],
        secret_env_key_names=env["secret_env_key_names"],
        package_refs=package_refs,
        repository=repository,
        remote_refs=remote_refs,
    )

    return {
        "stable_id": _stable_id(name, version),
        "registry_name": name,
        "title": _string(server.get("title")) or name,
        "description": _string(server.get("description")) or "",
        "version": version,
        "registry_status": status,
        "is_latest": is_latest,
        "published_at": published_at,
        "updated_at": updated_at,
        "freshness": str(freshness),
        "recommended_mode": str(mode),
        "eligible_for_first_live_batch": eligible,
        "selected_for_first_batch": False,
        "repository": repository,
        "package_refs": package_refs,
        "remote_refs": remote_refs,
        "env_key_names": env["env_key_names"],
        "secret_env_key_names": env["secret_env_key_names"],
        "required_secret_keys": env["required_secret_keys"],
        "dedupe_keys": dedupe_keys,
        "reasons": reasons,
        "caveats": [
            "Registry metadata does not declare actual runtime tool surfaces.",
            "A danger grade requires controlled MCPAudit tool enumeration.",
            "Environment variable names are metadata only; values must never enter the catalog.",
            "Tool annotations, if later observed, remain hints rather than enforcement.",
        ],
    }


def _official_meta(server: dict[str, Any]) -> dict[str, Any]:
    meta = server.get("_meta")
    if not isinstance(meta, dict):
        return {}
    for value in meta.values():
        if isinstance(value, dict) and (
            "status" in value or "updatedAt" in value or "publishedAt" in value
        ):
            return value
    return meta


def _packages(server: dict[str, Any]) -> list[dict[str, Any]]:
    packages = server.get("packages")
    if not isinstance(packages, list):
        return []
    return [package for package in packages if isinstance(package, dict)]


def _remotes(server: dict[str, Any]) -> list[dict[str, Any]]:
    remotes = server.get("remotes")
    if not isinstance(remotes, list):
        return []
    return [remote for remote in remotes if isinstance(remote, dict)]


def _repository(value: Any) -> dict[str, str | None]:
    if isinstance(value, str):
        return {"url": value, "source": None, "id": None}
    if isinstance(value, dict):
        return {
            "url": _string(value.get("url")),
            "source": _string(value.get("source")),
            "id": _string(value.get("id")),
        }
    return {"url": None, "source": None, "id": None}


def _package_ref(package: dict[str, Any]) -> dict[str, Any]:
    registry_type = _string(package.get("registryType") or package.get("registry")) or "unknown"
    identifier = _string(package.get("identifier") or package.get("name"))
    version = _string(package.get("version"))
    transport = _transport_type(package)
    runtime_hint = _string(package.get("runtimeHint"))
    file_sha256 = _string(package.get("fileSha256"))
    return {
        "registry_type": registry_type,
        "identifier": identifier,
        "version": version,
        "transport": transport,
        "runtime_hint": runtime_hint,
        "file_sha256": file_sha256,
        "exact_version": _is_exact_version(registry_type, identifier, version),
    }


def _remote_ref(remote: dict[str, Any]) -> dict[str, Any]:
    url = _string(remote.get("url") or remote.get("endpoint"))
    transport = _transport_type(remote)
    return {
        "url": url,
        "normalized_url": _normalize_url(url) if url else None,
        "transport": transport,
    }


def _environment_summary(
    packages: list[dict[str, Any]], remotes: list[dict[str, Any]]
) -> dict[str, list[str]]:
    keys: set[str] = set()
    secret_keys: set[str] = set()
    required_secret_keys: set[str] = set()
    for holder in [*packages, *remotes]:
        env_entries = [
            *_env_entries(holder.get("environmentVariables")),
            *_env_entries(holder.get("headers")),
        ]
        for env in env_entries:
            name = _string(env.get("name") or env.get("key"))
            if not name:
                continue
            keys.add(name)
            required = bool(env.get("isRequired") or env.get("required"))
            secret = bool(env.get("isSecret") or env.get("secret"))
            if secret:
                secret_keys.add(name)
            if required and secret:
                required_secret_keys.add(name)
    return {
        "env_key_names": sorted(keys),
        "secret_env_key_names": sorted(secret_keys),
        "required_secret_keys": sorted(required_secret_keys),
    }


def _env_entries(value: Any) -> list[dict[str, Any]]:
    if isinstance(value, list):
        return [item for item in value if isinstance(item, dict)]
    if isinstance(value, dict):
        entries: list[dict[str, Any]] = []
        for key, metadata in value.items():
            if isinstance(metadata, dict):
                entries.append({"name": key, **metadata})
            else:
                entries.append({"name": key})
        return entries
    return []


def _transport_type(value: dict[str, Any]) -> str | None:
    transport = value.get("transport")
    if isinstance(transport, str):
        return transport
    if isinstance(transport, dict):
        return _string(transport.get("type"))
    return _string(value.get("type"))


def _recommend_mode(
    *,
    status: str,
    is_latest: bool | None,
    packages: list[dict[str, Any]],
    remotes: list[dict[str, Any]],
    secret_keys: list[str],
    package_refs: list[dict[str, Any]],
) -> CandidateMode:
    if status in _NON_LIVE_STATUSES or is_latest is False:
        return CandidateMode.PACKAGE_ONLY
    if secret_keys:
        return CandidateMode.CREDENTIALED_SANDBOXED if packages else CandidateMode.REMOTE_NETWORKED
    if packages:
        if _has_exact_package_ref(package_refs):
            return CandidateMode.NO_AUTH_SANDBOXED
        return CandidateMode.NETWORKED_SANDBOXED
    if remotes:
        return CandidateMode.REMOTE_NETWORKED
    return CandidateMode.PACKAGE_ONLY


def _freshness(status: str, timestamp: str | None, generated_at: datetime) -> Freshness:
    if status == "deleted":
        return Freshness.DELETED
    if status == "deprecated":
        return Freshness.DEPRECATED
    if not timestamp:
        return Freshness.UNKNOWN
    parsed = _parse_datetime(timestamp)
    if parsed is None:
        return Freshness.UNKNOWN
    age_days = (generated_at - parsed).days
    if age_days <= 30:
        return Freshness.FRESH
    if age_days <= 180:
        return Freshness.AGING
    return Freshness.STALE


def _parse_datetime(value: str) -> datetime | None:
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None
    if parsed.tzinfo is None:
        return parsed.replace(tzinfo=UTC)
    return parsed.astimezone(UTC)


def _dedupe_keys(
    name: str,
    version: str | None,
    repository: dict[str, str | None],
    package_refs: list[dict[str, Any]],
    remote_refs: list[dict[str, Any]],
) -> list[str]:
    keys = [f"registry:{name}:{version or 'unversioned'}"]
    repo_url = repository.get("url")
    if repo_url:
        keys.append(f"repo:{_normalize_url(repo_url)}")
    for package in package_refs:
        identifier = package.get("identifier")
        if identifier:
            package_version = package.get("version") or "unversioned"
            keys.append(
                "package:"
                f"{package.get('registry_type')}:{identifier}:{package_version}"
            )
    for remote in remote_refs:
        if remote.get("normalized_url"):
            keys.append(f"remote:{remote['normalized_url']}")
    return sorted(dict.fromkeys(keys))


def _reasons(
    *,
    mode: CandidateMode,
    status: str,
    is_latest: bool | None,
    freshness: Freshness,
    required_secret_keys: list[str],
    secret_env_key_names: list[str],
    package_refs: list[dict[str, Any]],
    repository: dict[str, str | None],
    remote_refs: list[dict[str, Any]],
) -> list[str]:
    reasons = [f"mode={mode}"]
    if status not in _ACTIVE_STATUSES:
        reasons.append(f"registry status is {status}")
    if is_latest is False:
        reasons.append("registry metadata marks this as not latest")
    if freshness in {Freshness.STALE, Freshness.DEPRECATED, Freshness.DELETED}:
        reasons.append(f"freshness is {freshness}")
    if required_secret_keys:
        reasons.append("required secret env key names are present")
    elif secret_env_key_names:
        reasons.append("secret env key names are present")
    if remote_refs:
        reasons.append("remote endpoint metadata is present")
    if package_refs and not _has_exact_package_ref(package_refs):
        reasons.append("no exact package version was found")
    if not repository.get("url"):
        reasons.append("repository URL is missing")
    if mode == CandidateMode.NO_AUTH_SANDBOXED:
        reasons.append("candidate can be reviewed for a no-auth sandboxed scan batch")
    return reasons


def _counts(candidates: list[dict[str, Any]]) -> dict[str, Any]:
    modes = Counter(candidate["recommended_mode"] for candidate in candidates)
    statuses = Counter(candidate["registry_status"] for candidate in candidates)
    freshness = Counter(candidate["freshness"] for candidate in candidates)
    selected = sum(1 for candidate in candidates if candidate["selected_for_first_batch"])
    eligible = sum(1 for candidate in candidates if candidate["eligible_for_first_live_batch"])
    return {
        "candidates": len(candidates),
        "eligible_for_first_live_batch": eligible,
        "selected_for_first_batch": selected,
        "modes": dict(sorted(modes.items())),
        "registry_statuses": dict(sorted(statuses.items())),
        "freshness": dict(sorted(freshness.items())),
    }


def _candidate_sort_key(candidate: dict[str, Any]) -> tuple[int, str, str]:
    mode_rank = 0 if candidate["eligible_for_first_live_batch"] else 1
    freshness_rank = {
        str(Freshness.FRESH): 0,
        str(Freshness.AGING): 1,
        str(Freshness.UNKNOWN): 2,
        str(Freshness.STALE): 3,
        str(Freshness.DEPRECATED): 4,
        str(Freshness.DELETED): 5,
    }.get(candidate["freshness"], 9)
    return (mode_rank, str(freshness_rank), candidate["registry_name"])


def _has_exact_package_ref(package_refs: list[dict[str, Any]]) -> bool:
    return any(bool(package.get("exact_version")) for package in package_refs)


def _is_exact_version(registry_type: str, identifier: str | None, version: str | None) -> bool:
    if version:
        return True
    if not identifier:
        return False
    if registry_type.lower() == "pypi":
        return any(separator in identifier for separator in _EXACT_VERSION_SEPARATORS)
    if registry_type.lower() == "npm":
        if identifier.startswith("@") and "/" in identifier:
            return "@" in identifier.split("/", 1)[1]
        return "@" in identifier
    return False


def _stable_id(name: str, version: str | None) -> str:
    base = f"{name}-{version}" if version else name
    slug = []
    last_dash = False
    for char in base.lower():
        if char.isalnum():
            slug.append(char)
            last_dash = False
        elif not last_dash:
            slug.append("-")
            last_dash = True
    return "".join(slug).strip("-") or "registry-candidate"


def _normalize_url(value: str) -> str:
    parsed = urlsplit(value)
    scheme = parsed.scheme.lower()
    netloc = parsed.netloc.lower()
    path = parsed.path.rstrip("/")
    return urlunsplit((scheme, netloc, path, "", ""))


def _string(value: Any) -> str | None:
    return value if isinstance(value, str) and value else None


def _bool_or_none(value: Any) -> bool | None:
    if isinstance(value, bool):
        return value
    return None
