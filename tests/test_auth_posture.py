"""Tests for the credential-free remote authorization metadata preflight."""

from __future__ import annotations

import json
import socket
from dataclasses import replace
from datetime import UTC, datetime
from email.utils import format_datetime
from pathlib import Path
from typing import Any

import pytest
from typer.testing import CliRunner

import mcp_trust.auth_posture as auth_posture
from mcp_trust.auth_posture import (
    AuthPostureInputError,
    FetchResponse,
    PinnedHTTPSFetcher,
    RegistryBinding,
    load_registry_binding,
    probe_authorization_posture,
)
from mcp_trust.cli.main import app

RESOURCE_URL = "https://mcp.example.com/mcp"
RESOURCE_WELL_KNOWN = "https://mcp.example.com/.well-known/oauth-protected-resource/mcp"
RESOURCE_WELL_KNOWN_ROOT = "https://mcp.example.com/.well-known/oauth-protected-resource"
CHALLENGE_METADATA = "https://mcp.example.com/oauth-resource"
ISSUER = "https://auth.example.com/issuer"
RFC8414_METADATA = "https://auth.example.com/.well-known/oauth-authorization-server/issuer"
OIDC_INSERTION_METADATA = "https://auth.example.com/.well-known/openid-configuration/issuer"
OIDC_METADATA = "https://auth.example.com/issuer/.well-known/openid-configuration"


class FakeFetcher:
    def __init__(
        self,
        responses: dict[str, FetchResponse],
        *,
        add_current_date: bool = True,
    ) -> None:
        self.responses = responses
        self.add_current_date = add_current_date
        self.requests: list[tuple[str, float, int]] = []

    def fetch(
        self,
        url: str,
        *,
        timeout_seconds: float,
        max_body_bytes: int,
    ) -> FetchResponse:
        self.requests.append((url, timeout_seconds, max_body_bytes))
        response = self.responses.get(url, FetchResponse(url=url, reason_code="network_error"))
        if (
            self.add_current_date
            and response.status == 200
            and response.reason_code is None
            and response.http_date is None
        ):
            response = replace(
                response,
                http_date=format_datetime(datetime.now(UTC), usegmt=True),
                cache_control="max-age=60",
            )
        return response


def _json_response(url: str, document: dict[str, Any]) -> FetchResponse:
    return FetchResponse(
        url=url,
        status=200,
        content_type="application/json; charset=utf-8",
        body=json.dumps(document).encode(),
    )


def _binding() -> RegistryBinding:
    return RegistryBinding(
        stable_id="com.example/remote@1.0.0",
        resource_url=RESOURCE_URL,
        manifest_sha256="a" * 64,
        source_kind="official-mcp-registry-export",
    )


def _resource_document(*, resource: str = RESOURCE_URL) -> dict[str, Any]:
    return {
        "resource": resource,
        "authorization_servers": [ISSUER],
        "scopes_supported": [],
    }


def _authorization_document(
    *,
    issuer: str = ISSUER,
    methods: list[str] | None = None,
) -> dict[str, Any]:
    return {
        "issuer": issuer,
        "authorization_endpoint": "https://auth.example.com/authorize",
        "token_endpoint": "https://auth.example.com/token",
        "code_challenge_methods_supported": methods or ["S256"],
        "scopes_supported": [],
        "client_id_metadata_document_supported": True,
    }


def _valid_fetcher(*, resource_url: str = RESOURCE_WELL_KNOWN) -> FakeFetcher:
    return FakeFetcher(
        {
            resource_url: _json_response(resource_url, _resource_document()),
            RFC8414_METADATA: _json_response(
                RFC8414_METADATA,
                _authorization_document(),
            ),
        }
    )


def _write_manifest(path: Path) -> None:
    path.write_text(
        json.dumps(
            {
                "format_version": 1,
                "source": {"kind": "official-mcp-registry-export"},
                "candidates": [
                    {
                        "stable_id": "com.example/remote@1.0.0",
                        "remote_refs": [
                            {
                                "url": RESOURCE_URL,
                                "normalized_url": RESOURCE_URL,
                                "transport": "streamable-http",
                            }
                        ],
                    }
                ],
            }
        ),
        encoding="utf-8",
    )


def test_probe_validates_challenge_metadata_and_keeps_claims_advisory() -> None:
    fetcher = _valid_fetcher(resource_url=CHALLENGE_METADATA)

    result = probe_authorization_posture(
        _binding(),
        www_authenticate=(f'Bearer resource_metadata="{CHALLENGE_METADATA}", scope="read write"'),
        timeout_seconds=3,
        fetcher=fetcher,
    )

    assert result["schema_version"] == "McpAuthorizationPostureV1"
    assert result["observed_at"].endswith("Z")
    assert result["state"] == "metadata-ready"
    assert result["scan_eligibility"] == "policy-review-only"
    assert result["authorization_required"] is True
    assert result["challenge_scopes"] == ["read", "write"]
    assert result["resource_metadata"]["discovery"] == "www-authenticate"
    assert result["authorization_servers"][0]["state"] == "metadata-ready"
    assert result["claim_ceiling"] == {
        "authorization_proven": False,
        "credentials_available": False,
        "trust_grade_authority": False,
        "runtime_security_proven": False,
    }
    assert result["capability_boundary"]["credentials_supported"] is False
    assert result["capability_boundary"]["mutation_capabilities"] == []
    assert [request[0] for request in fetcher.requests] == [
        CHALLENGE_METADATA,
        RFC8414_METADATA,
    ]
    assert "body" not in result["fetches"][0]
    assert result["fetches"][0]["body_sha256"]
    assert result["fetches"][0]["freshness"]["state"] == "current"


def test_probe_uses_rfc9728_path_then_root_fallback() -> None:
    fetcher = FakeFetcher(
        {
            RESOURCE_WELL_KNOWN: FetchResponse(
                url=RESOURCE_WELL_KNOWN,
                status=404,
                content_type="application/json",
                body=b"{}",
            ),
            RESOURCE_WELL_KNOWN_ROOT: _json_response(
                RESOURCE_WELL_KNOWN_ROOT,
                _resource_document(),
            ),
            RFC8414_METADATA: _json_response(
                RFC8414_METADATA,
                _authorization_document(),
            ),
        }
    )

    result = probe_authorization_posture(_binding(), fetcher=fetcher)

    assert result["state"] == "metadata-ready"
    assert result["authorization_required"] is None
    assert result["resource_metadata"]["discovery"] == "well-known-root"
    assert [request[0] for request in fetcher.requests] == [
        RESOURCE_WELL_KNOWN,
        RESOURCE_WELL_KNOWN_ROOT,
        RFC8414_METADATA,
    ]


def test_probe_uses_oidc_append_fallback_after_rfc8414() -> None:
    fetcher = FakeFetcher(
        {
            RESOURCE_WELL_KNOWN: _json_response(
                RESOURCE_WELL_KNOWN,
                _resource_document(),
            ),
            RFC8414_METADATA: FetchResponse(url=RFC8414_METADATA, status=404),
            OIDC_INSERTION_METADATA: FetchResponse(
                url=OIDC_INSERTION_METADATA,
                status=404,
            ),
            OIDC_METADATA: _json_response(OIDC_METADATA, _authorization_document()),
        }
    )

    result = probe_authorization_posture(_binding(), fetcher=fetcher)

    assert result["state"] == "metadata-ready"
    assert result["authorization_servers"][0]["discovery"] == "openid-connect-path-append"
    assert [request[0] for request in fetcher.requests][-3:] == [
        RFC8414_METADATA,
        OIDC_INSERTION_METADATA,
        OIDC_METADATA,
    ]


def test_probe_preserves_mcp_oidc_path_insertion_priority() -> None:
    fetcher = FakeFetcher(
        {
            RESOURCE_WELL_KNOWN: _json_response(
                RESOURCE_WELL_KNOWN,
                _resource_document(),
            ),
            RFC8414_METADATA: FetchResponse(url=RFC8414_METADATA, status=404),
            OIDC_INSERTION_METADATA: _json_response(
                OIDC_INSERTION_METADATA,
                _authorization_document(),
            ),
        }
    )

    result = probe_authorization_posture(_binding(), fetcher=fetcher)

    assert result["state"] == "metadata-ready"
    assert result["authorization_servers"][0]["discovery"] == ("openid-connect-path-insertion")
    assert OIDC_METADATA not in [request[0] for request in fetcher.requests]


def test_probe_rejects_cross_origin_challenge_without_fetching() -> None:
    fetcher = FakeFetcher({})

    result = probe_authorization_posture(
        _binding(),
        www_authenticate=('Bearer resource_metadata="https://attacker.example/oauth-resource"'),
        fetcher=fetcher,
    )

    assert result["state"] == "unknown"
    assert result["scan_eligibility"] == "blocked"
    assert result["reason_codes"] == ["resource_metadata_origin_not_allowed"]
    assert fetcher.requests == []


@pytest.mark.parametrize(
    ("resource_response", "reason_code"),
    [
        (
            _json_response(
                RESOURCE_WELL_KNOWN,
                _resource_document(resource="https://mcp.example.com/other"),
            ),
            "resource_mismatch",
        ),
        (
            FetchResponse(
                url=RESOURCE_WELL_KNOWN,
                status=302,
                content_type="application/json",
                reason_code="redirect_not_allowed",
            ),
            "redirect_not_allowed",
        ),
        (
            FetchResponse(
                url=RESOURCE_WELL_KNOWN,
                status=200,
                content_type="text/html",
                body=b"{}",
            ),
            "content_type_invalid",
        ),
        (
            FetchResponse(
                url=RESOURCE_WELL_KNOWN,
                status=200,
                content_type="application/json",
                body=b'{"resource":"a","resource":"b"}',
            ),
            "json_duplicate_key",
        ),
    ],
)
def test_probe_fails_closed_on_invalid_resource_metadata(
    resource_response: FetchResponse,
    reason_code: str,
) -> None:
    fetcher = FakeFetcher(
        {
            RESOURCE_WELL_KNOWN: resource_response,
            RESOURCE_WELL_KNOWN_ROOT: FetchResponse(
                url=RESOURCE_WELL_KNOWN_ROOT,
                status=404,
            ),
        }
    )

    result = probe_authorization_posture(_binding(), fetcher=fetcher)

    assert result["state"] == "unknown"
    assert result["scan_eligibility"] == "blocked"
    assert reason_code in result["reason_codes"]


@pytest.mark.parametrize(
    ("http_date", "cache_control", "age", "reason_code"),
    [
        (
            "Tue, 04 Aug 2026 00:00:00 GMT",
            "max-age=60",
            "90000",
            "metadata_response_stale",
        ),
        (
            "Thu, 06 Aug 2026 00:00:00 GMT",
            "max-age=60",
            "0",
            "http_date_future",
        ),
        ("not-a-date", "max-age=60", "0", "http_date_invalid"),
        (
            "Wed, 05 Aug 2026 00:00:00 GMT",
            "max-age=invalid",
            "0",
            "cache_control_invalid",
        ),
    ],
)
def test_probe_fails_closed_on_invalid_or_stale_http_freshness(
    http_date: str,
    cache_control: str,
    age: str,
    reason_code: str,
) -> None:
    resource_response = _json_response(RESOURCE_WELL_KNOWN, _resource_document())
    resource_response = replace(
        resource_response,
        http_date=http_date,
        cache_control=cache_control,
        age=age,
    )
    fetcher = FakeFetcher(
        {
            RESOURCE_WELL_KNOWN: resource_response,
            RESOURCE_WELL_KNOWN_ROOT: FetchResponse(
                url=RESOURCE_WELL_KNOWN_ROOT,
                status=404,
            ),
        }
    )

    result = probe_authorization_posture(
        _binding(),
        fetcher=fetcher,
        observed_at=datetime(2026, 8, 5, tzinfo=UTC),
    )

    assert result["state"] == "unknown"
    assert result["scan_eligibility"] == "blocked"
    assert reason_code in result["reason_codes"]


def test_probe_fails_closed_when_successful_metadata_has_no_http_date() -> None:
    fetcher = FakeFetcher(
        {
            RESOURCE_WELL_KNOWN: _json_response(
                RESOURCE_WELL_KNOWN,
                _resource_document(),
            ),
            RESOURCE_WELL_KNOWN_ROOT: FetchResponse(
                url=RESOURCE_WELL_KNOWN_ROOT,
                status=404,
            ),
        },
        add_current_date=False,
    )

    result = probe_authorization_posture(_binding(), fetcher=fetcher)

    assert result["state"] == "unknown"
    assert "http_date_missing" in result["reason_codes"]


@pytest.mark.parametrize(
    ("document", "reason_code"),
    [
        (_authorization_document(issuer="https://auth.example.com/other"), "issuer_mismatch"),
        (_authorization_document(methods=["plain"]), "pkce_s256_missing"),
    ],
)
def test_probe_fails_closed_on_invalid_authorization_server_metadata(
    document: dict[str, Any],
    reason_code: str,
) -> None:
    fetcher = FakeFetcher(
        {
            RESOURCE_WELL_KNOWN: _json_response(
                RESOURCE_WELL_KNOWN,
                _resource_document(),
            ),
            RFC8414_METADATA: _json_response(RFC8414_METADATA, document),
            OIDC_INSERTION_METADATA: FetchResponse(
                url=OIDC_INSERTION_METADATA,
                status=404,
            ),
            OIDC_METADATA: FetchResponse(url=OIDC_METADATA, status=404),
        }
    )

    result = probe_authorization_posture(_binding(), fetcher=fetcher)

    assert result["state"] == "unknown"
    assert result["authorization_servers"][0]["state"] == "unknown"
    assert reason_code in result["authorization_servers"][0]["reason_codes"]


def test_probe_requires_exact_rfc8414_issuer_string() -> None:
    resource_document = _resource_document()
    resource_document["authorization_servers"] = ["https://AUTH.example.com/issuer"]
    fetcher = FakeFetcher(
        {
            RESOURCE_WELL_KNOWN: _json_response(
                RESOURCE_WELL_KNOWN,
                resource_document,
            ),
            RFC8414_METADATA: _json_response(
                RFC8414_METADATA,
                _authorization_document(),
            ),
            OIDC_INSERTION_METADATA: FetchResponse(
                url=OIDC_INSERTION_METADATA,
                status=404,
            ),
            OIDC_METADATA: FetchResponse(url=OIDC_METADATA, status=404),
        }
    )

    result = probe_authorization_posture(_binding(), fetcher=fetcher)

    assert result["state"] == "unknown"
    assert "issuer_mismatch" in result["authorization_servers"][0]["reason_codes"]


def test_probe_accepts_https_endpoint_query_without_fetching_it() -> None:
    document = _authorization_document()
    document["authorization_endpoint"] = "https://auth.example.com/authorize?tenant=one"
    fetcher = FakeFetcher(
        {
            RESOURCE_WELL_KNOWN: _json_response(
                RESOURCE_WELL_KNOWN,
                _resource_document(),
            ),
            RFC8414_METADATA: _json_response(RFC8414_METADATA, document),
        }
    )

    result = probe_authorization_posture(_binding(), fetcher=fetcher)

    assert result["state"] == "metadata-ready"
    assert result["authorization_servers"][0]["metadata"]["authorization_endpoint"] == (
        "https://auth.example.com/authorize?tenant=one"
    )


@pytest.mark.parametrize("address", ["127.0.0.1", "10.0.0.1", "169.254.169.254", "::1"])
def test_fetcher_rejects_non_public_dns_answers_without_connecting(address: str) -> None:
    family = socket.AF_INET6 if ":" in address else socket.AF_INET

    def resolver(*_args: Any, **_kwargs: Any) -> list[tuple[Any, ...]]:
        return [(family, socket.SOCK_STREAM, 6, "", (address, 443))]

    response = PinnedHTTPSFetcher(resolver=resolver).fetch(
        RESOURCE_WELL_KNOWN,
        timeout_seconds=1,
        max_body_bytes=1024,
    )

    assert response.reason_code == "non_public_address"


def test_fetcher_pins_socket_address_but_keeps_original_tls_authority(monkeypatch) -> None:
    observations: dict[str, Any] = {}

    class FakeHTTPResponse:
        status = 200

        def getheader(self, name: str) -> str | None:
            return "application/json" if name == "Content-Type" else None

        def read(self, _maximum: int) -> bytes:
            return b"{}"

        def close(self) -> None:
            observations["response_closed"] = True

    class FakeHTTPSConnection:
        def __init__(
            self,
            host: str,
            port: int,
            *,
            timeout: float,
            context: Any,
        ) -> None:
            observations["tls_authority"] = (host, port)
            observations["timeout"] = timeout
            observations["context"] = context
            self.host = host
            self.port = port
            self.timeout = timeout
            self._create_connection: Any = None

        def request(self, method: str, path: str, *, headers: dict[str, str]) -> None:
            observations["request"] = (method, path, headers)
            self._create_connection((self.host, self.port), self.timeout, None)

        def getresponse(self) -> FakeHTTPResponse:
            return FakeHTTPResponse()

        def close(self) -> None:
            observations["connection_closed"] = True

    def resolver(*_args: Any, **_kwargs: Any) -> list[tuple[Any, ...]]:
        return [
            (
                socket.AF_INET,
                socket.SOCK_STREAM,
                6,
                "",
                ("93.184.216.34", 443),
            )
        ]

    def create_connection(
        address: tuple[str, int],
        *,
        timeout: float | None,
        source_address: tuple[str, int] | None,
    ) -> object:
        observations["socket_address"] = address
        observations["source_address"] = source_address
        return object()

    monkeypatch.setattr(auth_posture.http.client, "HTTPSConnection", FakeHTTPSConnection)
    monkeypatch.setattr(auth_posture.socket, "create_connection", create_connection)

    response = PinnedHTTPSFetcher(resolver=resolver).fetch(
        RESOURCE_WELL_KNOWN,
        timeout_seconds=2,
        max_body_bytes=1024,
    )

    assert response.reason_code is None
    assert observations["tls_authority"] == ("mcp.example.com", 443)
    assert observations["socket_address"] == ("93.184.216.34", 443)
    assert observations["request"][0:2] == (
        "GET",
        "/.well-known/oauth-protected-resource/mcp",
    )
    assert "Authorization" not in observations["request"][2]
    assert observations["connection_closed"] is True
    assert observations["response_closed"] is True


def test_fetcher_rejects_mixed_public_and_private_dns_answers() -> None:
    def resolver(*_args: Any, **_kwargs: Any) -> list[tuple[Any, ...]]:
        return [
            (socket.AF_INET, socket.SOCK_STREAM, 6, "", ("93.184.216.34", 443)),
            (socket.AF_INET, socket.SOCK_STREAM, 6, "", ("127.0.0.1", 443)),
        ]

    response = PinnedHTTPSFetcher(resolver=resolver).fetch(
        RESOURCE_WELL_KNOWN,
        timeout_seconds=1,
        max_body_bytes=1024,
    )

    assert response.reason_code == "non_public_address"


@pytest.mark.parametrize(
    "resource_url",
    [
        "http://mcp.example.com/mcp",
        "https://127.0.0.1/mcp",
        "https://mcp.example.com/mcp?secret=value",
        "https://mcp.example.com\\@127.0.0.1/mcp",
    ],
)
def test_probe_rejects_candidate_urls_outside_the_boundary(resource_url: str) -> None:
    binding = RegistryBinding(
        stable_id="candidate",
        resource_url=resource_url,
        manifest_sha256="a" * 64,
        source_kind="official-mcp-registry-export",
    )

    with pytest.raises(AuthPostureInputError):
        probe_authorization_posture(binding, fetcher=FakeFetcher({}))


def test_manifest_loader_binds_one_exact_official_registry_remote(tmp_path: Path) -> None:
    manifest = tmp_path / "manifest.json"
    _write_manifest(manifest)

    binding = load_registry_binding(manifest, "com.example/remote@1.0.0")

    assert binding.resource_url == RESOURCE_URL
    assert binding.source_kind == "official-mcp-registry-export"
    assert len(binding.manifest_sha256) == 64


def test_manifest_loader_rejects_symlink(tmp_path: Path) -> None:
    manifest = tmp_path / "manifest.json"
    link = tmp_path / "manifest-link.json"
    _write_manifest(manifest)
    link.symlink_to(manifest)

    with pytest.raises(AuthPostureInputError, match="regular file"):
        load_registry_binding(link, "com.example/remote@1.0.0")


def test_manifest_loader_rejects_normalized_url_mismatch(tmp_path: Path) -> None:
    manifest = tmp_path / "manifest.json"
    _write_manifest(manifest)
    value = json.loads(manifest.read_text(encoding="utf-8"))
    value["candidates"][0]["remote_refs"][0]["normalized_url"] = "https://other.example/mcp"
    manifest.write_text(json.dumps(value), encoding="utf-8")

    with pytest.raises(AuthPostureInputError, match="normalized URL"):
        load_registry_binding(manifest, "com.example/remote@1.0.0")


def test_cli_emits_json_and_uses_terminal_exit_codes(tmp_path: Path, monkeypatch) -> None:
    manifest = tmp_path / "manifest.json"
    _write_manifest(manifest)
    monkeypatch.setattr(auth_posture, "PinnedHTTPSFetcher", lambda: _valid_fetcher())
    runner = CliRunner()

    ready = runner.invoke(
        app,
        [
            "auth-posture",
            "com.example/remote@1.0.0",
            "--manifest",
            str(manifest),
        ],
    )
    unknown = runner.invoke(
        app,
        [
            "auth-posture",
            "com.example/remote@1.0.0",
            "--manifest",
            str(manifest),
            "--www-authenticate",
            'Bearer resource_metadata="https://attacker.example/resource"',
        ],
    )
    invalid = runner.invoke(
        app,
        ["auth-posture", "missing", "--manifest", str(manifest)],
    )

    assert ready.exit_code == 0, ready.output
    assert json.loads(ready.output)["state"] == "metadata-ready"
    assert unknown.exit_code == 1
    assert json.loads(unknown.output)["state"] == "unknown"
    assert invalid.exit_code == 2
    assert "must match exactly one entry" in invalid.output
