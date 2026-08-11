from __future__ import annotations

import copy
import hashlib
import importlib.util
import json
import subprocess
import sys
import threading
from collections.abc import Iterator
from contextlib import contextmanager
from datetime import UTC, datetime
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from types import ModuleType

import pytest

REPO_ROOT = Path(__file__).resolve().parents[1]
VERIFIER_PATH = REPO_ROOT / "scripts" / "web_release_readback.py"
CONFORMANCE_PATH = (
    REPO_ROOT
    / "fixtures"
    / "contracts"
    / "web-release-readback-v1"
    / "conformance-manifest.json"
)
CONTRACT_MANIFEST_PATH = CONFORMANCE_PATH.with_name("manifest.json")
PRODUCT_MANIFEST_PATH = REPO_ROOT / "deploy" / "web-release-readback.json"


def _load_verifier() -> ModuleType:
    spec = importlib.util.spec_from_file_location("web_release_readback", VERIFIER_PATH)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


VERIFIER = _load_verifier()


class _FixtureHandler(BaseHTTPRequestHandler):
    unsafe_requests = 0

    def log_message(self, format: str, *args: object) -> None:  # noqa: A002
        return

    def _send(self, status: int, body: bytes = b"", **headers: str) -> None:
        self.send_response(status)
        self.send_header("Content-Length", str(len(body)))
        for name, value in headers.items():
            self.send_header(name, value)
        self.end_headers()
        if self.command != "HEAD":
            self.wfile.write(body)

    def do_GET(self) -> None:  # noqa: N802
        if self.path == "/":
            self._send(200, b"MCP Server Danger Catalog - Check before you connect\n")
        elif self.path == "/ui/servers/mcp-reference-time":
            self._send(200, b"MCP Reference Time - Automated danger grade:\n")
        elif self.path == "/servers/mcp-reference-time/badge.json":
            self._send(
                200,
                b'{"schemaVersion": 1, "label": "mcp trust", "message": "A"}\n',
            )
        elif self.path == "/text":
            self._send(200, "release-ready · café\n".encode())
        elif self.path == "/digest":
            self._send(200, b"\x00web-release\xff")
        elif self.path == "/missing":
            self._send(404, b"not found\n")
        elif self.path == "/unsafe":
            self._send(200, b"release-ready private-token\n")
        elif self.path == "/large":
            self._send(200, b"x" * 32)
        elif self.path == "/redirect":
            self._send(302, location="https://example.invalid/text")
        elif self.path == "/redirect-local":
            host, port = self.server.server_address
            self._send(302, location=f"http://{host}:{port}/text")
        else:
            self._send(404, b"not found\n")

    def do_HEAD(self) -> None:  # noqa: N802
        if self.path == "/head":
            self._send(204)
        else:
            self._send(404)

    def do_POST(self) -> None:  # noqa: N802
        type(self).unsafe_requests += 1
        self._send(500, b"unsafe method reached fixture")


@contextmanager
def _server() -> Iterator[str]:
    _FixtureHandler.unsafe_requests = 0
    server = ThreadingHTTPServer(("127.0.0.1", 0), _FixtureHandler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    host, port = server.server_address
    try:
        yield f"http://{host}:{port}"
    finally:
        server.shutdown()
        thread.join(timeout=5)
        server.server_close()


def _manifest() -> dict[str, object]:
    return json.loads(CONFORMANCE_PATH.read_text(encoding="utf-8"))


def _receipt(manifest: dict[str, object], target_url: str) -> dict[str, object]:
    return VERIFIER.verify_release(
        manifest=manifest,
        manifest_sha256=hashlib.sha256(
            json.dumps(manifest, sort_keys=True).encode()
        ).hexdigest(),
        target_url=target_url,
        checked_at=datetime(2026, 8, 5, 8, 0, tzinfo=UTC),
    )


def test_reference_manifest_passes_and_emits_bounded_receipt() -> None:
    with _server() as target_url:
        receipt = _receipt(_manifest(), target_url)

    assert receipt["schema"] == "WebReleaseReadbackV1"
    assert receipt["contract_version"] == "1.0.0"
    assert receipt["checked_at"] == "2026-08-05T08:00:00Z"
    assert receipt["state"] == "passed"
    assert receipt["summary"] == {"total": 4, "passed": 4, "failed": 0}
    assert [route["state"] for route in receipt["routes"]] == ["passed"] * 4
    assert receipt["verifier"] == {
        "name": "web-release-readback",
        "version": "1.0.0",
        "network_methods": ["GET", "HEAD"],
        "denied_methods": ["POST", "PUT", "PATCH", "DELETE", "CONNECT", "TRACE"],
        "credentials_supported": False,
        "proxy_environment_used": False,
        "same_origin_redirects_only": True,
        "mutation_capabilities": [],
    }
    assert _FixtureHandler.unsafe_requests == 0


def test_mcp_trust_release_manifest_passes_without_replacing_local_checks() -> None:
    manifest = json.loads(PRODUCT_MANIFEST_PATH.read_text(encoding="utf-8"))
    with _server() as target_url:
        receipt = _receipt(manifest, target_url)

    assert receipt["state"] == "passed"
    assert receipt["summary"] == {"total": 3, "passed": 3, "failed": 0}
    assert [route["id"] for route in receipt["routes"]] == [
        "catalog",
        "reference-detail",
        "reference-badge",
    ]
    assert _FixtureHandler.unsafe_requests == 0

    smoke = (REPO_ROOT / "deploy" / "smoke-readonly.sh").read_text(encoding="utf-8")
    assert "scripts/web_release_readback.py" in smoke
    assert "deploy/web-release-readback.json" in smoke
    assert '"$BASE_URL/healthz"' in smoke
    assert '"$BASE_URL/servers"' in smoke
    assert "report_ref must be portable" in smoke
    assert '-X POST "$BASE_URL/servers/$SLUG/scan"' in smoke


def test_status_sentinel_digest_and_body_bound_fail_closed() -> None:
    manifest = _manifest()
    manifest["routes"] = [
        {
            "id": "domain-sentinels",
            "method": "GET",
            "route": "/unsafe",
            "expected_status": 201,
            "required_sentinels": ["release-ready", "missing-copy"],
            "forbidden_sentinels": ["private-token"],
        },
        {
            "id": "digest-drift",
            "method": "GET",
            "route": "/digest",
            "expected_status": 200,
            "body_sha256": "0" * 64,
        },
        {
            "id": "body-bound",
            "method": "GET",
            "route": "/large",
            "expected_status": 200,
            "max_body_bytes": 8,
        },
    ]
    with _server() as target_url:
        receipt = _receipt(manifest, target_url)

    assert receipt["state"] == "failed"
    assert receipt["summary"] == {"total": 3, "passed": 0, "failed": 3}
    assert receipt["routes"][0]["reason_codes"] == [
        "status_mismatch",
        "required_sentinel_missing",
        "forbidden_sentinel_present",
    ]
    assert receipt["routes"][1]["reason_codes"] == ["body_digest_mismatch"]
    assert receipt["routes"][2]["reason_codes"] == ["body_too_large"]


def test_mutation_methods_are_rejected_before_network_access() -> None:
    manifest = _manifest()
    manifest["routes"][0]["method"] = "POST"
    with _server() as target_url:
        with pytest.raises(VERIFIER.ManifestError, match="only GET and HEAD"):
            _receipt(manifest, target_url)
    assert _FixtureHandler.unsafe_requests == 0


def test_denied_method_policy_cannot_be_weakened() -> None:
    manifest = _manifest()
    manifest["denied_methods"] = ["POST"]
    with pytest.raises(VERIFIER.ManifestError, match="must contain exactly"):
        VERIFIER.validate_manifest(manifest)


@pytest.mark.parametrize(
    "target",
    [
        "http://example.com",
        "https://user:secret@example.com",
        "https://example.com/path",
        "https://example.com?token=value",
        "file:///tmp/site",
    ],
)
def test_target_url_rejects_insecure_or_credential_bearing_inputs(target: str) -> None:
    with pytest.raises(VERIFIER.ManifestError):
        VERIFIER.validate_target_url(target)


def test_cross_origin_redirect_is_reported_without_following_it() -> None:
    manifest = _manifest()
    manifest["defaults"]["follow_same_origin_redirects"] = True
    manifest["routes"] = [
        {
            "id": "cross-origin",
            "method": "GET",
            "route": "/redirect",
            "expected_status": 200,
        }
    ]
    with _server() as target_url:
        receipt = _receipt(manifest, target_url)
    assert receipt["state"] == "failed"
    assert receipt["routes"][0]["reason_codes"] == ["redirect_cross_origin"]
    assert receipt["routes"][0]["actual_status"] is None


def test_same_origin_redirect_requires_explicit_manifest_opt_in() -> None:
    manifest = _manifest()
    manifest["routes"] = [
        {
            "id": "local-redirect",
            "method": "GET",
            "route": "/redirect-local",
            "expected_status": 200,
            "required_sentinels": ["release-ready"],
        }
    ]
    with _server() as target_url:
        blocked = _receipt(manifest, target_url)
        allowed_manifest = copy.deepcopy(manifest)
        allowed_manifest["defaults"]["follow_same_origin_redirects"] = True
        allowed = _receipt(allowed_manifest, target_url)
    assert blocked["routes"][0]["reason_codes"] == ["redirect_not_allowed"]
    assert allowed["state"] == "passed"
    assert allowed["routes"][0]["reason_codes"] == ["matched"]


def test_cli_requires_explicit_target_and_emits_json_only() -> None:
    with _server() as target_url:
        completed = subprocess.run(
            [
                sys.executable,
                str(VERIFIER_PATH),
                "--manifest",
                str(CONFORMANCE_PATH),
                "--target-url",
                target_url,
            ],
            check=False,
            capture_output=True,
            text=True,
        )
    assert completed.returncode == 0
    assert completed.stderr == ""
    assert json.loads(completed.stdout)["state"] == "passed"


def test_contract_manifest_binds_every_public_artifact() -> None:
    contract = json.loads(CONTRACT_MANIFEST_PATH.read_text(encoding="utf-8"))
    assert contract["schema"] == "WebReleaseReadbackContractManifestV1"
    assert contract["owner"]["repository"] == "saagpatel/mcp-trust"
    assert contract["capabilities"]["network_methods"] == ["GET", "HEAD"]
    assert contract["non_goals"] == [
        "deployment",
        "alias-mutation",
        "dns-mutation",
        "credential-use",
        "promotion",
        "domain-specific-release-policy",
    ]
    for artifact in contract["artifacts"].values():
        raw = (REPO_ROOT / artifact["path"]).read_bytes()
        assert len(raw) == artifact["bytes"]
        assert hashlib.sha256(raw).hexdigest() == artifact["sha256"]

    completed = subprocess.run(
        [sys.executable, "scripts/generate_web_release_readback_contract.py", "--check"],
        cwd=REPO_ROOT,
        check=False,
        capture_output=True,
        text=True,
    )
    assert completed.returncode == 0, completed.stdout + completed.stderr


def test_schema_documents_match_runtime_contract() -> None:
    manifest_schema = json.loads(
        (REPO_ROOT / "contracts/web-release-readback-v1/manifest.schema.json").read_text()
    )
    receipt_schema = json.loads(
        (REPO_ROOT / "contracts/web-release-readback-v1/receipt.schema.json").read_text()
    )
    assert manifest_schema["properties"]["schema"]["const"] == (
        "WebReleaseSentinelManifestV1"
    )
    assert manifest_schema["$defs"]["route"]["properties"]["method"]["enum"] == [
        "GET",
        "HEAD",
    ]
    assert receipt_schema["properties"]["schema"]["const"] == "WebReleaseReadbackV1"
    assert receipt_schema["properties"]["verifier"]["properties"][
        "credentials_supported"
    ]["const"] is False
