from __future__ import annotations

import importlib.util
import json
import sys
from datetime import UTC, datetime
from pathlib import Path

from mcp_trust.corpus.registry import build_registry_candidate_manifest

ROOT = Path(__file__).resolve().parents[1]
SCRIPTS = ROOT / "scripts"


def _load_module(name: str, path: Path):
    spec = importlib.util.spec_from_file_location(name, path)
    assert spec is not None
    assert spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


def _registry_payload() -> dict[str, object]:
    return {
        "servers": [
            {
                "name": "io.example.safe",
                "title": "Safe Example",
                "description": "No-auth stdio package.",
                "version": "1.2.3",
                "repository": {"url": "https://github.com/example/safe"},
                "packages": [
                    {
                        "registryType": "npm",
                        "identifier": "@example/safe-server",
                        "version": "1.2.3",
                        "transport": "stdio",
                        "environmentVariables": [],
                    }
                ],
                "_meta": {
                    "io.modelcontextprotocol.registry/official": {
                        "status": "active",
                        "publishedAt": "2026-06-01T00:00:00Z",
                        "updatedAt": "2026-06-20T00:00:00Z",
                        "isLatest": True,
                    }
                },
            },
            {
                "name": "io.example.credentialed",
                "version": "2.0.0",
                "repository": {"url": "https://github.com/example/credentialed"},
                "packages": [
                    {
                        "registryType": "pypi",
                        "identifier": "credentialed-mcp",
                        "version": "2.0.0",
                        "environmentVariables": [
                            {"name": "EXAMPLE_API_TOKEN", "isRequired": True, "isSecret": True}
                        ],
                    }
                ],
                "_meta": {
                    "io.modelcontextprotocol.registry/official": {
                        "status": "active",
                        "updatedAt": "2026-06-15T00:00:00Z",
                        "isLatest": True,
                    }
                },
            },
            {
                "name": "io.example.optional-secret",
                "version": "1.0.0",
                "repository": {"url": "https://github.com/example/optional-secret"},
                "packages": [
                    {
                        "registryType": "npm",
                        "identifier": "@example/optional-secret",
                        "version": "1.0.0",
                        "environmentVariables": [
                            {"name": "OPTIONAL_TOKEN", "isSecret": True}
                        ],
                    }
                ],
                "_meta": {
                    "io.modelcontextprotocol.registry/official": {
                        "status": "active",
                        "updatedAt": "2026-06-15T00:00:00Z",
                        "isLatest": True,
                    }
                },
            },
            {
                "name": "io.example.remote",
                "version": "1.0.0",
                "remotes": [{"url": "https://mcp.example.com/mcp", "transport": "streamable-http"}],
                "_meta": {
                    "io.modelcontextprotocol.registry/official": {
                        "status": "active",
                        "updatedAt": "2026-02-01T00:00:00Z",
                        "isLatest": True,
                    }
                },
            },
            {
                "name": "io.example.old",
                "version": "0.1.0",
                "repository": {"url": "https://github.com/example/old"},
                "packages": [
                    {
                        "registryType": "npm",
                        "identifier": "@example/old-server",
                        "version": "0.1.0",
                    }
                ],
                "_meta": {
                    "io.modelcontextprotocol.registry/official": {
                        "status": "deprecated",
                        "updatedAt": "2025-01-01T00:00:00Z",
                        "isLatest": False,
                    }
                },
            },
        ]
    }


def test_registry_manifest_classifies_modes_without_grades() -> None:
    manifest = build_registry_candidate_manifest(
        _registry_payload(),
        generated_at=datetime(2026, 6, 28, tzinfo=UTC),
        first_batch_limit=25,
    )

    assert manifest["notice"].startswith("Dry-run only")
    assert manifest["counts"]["candidates"] == 5
    assert manifest["counts"]["eligible_for_first_live_batch"] == 1

    by_name = {candidate["registry_name"]: candidate for candidate in manifest["candidates"]}
    assert by_name["io.example.safe"]["recommended_mode"] == "no-auth-sandboxed"
    assert by_name["io.example.safe"]["selected_for_first_batch"] is True
    assert by_name["io.example.safe"]["eligible_for_first_live_batch"] is True

    assert by_name["io.example.credentialed"]["recommended_mode"] == "credentialed-sandboxed"
    assert by_name["io.example.credentialed"]["secret_env_key_names"] == ["EXAMPLE_API_TOKEN"]
    assert by_name["io.example.credentialed"]["required_secret_keys"] == ["EXAMPLE_API_TOKEN"]
    assert by_name["io.example.credentialed"]["eligible_for_first_live_batch"] is False

    assert by_name["io.example.optional-secret"]["recommended_mode"] == "credentialed-sandboxed"
    assert by_name["io.example.optional-secret"]["secret_env_key_names"] == ["OPTIONAL_TOKEN"]
    assert by_name["io.example.optional-secret"]["required_secret_keys"] == []
    assert by_name["io.example.optional-secret"]["eligible_for_first_live_batch"] is False

    assert by_name["io.example.remote"]["recommended_mode"] == "remote-networked"
    assert by_name["io.example.remote"]["freshness"] == "aging"

    assert by_name["io.example.old"]["recommended_mode"] == "package-only"
    assert by_name["io.example.old"]["freshness"] == "deprecated"

    text = json.dumps(manifest)
    assert '"grade"' not in text
    assert "tools" not in manifest["candidates"][0]


def test_registry_manifest_records_dedupe_keys_and_caveats() -> None:
    manifest = build_registry_candidate_manifest(
        _registry_payload(),
        generated_at=datetime(2026, 6, 28, tzinfo=UTC),
    )
    safe = next(
        candidate
        for candidate in manifest["candidates"]
        if candidate["registry_name"] == "io.example.safe"
    )

    assert "package:npm:@example/safe-server:1.2.3" in safe["dedupe_keys"]
    assert "repo:https://github.com/example/safe" in safe["dedupe_keys"]
    assert any("does not declare actual runtime tool surfaces" in c for c in safe["caveats"])


def test_registry_manifest_accepts_official_wrapped_api_shape() -> None:
    payload = {
        "servers": [
            {
                "server": {
                    "name": "com.example/wrapped",
                    "description": "Official list response wrapper.",
                    "version": "1.0.0",
                    "repository": {
                        "url": "https://github.com/example/wrapped",
                        "source": "github",
                        "id": "123",
                    },
                    "packages": [
                        {
                            "registryType": "npm",
                            "identifier": "@example/wrapped",
                            "version": "1.0.0",
                            "transport": {"type": "stdio"},
                            "environmentVariables": [
                                {"name": "OPTIONAL_FLAG", "isRequired": False, "isSecret": False}
                            ],
                        }
                    ],
                },
                "_meta": {
                    "io.modelcontextprotocol.registry/official": {
                        "status": "active",
                        "publishedAt": "2026-06-20T00:00:00Z",
                        "updatedAt": "2026-06-22T00:00:00Z",
                        "isLatest": True,
                    }
                },
            },
            {
                "server": {
                    "name": "com.example/remote-secret",
                    "version": "1.0.0",
                    "remotes": [
                        {
                            "type": "streamable-http",
                            "url": "https://remote.example.com/mcp",
                            "headers": [
                                {"name": "Authorization", "isRequired": True, "isSecret": True}
                            ],
                        }
                    ],
                },
                "_meta": {
                    "io.modelcontextprotocol.registry/official": {
                        "status": "active",
                        "updatedAt": "2026-06-22T00:00:00Z",
                        "isLatest": True,
                    }
                },
            },
        ]
    }

    manifest = build_registry_candidate_manifest(
        payload,
        generated_at=datetime(2026, 6, 28, tzinfo=UTC),
    )

    by_name = {candidate["registry_name"]: candidate for candidate in manifest["candidates"]}
    wrapped = by_name["com.example/wrapped"]
    remote = by_name["com.example/remote-secret"]

    assert wrapped["recommended_mode"] == "no-auth-sandboxed"
    assert wrapped["package_refs"][0]["transport"] == "stdio"
    assert wrapped["env_key_names"] == ["OPTIONAL_FLAG"]
    assert wrapped["registry_status"] == "active"
    assert wrapped["is_latest"] is True

    assert remote["recommended_mode"] == "remote-networked"
    assert remote["required_secret_keys"] == ["Authorization"]
    assert remote["remote_refs"][0]["transport"] == "streamable-http"


def test_registry_corpus_script_is_stdout_only(tmp_path: Path, capsys) -> None:
    path = tmp_path / "registry.json"
    path.write_text(json.dumps(_registry_payload()), encoding="utf-8")
    planner = _load_module("plan_registry_corpus", SCRIPTS / "plan_registry_corpus.py")

    rc = planner.main(
        [
            "--input",
            str(path),
            "--generated-at",
            "2026-06-28T00:00:00Z",
            "--format",
            "summary",
        ]
    )

    out = capsys.readouterr().out
    assert rc == 0
    assert "Dry-run only" in out
    assert "eligible for first live batch: 1" in out
    assert "mcp-trust scan" not in out
    assert "docker run" not in out
