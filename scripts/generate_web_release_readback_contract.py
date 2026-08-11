#!/usr/bin/env python3
"""Generate the deterministic WebReleaseReadbackV1 artifact manifest."""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
OUTPUT = (
    REPO_ROOT
    / "fixtures"
    / "contracts"
    / "web-release-readback-v1"
    / "manifest.json"
)
ARTIFACTS = {
    "reference_verifier": "scripts/web_release_readback.py",
    "route_manifest_schema": "contracts/web-release-readback-v1/manifest.schema.json",
    "receipt_schema": "contracts/web-release-readback-v1/receipt.schema.json",
    "conformance_manifest": (
        "fixtures/contracts/web-release-readback-v1/conformance-manifest.json"
    ),
}


def _sha256(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def render() -> bytes:
    artifacts = {}
    for name, relative_path in ARTIFACTS.items():
        raw = (REPO_ROOT / relative_path).read_bytes()
        artifacts[name] = {
            "path": relative_path,
            "sha256": _sha256(raw),
            "bytes": len(raw),
        }
    payload = {
        "schema": "WebReleaseReadbackContractManifestV1",
        "contract_version": "1.0.0",
        "owner": {
            "repository": "saagpatel/mcp-trust",
            "policy": "additive-within-major",
        },
        "artifacts": artifacts,
        "capabilities": {
            "network_methods": ["GET", "HEAD"],
            "denied_methods": [
                "POST",
                "PUT",
                "PATCH",
                "DELETE",
                "CONNECT",
                "TRACE",
            ],
            "assertions": [
                "expected-status",
                "required-sentinel",
                "forbidden-sentinel",
                "exact-utf8-body",
                "sha256-body-digest",
                "bounded-timeout",
                "bounded-body",
            ],
        },
        "non_goals": [
            "deployment",
            "alias-mutation",
            "dns-mutation",
            "credential-use",
            "promotion",
            "domain-specific-release-policy",
        ],
        "adoption_order": [
            "saagpatel/portfolio-index",
            "saagpatel/mcp-trust",
            "saagpatel/operator-os-explainer",
        ],
        "rollback": "remove-consumer-invocation-and-keep-existing-domain-checks",
    }
    return (json.dumps(payload, indent=2, sort_keys=True) + "\n").encode("utf-8")


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--check", action="store_true")
    args = parser.parse_args()
    expected = render()
    if args.check:
        if not OUTPUT.exists() or OUTPUT.read_bytes() != expected:
            print(f"contract manifest drift: {OUTPUT}")
            return 1
        print("WebReleaseReadbackV1 contract manifest is deterministic and current.")
        return 0
    OUTPUT.parent.mkdir(parents=True, exist_ok=True)
    OUTPUT.write_bytes(expected)
    print(OUTPUT)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
