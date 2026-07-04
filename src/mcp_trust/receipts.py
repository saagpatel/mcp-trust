"""Durable scan receipt artifacts.

SQLite stores the queryable registry state; receipts preserve the public proof
packet behind a grade. Receipt writing is opt-in via ``MCP_TRUST_RECEIPTS_DIR``
so local tests and quickstarts stay lightweight.
"""

from __future__ import annotations

import json
import os
from pathlib import Path
from typing import Any

from mcp_trust.core import grading
from mcp_trust.core.models import ScanRecord, Server
from mcp_trust.engine.sandbox import effective_docker_image

_RECEIPTS_DIR_ENV = "MCP_TRUST_RECEIPTS_DIR"
_SCAN_APPROVAL_REF_ENV = "MCP_TRUST_SCAN_APPROVAL_REF"
_SCANNER_GIT_REF_ENV = "MCP_TRUST_SCANNER_GIT_REF"
_CREDENTIALS_MODE_ENV = "MCP_TRUST_SCAN_CREDENTIALS"
_SANDBOX_ENV_KEYS = (
    "MCP_TRUST_SANDBOX",
    "MCP_TRUST_SANDBOX_IMAGE",
    "MCP_TRUST_SANDBOX_NETWORK",
    # The credentialed-scan MODE name (e.g. "dummy") is provenance, not a secret;
    # dummy credential VALUES live only in the container and are never recorded.
    _CREDENTIALS_MODE_ENV,
)


def receipts_dir_from_env() -> Path | None:
    """Return the configured receipt directory, or ``None`` when disabled."""
    value = os.environ.get(_RECEIPTS_DIR_ENV)
    if not value:
        return None
    return Path(value)


def _sandbox_provenance(server: Server, scan: ScanRecord) -> dict[str, Any]:
    """Sandbox section of the receipt: env config plus the image actually used.

    The env keys alone misstate provenance for servers with a per-server image
    pin — the engine resolves ``source.sandbox_image`` AHEAD of the
    ``MCP_TRUST_SANDBOX_IMAGE`` corpus default (``select_sandbox``), so a
    receipt recording only the env value claims the wrong image for pinned
    rows. ``image_used`` records the resolved image, via the same helper the
    engine resolves with. Recorded only for real docker-sandboxed scans; the
    stub engine never launches a sandbox.
    """
    sandbox = {key: os.environ.get(key) for key in _SANDBOX_ENV_KEYS if os.environ.get(key)}
    if scan.engine_name == "mcpaudit" and sandbox.get("MCP_TRUST_SANDBOX") == "docker":
        sandbox["image_used"] = effective_docker_image(server.source.sandbox_image)
    return sandbox


def build_scan_receipt(server: Server, scan: ScanRecord) -> dict[str, Any]:
    """Build the public proof packet for one persisted scan."""
    caveats = [
        "Automated scan output is not an endorsement.",
        "Danger grade and transparency are separate signals.",
        "Low transparency means cannot verify safe, not known dangerous.",
        "Network-off sandboxing may suppress behavior that requires live egress.",
    ]
    # Gate the caveat on ACTUAL injection, not just the global mode: credentials
    # are only injected for a server that declares env_keys, scanned by the real
    # engine (the stub never launches a sandbox). Without this, a no-credential
    # scan run during a dummy-mode batch would record false provenance.
    injected_credentials = (
        os.environ.get(_CREDENTIALS_MODE_ENV, "none").lower() == "dummy"
        and bool(server.source.env_keys)
        and scan.engine_name == "mcpaudit"
    )
    if injected_credentials:
        caveats.append(
            "Scanned with injected non-functional dummy credentials (network-off): "
            "the enumerated tool surface is real; no live authentication or egress "
            "occurred, and dummy credential values are never recorded."
        )
    return {
        "format_version": 1,
        "scan_id": scan.id,
        "server_slug": scan.server_slug,
        "server": server.model_dump(mode="json"),
        "scan": scan.model_dump(mode="json"),
        "evidence": scan.evidence.model_dump(mode="json") if scan.evidence else None,
        "danger_score": grading.danger_score(scan.risk),
        "sandbox": _sandbox_provenance(server, scan),
        "scanner": {
            "engine_name": scan.engine_name,
            "engine_version": scan.engine_version,
            "scanner_git_ref": os.environ.get(_SCANNER_GIT_REF_ENV),
        },
        "approval": {
            "approval_ref": os.environ.get(_SCAN_APPROVAL_REF_ENV),
        },
        "caveats": caveats,
    }


def write_scan_receipt(
    server: Server,
    scan: ScanRecord,
    receipts_dir: Path | None = None,
) -> str | None:
    """Write a receipt JSON file and return its portable artifact name.

    Returns ``None`` when receipt writing is not configured.
    """
    destination_dir = receipts_dir if receipts_dir is not None else receipts_dir_from_env()
    if destination_dir is None:
        return None

    destination_dir.mkdir(parents=True, exist_ok=True)
    receipt_path = destination_dir / f"{scan.server_slug}-{scan.id}.json"
    tmp_path = receipt_path.with_suffix(".json.tmp")
    payload = build_scan_receipt(server, scan)
    tmp_path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    tmp_path.replace(receipt_path)
    return receipt_path.name
