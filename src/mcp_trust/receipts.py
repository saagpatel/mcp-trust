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

_RECEIPTS_DIR_ENV = "MCP_TRUST_RECEIPTS_DIR"
_SCAN_APPROVAL_REF_ENV = "MCP_TRUST_SCAN_APPROVAL_REF"
_SCANNER_GIT_REF_ENV = "MCP_TRUST_SCANNER_GIT_REF"
_SANDBOX_ENV_KEYS = (
    "MCP_TRUST_SANDBOX",
    "MCP_TRUST_SANDBOX_IMAGE",
    "MCP_TRUST_SANDBOX_NETWORK",
)


def receipts_dir_from_env() -> Path | None:
    """Return the configured receipt directory, or ``None`` when disabled."""
    value = os.environ.get(_RECEIPTS_DIR_ENV)
    if not value:
        return None
    return Path(value)


def build_scan_receipt(server: Server, scan: ScanRecord) -> dict[str, Any]:
    """Build the public proof packet for one persisted scan."""
    return {
        "format_version": 1,
        "scan_id": scan.id,
        "server_slug": scan.server_slug,
        "server": server.model_dump(mode="json"),
        "scan": scan.model_dump(mode="json"),
        "danger_score": grading.danger_score(scan.risk),
        "sandbox": {key: os.environ.get(key) for key in _SANDBOX_ENV_KEYS if os.environ.get(key)},
        "scanner": {
            "engine_name": scan.engine_name,
            "engine_version": scan.engine_version,
            "scanner_git_ref": os.environ.get(_SCANNER_GIT_REF_ENV),
        },
        "approval": {
            "approval_ref": os.environ.get(_SCAN_APPROVAL_REF_ENV),
        },
        "caveats": [
            "Automated scan output is not an endorsement.",
            "Danger grade and transparency are separate signals.",
            "Low transparency means cannot verify safe, not known dangerous.",
            "Network-off sandboxing may suppress behavior that requires live egress.",
        ],
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
