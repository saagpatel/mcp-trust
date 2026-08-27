"""Deterministic receipt fixtures shared by grade-refresh tests."""

from __future__ import annotations

import copy
from datetime import datetime
from pathlib import Path
from typing import Any

from mcp_trust import grade_refresh
from mcp_trust.engine.runtime import MCP_AUDIT_RUNTIME_MODULES


def engine_materialization_receipt(
    *,
    source_binding: dict[str, Any],
    observed_at: datetime,
    repo_root: Path,
    python_version: str = "3.11.15",
) -> dict[str, Any]:
    """Build a structurally exact READY receipt without observing host state."""
    lock_binding = grade_refresh._locked_engine_binding(repo_root)
    assert lock_binding is not None
    payload: dict[str, Any] = {
        "schema": grade_refresh.ENGINE_MATERIALIZATION_SCHEMA,
        "observed_at": observed_at.isoformat(),
        "status": "READY",
        "safe_to_execute": True,
        "exit_classification": "ready",
        "source_binding": copy.deepcopy(source_binding),
        "lock_binding": lock_binding,
        "environment": {
            "project_environment": ".venv",
            "project_environment_bound": True,
            "python": python_version,
            "required_python": python_version,
            "python_pin_sha256": "sha256:" + "1" * 64,
            "python_implementation": "CPython",
            "python_executable": "python3.11",
            "python_executable_sha256": "sha256:" + "2" * 64,
            "uv": {
                "version": "0.12.5",
                "executable": "uv",
                "executable_sha256": "sha256:" + "3" * 64,
            },
            "mcp_audits": grade_refresh.EXPECTED_MCP_AUDITS_VERSION,
        },
        "distribution_binding": {
            "distribution": {
                "name": "mcp-audits",
                "version": grade_refresh.EXPECTED_MCP_AUDITS_VERSION,
                "metadata_version": "2.4",
                "installer": "uv",
                "record_path": "mcp_audits-2.7.0.dist-info/RECORD",
                "record_sha256": "sha256:" + "4" * 64,
                "record_size": 100,
            },
            "modules": [
                {
                    "module": module,
                    "path": module.replace(".", "/") + ".py",
                    "origin": module.replace(".", "/") + ".py",
                    "record_hash": "sha256=" + "A" * 43,
                    "sha256": "sha256:" + f"{index:064x}",
                    "size": index,
                }
                for index, module in enumerate(MCP_AUDIT_RUNTIME_MODULES, start=1)
            ],
        },
        "reasons": [],
        "authority": {
            "observation_only": True,
            "package_install_performed": False,
            "registry_request_performed": False,
            "docker_invoked": False,
            "mcp_execution": False,
            "publication_performed": False,
            "deployment_performed": False,
            "scheduler_change_performed": False,
        },
        "claim_ceiling": "Deterministic test fixture only.",
    }
    payload["receipt_digest"] = grade_refresh.digest_bytes(grade_refresh.canonical_bytes(payload))
    return payload
