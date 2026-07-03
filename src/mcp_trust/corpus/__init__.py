"""Discovery-only corpus planning helpers.

These helpers never scan, install, launch, authenticate, or contact MCP servers.
They turn already-fetched public metadata into reviewable candidate manifests.
"""

from mcp_trust.corpus.registry import build_registry_candidate_manifest

__all__ = ["build_registry_candidate_manifest"]
