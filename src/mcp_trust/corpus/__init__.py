"""Discovery-only corpus planning and reviewed-record helpers.

These helpers never scan, install, launch, authenticate, or contact MCP servers.
They turn already-fetched public metadata into reviewable candidate manifests.
"""

from mcp_trust.corpus.records import CorpusRecordSet, PublicCorpusRecord, summarize_corpus_records
from mcp_trust.corpus.registry import build_registry_candidate_manifest

__all__ = [
    "CorpusRecordSet",
    "PublicCorpusRecord",
    "build_registry_candidate_manifest",
    "summarize_corpus_records",
]
