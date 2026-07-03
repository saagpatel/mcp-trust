from __future__ import annotations

from types import SimpleNamespace

from mcp_trust.engine.mcpaudit import _build_evidence


def test_build_evidence_hashes_schemas_without_storing_raw_schema() -> None:
    audit = SimpleNamespace(
        tools=[
            SimpleNamespace(
                name="search_docs",
                input_schema={
                    "type": "object",
                    "properties": {"query": {"type": "string"}},
                    "required": ["query"],
                },
                annotations=SimpleNamespace(readOnlyHint=True),
            ),
            SimpleNamespace(name="ping", input_schema=None, annotations=None),
        ],
        prompts=[object()],
        resources=[object(), object()],
    )

    evidence = _build_evidence(audit)

    assert evidence.tool_count == 2
    assert evidence.prompt_count == 1
    assert evidence.resource_count == 2
    assert evidence.tools[0].name == "search_docs"
    assert evidence.tools[0].has_input_schema is True
    assert len(evidence.tools[0].input_schema_sha256 or "") == 64
    assert evidence.tools[0].has_annotations is True
    assert evidence.tools[1].has_input_schema is False
    assert evidence.tools[1].input_schema_sha256 is None
