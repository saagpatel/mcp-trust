"""Workflow pin and history requirements."""

from __future__ import annotations

import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def test_workflow_actions_are_pinned_and_checkout_keeps_history() -> None:
    workflows = sorted((ROOT / ".github/workflows").glob("*.yml"))
    assert workflows

    for workflow in workflows:
        contents = workflow.read_text(encoding="utf-8")
        for line in contents.splitlines():
            if re.match(r"\s*-?\s*uses:\s*", line):
                assert re.search(r"@[0-9a-fA-F]{40}(?:\s|$)", line), line
        assert re.search(r"fetch-depth:\s*0", contents), workflow.name
