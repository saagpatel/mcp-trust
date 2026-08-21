from __future__ import annotations

import copy
import importlib.util
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts" / "verify_reference_corpus_evidence.py"
SPEC = importlib.util.spec_from_file_location("verify_reference_corpus_evidence", SCRIPT)
assert SPEC is not None and SPEC.loader is not None
module = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(module)


def test_committed_reference_corpus_evidence_and_docs_match() -> None:
    result = module.verify(ROOT)

    assert result["engine"] == "mcpaudit@2.7.0"
    assert result["rows"] == 7
    assert result["distribution"]["grades"] == {"A": 1, "B": 3, "C": 1, "D": 1, "F": 1}
    assert result["distribution"]["transparency"] == {
        "high": 3,
        "medium": 0,
        "low": 4,
    }


def test_distribution_must_be_derived_from_rows() -> None:
    payload = module.load_evidence(ROOT / "docs/reference-corpus-evidence-v1.json")
    drifted = copy.deepcopy(payload)
    drifted["distribution"]["grades"]["B"] = 2

    with pytest.raises(module.EvidenceError, match="distribution"):
        module.validate_evidence(drifted)


def test_launch_docs_must_match_evidence(tmp_path: Path) -> None:
    payload = module.load_evidence(ROOT / "docs/reference-corpus-evidence-v1.json")
    for name in ("LAUNCH-CATALOG.md", "LAUNCH-GATE.md"):
        text = (ROOT / name).read_text(encoding="utf-8")
        (tmp_path / name).write_text(
            text.replace("A=1, B=3, C=1, D=1, F=1", "A=1, B=2, C=1, D=1, F=2"),
            encoding="utf-8",
        )

    with pytest.raises(module.EvidenceError, match="stale corpus claim remains"):
        module.validate_docs(tmp_path, payload)


def test_launch_docs_reject_a_duplicate_stale_claim(tmp_path: Path) -> None:
    payload = module.load_evidence(ROOT / "docs/reference-corpus-evidence-v1.json")
    for name in ("LAUNCH-CATALOG.md", "LAUNCH-GATE.md"):
        text = (ROOT / name).read_text(encoding="utf-8")
        (tmp_path / name).write_text(
            f"{text}\nA=1, B=2, C=1, D=1, F=2\n",
            encoding="utf-8",
        )

    with pytest.raises(module.EvidenceError, match="stale corpus claim remains"):
        module.validate_docs(tmp_path, payload)
