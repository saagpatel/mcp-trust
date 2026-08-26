#!/usr/bin/env python3
"""Review-only MCP Trust grade-refresh qualification entrypoint.

No subcommand can publish, deploy, change a scheduler, or run a real MCP
server.  ``preflight`` stops before execution and ``fixture-repeat`` uses only
the deterministic in-process StubEngine.
"""

from __future__ import annotations

import argparse
import os
import sys
from datetime import UTC, datetime
from pathlib import Path

from mcp_trust.grade_refresh import (
    GradeRefreshError,
    build_fixture_repeatability_receipt,
    build_preflight_receipt,
    build_publication_review_decision,
    build_publication_review_state_card,
    build_resume_capsule,
    build_state_card,
    canonical_bytes,
    catalog_inventory,
    load_json,
    publication_review_markdown,
    triage_candidate,
)

_ROOT = Path(__file__).resolve().parents[1]
_SEED = _ROOT / "src/mcp_trust/catalog/seed_servers.json"
_MASKED = _ROOT / "masked-grades.json"
_POLICY = _ROOT / "src/mcp_trust/catalog/refresh_policy.json"
_DISPOSITIONS = _ROOT / "src/mcp_trust/catalog/refresh_disposition_policy.json"
_ACCEPTED_REVIEW = (
    _ROOT / "src/mcp_trust/catalog/accepted_publication_review_v38.json"
)


def _write_json(path: Path, payload: object) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    descriptor = os.open(path, flags, 0o600)
    try:
        content = canonical_bytes(payload)
        written = os.write(descriptor, content)
        if written != len(content):
            raise OSError("short receipt write")
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def _emit(payload: object, out: Path | None) -> None:
    if out is not None:
        _write_json(out, payload)
    sys.stdout.buffer.write(canonical_bytes(payload))


def _write_text(path: Path, content: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    descriptor = os.open(path, flags, 0o600)
    try:
        encoded = content.encode("utf-8")
        written = os.write(descriptor, encoded)
        if written != len(encoded):
            raise OSError("short text write")
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def _common_inputs(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--seed", type=Path, default=_SEED)
    parser.add_argument("--masked-grades", type=Path, default=_MASKED)
    parser.add_argument("--policy", type=Path, default=_POLICY)


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    subcommands = parser.add_subparsers(dest="command", required=True)

    inventory = subcommands.add_parser("inventory", help="Emit the exact 31-entry inventory.")
    _common_inputs(inventory)
    inventory.add_argument("--out", type=Path)

    preflight = subcommands.add_parser(
        "preflight", help="Bind source/tool/image state without executing a catalog server."
    )
    _common_inputs(preflight)
    preflight.add_argument("--repo-root", type=Path, default=_ROOT)
    preflight.add_argument("--out", type=Path)

    repeat = subcommands.add_parser(
        "fixture-repeat", help="Run the deterministic in-process fixture corpus twice."
    )
    _common_inputs(repeat)
    repeat.add_argument("--out", type=Path)

    triage = subcommands.add_parser(
        "triage", help="Create severity-first review triage for one immutable candidate."
    )
    _common_inputs(triage)
    triage.add_argument("--candidate", type=Path, required=True)
    triage.add_argument("--repeat-candidate", type=Path)
    triage.add_argument("--preflight", type=Path, required=True)
    triage.add_argument("--repeatability", type=Path, required=True)
    triage.add_argument("--out", type=Path)

    package = subcommands.add_parser(
        "package", help="Write a local operator review package; never publish it."
    )
    _common_inputs(package)
    package.add_argument("--preflight", type=Path, required=True)
    package.add_argument("--repeatability", type=Path, required=True)
    package.add_argument("--triage", type=Path)
    package.add_argument("--candidate", type=Path)
    package.add_argument("--repeat-candidate", type=Path)
    package.add_argument("--task-id", required=True)
    package.add_argument("--out-dir", type=Path, required=True)

    publication_review = subcommands.add_parser(
        "publication-review",
        help="Build a deterministic local disposition packet; never publish it.",
    )
    _common_inputs(publication_review)
    publication_review.add_argument("--candidate", type=Path, required=True)
    publication_review.add_argument("--repeat-candidate", type=Path, required=True)
    publication_review.add_argument("--preflight", type=Path, required=True)
    publication_review.add_argument("--repeatability", type=Path, required=True)
    publication_review.add_argument("--triage", type=Path, required=True)
    publication_review.add_argument(
        "--dispositions", type=Path, default=_DISPOSITIONS
    )
    publication_review.add_argument(
        "--accepted-review",
        type=Path,
        default=_ACCEPTED_REVIEW,
        help="Receipt-bound proposal artifact named by the disposition policy.",
    )
    publication_review.add_argument("--out", type=Path)
    publication_review.add_argument("--markdown-out", type=Path)
    publication_review.add_argument("--state-card-out", type=Path)
    return parser


def _review_markdown(state: dict[str, object]) -> str:
    gates = state.get("outstanding_gates")
    gate_lines = (
        "\n".join(f"- {gate}" for gate in gates)
        if isinstance(gates, list) and gates
        else "- none"
    )
    findings = state.get("findings")
    finding_lines = (
        "\n".join(
            f"- {finding.get('severity', 'UNKNOWN')}: "
            f"`{finding.get('code', 'unknown')}` ({finding.get('scope', 'catalog')})"
            for finding in findings
            if isinstance(finding, dict)
        )
        if isinstance(findings, list) and findings
        else "- none"
    )
    return f"""# MCP Trust grade-refresh operator review

This package is review-only. It grants no publication, deployment, scheduler,
credential, third-party execution, or outreach authority.

## Current decision

- Source revision: `{state.get('source_revision', 'UNKNOWN')}`
- Source tree digest: `{state.get('source_tree_digest', 'UNKNOWN')}`
- Catalog denominator: `{state.get('catalog_denominator', 0)}`
- Catalog execution ready: `{state.get('safe_to_execute_catalog', False)}`
- Fixture repeatability: `{state.get('fixture_repeatability', 'UNKNOWN')}`
- Production freshness: `{state.get('production_freshness', 'UNKNOWN')}`
- Publication state: `{state.get('publication_state', 'UNKNOWN')}`

## Findings (Critical, High, Medium, Low)

{finding_lines}

## Outstanding gates

{gate_lines}

## Next action

{state.get('next_action', 'UNKNOWN')}
"""


def _rollback_markdown() -> str:
    return """# Future publication rollback procedure

Rollback is a separate, explicitly approved publication action. Before any
future publication, retain the prior deployment revision, site artifact digest,
catalog snapshot digest, masking digest, and provider deployment identifier.

If post-publication readback fails or differs from the approved candidate:

1. Stop; do not rescan, rebuild, or overwrite evidence.
2. Mark the new publication `WITHDRAWN_PENDING_REVIEW` and preserve receipts.
3. Re-authorize the exact prior immutable site artifact and deployment target.
4. Restore only through the manual deployment lane with its TTY confirmation.
5. Read back health, catalog denominator, masking, grade/staleness semantics,
   badges, source identity, and denied scan POST behavior.
6. Record both failed and restored deployment identifiers and artifact digests.

Local candidate deletion, scheduler enablement, force pushes, and provider
rollback commands are not authorized by this document.
"""


def main(argv: list[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    now = datetime.now(tz=UTC)
    try:
        if args.command == "inventory":
            payload = catalog_inventory(
                seed_path=args.seed,
                masked_path=args.masked_grades,
                policy_path=args.policy,
            )
            _emit(payload, args.out)
            return 0
        if args.command == "preflight":
            payload = build_preflight_receipt(
                repo_root=args.repo_root,
                seed_path=args.seed,
                masked_path=args.masked_grades,
                policy_path=args.policy,
                now=now,
                include_scheduler_readback=True,
            )
            _emit(payload, args.out)
            return 0 if payload["status"] == "READY" else 2
        if args.command == "fixture-repeat":
            payload = build_fixture_repeatability_receipt(
                seed_path=args.seed,
                masked_path=args.masked_grades,
                policy_path=args.policy,
                now=now,
            )
            _emit(payload, args.out)
            return 0 if payload["status"] == "PASS" else 2
        if args.command == "triage":
            payload = triage_candidate(
                candidate=args.candidate,
                preflight=load_json(args.preflight),
                repeatability=load_json(args.repeatability),
                seed_path=args.seed,
                masked_path=args.masked_grades,
                repeat_candidate=args.repeat_candidate,
            )
            _emit(payload, args.out)
            return 0
        if args.command == "package":
            preflight = load_json(args.preflight)
            repeatability = load_json(args.repeatability)
            triage = None
            if args.triage is not None:
                if args.candidate is None:
                    raise GradeRefreshError(
                        "package requires --candidate to independently verify triage"
                    )
                supplied_triage = load_json(args.triage)
                triage = triage_candidate(
                    candidate=args.candidate,
                    preflight=preflight,
                    repeatability=repeatability,
                    seed_path=args.seed,
                    masked_path=args.masked_grades,
                    repeat_candidate=args.repeat_candidate,
                )
                if supplied_triage != triage:
                    raise GradeRefreshError(
                        "triage receipt differs from independently recomputed evidence"
                    )
            state = build_state_card(
                preflight=preflight,
                repeatability=repeatability,
                triage=triage,
            )
            capsule = build_resume_capsule(task_id=args.task_id, state_card=state, now=now)
            args.out_dir.mkdir(parents=True, exist_ok=False)
            _write_json(args.out_dir / "state-card.json", state)
            _write_json(args.out_dir / "HumanGateResumeCapsuleV1.json", capsule)
            (args.out_dir / "operator-review.md").write_text(
                _review_markdown(state), encoding="utf-8"
            )
            (args.out_dir / "rollback.md").write_text(
                _rollback_markdown(), encoding="utf-8"
            )
            _emit(
                {
                    "schema": "McpTrustOperatorReviewPackageV1",
                    "state": "CREATED",
                    "path": str(args.out_dir.resolve()),
                    "publication_allowed": False,
                    "deployment_allowed": False,
                },
                None,
            )
            return 0
        if args.command == "publication-review":
            payload = build_publication_review_decision(
                candidate=args.candidate,
                repeat_candidate=args.repeat_candidate,
                preflight=load_json(args.preflight),
                repeatability=load_json(args.repeatability),
                triage=load_json(args.triage),
                seed_path=args.seed,
                masked_path=args.masked_grades,
                policy_path=args.policy,
                disposition_path=args.dispositions,
                accepted_review_path=args.accepted_review,
            )
            if args.markdown_out is not None:
                _write_text(args.markdown_out, publication_review_markdown(payload))
            if args.state_card_out is not None:
                _write_json(
                    args.state_card_out,
                    build_publication_review_state_card(payload),
                )
            _emit(payload, args.out)
            return 0
    except GradeRefreshError as exc:
        _emit(
            {
                "schema": "McpTrustGradeRefreshErrorV1",
                "state": "UNKNOWN",
                "error": str(exc),
                "publication_allowed": False,
                "deployment_allowed": False,
            },
            None,
        )
        return 2
    raise AssertionError("unreachable command")


if __name__ == "__main__":
    raise SystemExit(main())
