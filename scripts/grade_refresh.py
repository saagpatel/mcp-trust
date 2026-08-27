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
    canonical_bytes,
    catalog_inventory,
    load_json,
    publication_review_markdown,
    triage_candidate,
)
from mcp_trust.operator_package import (
    build_operator_review_package,
    verify_operator_review_package,
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
    triage.add_argument("--repeat-candidate", type=Path, required=True)
    triage.add_argument("--preflight", type=Path, required=True)
    triage.add_argument("--repeatability", type=Path, required=True)
    triage.add_argument("--repo-root", type=Path, default=_ROOT)
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
    package.add_argument("--repo-root", type=Path, default=_ROOT)
    package.add_argument("--out-dir", type=Path, required=True)

    verify_package = subcommands.add_parser(
        "verify-package",
        help="Independently re-read one local operator package and all receipt inputs.",
    )
    _common_inputs(verify_package)
    verify_package.add_argument("--package", type=Path, required=True)
    verify_package.add_argument("--preflight", type=Path, required=True)
    verify_package.add_argument("--repeatability", type=Path, required=True)
    verify_package.add_argument("--triage", type=Path)
    verify_package.add_argument("--candidate", type=Path)
    verify_package.add_argument("--repeat-candidate", type=Path)
    verify_package.add_argument("--task-id", required=True)
    verify_package.add_argument("--repo-root", type=Path, default=_ROOT)

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
    publication_review.add_argument("--repo-root", type=Path, default=_ROOT)
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


def main(argv: list[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    now = datetime.now(tz=UTC)
    try:
        if args.command == "inventory":
            payload = catalog_inventory(
                seed_path=args.seed,
                masked_path=args.masked_grades,
                repo_root=args.repo_root,
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
                repo_root=args.repo_root,
                repeat_candidate=args.repeat_candidate,
            )
            _emit(payload, args.out)
            return 0
        if args.command == "package":
            output = build_operator_review_package(
                output_path=args.out_dir,
                task_id=args.task_id,
                preflight_path=args.preflight,
                repeatability_path=args.repeatability,
                triage_path=args.triage,
                candidate_path=args.candidate,
                repeat_candidate_path=args.repeat_candidate,
                seed_path=args.seed,
                masked_path=args.masked_grades,
                policy_path=args.policy,
                repo_root=args.repo_root,
                now=now,
            )
            _emit(
                verify_operator_review_package(
                    output,
                    task_id=args.task_id,
                    preflight_path=args.preflight,
                    repeatability_path=args.repeatability,
                    triage_path=args.triage,
                    candidate_path=args.candidate,
                    repeat_candidate_path=args.repeat_candidate,
                    seed_path=args.seed,
                    masked_path=args.masked_grades,
                    policy_path=args.policy,
                    repo_root=args.repo_root,
                    now=now,
                ),
                None,
            )
            return 0
        if args.command == "verify-package":
            _emit(
                verify_operator_review_package(
                    args.package,
                    task_id=args.task_id,
                    preflight_path=args.preflight,
                    repeatability_path=args.repeatability,
                    triage_path=args.triage,
                    candidate_path=args.candidate,
                    repeat_candidate_path=args.repeat_candidate,
                    seed_path=args.seed,
                    masked_path=args.masked_grades,
                    policy_path=args.policy,
                    repo_root=args.repo_root,
                    now=now,
                ),
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
                repo_root=args.repo_root,
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
