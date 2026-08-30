#!/usr/bin/env python3
"""Create, verify, approve, or locally stage a refresh candidate.

This command has no deployment authority. Candidate creation scans only through
the existing network-off Docker/MCPAudit path and fails before scanning when
the daemon, a pinned image, or required evidence is unavailable.
"""

from __future__ import annotations

import argparse
import json
import os
from pathlib import Path

from mcp_trust.refresh import (
    RefreshCandidateError,
    approve_refresh_candidate,
    create_refresh_candidate,
    publish_refresh_candidate,
    verify_refresh_candidate,
)
from mcp_trust.target_scan import (
    create_target_scan_artifact,
    verify_target_scan_artifact,
)


class _SingleTargetAction(argparse.Action):
    """Reject repeated target selectors instead of silently taking the last one."""

    def __call__(
        self,
        parser: argparse.ArgumentParser,
        namespace: argparse.Namespace,
        values: str,
        option_string: str | None = None,
    ) -> None:
        if getattr(namespace, self.dest, None) is not None:
            parser.error(f"{option_string or self.dest} may be supplied exactly once")
        setattr(namespace, self.dest, values)


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    subcommands = parser.add_subparsers(dest="command", required=True)

    create = subcommands.add_parser("create", help="Create one immutable review candidate.")
    create.add_argument("--db", type=Path, default=Path("registry.db"))
    create.add_argument(
        "--seed",
        type=Path,
        default=Path("src/mcp_trust/catalog/seed_servers.json"),
    )
    create.add_argument("--masked-grades", type=Path, default=Path("masked-grades.json"))
    create.add_argument(
        "--out-dir",
        type=Path,
        default=Path("dist/refresh-candidates"),
    )
    create.add_argument(
        "--sandbox-image",
        default=os.environ.get(
            "MCP_TRUST_SANDBOX_IMAGE",
            "mcp-trust-scan:corpus-2026-07-03",
        ),
    )
    create.add_argument("--name")
    create.add_argument(
        "--repo-root",
        type=Path,
        default=Path.cwd(),
        help="Git worktree whose exact clean source binding qualified execution.",
    )
    create.add_argument(
        "--qualification-receipt",
        type=Path,
        required=True,
        help="READY review-only preflight receipt bound into the candidate.",
    )
    create.add_argument(
        "--policy",
        type=Path,
        default=Path("src/mcp_trust/catalog/refresh_policy.json"),
        help="Reviewed execution policy whose scannable rows may run.",
    )

    target = subcommands.add_parser(
        "target-receipt",
        help="Create one review-only target receipt without changing the registry.",
    )
    target.add_argument("--slug", required=True, action=_SingleTargetAction)
    target.add_argument("--db", type=Path, required=True)
    target.add_argument(
        "--expected-db-canonical-path-sha256",
        required=True,
        help="Operator-authorized sha256 of the canonical absolute registry DB path.",
    )
    target.add_argument(
        "--expected-db-content-sha256",
        required=True,
        help="Operator-authorized sha256 of the exact registry DB bytes.",
    )
    target.add_argument(
        "--seed",
        type=Path,
        default=None,
    )
    target.add_argument("--masked-grades", type=Path, default=None)
    target.add_argument(
        "--policy",
        type=Path,
        default=None,
    )
    target.add_argument("--qualification-receipt", type=Path, required=True)
    target.add_argument("--repo-root", type=Path, default=Path.cwd())
    target.add_argument("--out", type=Path, required=True)

    verify = subcommands.add_parser("verify", help="Verify a candidate without mutation.")
    verify.add_argument("candidate", type=Path)
    verify.add_argument(
        "--seed",
        type=Path,
        default=Path("src/mcp_trust/catalog/seed_servers.json"),
    )
    verify.add_argument("--masked-grades", type=Path, default=Path("masked-grades.json"))
    verify.add_argument("--repo-root", type=Path, default=Path.cwd())

    approve = subcommands.add_parser(
        "approve",
        help="Create a short-lived approval bound to one candidate and local target.",
    )
    approve.add_argument("candidate", type=Path)
    approve.add_argument("--approval", type=Path, required=True)
    approve.add_argument("--actor", required=True)
    approve.add_argument("--reason", required=True)
    approve.add_argument("--target", type=Path, required=True)
    approve.add_argument(
        "--seed",
        type=Path,
        default=Path("src/mcp_trust/catalog/seed_servers.json"),
    )
    approve.add_argument("--masked-grades", type=Path, default=Path("masked-grades.json"))
    approve.add_argument("--repo-root", type=Path, default=Path.cwd())
    approve.add_argument(
        "--confirm-manifest-sha256",
        required=True,
        help="Exact digest printed by the verify command.",
    )

    publish = subcommands.add_parser(
        "publish",
        help="Atomically stage an approved candidate locally; never deploy.",
    )
    publish.add_argument("candidate", type=Path)
    publish.add_argument("--approval", type=Path, required=True)
    publish.add_argument("--destination", type=Path, required=True)
    publish.add_argument(
        "--seed",
        type=Path,
        default=Path("src/mcp_trust/catalog/seed_servers.json"),
    )
    publish.add_argument("--masked-grades", type=Path, default=Path("masked-grades.json"))
    publish.add_argument("--repo-root", type=Path, default=Path.cwd())
    return parser


def _target_receipt_inputs(
    args: argparse.Namespace,
) -> tuple[Path, Path, Path, Path]:
    """Bind omitted reviewed inputs to the exact target-receipt source root."""
    repo_root = args.repo_root.resolve()
    seed_path = (
        args.seed
        if args.seed is not None
        else repo_root / "src/mcp_trust/catalog/seed_servers.json"
    )
    masked_path = (
        args.masked_grades
        if args.masked_grades is not None
        else repo_root / "masked-grades.json"
    )
    policy_path = (
        args.policy
        if args.policy is not None
        else repo_root / "src/mcp_trust/catalog/refresh_policy.json"
    )
    return repo_root, seed_path, masked_path, policy_path


def main(argv: list[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    try:
        if args.command == "create":
            candidate = create_refresh_candidate(
                source_db=args.db,
                seed_path=args.seed,
                masked_path=args.masked_grades,
                output_parent=args.out_dir,
                default_image=args.sandbox_image,
                candidate_name=args.name,
                repo_root=args.repo_root,
                policy_path=args.policy,
                qualification_receipt=json.loads(
                    args.qualification_receipt.read_text(encoding="utf-8")
                ),
            )
            verification = verify_refresh_candidate(
                candidate,
                expected_seed_path=args.seed,
                expected_masked_path=args.masked_grades,
                repo_root=args.repo_root,
            )
            print(
                json.dumps(
                    {
                        "candidate": str(candidate),
                        **verification,
                        "deployment_performed": False,
                    },
                    indent=2,
                    sort_keys=True,
                )
            )
            return 0 if verification["publication_ready"] else 1
        if args.command == "target-receipt":
            repo_root, seed_path, masked_path, policy_path = _target_receipt_inputs(args)
            artifact = create_target_scan_artifact(
                slug=args.slug,
                source_db=args.db,
                expected_db_canonical_path_sha256=args.expected_db_canonical_path_sha256,
                expected_db_content_sha256=args.expected_db_content_sha256,
                seed_path=seed_path,
                masked_path=masked_path,
                policy_path=policy_path,
                qualification_receipt_path=args.qualification_receipt,
                repo_root=repo_root,
                output_path=args.out,
            )
            verification = verify_target_scan_artifact(
                artifact,
                source_db=args.db,
                expected_db_canonical_path_sha256=args.expected_db_canonical_path_sha256,
                expected_db_content_sha256=args.expected_db_content_sha256,
                seed_path=seed_path,
                masked_path=masked_path,
                policy_path=policy_path,
                qualification_receipt_path=args.qualification_receipt,
                repo_root=repo_root,
            )
            print(json.dumps(verification, indent=2, sort_keys=True))
            return 0 if verification["verified"] else 1
        if args.command == "verify":
            verification = verify_refresh_candidate(
                args.candidate,
                expected_seed_path=args.seed,
                expected_masked_path=args.masked_grades,
                repo_root=args.repo_root,
            )
            print(json.dumps(verification, indent=2, sort_keys=True))
            return 0 if verification["publication_ready"] else 1
        if args.command == "approve":
            path = approve_refresh_candidate(
                candidate=args.candidate,
                approval_path=args.approval,
                actor=args.actor,
                reason=args.reason,
                publication_target=args.target,
                confirmation_digest=args.confirm_manifest_sha256,
                seed_path=args.seed,
                masked_path=args.masked_grades,
                repo_root=args.repo_root,
            )
            print(path)
            return 0
        if args.command == "publish":
            path = publish_refresh_candidate(
                candidate=args.candidate,
                approval_path=args.approval,
                destination_parent=args.destination,
                seed_path=args.seed,
                masked_path=args.masked_grades,
                repo_root=args.repo_root,
            )
            print(path)
            return 0
    except RefreshCandidateError as exc:
        print(f"refresh candidate refused: {exc}", file=os.sys.stderr)
        return 1
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
