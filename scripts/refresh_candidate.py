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

    verify = subcommands.add_parser("verify", help="Verify a candidate without mutation.")
    verify.add_argument("candidate", type=Path)
    verify.add_argument(
        "--seed",
        type=Path,
        default=Path("src/mcp_trust/catalog/seed_servers.json"),
    )
    verify.add_argument("--masked-grades", type=Path, default=Path("masked-grades.json"))

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
    return parser


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
            )
            verification = verify_refresh_candidate(
                candidate,
                expected_seed_path=args.seed,
                expected_masked_path=args.masked_grades,
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
        if args.command == "verify":
            verification = verify_refresh_candidate(
                args.candidate,
                expected_seed_path=args.seed,
                expected_masked_path=args.masked_grades,
            )
            print(json.dumps(verification, indent=2, sort_keys=True))
            return 0 if verification["structural_valid"] else 1
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
            )
            print(path)
            return 0
    except RefreshCandidateError as exc:
        print(f"refresh candidate refused: {exc}", file=os.sys.stderr)
        return 1
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
