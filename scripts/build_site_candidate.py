#!/usr/bin/env python3
"""Build or verify a deterministic, non-publishing static-site candidate."""

from __future__ import annotations

import argparse
import hashlib
import json
import subprocess
import sys
from pathlib import Path

from mcp_trust.site.candidate import (
    SiteCandidateError,
    build_site_candidate,
    site_candidate_readback_manifest,
    verify_site_candidate,
)

ROOT = Path(__file__).resolve().parents[1]


def _implementation_binding() -> dict[str, str]:
    status = subprocess.run(
        ["git", "status", "--porcelain", "--untracked-files=all"],
        cwd=ROOT,
        check=True,
        text=True,
        capture_output=True,
    ).stdout
    if status:
        raise SiteCandidateError("site candidate build requires a clean committed worktree")
    revision = subprocess.run(
        ["git", "rev-parse", "HEAD"],
        cwd=ROOT,
        check=True,
        text=True,
        capture_output=True,
    ).stdout.strip()
    tree = subprocess.run(
        ["git", "ls-tree", "-r", "--full-tree", "HEAD"],
        cwd=ROOT,
        check=True,
        capture_output=True,
    ).stdout
    return {
        "state": "CLEAN_COMMITTED",
        "revision": revision,
        "source_tree_digest": "sha256:" + hashlib.sha256(tree).hexdigest(),
    }


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    read_mode = parser.add_mutually_exclusive_group()
    read_mode.add_argument(
        "--verify", type=Path, help="Verify an existing site-candidate directory."
    )
    read_mode.add_argument(
        "--readback-manifest",
        type=Path,
        help="Emit the candidate's receipt-bound exact public readback manifest.",
    )
    parser.add_argument("--candidate", type=Path, help="Verified refresh-candidate directory.")
    parser.add_argument(
        "--review",
        type=Path,
        default=ROOT / "src/mcp_trust/catalog/sanitized_publication_review_v24.json",
    )
    parser.add_argument(
        "--disposition",
        type=Path,
        default=ROOT / "src/mcp_trust/catalog/refresh_disposition_policy.json",
    )
    parser.add_argument(
        "--seed",
        type=Path,
        default=ROOT / "src/mcp_trust/catalog/seed_servers.json",
    )
    parser.add_argument("--masked-grades", type=Path, default=ROOT / "masked-grades.json")
    parser.add_argument(
        "--policy",
        type=Path,
        default=ROOT / "src/mcp_trust/catalog/refresh_policy.json",
    )
    parser.add_argument("--corrections", type=Path, default=ROOT / "corrections.json")
    parser.add_argument("--out", type=Path)
    parser.add_argument("--base-url", default="https://mcp-trust.vercel.app")
    parser.add_argument("--rollback-candidate", type=Path)
    return parser


def main(argv: list[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    try:
        if args.verify is not None:
            if args.candidate is not None or args.out is not None:
                raise SiteCandidateError("--verify cannot be combined with build arguments")
            result = verify_site_candidate(args.verify)
            print(json.dumps(result, indent=2, sort_keys=True))
            return 0
        if args.readback_manifest is not None:
            if args.candidate is not None or args.out is not None:
                raise SiteCandidateError(
                    "--readback-manifest cannot be combined with build arguments"
                )
            result = site_candidate_readback_manifest(args.readback_manifest)
            print(json.dumps(result, indent=2, sort_keys=True))
            return 0
        if args.candidate is None or args.out is None:
            raise SiteCandidateError("build mode requires --candidate and --out")
        output = build_site_candidate(
            candidate_path=args.candidate,
            review_path=args.review,
            disposition_path=args.disposition,
            seed_path=args.seed,
            masked_path=args.masked_grades,
            policy_path=args.policy,
            corrections_path=args.corrections,
            output_path=args.out,
            base_url=args.base_url,
            rollback_candidate=args.rollback_candidate,
            implementation_binding=_implementation_binding(),
        )
        result = verify_site_candidate(output)
        print(json.dumps({"path": str(output), **result}, indent=2, sort_keys=True))
        return 0
    except (OSError, SiteCandidateError, ValueError, subprocess.CalledProcessError) as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
