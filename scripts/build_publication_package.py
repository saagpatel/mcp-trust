#!/usr/bin/env python3
"""Verify local content approval or build a deterministic non-publishing package."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from mcp_trust.site.publication import (
    PublicationAdmissionError,
    build_publication_package,
    verify_publication_approval,
    verify_publication_package,
)


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument("--verify-approval", type=Path)
    mode.add_argument("--verify-package", type=Path)
    mode.add_argument("--build", action="store_true")
    parser.add_argument("--candidate", type=Path)
    parser.add_argument("--approval", type=Path)
    parser.add_argument("--out", type=Path)
    return parser


def main(argv: list[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    try:
        if args.verify_approval is not None:
            if args.candidate is None or args.approval is not None or args.out is not None:
                raise PublicationAdmissionError(
                    "--verify-approval requires --candidate and no build arguments"
                )
            result = verify_publication_approval(
                args.verify_approval,
                candidate_path=args.candidate,
            )
        elif args.verify_package is not None:
            if args.approval is None or args.candidate is not None or args.out is not None:
                raise PublicationAdmissionError(
                    "--verify-package requires --approval and no build arguments"
                )
            result = verify_publication_package(
                args.verify_package,
                approval_path=args.approval,
            )
        else:
            if args.candidate is None or args.approval is None or args.out is None:
                raise PublicationAdmissionError(
                    "--build requires --candidate, --approval, and --out"
                )
            output = build_publication_package(
                candidate_path=args.candidate,
                approval_path=args.approval,
                output_path=args.out,
            )
            result = {
                "path": str(output),
                **verify_publication_package(output, approval_path=args.approval),
            }
        print(json.dumps(result, indent=2, sort_keys=True))
        return 0
    except (OSError, PublicationAdmissionError, ValueError) as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
