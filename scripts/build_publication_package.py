#!/usr/bin/env python3
"""Verify local content approval or build a deterministic non-publishing package."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from mcp_trust.site.publication import (  # noqa: E402 - isolated script binds repo source
    PublicationAdmissionError,
    build_publication_package,
    verify_production_publication_receipt,
    verify_publication_approval,
    verify_publication_package,
)


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument("--verify-approval", type=Path)
    mode.add_argument("--verify-package", type=Path)
    mode.add_argument("--verify-production-receipt", type=Path)
    mode.add_argument("--build", action="store_true")
    parser.add_argument("--candidate", type=Path)
    parser.add_argument("--approval", type=Path)
    parser.add_argument("--out", type=Path)
    parser.add_argument("--deployment-authorization", type=Path)
    parser.add_argument("--readback-receipt", type=Path)
    return parser


def main(argv: list[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    try:
        if args.verify_approval is not None:
            if (
                args.candidate is None
                or args.approval is not None
                or args.out is not None
                or args.deployment_authorization is not None
                or args.readback_receipt is not None
            ):
                raise PublicationAdmissionError(
                    "--verify-approval requires --candidate and no build arguments"
                )
            result = verify_publication_approval(
                args.verify_approval,
                candidate_path=args.candidate,
            )
        elif args.verify_package is not None:
            if (
                args.approval is None
                or args.candidate is not None
                or args.out is not None
                or args.deployment_authorization is not None
                or args.readback_receipt is not None
            ):
                raise PublicationAdmissionError(
                    "--verify-package requires --approval and no build arguments"
                )
            result = verify_publication_package(
                args.verify_package,
                approval_path=args.approval,
            )
        elif args.verify_production_receipt is not None:
            if (
                args.candidate is None
                or args.approval is None
                or args.deployment_authorization is None
                or args.readback_receipt is None
                or args.out is not None
            ):
                raise PublicationAdmissionError(
                    "--verify-production-receipt requires --candidate package, "
                    "--approval, --deployment-authorization, and --readback-receipt"
                )
            result = verify_production_publication_receipt(
                args.verify_production_receipt,
                package_path=args.candidate,
                approval_path=args.approval,
                deployment_authorization_path=args.deployment_authorization,
                readback_receipt_path=args.readback_receipt,
            )
        else:
            if (
                args.candidate is None
                or args.approval is None
                or args.out is None
                or args.deployment_authorization is not None
                or args.readback_receipt is not None
            ):
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
