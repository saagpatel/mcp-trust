"""Print the approval-gated reference scan plan without running it."""

from __future__ import annotations

import argparse
import json
import shlex
import sys
from typing import TextIO

from reference_scan_plan import IMAGE_TAG, REFERENCE_SCAN_CANDIDATES, SANDBOX_ENV, plan_payload


def write_shell_plan(out: TextIO = sys.stdout) -> None:
    print("# Dry-run only: this prints the approved-lane plan and launches nothing.", file=out)
    print(
        "# Review LAUNCH-CATALOG.md before building images, editing seed data, or scanning.",
        file=out,
    )
    print(f"# Proposed image build: docker build -f Dockerfile.scan -t {IMAGE_TAG} .", file=out)
    print("", file=out)
    for key, value in SANDBOX_ENV.items():
        print(f"export {key}={shlex.quote(value)}", file=out)
    print("", file=out)
    print("# After catalog and sandbox approval, seed these entries and scan by slug:", file=out)
    for candidate in REFERENCE_SCAN_CANDIDATES:
        source = json.dumps(candidate.source_preview(), sort_keys=True)
        print(f"# {candidate.slug}: {source}", file=out)
        print(f"mcp-trust scan {shlex.quote(candidate.slug)}", file=out)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--format",
        choices=("shell", "json"),
        default="shell",
        help="Output format. Both formats are dry-run only.",
    )
    args = parser.parse_args(argv)

    if args.format == "json":
        print(json.dumps(plan_payload(), indent=2, sort_keys=True))
    else:
        write_shell_plan()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
