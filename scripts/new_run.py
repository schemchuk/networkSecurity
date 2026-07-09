#!/usr/bin/env python3
"""Initialize a new lab run.

Creates the run directory structure and writes a manifest. Prints only the
run_id to stdout so shell wrappers can capture it easily.
"""

from __future__ import annotations

import argparse
import sys

from tools.run_utils import init_run


def main() -> None:
    parser = argparse.ArgumentParser(description="Initialize a new lab run")
    parser.add_argument("--scenario", required=True, help="Scenario name")
    parser.add_argument(
        "--targets", default="", help="Comma-separated list of targets"
    )
    parser.add_argument(
        "--operator",
        help="Operator name (default: $USER)",
    )
    parser.add_argument("--run-id", help="Run ID (default: auto-generated)")
    args = parser.parse_args()

    run_id, log_dir, run_dir = init_run(
        scenario=args.scenario,
        targets=args.targets,
        operator=args.operator,
        run_id=args.run_id,
    )

    print(f"Created run directories: {log_dir}, {run_dir / 'raw'}", file=sys.stderr)
    print(f"Wrote manifest: {run_dir / 'manifest.json'}", file=sys.stderr)
    print(run_id)


if __name__ == "__main__":
    main()
