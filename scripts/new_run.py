#!/usr/bin/env python3
"""Initialize a new lab run.

Creates the run directory structure and writes a manifest. Prints only the
run_id to stdout so shell wrappers can capture it easily.
"""

from __future__ import annotations

import argparse
import json
import os
import sys
from datetime import datetime, timezone
from pathlib import Path

from tools.schemas import Manifest


def _default_run_id(scenario: str) -> str:
    stamp = datetime.now(timezone.utc).strftime("%Y-%m-%d_%H%M%S")
    return f"{stamp}_{scenario}"


def main() -> None:
    parser = argparse.ArgumentParser(description="Initialize a new lab run")
    parser.add_argument("--scenario", required=True, help="Scenario name")
    parser.add_argument(
        "--targets", default="", help="Comma-separated list of targets"
    )
    parser.add_argument(
        "--operator",
        default=os.environ.get("USER", "unknown"),
        help="Operator name (default: $USER)",
    )
    parser.add_argument("--run-id", help="Run ID (default: auto-generated)")
    args = parser.parse_args()

    run_id = args.run_id or _default_run_id(args.scenario)
    targets = [t.strip() for t in args.targets.split(",") if t.strip()]

    log_dir = Path("logs") / run_id
    run_dir = Path("runs") / run_id
    raw_dir = run_dir / "raw"

    log_dir.mkdir(parents=True, exist_ok=True)
    raw_dir.mkdir(parents=True, exist_ok=True)

    manifest = Manifest(
        run_id=run_id,
        started=datetime.now(timezone.utc),
        scenario=args.scenario,
        targets=targets,
        operator=args.operator,
        tool_versions={},
    )

    manifest_path = run_dir / "manifest.json"
    manifest_path.write_text(
        manifest.model_dump_json(indent=2), encoding="utf-8"
    )

    print(f"Created run directories: {log_dir}, {raw_dir}", file=sys.stderr)
    print(f"Wrote manifest: {manifest_path}", file=sys.stderr)
    print(run_id)


if __name__ == "__main__":
    main()
