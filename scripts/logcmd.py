#!/usr/bin/env python3
"""Append a single command log entry to a JSONL file."""

from __future__ import annotations

import argparse
import json
import os
from datetime import datetime, timezone
from pathlib import Path

from tools.schemas import CommandLogEntry


def main() -> None:
    parser = argparse.ArgumentParser(description="Log a command to JSONL")
    parser.add_argument("--file", required=True, help="Path to commands.jsonl")
    parser.add_argument("--cmd", required=True, help="Executed command")
    parser.add_argument(
        "--exit", type=int, required=True, help="Exit code"
    )
    parser.add_argument(
        "--cwd",
        default=os.getcwd(),
        help="Working directory (default: current directory)",
    )
    args = parser.parse_args()

    entry = CommandLogEntry(
        ts=datetime.now(timezone.utc),
        cwd=args.cwd,
        cmd=args.cmd,
        exit_code=args.exit,
    )

    log_path = Path(args.file)
    log_path.parent.mkdir(parents=True, exist_ok=True)
    with log_path.open("a", encoding="utf-8") as f:
        f.write(entry.model_dump_json() + "\n")


if __name__ == "__main__":
    main()
