#!/usr/bin/env python3
"""CLI entrypoint for the end-to-end recon pipeline.

Prerequisites:
    - Ollama server is running locally (``ollama serve``).
    - The configured model is pulled (default ``qwen2.5-coder:7b``).

Example:
    python scripts/run.py --nmap tests/fixtures/nmap_sample.xml --scenario recon-test --targets 10.10.10.5
"""

from __future__ import annotations

import argparse
import os
import sys

from agents.pipeline import run_recon_pipeline
from tools.llm import LLMClient
from tools.nmap_parser import parse_nmap_xml
from tools.run_utils import init_run
from tools.scope import ScopeError, assert_in_scope, load_engagement


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Run the recon pipeline on an nmap XML file"
    )
    parser.add_argument("--nmap", required=True, help="Path to nmap XML output")
    parser.add_argument(
        "--run-id", help="Run ID (default: YYYY-MM-DD_HHMMSS_<scenario>)"
    )
    parser.add_argument("--scenario", default="recon", help="Scenario name")
    parser.add_argument("--runs-dir", default="runs", help="Runs directory")
    parser.add_argument(
        "--targets", default="", help="Comma-separated list of targets"
    )
    parser.add_argument(
        "--operator",
        default=os.environ.get("USER", "unknown"),
        help="Operator name (default: $USER)",
    )
    parser.add_argument(
        "--engagement",
        help="Path to engagement YAML scope definition",
    )
    args = parser.parse_args()

    if args.engagement:
        engagement = load_engagement(args.engagement)
        for target in (t.strip() for t in args.targets.split(",") if t.strip()):
            try:
                assert_in_scope(target, engagement)
            except ScopeError as exc:
                print(f"ERROR: {exc}", file=sys.stderr)
                sys.exit(2)
    else:
        print(
            "WARNING: no engagement scope provided -- LAB USE ONLY. "
            "Do not run against systems you are not authorized to test.",
            file=sys.stderr,
        )

    run_id, _, _ = init_run(
        scenario=args.scenario,
        targets=args.targets,
        operator=args.operator,
        run_id=args.run_id,
        base_dir=".",
        runs_subdir=args.runs_dir,
        logs_subdir="logs",
    )

    if args.engagement:
        for finding in parse_nmap_xml(args.nmap):
            try:
                assert_in_scope(finding.host, engagement)
            except ScopeError as exc:
                print(f"ERROR: {exc}", file=sys.stderr)
                sys.exit(2)

    report_path = run_recon_pipeline(
        nmap_path=args.nmap,
        run_id=run_id,
        runs_dir=args.runs_dir,
        llm=LLMClient(),
    )

    print(report_path)


if __name__ == "__main__":
    main()
