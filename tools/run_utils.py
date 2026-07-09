"""Shared helpers for initializing a lab run."""

from __future__ import annotations

import os
from datetime import datetime, timezone
from pathlib import Path

from tools.schemas import Manifest


def _default_run_id(scenario: str) -> str:
    """Generate a run ID from the current UTC timestamp and scenario name."""
    stamp = datetime.now(timezone.utc).strftime("%Y-%m-%d_%H%M%S")
    return f"{stamp}_{scenario}"


def init_run(
    scenario: str,
    targets: str = "",
    operator: str | None = None,
    run_id: str | None = None,
    base_dir: str | Path = ".",
    runs_subdir: str = "runs",
    logs_subdir: str = "logs",
) -> tuple[str, Path, Path]:
    """Create run directories and write the manifest.

    Args:
        scenario: Scenario name.
        targets: Comma-separated list of targets.
        operator: Operator name (default: ``$USER``).
        run_id: Explicit run ID (default: auto-generated).
        base_dir: Base directory for ``runs`` and ``logs`` subdirectories.
        runs_subdir: Name of the runs subdirectory.
        logs_subdir: Name of the logs subdirectory.

    Returns:
        Tuple of ``(run_id, log_dir, run_dir)``.
    """
    base_path = Path(base_dir)
    run_id = run_id or _default_run_id(scenario)
    operator = operator or os.environ.get("USER", "unknown")
    targets_list = [t.strip() for t in targets.split(",") if t.strip()]

    log_dir = base_path / logs_subdir / run_id
    run_dir = base_path / runs_subdir / run_id
    raw_dir = run_dir / "raw"

    log_dir.mkdir(parents=True, exist_ok=True)
    raw_dir.mkdir(parents=True, exist_ok=True)

    manifest = Manifest(
        run_id=run_id,
        started=datetime.now(timezone.utc),
        scenario=scenario,
        targets=targets_list,
        operator=operator,
        tool_versions={},
    )

    manifest_path = run_dir / "manifest.json"
    manifest_path.write_text(
        manifest.model_dump_json(indent=2), encoding="utf-8"
    )

    return run_id, log_dir, run_dir
