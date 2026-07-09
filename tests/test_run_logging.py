"""Tests for run initialization and command logging.

These tests use temporary directories and subprocess calls to avoid polluting
the project tree or relying on an interactive shell.
"""

import subprocess
import sys
from pathlib import Path

from tools.schemas import CommandLogEntry, Manifest


PROJECT_ROOT = Path(__file__).resolve().parent.parent
NEW_RUN = PROJECT_ROOT / "scripts" / "new_run.py"
LOGCMD = PROJECT_ROOT / "scripts" / "logcmd.py"


def test_new_run_creates_directories_and_manifest(tmp_path):
    result = subprocess.run(
        [
            sys.executable,
            str(NEW_RUN),
            "--scenario",
            "recon-test",
            "--targets",
            "10.10.10.5,10.10.10.6",
            "--operator",
            "tester",
        ],
        cwd=tmp_path,
        capture_output=True,
        text=True,
        check=True,
    )
    run_id = result.stdout.strip()

    assert (tmp_path / "logs" / run_id).is_dir()
    assert (tmp_path / "runs" / run_id / "raw").is_dir()

    manifest_path = tmp_path / "runs" / run_id / "manifest.json"
    assert manifest_path.exists()

    manifest = Manifest.model_validate_json(manifest_path.read_text())
    assert manifest.run_id == run_id
    assert manifest.scenario == "recon-test"
    assert manifest.targets == ["10.10.10.5", "10.10.10.6"]
    assert manifest.operator == "tester"
    assert manifest.tool_versions == {}


def test_logcmd_appends_valid_entries(tmp_path):
    log_file = tmp_path / "commands.jsonl"

    subprocess.run(
        [
            sys.executable,
            str(LOGCMD),
            "--file",
            str(log_file),
            "--cmd",
            "nmap -sV 10.10.10.5",
            "--exit",
            "0",
            "--cwd",
            "/home/lab",
        ],
        check=True,
    )
    subprocess.run(
        [
            sys.executable,
            str(LOGCMD),
            "--file",
            str(log_file),
            "--cmd",
            "ls -la",
            "--exit",
            "1",
        ],
        cwd=tmp_path,
        check=True,
    )

    lines = log_file.read_text(encoding="utf-8").strip().split("\n")
    assert len(lines) == 2

    first = CommandLogEntry.model_validate_json(lines[0])
    assert first.cmd == "nmap -sV 10.10.10.5"
    assert first.exit_code == 0
    assert first.cwd == "/home/lab"

    second = CommandLogEntry.model_validate_json(lines[1])
    assert second.cmd == "ls -la"
    assert second.exit_code == 1
    assert second.cwd == str(tmp_path)


def test_command_log_entry_round_trip():
    from datetime import datetime, timezone

    original = CommandLogEntry(
        ts=datetime.now(timezone.utc),
        cmd="echo hello",
        cwd="/tmp",
        exit_code=0,
    )
    restored = CommandLogEntry.model_validate_json(original.model_dump_json())
    assert restored.cmd == original.cmd
    assert restored.cwd == original.cwd
    assert restored.exit_code == original.exit_code
    assert restored.ts == original.ts
