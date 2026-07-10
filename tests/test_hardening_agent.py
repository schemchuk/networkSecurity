"""Tests for the Hardening/Detection advisor agent.

All tests mock the LLM; no real network calls are made.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from agents.hardening import HardeningAdvice, HardeningAgent
from tools.llm import LLMError
from tools.schemas import CVE, Event, Finding, Severity


class _FakeLLM:
    def chat_json(self, prompt, schema, system=None, retries=1):
        return HardeningAdvice(
            mitigation="Patch or upgrade the affected service.",
            detection="IDS/IPS alert on suspicious traffic to the port.",
        )


class _FailingLLM:
    def chat_json(self, prompt, schema, system=None, retries=1):
        raise LLMError("model offline")


@pytest.fixture
def sample_findings() -> list[Finding]:
    return [
        Finding(
            id="F-0001",
            host="10.10.10.5",
            port=22,
            protocol="tcp",
            service="ssh",
            product="OpenSSH",
            version="8.2p1",
            source="nmap",
            severity=Severity.INFO,
        ),
        Finding(
            id="F-0002",
            host="10.10.10.5",
            port=445,
            protocol="tcp",
            service="microsoft-ds",
            product="Samba smbd",
            version="3.0.20",
            source="nmap",
            severity=Severity.HIGH,
            cves=[CVE(id="CVE-2007-2447", cvss=None, source="exploitdb")],
        ),
    ]


def _load_events(run_dir: Path) -> list[Event]:
    events_path = run_dir / "events.jsonl"
    lines = events_path.read_text(encoding="utf-8").strip().split("\n")
    return [Event.model_validate_json(line) for line in lines if line]


def test_enriches_only_prioritized(
    tmp_path: Path, sample_findings: list[Finding]
) -> None:
    agent = HardeningAgent(
        run_id="test-run",
        runs_dir=tmp_path,
        llm=_FakeLLM(),
    )

    enriched = agent.run(sample_findings)

    assert enriched[1].mitigation
    assert enriched[1].detection
    assert not enriched[0].mitigation
    assert not enriched[0].detection


def test_high_severity_without_cve_is_enriched(tmp_path: Path) -> None:
    findings = [
        Finding(
            id="F-0001",
            host="10.10.10.5",
            port=22,
            protocol="tcp",
            service="ssh",
            product="OpenSSH",
            version="8.2p1",
            source="nmap",
            severity=Severity.HIGH,
        ),
    ]
    agent = HardeningAgent(
        run_id="test-run",
        runs_dir=tmp_path,
        llm=_FakeLLM(),
    )

    enriched = agent.run(findings)

    assert enriched[0].mitigation
    assert enriched[0].detection


def test_emits_selected_count(
    tmp_path: Path, sample_findings: list[Finding]
) -> None:
    agent = HardeningAgent(
        run_id="test-run",
        runs_dir=tmp_path,
        llm=_FakeLLM(),
    )

    agent.run(sample_findings)

    events = _load_events(tmp_path / "test-run")
    note = next(e for e in events if e.type == "note")
    assert note.data.get("total") == 2
    assert note.data.get("selected") == 1


def test_tolerates_llm_error(
    tmp_path: Path, sample_findings: list[Finding]
) -> None:
    agent = HardeningAgent(
        run_id="test-run",
        runs_dir=tmp_path,
        llm=_FailingLLM(),
    )

    enriched = agent.run(sample_findings)

    assert not enriched[1].mitigation
    assert not enriched[1].detection

    events = _load_events(tmp_path / "test-run")
    error_events = [e for e in events if e.type == "error"]
    assert len(error_events) == 1
    assert error_events[0].ref == "F-0002"


def test_writes_findings_json(
    tmp_path: Path, sample_findings: list[Finding]
) -> None:
    agent = HardeningAgent(
        run_id="test-run",
        runs_dir=tmp_path,
        llm=_FakeLLM(),
    )

    agent.run(sample_findings)

    findings_path = tmp_path / "test-run" / "findings.json"
    assert findings_path.exists()

    raw = json.loads(findings_path.read_text(encoding="utf-8"))
    restored = [Finding.model_validate(item) for item in raw]
    assert len(restored) == 2
    assert restored[1].id == "F-0002"
