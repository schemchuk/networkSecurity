"""Tests for the Recon agent."""

import json
from pathlib import Path

import pytest

from agents.recon import ReconAgent, ReconEnrichment
from tools.llm import LLMError
from tools.schemas import Event, Finding


class _FakeLLM:
    def chat_json(self, prompt, schema, system=None, retries=1):
        return ReconEnrichment(
            summary="Exposed service may reveal version-specific weaknesses.",
            next_steps=["Compare version against vendor advisories", "Review default config"],
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
        ),
    ]


def _load_events(run_dir: Path) -> list[Event]:
    events_path = run_dir / "events.jsonl"
    lines = events_path.read_text(encoding="utf-8").strip().split("\n")
    return [Event.model_validate_json(line) for line in lines if line]


def test_enriches_findings(tmp_path: Path, sample_findings: list[Finding]):
    agent = ReconAgent(
        run_id="test-run",
        runs_dir=tmp_path,
        llm=_FakeLLM(),
    )

    enriched = agent.run(sample_findings)

    assert len(enriched) == 2
    for finding in enriched:
        assert finding.summary
        assert finding.next_steps


def test_writes_findings_json(tmp_path: Path, sample_findings: list[Finding]):
    agent = ReconAgent(
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
    assert restored[0].id == "F-0001"
    assert restored[1].id == "F-0002"


def test_emits_events(tmp_path: Path, sample_findings: list[Finding]):
    agent = ReconAgent(
        run_id="test-run",
        runs_dir=tmp_path,
        llm=_FakeLLM(),
    )

    agent.run(sample_findings)

    events = _load_events(tmp_path / "test-run")
    types = [e.type for e in events]
    assert types[0] == "note"
    assert types[1:] == ["llm_call", "llm_call"]
    assert all(e.agent == "recon" for e in events)
    assert events[0].data.get("count") == 2


def test_llm_error_is_tolerated(tmp_path: Path, sample_findings: list[Finding]):
    agent = ReconAgent(
        run_id="test-run",
        runs_dir=tmp_path,
        llm=_FailingLLM(),
    )

    enriched = agent.run(sample_findings)

    assert len(enriched) == 2
    assert all(not f.summary for f in enriched)
    assert all(not f.next_steps for f in enriched)

    events = _load_events(tmp_path / "test-run")
    error_events = [e for e in events if e.type == "error"]
    assert len(error_events) == 2
    assert all(e.ref in ("F-0001", "F-0002") for e in error_events)
