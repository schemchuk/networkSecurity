"""Tests for the deterministic Vuln Analysis agent.

All tests inject a fake CVE lookup; no real ``searchsploit`` binary is used.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from agents.vuln_analysis import VulnAnalysisAgent
from tools.cve_lookup import CVELookupError
from tools.schemas import CVE, Finding, Severity


def _fake_cve_lookup(product: str | None, version: str | None) -> list[CVE]:
    if product and "Samba" in product:
        return [CVE(id="CVE-2007-2447", cvss=None, source="exploitdb")]
    return []


def _failing_cve_lookup(product: str | None, version: str | None) -> list[CVE]:
    raise CVELookupError("searchsploit not found")


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


def test_attaches_cves(tmp_path: Path, sample_findings: list[Finding]) -> None:
    agent = VulnAnalysisAgent(
        run_id="test-run",
        runs_dir=tmp_path,
        cve_lookup=_fake_cve_lookup,
    )

    enriched = agent.run(sample_findings)

    assert any(cve.id == "CVE-2007-2447" for cve in enriched[1].cves)
    assert not enriched[0].cves


def test_sets_high_severity_for_cve(
    tmp_path: Path, sample_findings: list[Finding]
) -> None:
    agent = VulnAnalysisAgent(
        run_id="test-run",
        runs_dir=tmp_path,
        cve_lookup=_fake_cve_lookup,
    )

    enriched = agent.run(sample_findings)

    assert enriched[1].severity == Severity.HIGH
    assert enriched[0].severity != Severity.HIGH


def test_priority_orders_cve_first(
    tmp_path: Path, sample_findings: list[Finding]
) -> None:
    agent = VulnAnalysisAgent(
        run_id="test-run",
        runs_dir=tmp_path,
        cve_lookup=_fake_cve_lookup,
    )

    enriched = agent.run(sample_findings)

    cve_finding = next(f for f in enriched if f.cves)
    no_cve_finding = next(f for f in enriched if not f.cves)
    assert cve_finding.priority < no_cve_finding.priority


def test_dedupes_existing_cve(
    tmp_path: Path, sample_findings: list[Finding]
) -> None:
    sample_findings[1].cves = [
        CVE(id="CVE-2007-2447", cvss=None, source="exploitdb")
    ]
    agent = VulnAnalysisAgent(
        run_id="test-run",
        runs_dir=tmp_path,
        cve_lookup=_fake_cve_lookup,
    )

    enriched = agent.run(sample_findings)

    assert len(enriched[1].cves) == 1


def test_tolerates_missing_searchsploit(
    tmp_path: Path, sample_findings: list[Finding]
) -> None:
    agent = VulnAnalysisAgent(
        run_id="test-run",
        runs_dir=tmp_path,
        cve_lookup=_failing_cve_lookup,
    )

    enriched = agent.run(sample_findings)

    assert all(not f.cves for f in enriched)
    assert all(f.severity != Severity.HIGH for f in enriched)


def test_writes_findings_json(
    tmp_path: Path, sample_findings: list[Finding]
) -> None:
    agent = VulnAnalysisAgent(
        run_id="test-run",
        runs_dir=tmp_path,
        cve_lookup=_fake_cve_lookup,
    )

    agent.run(sample_findings)

    findings_path = tmp_path / "test-run" / "findings.json"
    assert findings_path.exists()

    raw = json.loads(findings_path.read_text(encoding="utf-8"))
    restored = [Finding.model_validate(item) for item in raw]
    assert len(restored) == 2
    assert restored[1].id == "F-0002"
