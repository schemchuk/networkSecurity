"""Tests for the Markdown report renderer and the end-to-end pipeline."""

import json
from pathlib import Path

import pytest

from agents.pipeline import run_recon_pipeline
from agents.recon import ReconEnrichment
from tools.report_render import render_report
from tools.schemas import CVE, Finding, Severity


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
            summary="SSH service exposed.",
            next_steps=["Check for weak credentials"],
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
            summary="SMB service exposed.",
            next_steps=["Review share permissions"],
        ),
    ]


def test_render_report_contains_findings(sample_findings: list[Finding]):
    report = render_report(sample_findings)

    assert "# Recon Report" in report
    assert "## Summary" in report
    assert "## Findings" in report
    assert "10.10.10.5" in report
    assert "ssh" in report
    assert "microsoft-ds" in report
    assert "F-0001" in report
    assert "F-0002" in report
    assert Severity.INFO.value in report
    assert "| Priority |" in report


def test_render_empty():
    report = render_report([])

    assert "## Findings" in report
    assert "_No open services found._" in report


def test_render_orders_by_priority():
    low_priority = Finding(
        id="F-0001",
        host="10.10.10.5",
        port=22,
        protocol="tcp",
        service="ssh",
        product="OpenSSH",
        version="8.2p1",
        source="nmap",
        priority=2,
    )
    high_priority = Finding(
        id="F-0002",
        host="10.10.10.5",
        port=445,
        protocol="tcp",
        service="microsoft-ds",
        product="Samba smbd",
        version="3.0.20",
        source="nmap",
        priority=1,
    )

    report = render_report([low_priority, high_priority])

    assert "| Priority |" in report
    first_finding_pos = report.index("F-0002")
    second_finding_pos = report.index("F-0001", first_finding_pos)
    assert first_finding_pos < second_finding_pos


def _fake_cve_lookup(product: str | None, version: str | None) -> list[CVE]:
    if product and "Samba" in product:
        return [CVE(id="CVE-2007-2447", cvss=None, source="exploitdb")]
    return []


def test_pipeline_end_to_end(tmp_path: Path):
    class _FakeLLM:
        def chat_json(self, prompt, schema, system=None, retries=1):
            return ReconEnrichment(
                summary="Exposed service may reveal version-specific weaknesses.",
                next_steps=["Compare version against vendor advisories"],
            )

    nmap_xml = Path(__file__).resolve().parent / "fixtures" / "nmap_sample.xml"
    report_path = run_recon_pipeline(
        nmap_path=nmap_xml,
        run_id="pipeline-test",
        runs_dir=tmp_path,
        llm=_FakeLLM(),
        cve_lookup=_fake_cve_lookup,
    )

    assert report_path.exists()
    assert report_path == tmp_path / "pipeline-test" / "report.md"

    findings_path = tmp_path / "pipeline-test" / "findings.json"
    assert findings_path.exists()

    raw = json.loads(findings_path.read_text(encoding="utf-8"))
    findings = [Finding.model_validate(item) for item in raw]
    assert len(findings) == 2

    samba_finding = next(f for f in findings if f.product and "Samba" in f.product)
    assert any(cve.id == "CVE-2007-2447" for cve in samba_finding.cves)
    assert samba_finding.severity == Severity.HIGH

    report_text = report_path.read_text(encoding="utf-8")
    assert "microsoft-ds" in report_text
    assert "10.10.10.5" in report_text
    assert "CVE-2007-2447" in report_text
