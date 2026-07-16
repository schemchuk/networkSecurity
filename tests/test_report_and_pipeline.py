"""Tests for the Markdown report renderer and the end-to-end pipeline."""

import json
from pathlib import Path

import pytest

from agents.hardening import HardeningAdvice
from agents.pipeline import run_recon_pipeline
from agents.recon import ReconEnrichment
from tools.report_render import render_report
from tools.schemas import CVE, Finding, Severity
from tools.scope import Engagement


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
            if schema is HardeningAdvice:
                return HardeningAdvice(
                    mitigation="Upgrade the service.",
                    detection="Watch auth logs.",
                )
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
    assert "**Mitigation:** Upgrade the service." in report_text
    assert "**Detection:** Watch auth logs." in report_text


def test_render_shows_mitigation_detection():
    with_advice = Finding(
        id="F-0001",
        host="10.10.10.5",
        port=22,
        protocol="tcp",
        service="ssh",
        product="OpenSSH",
        version="8.2p1",
        source="nmap",
        mitigation="Disable password auth.",
        detection="Monitor failed SSH logins.",
    )
    without_advice = Finding(
        id="F-0002",
        host="10.10.10.5",
        port=80,
        protocol="tcp",
        service="http",
        source="nmap",
    )

    report = render_report([with_advice, without_advice])

    assert "**Mitigation:** Disable password auth." in report
    assert "**Detection:** Monitor failed SSH logins." in report
    assert report.count("**Mitigation:**") == 1
    assert report.count("**Detection:**") == 1


def test_render_report_engagement_section():
    engagement = Engagement(
        client="Acme Corp",
        authorized_by="Jane Doe",
        authorization_ref="ENG-2024-001",
        authorized_targets=["10.10.10.0/24"],
    )
    finding = Finding(
        id="F-0001",
        host="10.10.10.5",
        port=22,
        source="nmap",
    )

    report_with = render_report([finding], engagement=engagement)
    assert "## Engagement" in report_with
    assert "**Client:** Acme Corp" in report_with
    assert "**Authorized by:** Jane Doe" in report_with
    assert "**Authorization ref:** ENG-2024-001" in report_with
    assert "**Window:** open-ended" in report_with

    report_without = render_report([finding])
    assert "## Engagement" not in report_without


def test_render_report_executive_summary_counts():
    findings = [
        Finding(id="F-0001", host="10.10.10.1", source="nmap", severity=Severity.CRITICAL),
        Finding(id="F-0002", host="10.10.10.2", source="nmap", severity=Severity.HIGH),
        Finding(id="F-0003", host="10.10.10.3", source="nmap", severity=Severity.HIGH),
        Finding(id="F-0004", host="10.10.10.4", source="nmap", severity=Severity.MEDIUM),
        Finding(id="F-0005", host="10.10.10.5", source="nmap", severity=Severity.LOW),
        Finding(id="F-0006", host="10.10.10.6", source="nmap", severity=Severity.INFO),
    ]
    report = render_report(findings)

    assert "## Executive Summary" in report
    assert "**Total findings:** 6" in report
    assert "critical: 1, high: 2, medium: 1, low: 1, info: 1" in report
    assert "**Overall risk:** Critical" in report


def test_render_report_top_recommendations_dedup_and_limit():
    findings = [
        Finding(
            id=f"F-{idx:04d}",
            host=f"10.10.10.{idx}",
            source="nmap",
            severity=Severity.CRITICAL if idx % 2 == 0 else Severity.HIGH,
            priority=idx,
            mitigation=f"Mitigation {idx}",
        )
        for idx in range(1, 8)
    ]
    # Duplicate the mitigation from F-0001 to ensure deduplication.
    findings.append(
        Finding(
            id="F-0008",
            host="10.10.10.8",
            source="nmap",
            severity=Severity.HIGH,
            priority=8,
            mitigation="Mitigation 1",
        )
    )
    report = render_report(findings)

    assert "## Executive Summary" in report
    for idx in range(1, 6):
        assert f"{idx}. Mitigation {idx}" in report
    assert "6. Mitigation 6" not in report
    assert report.count("1. Mitigation 1") == 1


def test_render_report_no_high_priority_mitigations():
    findings = [
        Finding(
            id="F-0001",
            host="10.10.10.5",
            source="nmap",
            severity=Severity.INFO,
            mitigation="Informative note.",
        ),
        Finding(
            id="F-0002",
            host="10.10.10.6",
            source="nmap",
            severity=Severity.LOW,
            mitigation="Low priority fix.",
        ),
    ]
    report = render_report(findings)

    assert "_No high-priority mitigations identified._" in report


def test_render_report_cvss_column_and_cve_format():
    with_cvss = Finding(
        id="F-0001",
        host="10.10.10.5",
        port=80,
        source="nmap",
        cves=[CVE(id="CVE-2024-0001", cvss=7.5, source="nvd")],
    )
    without_cvss = Finding(
        id="F-0002",
        host="10.10.10.6",
        port=443,
        source="nmap",
        cves=[CVE(id="CVE-2024-0002", cvss=None, source="nvd")],
    )
    report = render_report([with_cvss, without_cvss])

    assert "| Severity | CVSS |" in report
    assert "| 7.5 |" in report
    assert "|  |" in report  # empty CVSS cell for the second finding
    assert "CVE-2024-0001 (CVSS 7.5)" in report
    assert "CVE-2024-0002" in report
    assert "CVE-2024-0002 (CVSS" not in report
