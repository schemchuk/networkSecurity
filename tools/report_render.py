"""Markdown renderer for reconnaissance findings."""

from __future__ import annotations

from pathlib import Path
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from tools.schemas import CVE, Finding, Manifest
    from tools.scope import Engagement


def _escape_pipe(value: str | None) -> str:
    """Escape pipe characters so Markdown tables stay intact."""
    if value is None:
        return ""
    return str(value).replace("|", "\\|")


def _priority_key(finding: "Finding") -> tuple[bool, int, str]:
    """Sort key for findings: lower priority first, ``None`` last."""
    if finding.priority is None:
        return (True, 0, finding.id)
    return (False, finding.priority, finding.id)


def _max_cvss(finding: "Finding") -> float | None:
    """Return the highest CVSS score attached to a finding, if any."""
    scores = [cve.cvss for cve in finding.cves if cve.cvss is not None]
    return max(scores) if scores else None


def _overall_risk(findings: list["Finding"]) -> str:
    """Return the highest severity across findings as a Title Case rating."""
    if not findings:
        return "None"
    severity_rank = {
        "info": 0,
        "low": 1,
        "medium": 2,
        "high": 3,
        "critical": 4,
    }
    risk = max(findings, key=lambda f: severity_rank[f.severity.value])
    return risk.severity.value.capitalize()


def _top_recommendations(findings: list["Finding"], limit: int = 5) -> list[str]:
    """Return up to *limit* unique mitigations for critical/high findings."""
    high_priority = [f for f in findings if f.severity.value in {"critical", "high"}]
    sorted_findings = sorted(high_priority, key=_priority_key)
    seen: set[str] = set()
    recommendations: list[str] = []
    for finding in sorted_findings:
        mitigation = finding.mitigation
        if not mitigation or mitigation in seen:
            continue
        seen.add(mitigation)
        recommendations.append(mitigation)
        if len(recommendations) >= limit:
            break
    return recommendations


def _format_cve(cve: "CVE") -> str:
    """Format a CVE reference for the report body."""
    if cve.cvss is None:
        return cve.id
    return f"{cve.id} (CVSS {cve.cvss:.1f})"


def _render_engagement(engagement: "Engagement") -> list[str]:
    """Render the ``## Engagement`` section."""
    lines = [
        "## Engagement",
        "",
        f"- **Client:** {engagement.client}",
        f"- **Authorized by:** {engagement.authorized_by}",
        f"- **Authorization ref:** {engagement.authorization_ref}",
    ]

    start = engagement.start_date.isoformat() if engagement.start_date else None
    end = engagement.end_date.isoformat() if engagement.end_date else None
    if start is None and end is None:
        window = "open-ended"
    else:
        window = f"{start or 'open-ended'} – {end or 'open-ended'}"
    lines.append(f"- **Window:** {window}")
    lines.append("")
    return lines


def _render_executive_summary(findings: list["Finding"]) -> list[str]:
    """Render the ``## Executive Summary`` section."""
    order = ["critical", "high", "medium", "low", "info"]
    counts = {level: 0 for level in order}
    for finding in findings:
        counts[finding.severity.value] += 1

    non_zero = [f"{level}: {counts[level]}" for level in order if counts[level] > 0]
    by_severity = ", ".join(non_zero) if non_zero else "none"

    lines = [
        "## Executive Summary",
        "",
        f"- **Total findings:** {len(findings)}",
        f"- **By severity:** {by_severity}",
        f"- **Overall risk:** {_overall_risk(findings)}",
        "",
        "**Top recommendations:**",
        "",
    ]

    recommendations = _top_recommendations(findings)
    if recommendations:
        for idx, rec in enumerate(recommendations, start=1):
            lines.append(f"{idx}. {rec}")
    else:
        lines.append("_No high-priority mitigations identified._")

    lines.append("")
    return lines


def _render_methodology() -> list[str]:
    """Render the static ``## Methodology`` section."""
    return [
        "## Methodology",
        "",
        "1. **Service discovery:** nmap service/version scan against authorized targets.",
        "2. **Normalization:** raw nmap output is parsed into structured ``Finding`` objects.",
        "3. **Recon enrichment:** an LLM agent adds service summaries and investigation next steps.",
        "4. **Vulnerability analysis:** CVE correlation, severity scoring, and prioritization.",
        "5. **Hardening advice:** mitigation and detection recommendations per finding.",
        "6. **Reporting:** findings are rendered into a Markdown report for review.",
        "",
    ]


def render_report(
    findings: list["Finding"],
    manifest: "Manifest" | None = None,
    engagement: "Engagement" | None = None,
) -> str:
    """Render a Markdown report from a list of findings.

    Args:
        findings: Findings to include in the report.
        manifest: Optional run manifest with metadata.
        engagement: Optional signed engagement authorizing the work.

    Returns:
        Markdown-formatted report as a string.
    """
    run_id = manifest.run_id if manifest else "—"
    lines: list[str] = [
        f"# Recon Report — {run_id}",
        "",
    ]

    if manifest:
        lines.extend(
            [
                "## Run metadata",
                "",
                f"- **Scenario:** {manifest.scenario}",
                f"- **Targets:** {', '.join(manifest.targets)}",
                f"- **Operator:** {manifest.operator}",
                f"- **Started:** {manifest.started.isoformat()}",
                "",
            ]
        )

    if engagement:
        lines.extend(_render_engagement(engagement))

    lines.extend(_render_executive_summary(findings))
    lines.extend(_render_methodology())

    lines.extend(
        [
            "## Summary",
            "",
            "| ID | Priority | Host | Port | Service | Product | Version | Severity | CVSS |",
            "|---|---|---|---|---|---|---|---|---|",
        ]
    )

    display_findings = sorted(findings, key=_priority_key)

    if display_findings:
        for finding in display_findings:
            cvss = _max_cvss(finding)
            cvss_text = f"{cvss:.1f}" if cvss is not None else ""
            lines.append(
                "| "
                + " | ".join(
                    [
                        _escape_pipe(finding.id),
                        str(finding.priority) if finding.priority is not None else "",
                        _escape_pipe(finding.host),
                        str(finding.port) if finding.port is not None else "",
                        _escape_pipe(finding.service),
                        _escape_pipe(finding.product),
                        _escape_pipe(finding.version),
                        finding.severity.value,
                        cvss_text,
                    ]
                )
                + " |"
            )
    else:
        lines.append("| — | — | — | — | — | — | — | — | — |")

    lines.extend(
        [
            "",
            "## Findings",
            "",
        ]
    )

    if display_findings:
        for finding in display_findings:
            protocol = finding.protocol or ""
            port = finding.port if finding.port is not None else ""
            lines.append(
                f"### {finding.id} — {finding.host}:{port}/{protocol} {finding.service or ''}"
            )
            lines.append("")

            if finding.summary:
                lines.append(f"**Summary:** {finding.summary}")
            else:
                lines.append("**Summary:** _(no summary)_")

            if finding.next_steps:
                lines.append("")
                lines.append("**Next steps:**")
                for step in finding.next_steps:
                    lines.append(f"- {step}")

            if finding.cves:
                lines.append("")
                lines.append(
                    "**CVEs:** " + ", ".join(_format_cve(cve) for cve in finding.cves)
                )

            if finding.mitigation:
                lines.append("")
                lines.append(f"**Mitigation:** {finding.mitigation}")

            if finding.detection:
                lines.append("")
                lines.append(f"**Detection:** {finding.detection}")

            lines.append("")
    else:
        lines.append("_No open services found._")
        lines.append("")

    return "\n".join(lines)


def write_report(
    findings: list["Finding"],
    path: str | Path,
    manifest: "Manifest" | None = None,
    engagement: "Engagement" | None = None,
) -> None:
    """Write a Markdown report to the specified path.

    Args:
        findings: Findings to render.
        path: Destination file path.
        manifest: Optional run manifest.
        engagement: Optional signed engagement authorizing the work.
    """
    report_path = Path(path)
    report_path.parent.mkdir(parents=True, exist_ok=True)
    report_path.write_text(
        render_report(findings, manifest, engagement), encoding="utf-8"
    )
