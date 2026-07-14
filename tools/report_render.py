"""Markdown renderer for reconnaissance findings."""

from __future__ import annotations

from pathlib import Path
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from tools.schemas import Finding, Manifest


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


def render_report(
    findings: list["Finding"],
    manifest: "Manifest" | None = None,
) -> str:
    """Render a Markdown report from a list of findings.

    Args:
        findings: Findings to include in the report.
        manifest: Optional run manifest with metadata.

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

    lines.extend(
        [
            "## Summary",
            "",
            "| ID | Priority | Host | Port | Service | Product | Version | Severity |",
            "|---|---|---|---|---|---|---|---|",
        ]
    )

    display_findings = sorted(findings, key=_priority_key)

    if display_findings:
        for finding in display_findings:
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
                    ]
                )
                + " |"
            )
    else:
        lines.append("| — | — | — | — | — | — | — | — |")

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
                    "**CVEs:** " + ", ".join(cve.id for cve in finding.cves)
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
) -> None:
    """Write a Markdown report to the specified path.

    Args:
        findings: Findings to render.
        path: Destination file path.
        manifest: Optional run manifest.
    """
    report_path = Path(path)
    report_path.parent.mkdir(parents=True, exist_ok=True)
    report_path.write_text(render_report(findings, manifest), encoding="utf-8")
