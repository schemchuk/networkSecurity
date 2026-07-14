"""End-to-end reconnaissance pipeline: nmap XML → findings → report."""

from __future__ import annotations

import json
from pathlib import Path
from typing import TYPE_CHECKING

from agents.hardening import HardeningAgent
from agents.recon import ReconAgent
from agents.vuln_analysis import VulnAnalysisAgent
from tools.cve_lookup import search_cves
from tools.nmap_parser import parse_nmap_xml
from tools.report_render import write_report
from tools.schemas import Manifest

if TYPE_CHECKING:
    from tools.llm import LLMClient


def run_recon_pipeline(
    nmap_path: str | Path,
    run_id: str,
    runs_dir: str | Path = "runs",
    llm: "LLMClient" | None = None,
    cve_lookup=None,
) -> Path:
    """Run the full recon pipeline on an nmap XML file.

    Steps:
        1. Parse the nmap XML into raw ``Finding`` objects.
        2. Enrich findings with the Recon agent (LLM summaries + next steps).
        3. Enrich findings with the Vuln Analysis agent (real CVEs, severity, priority).
        4. Enrich findings with the Hardening agent (mitigation + detection advice).
        5. Render and write a Markdown report to ``runs/<run_id>/report.md``.

    Args:
        nmap_path: Path to the nmap XML output file.
        run_id: Unique identifier for this run.
        runs_dir: Root directory containing run subdirectories.
        llm: Optional LLM client for testing; otherwise the Recon agent creates one.
        cve_lookup: Optional CVE lookup callable. Defaults to ``search_cves``.

    Returns:
        Path to the generated ``report.md``.
    """
    nmap_path = Path(nmap_path)
    runs_dir = Path(runs_dir)
    run_dir = runs_dir / run_id

    findings = parse_nmap_xml(nmap_path)

    recon_agent = ReconAgent(run_id, runs_dir=runs_dir, llm=llm)
    enriched = recon_agent.run(findings)

    vuln_agent = VulnAnalysisAgent(
        run_id,
        runs_dir=runs_dir,
        cve_lookup=cve_lookup or search_cves,
    )
    vuln_agent.run(enriched)

    HardeningAgent(run_id, runs_dir=runs_dir, llm=llm).run(enriched)

    manifest: Manifest | None = None
    manifest_path = run_dir / "manifest.json"
    if manifest_path.exists():
        manifest = Manifest.model_validate_json(
            manifest_path.read_text(encoding="utf-8")
        )

    report_path = run_dir / "report.md"
    write_report(enriched, report_path, manifest=manifest)

    return report_path
