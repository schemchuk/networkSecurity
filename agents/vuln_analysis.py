"""Vulnerability-analysis agent: attaches real CVEs and prioritizes findings.

This agent is fully deterministic — it uses the local exploitdb via
``tools.cve_lookup`` and a transparent heuristic for severity/priority.
No LLM calls are made.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Callable

from agents.base import BaseAgent
from tools.cve_lookup import CVELookupError, search_cves
from tools.schemas import CVE, Finding, Severity


class VulnAnalysisAgent(BaseAgent):
    """Enrich findings with real CVEs, severity, and deterministic priority."""

    name = "vuln_analysis"

    def __init__(
        self,
        run_id: str,
        runs_dir: str | Path = "runs",
        llm=None,
        cve_lookup: Callable[[str | None, str | None], list[CVE]] = search_cves,
    ) -> None:
        """Initialize the agent.

        Args:
            run_id: Unique identifier of the run.
            runs_dir: Root directory containing run subdirectories.
            llm: Ignored; kept for API compatibility with other agents.
            cve_lookup: Callable that returns CVE references for a product/version.
                Injected in tests to avoid calling the real ``searchsploit``.
        """
        super().__init__(run_id, runs_dir=runs_dir, llm=llm)
        self.cve_lookup = cve_lookup

    def run(self, findings: list[Finding]) -> list[Finding]:
        """Attach CVEs, set severity/priority, and persist findings.

        Args:
            findings: Raw findings produced by earlier pipeline stages.

        Returns:
            The same list with ``cves``, ``severity``, and ``priority`` populated.
        """
        self.emit_event("note", data={"count": len(findings)})

        lookup_disabled = False
        for finding in findings:
            if lookup_disabled or not finding.product:
                continue

            try:
                new_cves = self.cve_lookup(finding.product, finding.version)
            except CVELookupError as exc:
                self.emit_event(
                    "error",
                    ref=finding.id,
                    data={"reason": str(exc)},
                )
                lookup_disabled = True
                continue

            existing_ids = {cve.id for cve in finding.cves}
            added = 0
            for cve in new_cves:
                if cve.id not in existing_ids:
                    finding.cves.append(cve)
                    existing_ids.add(cve.id)
                    added += 1

            self.emit_event(
                "note",
                ref=finding.id,
                data={"cves": added},
            )

        for finding in findings:
            if finding.cves:
                finding.severity = Severity.HIGH

        ranked = sorted(
            range(len(findings)),
            key=lambda i: (-len(findings[i].cves), findings[i].port or 0),
        )
        for priority, idx in enumerate(ranked, start=1):
            findings[idx].priority = priority

        findings_path = self.run_dir / "findings.json"
        findings_path.write_text(
            json.dumps(
                [finding.model_dump(mode="json") for finding in findings],
                indent=2,
            ),
            encoding="utf-8",
        )

        return findings
