"""Recon agent — enriches raw findings with LLM-generated analysis."""

from __future__ import annotations

import json

from pydantic import BaseModel

from agents.base import BaseAgent
from tools.llm import LLMError
from tools.schemas import Finding


class ReconEnrichment(BaseModel):
    """Structured output expected from the LLM for a single finding."""

    summary: str
    next_steps: list[str] = []


RECON_SYSTEM_PROMPT = (
    "You are a reconnaissance analyst reviewing observed network services. "
    "Based only on the provided host, port, service, product, and version facts, "
    "summarize the attack surface and suggest 1-3 high-level next analysis steps. "
    "Do not propose ready-to-use exploits, payloads, or commands. "
    "Do not invent CVE IDs or CVSS scores."
)


class ReconAgent(BaseAgent):
    """Agent that enriches reconnaissance findings with LLM-generated summaries."""

    name = "recon"

    def _build_prompt(self, finding: Finding) -> str:
        return (
            "Analyze the following service observed during reconnaissance:\n"
            f"- Host: {finding.host}\n"
            f"- Port: {finding.port}/{finding.protocol}\n"
            f"- Service: {finding.service}\n"
            f"- Product: {finding.product}\n"
            f"- Version: {finding.version}\n\n"
            "Provide a brief summary of the attack surface and 1-3 concrete next "
            "analysis steps (e.g., check for known weaknesses, compare versions, "
            "review configuration). Do not include ready-to-use exploits or payloads, "
            "and do not invent CVE identifiers."
        )

    def run(self, findings: list[Finding]) -> list[Finding]:
        """Enrich each finding with a summary and next steps, then persist results.

        Args:
            findings: Raw findings produced by the nmap parser.

        Returns:
            The same list of findings with ``summary`` and ``next_steps`` populated.
        """
        self.emit_event("note", data={"count": len(findings)})

        for finding in findings:
            try:
                enrichment = self.llm.chat_json(
                    prompt=self._build_prompt(finding),
                    schema=ReconEnrichment,
                    system=RECON_SYSTEM_PROMPT,
                )
                finding.summary = enrichment.summary
                finding.next_steps = enrichment.next_steps
                self.emit_event("llm_call", ref=finding.id)
            except LLMError:
                self.emit_event("error", ref=finding.id)

        findings_path = self.run_dir / "findings.json"
        findings_path.write_text(
            json.dumps(
                [finding.model_dump(mode="json") for finding in findings],
                indent=2,
            ),
            encoding="utf-8",
        )

        return findings
