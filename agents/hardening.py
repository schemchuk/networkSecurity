"""Blue-team hardening/detection advisor agent.

Generates defensive mitigation advice and detection hints only for prioritized
findings (those with CVEs or high/critical severity), keeping LLM usage low on
constrained hardware.
"""

from __future__ import annotations

import json

from pydantic import BaseModel, field_validator

from agents.base import BaseAgent
from tools.llm import LLMError
from tools.schemas import Finding, Severity


class HardeningAdvice(BaseModel):
    """Defensive advice produced by the Hardening agent."""

    mitigation: str
    detection: str

    @field_validator("mitigation", "detection", mode="before")
    @classmethod
    def _coerce_to_str(cls, value: object) -> str:
        """Flatten non-string values into a readable string.

        Small models in JSON mode (e.g. qwen2.5:3b) sometimes emit these fields
        as nested objects/lists instead of a plain string. Coerce gracefully so
        a valid response is not discarded over formatting.
        """
        if isinstance(value, str):
            return value
        if isinstance(value, dict):
            if "description" in value:
                return str(value["description"])
            return "; ".join(f"{k}: {v}" for k, v in value.items())
        if isinstance(value, (list, tuple)):
            return "; ".join(str(item) for item in value)
        return str(value)


HARDENING_SYSTEM_PROMPT = (
    "You are a blue-team defensive analyst. For the observed service or CVE, "
    "provide concise defensive guidance in 2–5 sentences: "
    "(1) mitigation — how to eliminate or reduce the risk, "
    "(2) detection — what logs, alerts, or artifacts a defender would see. "
    "Do not include exploits, payloads, or offensive commands."
)


class HardeningAgent(BaseAgent):
    """Adds mitigation and detection advice to prioritized findings."""

    name = "hardening"

    def _should_enrich(self, finding: Finding) -> bool:
        """Return True for findings that deserve LLM-based hardening advice."""
        if finding.cves:
            return True
        return finding.severity in {Severity.HIGH, Severity.CRITICAL}

    def _build_prompt(self, finding: Finding) -> str:
        cve_part = ""
        if finding.cves:
            cve_part = " | CVEs: " + ", ".join(cve.id for cve in finding.cves)
        return (
            f"Service: {finding.service or 'unknown'} on {finding.host}:{finding.port}\n"
            f"Product: {finding.product or 'unknown'} {finding.version or ''}\n"
            f"Severity: {finding.severity.value}{cve_part}\n\n"
            "Give defensive mitigation and detection advice."
        )

    def run(self, findings: list[Finding]) -> list[Finding]:
        """Enrich prioritized findings with mitigation/detection advice.

        Args:
            findings: Findings already enriched by recon and vuln analysis.

        Returns:
            The same list with ``mitigation`` and ``detection`` populated for
            prioritized findings.
        """
        selected = [f for f in findings if self._should_enrich(f)]
        self.emit_event(
            "note",
            data={"total": len(findings), "selected": len(selected)},
        )

        for finding in findings:
            if not self._should_enrich(finding):
                continue

            try:
                advice = self.llm.chat_json(
                    prompt=self._build_prompt(finding),
                    schema=HardeningAdvice,
                    system=HARDENING_SYSTEM_PROMPT,
                )
                finding.mitigation = advice.mitigation
                finding.detection = advice.detection
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
