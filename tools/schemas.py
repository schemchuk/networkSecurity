"""Pydantic data schemas for findings, events, and run manifests.

Implements the data contracts defined in §7 of docs/ARCHITECTURE.md.
"""

from __future__ import annotations

from datetime import datetime, timezone
from enum import Enum
from typing import Literal

from pydantic import BaseModel, Field


class Severity(str, Enum):
    """Severity levels for a finding."""

    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class CVE(BaseModel):
    """A CVE reference attached to a finding."""

    id: str
    cvss: float | None = None
    source: str


class Finding(BaseModel):
    """Normalized security finding produced by agents/tools."""

    id: str
    host: str
    port: int | None = None
    protocol: str | None = None
    service: str | None = None
    product: str | None = None
    version: str | None = None
    source: str
    cves: list[CVE] = []
    severity: Severity = Severity.INFO
    priority: int | None = None
    summary: str = ""
    mitigation: str = ""
    detection: str = ""
    next_steps: list[str] = []
    evidence: str | None = None


class Event(BaseModel):
    """Append-only event written to a run's events.jsonl log."""

    ts: datetime
    run_id: str
    agent: str
    type: Literal["finding_added", "llm_call", "error", "note"]
    ref: str | None = None
    data: dict = Field(default_factory=dict)

    @classmethod
    def now(
        cls,
        run_id: str,
        agent: str,
        type: Literal["finding_added", "llm_call", "error", "note"],
        ref: str | None = None,
        data: dict | None = None,
    ) -> "Event":
        """Create an Event with the current UTC timestamp."""
        return cls(
            ts=datetime.now(timezone.utc),
            run_id=run_id,
            agent=agent,
            type=type,
            ref=ref,
            data=data or {},
        )


class Manifest(BaseModel):
    """Run manifest describing a single pentest session."""

    run_id: str
    started: datetime
    scenario: str
    targets: list[str]
    operator: str
    tool_versions: dict[str, str] = {}
