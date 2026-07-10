"""Base class for AI agents in the AI CyberSec Lab."""

from __future__ import annotations

from pathlib import Path

from tools.llm import LLMClient
from tools.schemas import Event


class BaseAgent:
    """Common context for all lab agents: run directory, LLM client, event log.

    Subclasses override ``name`` and implement ``run()``.
    """

    name: str = "base"

    def __init__(
        self,
        run_id: str,
        runs_dir: str | Path = "runs",
        llm: LLMClient | None = None,
    ) -> None:
        """Initialize the agent for a specific run.

        Args:
            run_id: Unique identifier of the run.
            runs_dir: Root directory containing run subdirectories.
            llm: Optional LLM client. If not provided, one is created lazily on first use.
        """
        self.run_id = run_id
        self.run_dir = Path(runs_dir) / run_id
        self.run_dir.mkdir(parents=True, exist_ok=True)
        self._llm = llm

    @property
    def llm(self) -> LLMClient:
        """Return the LLM client, creating it lazily on first access."""
        if self._llm is None:
            self._llm = LLMClient()
        return self._llm

    def emit_event(
        self,
        type: str,
        ref: str | None = None,
        data: dict | None = None,
    ) -> None:
        """Append an event to the run's events.jsonl log."""
        event = Event.now(
            run_id=self.run_id,
            agent=self.name,
            type=type,  # type: ignore[arg-type]
            ref=ref,
            data=data or {},
        )
        events_path = self.run_dir / "events.jsonl"
        with events_path.open("a", encoding="utf-8") as f:
            f.write(event.model_dump_json() + "\n")

    def run(self, *args, **kwargs):
        """Execute the agent's task. Must be implemented by subclasses."""
        raise NotImplementedError("Subclasses must implement run()")
