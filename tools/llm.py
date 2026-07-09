"""Thin Ollama LLM client with plain chat and structured JSON output.

Implements §5.4 of docs/ARCHITECTURE.md: structured output, Pydantic validation,
and one retry on validation failure.
"""

from __future__ import annotations

import json
from typing import TYPE_CHECKING

from pydantic import BaseModel, ValidationError

from tools.config import ModelConfig, load_model_config

if TYPE_CHECKING:
    import ollama
else:
    import ollama


class LLMError(Exception):
    """Raised when the LLM client fails to produce a valid response."""


class LLMClient:
    """Client for chatting with a local Ollama model.

    Attributes:
        config: Resolved model configuration.
        client: Underlying Ollama client instance.
    """

    def __init__(self, config: ModelConfig | None = None) -> None:
        """Initialize the client.

        Args:
            config: Model configuration. If ``None``, loads ``configs/model.yaml``.
        """
        self.config = config if config is not None else load_model_config()
        self.client = ollama.Client(host=self.config.host)

    def _build_messages(self, prompt: str, system: str | None = None) -> list[dict]:
        messages: list[dict] = []
        if system:
            messages.append({"role": "system", "content": system})
        messages.append({"role": "user", "content": prompt})
        return messages

    def _options(self) -> dict:
        return {
            "temperature": self.config.temperature,
            "num_ctx": self.config.context_tokens,
        }

    def chat(self, prompt: str, system: str | None = None) -> str:
        """Send a single chat request and return the model's text response.

        Args:
            prompt: User prompt.
            system: Optional system message.

        Returns:
            Text content of the model's response.

        Raises:
            LLMError: If the response cannot be retrieved.
        """
        try:
            response = self.client.chat(
                model=self.config.model,
                messages=self._build_messages(prompt, system),
                options=self._options(),
            )
        except Exception as exc:
            raise LLMError(f"Ollama chat request failed: {exc}") from exc

        try:
            return response["message"]["content"]
        except (KeyError, TypeError) as exc:
            raise LLMError(f"Unexpected Ollama response shape: {response}") from exc

    def chat_json(
        self,
        prompt: str,
        schema: type[BaseModel],
        system: str | None = None,
        retries: int = 1,
    ) -> BaseModel:
        """Request JSON output from the model and validate it against a Pydantic schema.

        Uses Ollama's ``format="json"`` mode. On validation failure, retries up to
        ``retries`` times, feeding the validation error back into the prompt.

        Args:
            prompt: User prompt.
            schema: Pydantic model class to validate against.
            system: Optional system message.
            retries: Number of retries on validation failure (default 1).

        Returns:
            Validated instance of ``schema``.

        Raises:
            LLMError: If all attempts fail to produce a valid response.
        """
        current_prompt = prompt
        last_error: Exception | None = None
        max_attempts = 1 + retries

        for attempt in range(max_attempts):
            try:
                response = self.client.chat(
                    model=self.config.model,
                    messages=self._build_messages(current_prompt, system),
                    options=self._options(),
                    format="json",
                )
            except Exception as exc:
                raise LLMError(f"Ollama chat request failed: {exc}") from exc

            try:
                content = response["message"]["content"]
            except (KeyError, TypeError) as exc:
                raise LLMError(
                    f"Unexpected Ollama response shape: {response}"
                ) from exc

            try:
                return schema.model_validate_json(content)
            except (ValidationError, json.JSONDecodeError) as exc:
                last_error = exc
                if attempt < retries:
                    current_prompt = (
                        f"{prompt}\n\n"
                        f"Your previous response was invalid. Error: {exc}\n"
                        f"Please return a valid JSON object matching the schema."
                    )

        raise LLMError(
            f"Failed to get valid JSON after {max_attempts} attempt(s): {last_error}"
        ) from last_error
