"""Tests for the Ollama LLM client.

All tests mock the underlying ``ollama.Client`` to avoid network calls.
"""

from unittest.mock import MagicMock

import pytest
from pydantic import BaseModel

from tools.config import ModelConfig
from tools.llm import LLMClient, LLMError


def _fake_config() -> ModelConfig:
    return ModelConfig(
        backend="ollama",
        host="http://localhost:11434",
        model="qwen2.5-coder:7b",
        embed_model="nomic-embed-text",
        context_tokens=8192,
        temperature=0.2,
    )


def _patched_client(monkeypatch, chat_return_value) -> LLMClient:
    mock_instance = MagicMock()
    mock_instance.chat.return_value = chat_return_value
    monkeypatch.setattr("ollama.Client", lambda *args, **kwargs: mock_instance)
    return LLMClient(config=_fake_config()), mock_instance


class _Answer(BaseModel):
    value: str
    count: int


def test_chat_returns_text(monkeypatch):
    client, mock = _patched_client(
        monkeypatch, {"message": {"content": "pong"}}
    )

    result = client.chat("Say 'pong' and nothing else.")

    assert result == "pong"
    mock.chat.assert_called_once()
    call_kwargs = mock.chat.call_args.kwargs
    assert call_kwargs["model"] == client.config.model
    assert call_kwargs["options"]["temperature"] == client.config.temperature
    assert call_kwargs["options"]["num_ctx"] == client.config.context_tokens


def test_chat_json_valid(monkeypatch):
    valid_json = '{"value": "pong", "count": 42}'
    client, mock = _patched_client(
        monkeypatch, {"message": {"content": valid_json}}
    )

    result = client.chat_json("Return a JSON object.", schema=_Answer)

    assert isinstance(result, _Answer)
    assert result.value == "pong"
    assert result.count == 42
    mock.chat.assert_called_once()
    assert mock.chat.call_args.kwargs["format"] == "json"


def test_chat_json_retries_then_raises(monkeypatch):
    client, mock = _patched_client(
        monkeypatch, {"message": {"content": "not valid json"}}
    )

    with pytest.raises(LLMError):
        client.chat_json("Return a JSON object.", schema=_Answer, retries=1)

    assert mock.chat.call_count == 2
