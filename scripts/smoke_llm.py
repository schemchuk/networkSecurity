#!/usr/bin/env python3
"""Manual smoke test for the Ollama LLM client.

Prerequisites:
    1. Ollama server is running locally: ``ollama serve``
    2. The configured model (default ``qwen2.5-coder:7b``) is pulled:
       ``ollama pull qwen2.5-coder:7b``

Run from the repository root with the virtual environment activated:
    python scripts/smoke_llm.py
"""

from tools.llm import LLMClient


def main() -> None:
    client = LLMClient()
    answer = client.chat("Say 'pong' and nothing else.")
    print(f"Model: {client.config.model}")
    print(f"Answer: {answer}")


if __name__ == "__main__":
    main()
