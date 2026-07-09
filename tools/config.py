"""Configuration loaders for the AI CyberSec Lab."""

from __future__ import annotations

import os
from pathlib import Path

import yaml
from pydantic import BaseModel


class ModelConfig(BaseModel):
    """LLM configuration loaded from configs/model.yaml."""

    backend: str
    host: str
    model: str
    embed_model: str
    context_tokens: int
    temperature: float


def load_model_config(path: str = "configs/model.yaml") -> ModelConfig:
    """Load and validate the model configuration.

    The path can be overridden via the AILAB_MODEL_CONFIG environment variable.
    """
    effective_path = os.environ.get("AILAB_MODEL_CONFIG", path)
    file_path = Path(effective_path)

    if not file_path.is_absolute():
        file_path = Path.cwd() / file_path

    with file_path.open("r", encoding="utf-8") as f:
        raw = yaml.safe_load(f)

    return ModelConfig.model_validate(raw)
