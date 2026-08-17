"""Configuration helper for ReconPilot's local AI Advisor.

The advisor uses Ollama by default. Settings are stored in:

    ~/.config/reconpilot/config.json

with this shape::

    {
      "ai_provider": "ollama",
      "ollama_base_url": "http://127.0.0.1:11434",
      "ollama_model": "gemma3:1b"
    }

Environment variables are supported as fallbacks when a file value is absent:
``RECONPILOT_AI_PROVIDER``, ``OLLAMA_BASE_URL`` and ``OLLAMA_MODEL``.
"""
from __future__ import annotations

import json
import os
import re
from pathlib import Path

CONFIG_DIR = Path.home() / ".config" / "reconpilot"
CONFIG_PATH = CONFIG_DIR / "config.json"

DEFAULT_AI_PROVIDER = "ollama"
DEFAULT_OLLAMA_BASE_URL = "http://127.0.0.1:11434"
DEFAULT_OLLAMA_MODEL = "gemma3:1b"


def _load_config() -> dict:
    if not CONFIG_PATH.exists():
        return {}
    try:
        data = json.loads(CONFIG_PATH.read_text(encoding="utf-8"))
        return data if isinstance(data, dict) else {}
    except Exception:
        return {}


def _normalise_url(value: str) -> str:
    """Return a clean base URL, tolerating Markdown-link text if pasted."""
    value = (value or "").strip()
    match = re.fullmatch(r"\[([^\]]+)\]\(([^)]+)\)", value)
    if match:
        value = match.group(2).strip()
    return value.rstrip("/")


def get_ai_provider() -> str:
    cfg = _load_config()
    return (
        cfg.get("ai_provider")
        or os.environ.get("RECONPILOT_AI_PROVIDER")
        or DEFAULT_AI_PROVIDER
    ).strip().lower()


def get_ollama_base_url() -> str:
    cfg = _load_config()
    value = (
        cfg.get("ollama_base_url")
        or os.environ.get("OLLAMA_BASE_URL")
        or DEFAULT_OLLAMA_BASE_URL
    )
    return _normalise_url(str(value))


def get_ollama_model() -> str:
    cfg = _load_config()
    return str(
        cfg.get("ollama_model")
        or os.environ.get("OLLAMA_MODEL")
        or DEFAULT_OLLAMA_MODEL
    ).strip()


def get_ai_config() -> dict[str, str]:
    """Return the effective AI Advisor configuration."""
    return {
        "ai_provider": get_ai_provider(),
        "ollama_base_url": get_ollama_base_url(),
        "ollama_model": get_ollama_model(),
    }


def save_ai_config(
    ai_provider: str,
    ollama_base_url: str,
    ollama_model: str,
) -> Path:
    """Persist AI Advisor settings and return the config-file path."""
    provider = (ai_provider or "").strip().lower()
    base_url = _normalise_url(ollama_base_url)
    model = (ollama_model or "").strip()

    if not provider:
        raise ValueError("AI provider cannot be empty.")
    if not base_url:
        raise ValueError("Ollama base URL cannot be empty.")
    if not model:
        raise ValueError("Ollama model cannot be empty.")
    if not base_url.startswith(("http://", "https://")):
        raise ValueError("Ollama base URL must start with http:// or https://.")

    CONFIG_DIR.mkdir(parents=True, exist_ok=True)
    cfg = _load_config()
    cfg["ai_provider"] = provider
    cfg["ollama_base_url"] = base_url
    cfg["ollama_model"] = model

    # Remove obsolete OpenAI credentials/settings when the new local-provider
    # configuration is explicitly saved through ReconPilot.
    cfg.pop("openai_api_key", None)
    cfg.pop("openai_model", None)

    tmp = CONFIG_PATH.with_suffix(".json.tmp")
    tmp.write_text(json.dumps(cfg, indent=2) + "\n", encoding="utf-8")
    try:
        os.chmod(tmp, 0o600)
    except Exception:
        pass
    tmp.replace(CONFIG_PATH)
    return CONFIG_PATH
