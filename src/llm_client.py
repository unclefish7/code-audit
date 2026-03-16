"""LLM client for OpenAI-compatible providers (default: DeepSeek)."""

from __future__ import annotations

import logging
import os
from pathlib import Path
from typing import Any, Dict, List, Optional


class LLMClientError(Exception):
    """Raised when LLM configuration or request fails."""


class LLMClient:
    """Chat completion wrapper that returns response text and token usage."""

    @staticmethod
    def _load_dotenv_file() -> None:
        """Load key-value pairs from project .env into process environment if present."""
        project_root = Path(__file__).resolve().parents[1]
        dotenv_path = project_root / ".env"
        if not dotenv_path.exists():
            return

        try:
            raw_lines = dotenv_path.read_text(encoding="utf-8").splitlines()
        except OSError:
            return

        for raw in raw_lines:
            line = raw.strip()
            if not line or line.startswith("#"):
                continue
            if line.startswith("export "):
                line = line[len("export ") :].strip()
            if "=" not in line:
                continue
            key, value = line.split("=", 1)
            key = key.strip()
            value = value.strip()
            if not key:
                continue
            if (value.startswith('"') and value.endswith('"')) or (
                value.startswith("'") and value.endswith("'")
            ):
                value = value[1:-1]
            os.environ.setdefault(key, value)

    def __init__(self, config: Dict[str, Any]):
        self.logger = logging.getLogger(__name__)
        self._load_dotenv_file()
        llm_cfg = config.get("llm", {})
        self.provider = str(llm_cfg.get("provider", "deepseek"))
        self.model = str(llm_cfg.get("model", "deepseek-reasoner"))
        self.base_url = str(llm_cfg.get("base_url", "https://api.deepseek.com"))
        self.temperature = float(llm_cfg.get("temperature", 0.0))
        self.max_tokens = int(llm_cfg.get("max_tokens", 4096))

        api_key_env = str(llm_cfg.get("api_key_env", "DEEPSEEK_API_KEY")).strip()
        if not api_key_env:
            raise LLMClientError("llm.api_key_env is empty in config")

        api_key = os.getenv(api_key_env, "").strip()
        if not api_key:
            raise LLMClientError(
                f"Missing API key from environment variable: {api_key_env}. "
                "Please export it before running audit."
            )

        try:
            from openai import OpenAI
        except ImportError as exc:
            raise LLMClientError(
                "openai package is required for LLM audit. Install with: pip install openai"
            ) from exc

        self._client = OpenAI(api_key=api_key, base_url=self.base_url)
        self.logger.info("LLM initialized. provider=%s model=%s", self.provider, self.model)

    @staticmethod
    def _extract_usage(usage_obj: Any) -> Dict[str, int]:
        """Extract token usage from SDK response usage object."""
        if usage_obj is None:
            return {"prompt_tokens": 0, "completion_tokens": 0, "total_tokens": 0}

        prompt_tokens = int(getattr(usage_obj, "prompt_tokens", 0) or 0)
        completion_tokens = int(getattr(usage_obj, "completion_tokens", 0) or 0)
        total_tokens = int(getattr(usage_obj, "total_tokens", 0) or 0)

        if total_tokens <= 0:
            total_tokens = prompt_tokens + completion_tokens

        return {
            "prompt_tokens": prompt_tokens,
            "completion_tokens": completion_tokens,
            "total_tokens": total_tokens,
        }

    def chat(self, messages: List[Dict[str, str]]) -> Dict[str, Any]:
        """Call chat completion and return assistant text + token usage."""
        try:
            response = self._client.chat.completions.create(
                model=self.model,
                messages=messages,
                temperature=self.temperature,
                max_tokens=self.max_tokens,
                response_format={"type": "json_object"},
            )
        except Exception as exc:  # noqa: BLE001 - keep first version robust
            raise LLMClientError(f"LLM chat completion failed: {exc}") from exc

        content: Optional[str] = None
        if response.choices:
            content = response.choices[0].message.content

        text = (content or "").strip()
        usage = self._extract_usage(getattr(response, "usage", None))

        return {
            "text": text,
            "usage": usage,
        }
