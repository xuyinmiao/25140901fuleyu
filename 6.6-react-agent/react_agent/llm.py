from __future__ import annotations

import os
import re


class LLMError(RuntimeError):
    pass


class OpenAIChatClient:
    def __init__(self, model: str, api_key_env: str = "OPENAI_API_KEY", base_url: str | None = None):
        self.model = model
        self.api_key_env = api_key_env
        self.base_url = base_url

        api_key = os.getenv(api_key_env)
        if not api_key:
            raise LLMError(
                f"Missing API key. Set {api_key_env}=... or pass --api-key-env with another env var name."
            )

        try:
            from openai import OpenAI
        except ImportError as exc:
            raise LLMError("Python package 'openai' is not installed. Run: pip install -r requirements.txt") from exc

        kwargs = {"api_key": api_key}
        if base_url:
            kwargs["base_url"] = base_url
        self.client = OpenAI(**kwargs)

    def complete(self, messages: list[dict[str, str]]) -> str:
        try:
            response = self.client.chat.completions.create(
                model=self.model,
                messages=messages,
                temperature=0,
            )
        except Exception as exc:
            raise LLMError(f"LLM request failed: {_redact_secret(str(exc))}") from exc

        content = response.choices[0].message.content
        if not content:
            raise LLMError("LLM returned an empty message.")
        return content.strip()


def _redact_secret(text: str) -> str:
    return re.sub(r"sk-[A-Za-z0-9_*.-]+", "sk-***REDACTED***", text)
