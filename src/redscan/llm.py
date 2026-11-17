"""Thin wrapper around the OpenAI SDK used by the attacker, the judge and the generic target."""

from __future__ import annotations

import json
import os
import re
from typing import Any, Protocol


class LLM(Protocol):
    def chat(self, messages: list[dict[str, str]], *, json_mode: bool = False) -> str: ...


class ChatLLM:
    def __init__(
        self,
        model: str,
        *,
        base_url: str | None = None,
        api_key: str | None = None,
        temperature: float = 1.0,
    ) -> None:
        from openai import OpenAI  # imported lazily so tests don't need network or keys

        base_url = base_url or os.getenv("REDSCAN_LLM_BASE_URL") or None
        api_key = api_key or os.getenv("OPENAI_API_KEY") or ("ollama" if base_url else None)
        if not api_key:
            raise RuntimeError("OPENAI_API_KEY is not set. Copy .env.example to .env and add your key.")
        self.model = model
        self.temperature = temperature
        self._client = OpenAI(api_key=api_key, base_url=base_url)

    def chat(self, messages: list[dict[str, str]], *, json_mode: bool = False) -> str:
        kwargs: dict[str, Any] = {"model": self.model, "messages": messages, "temperature": self.temperature}
        if json_mode:
            kwargs["response_format"] = {"type": "json_object"}
        resp = self._client.chat.completions.create(**kwargs)
        return resp.choices[0].message.content or ""


def parse_json(text: str) -> dict[str, Any]:
    """Parse a JSON object from an LLM reply, tolerating code fences and surrounding prose."""
    text = text.strip()
    fenced = re.search(r"```(?:json)?\s*(\{.*?\})\s*```", text, re.S)
    if fenced:
        text = fenced.group(1)
    try:
        return json.loads(text)
    except json.JSONDecodeError:
        start, end = text.find("{"), text.rfind("}")
        if start != -1 and end > start:
            return json.loads(text[start : end + 1])
        raise
