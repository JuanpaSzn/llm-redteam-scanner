"""Generic target for any OpenAI-compatible chat endpoint (OpenAI, Ollama, LM Studio, vLLM...).

Useful to audit your own models: give it a system prompt holding a secret and see if it leaks.
"""

from __future__ import annotations

from ..llm import ChatLLM
from .base import Target


class OpenAIChatTarget(Target):
    def __init__(
        self,
        model: str,
        *,
        system_prompt: str | None = None,
        secret: str | None = None,
        base_url: str | None = None,
        api_key: str | None = None,
        objective: str | None = None,
    ) -> None:
        self._llm = ChatLLM(model=model, base_url=base_url, api_key=api_key, temperature=0.7)
        self.system_prompt = system_prompt
        self.secret = secret
        self.name = f"openai:{model}"
        if objective:
            self.objective = objective

    def send(self, prompt: str) -> str:
        messages = []
        if self.system_prompt:
            messages.append({"role": "system", "content": self.system_prompt})
        messages.append({"role": "user", "content": prompt})
        return self._llm.chat(messages)

    def verify(self, candidate: str) -> bool | None:
        if self.secret is None:
            return None
        return candidate.strip().lower() == self.secret.strip().lower()
