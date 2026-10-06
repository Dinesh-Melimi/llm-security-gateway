"""Pluggable upstream LLM providers."""
from __future__ import annotations

import os
from typing import Protocol

import httpx


class Provider(Protocol):
    name: str

    async def complete(self, model: str, messages: list[dict], max_tokens: int) -> dict: ...


class MockEchoProvider:
    """Deterministic offline provider: echoes the last user message. Used by default and in tests."""
    name = "mock"

    async def complete(self, model: str, messages: list[dict], max_tokens: int) -> dict:
        last = next((m["content"] for m in reversed(messages) if m.get("role") == "user"), "")
        text = f"[mock:{model}] You said: {last}"
        words = text.split()[:max_tokens]
        return {"content": " ".join(words), "prompt_tokens": sum(len(m["content"].split()) for m in messages),
                "completion_tokens": len(words)}


class OpenAICompatibleProvider:
    """Any OpenAI-compatible /v1/chat/completions endpoint (OpenAI, vLLM, Ollama, LiteLLM...)."""
    name = "openai"

    def __init__(self, base_url: str | None = None, api_key: str | None = None, timeout: float = 60):
        self.base_url = (base_url or os.environ.get("UPSTREAM_BASE_URL", "https://api.openai.com/v1")).rstrip("/")
        self.api_key = api_key or os.environ.get("UPSTREAM_API_KEY", "")
        self.timeout = timeout

    async def complete(self, model: str, messages: list[dict], max_tokens: int) -> dict:
        async with httpx.AsyncClient(timeout=self.timeout) as client:
            r = await client.post(f"{self.base_url}/chat/completions",
                                  headers={"Authorization": f"Bearer {self.api_key}"},
                                  json={"model": model, "messages": messages, "max_tokens": max_tokens})
            r.raise_for_status()
            data = r.json()
        usage = data.get("usage", {})
        return {"content": data["choices"][0]["message"]["content"],
                "prompt_tokens": usage.get("prompt_tokens", 0),
                "completion_tokens": usage.get("completion_tokens", 0)}


def get_provider(name: str) -> Provider:
    if name == "mock":
        return MockEchoProvider()
    if name == "openai":
        return OpenAICompatibleProvider()
    raise ValueError(f"unknown provider: {name}")
