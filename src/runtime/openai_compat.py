"""Minimal OpenAI-compatible chat client for local vLLM servers.

Uses only the Python standard library so the pipeline can run on fresh lab
machines without requiring the optional cloud SDKs. Intended for local,
air-gapped, OpenAI-compatible endpoints such as vLLM.
"""

from __future__ import annotations

import json
import os
import urllib.error
import urllib.request
from dataclasses import dataclass
from typing import Any


@dataclass(slots=True)
class ChatCompletionResult:
    content: str
    model: str = ""
    prompt_tokens: int = 0
    completion_tokens: int = 0
    total_tokens: int = 0
    finish_reason: str = ""
    raw: dict[str, Any] | None = None


class OpenAICompatError(RuntimeError):
    """Raised when the OpenAI-compatible endpoint fails."""


class OpenAICompatChatClient:
    """Tiny client for `/v1/chat/completions` compatible endpoints."""

    def __init__(
        self,
        *,
        base_url: str | None = None,
        api_key: str | None = None,
        timeout_seconds: int = 90,
    ) -> None:
        resolved_base = base_url or os.getenv("MODEL_SERVER_URL") or "http://localhost:8001"
        self.base_url = resolved_base.rstrip("/")
        self.api_key = api_key or os.getenv("OPENAI_API_KEY") or "EMPTY"
        self.timeout_seconds = timeout_seconds

    def chat_completion(
        self,
        *,
        model: str,
        system: str,
        user: str,
        temperature: float = 0.0,
        max_tokens: int = 512,
        seed: int | None = None,
        response_format: dict[str, Any] | None = None,
    ) -> ChatCompletionResult:
        payload: dict[str, Any] = {
            "model": model,
            "messages": [
                {"role": "system", "content": system},
                {"role": "user", "content": user},
            ],
            "temperature": temperature,
            "max_tokens": max_tokens,
        }
        if seed is not None:
            payload["seed"] = seed
        if response_format is not None:
            payload["response_format"] = response_format

        request = urllib.request.Request(
            url=f"{self.base_url}/v1/chat/completions",
            data=json.dumps(payload).encode("utf-8"),
            headers={
                "Content-Type": "application/json",
                "Authorization": f"Bearer {self.api_key}",
            },
            method="POST",
        )

        try:
            with urllib.request.urlopen(request, timeout=self.timeout_seconds) as response:
                body = response.read().decode("utf-8")
        except urllib.error.HTTPError as exc:
            detail = exc.read().decode("utf-8", errors="replace")
            raise OpenAICompatError(f"HTTP {exc.code} from model server: {detail[:500]}") from exc
        except urllib.error.URLError as exc:
            raise OpenAICompatError(f"Model server unreachable: {exc.reason}") from exc

        try:
            data = json.loads(body)
        except json.JSONDecodeError as exc:
            raise OpenAICompatError(f"Invalid JSON from model server: {body[:500]}") from exc

        choices = data.get("choices") or []
        if not choices:
            raise OpenAICompatError(f"No choices returned from model server: {data}")

        first_choice = choices[0]
        message = first_choice.get("message") or {}
        usage = data.get("usage") or {}

        return ChatCompletionResult(
            content=str(message.get("content", "")),
            model=str(data.get("model", model)),
            prompt_tokens=int(usage.get("prompt_tokens", 0) or 0),
            completion_tokens=int(usage.get("completion_tokens", 0) or 0),
            total_tokens=int(usage.get("total_tokens", 0) or 0),
            finish_reason=str(first_choice.get("finish_reason", "")),
            raw=data,
        )


__all__ = [
    "ChatCompletionResult",
    "OpenAICompatChatClient",
    "OpenAICompatError",
]
