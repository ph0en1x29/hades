"""Runtime adapters and model clients for Hades."""

from src.runtime.openai_compat import (
    ChatCompletionResult,
    OpenAICompatChatClient,
    OpenAICompatError,
)

__all__ = [
    "ChatCompletionResult",
    "OpenAICompatChatClient",
    "OpenAICompatError",
]
