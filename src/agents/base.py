"""Base agent interface for all Hades agents."""

from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from src.ingestion.schema import UnifiedAlert


@dataclass
class AgentResult:
    """Standard result returned by every agent."""

    agent_name: str
    success: bool
    data: dict[str, Any] = field(default_factory=dict)
    error: str | None = None
    latency_ms: int = 0
    tokens_used: int = 0


class BaseAgent(ABC):
    """Abstract base for all Hades pipeline agents.

    Every agent receives a unified alert (plus optional context)
    and returns an AgentResult. Agents are stateless. Runtime state
    lives in the surrounding pipeline and audit store.
    """

    def __init__(self, config: dict[str, Any]) -> None:
        self.config = config

    @property
    @abstractmethod
    def name(self) -> str:
        """Agent identifier used in reasoning chains and logs."""

    @abstractmethod
    async def run(
        self,
        alert: UnifiedAlert,
        context: dict[str, Any] | None = None,
    ) -> AgentResult:
        """Process an alert and return structured result.

        Args:
            alert: Normalized SIEM alert to process.
            context: Optional enrichment from prior agents
                     (e.g., correlated events, RAG results).

        Returns:
            AgentResult with classification, correlation, or playbook data.
        """
