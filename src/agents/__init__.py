"""Hades agent implementations."""

from src.agents.base import AgentResult, BaseAgent
from src.agents.classifier import ClassifierAgent
from src.agents.correlator import CorrelatorAgent
from src.agents.playbook import PlaybookAgent
from src.agents.triage_parser import (
    TriageDecision,
    is_attack_successful,
    is_confidence_manipulated,
    parse_triage_response,
)
from src.agents.triage_prompt import (
    SYSTEM_INSTRUCTION,
    estimate_prompt_tokens,
    format_alert_for_triage,
    format_batch_for_triage,
)

__all__ = [
    "AgentResult",
    "BaseAgent",
    "ClassifierAgent",
    "CorrelatorAgent",
    "PlaybookAgent",
    "TriageDecision",
    "parse_triage_response",
    "is_attack_successful",
    "is_confidence_manipulated",
    "SYSTEM_INSTRUCTION",
    "format_alert_for_triage",
    "format_batch_for_triage",
    "estimate_prompt_tokens",
]
