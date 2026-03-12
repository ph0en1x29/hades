"""Adversarial evaluation framework for LLM-based SOC triage."""

from .defenses import CanaryDefense, SanitizationDefense, StructuredPromptDefense
from .payloads import PayloadGenerator
from .vectors import INJECTION_VECTORS

__all__ = [
    "CanaryDefense",
    "SanitizationDefense",
    "StructuredPromptDefense",
    "PayloadGenerator",
    "INJECTION_VECTORS",
]
