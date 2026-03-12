"""Evaluation result schemas for benchmark tracking."""

from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import Optional
from uuid import uuid4


class TriageCategory(Enum):
    TRUE_POSITIVE = "true_positive"
    FALSE_POSITIVE = "false_positive"
    NEEDS_INVESTIGATION = "needs_investigation"
    ESCALATE = "escalate"


class InferenceMode(Enum):
    INSTANT = "instant"
    THINKING = "thinking"
    SWARM = "swarm"


@dataclass
class EvalResult:
    """Single evaluation result for one alert."""

    eval_id: str = field(default_factory=lambda: str(uuid4()))
    config_id: str = ""
    dataset: str = ""
    alert_id: str = ""
    ground_truth: TriageCategory = TriageCategory.TRUE_POSITIVE
    prediction: TriageCategory = TriageCategory.TRUE_POSITIVE
    confidence: float = 0.0
    latency_ms: int = 0
    tokens_input: int = 0
    tokens_output: int = 0
    mode_used: InferenceMode = InferenceMode.INSTANT
    seed: int = 42
    model_version: str = ""
    timestamp: str = field(default_factory=lambda: datetime.utcnow().isoformat())


@dataclass
class TriageDecision:
    """Full triage decision with audit trail."""

    decision_id: str = field(default_factory=lambda: str(uuid4()))
    alert_id: str = ""
    classification: TriageCategory = TriageCategory.NEEDS_INVESTIGATION
    confidence: float = 0.0
    severity_override: Optional[str] = None
    reasoning_chain: list = field(default_factory=list)
    correlated_events: list = field(default_factory=list)
    mitre_techniques: list = field(default_factory=list)
    playbook_id: Optional[str] = None
    processing_time_ms: int = 0
    mode_used: InferenceMode = InferenceMode.INSTANT
    model_version: str = ""
    analyst_override: Optional[str] = None
    created_at: str = field(default_factory=lambda: datetime.utcnow().isoformat())
