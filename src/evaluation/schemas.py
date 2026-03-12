"""Evaluation and triage decision schemas for benchmark tracking."""

from __future__ import annotations

import json
from dataclasses import asdict, dataclass, field
from datetime import UTC, datetime
from enum import Enum
from typing import Optional, Self
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


@dataclass(slots=True)
class EvalResult:
    """Single evaluation result for one alert against ground truth."""

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
    timestamp: str = field(
        default_factory=lambda: datetime.now(UTC).isoformat()
    )

    @property
    def correct(self) -> bool:
        return self.ground_truth == self.prediction

    def to_dict(self) -> dict:
        d = asdict(self)
        d["ground_truth"] = self.ground_truth.value
        d["prediction"] = self.prediction.value
        d["mode_used"] = self.mode_used.value
        return d

    def to_json(self) -> str:
        return json.dumps(self.to_dict())

    @classmethod
    def from_dict(cls, data: dict) -> Self:
        return cls(
            eval_id=data.get("eval_id", str(uuid4())),
            config_id=data.get("config_id", ""),
            dataset=data.get("dataset", ""),
            alert_id=data.get("alert_id", ""),
            ground_truth=TriageCategory(data["ground_truth"]) if "ground_truth" in data else TriageCategory.TRUE_POSITIVE,
            prediction=TriageCategory(data["prediction"]) if "prediction" in data else TriageCategory.TRUE_POSITIVE,
            confidence=data.get("confidence", 0.0),
            latency_ms=data.get("latency_ms", 0),
            tokens_input=data.get("tokens_input", 0),
            tokens_output=data.get("tokens_output", 0),
            mode_used=InferenceMode(data["mode_used"]) if "mode_used" in data else InferenceMode.INSTANT,
            seed=data.get("seed", 42),
            model_version=data.get("model_version", ""),
            timestamp=data.get("timestamp", datetime.now(UTC).isoformat()),
        )


@dataclass(slots=True)
class ReasoningStep:
    """Single step in an agent's reasoning chain."""

    step: int = 0
    agent: str = ""
    action: str = ""
    result: str = ""


@dataclass(slots=True)
class TriageDecision:
    """Full triage decision with audit trail.

    Every field is logged to the append-only audit database.
    The reasoning_chain provides full transparency for compliance review.
    """

    decision_id: str = field(default_factory=lambda: str(uuid4()))
    alert_id: str = ""
    classification: TriageCategory = TriageCategory.NEEDS_INVESTIGATION
    confidence: float = 0.0
    severity_override: Optional[str] = None
    reasoning_chain: list[ReasoningStep] = field(default_factory=list)
    correlated_events: list[str] = field(default_factory=list)
    mitre_techniques: list[str] = field(default_factory=list)
    playbook_id: Optional[str] = None
    processing_time_ms: int = 0
    mode_used: InferenceMode = InferenceMode.INSTANT
    model_version: str = ""
    analyst_override: Optional[str] = None
    created_at: str = field(
        default_factory=lambda: datetime.now(UTC).isoformat()
    )

    def to_dict(self) -> dict:
        d = asdict(self)
        d["classification"] = self.classification.value
        d["mode_used"] = self.mode_used.value
        return d

    def to_json(self) -> str:
        return json.dumps(self.to_dict())
