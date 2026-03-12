"""Public evaluation and decision schemas for the Hades v1 prototype."""

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
    DETERMINISTIC = "deterministic"
    RETRIEVAL_AUGMENTED = "retrieval_augmented"


@dataclass
class EvidenceItem:
    source_type: str = ""
    source_ref: str = ""
    summary: str = ""
    score: Optional[float] = None


@dataclass
class ToolInvocation:
    tool_name: str = ""
    arguments: dict = field(default_factory=dict)
    status: str = "not_run"
    duration_ms: Optional[int] = None


@dataclass
class OverrideRecord:
    actor: str = ""
    reason: str = ""
    previous_classification: Optional[str] = None
    new_classification: Optional[str] = None
    overridden_at: str = field(default_factory=lambda: datetime.utcnow().isoformat())


@dataclass
class EvalResult:
    """Single locked-benchmark result for one normalized alert."""

    eval_id: str = field(default_factory=lambda: str(uuid4()))
    config_id: str = ""
    dataset_name: str = ""
    dataset_split: str = "test"
    transform_version: str = "alert_projection_v1"
    annotation_protocol: str = "benchmark_label_v1"
    alert_id: str = ""
    ground_truth: TriageCategory = TriageCategory.TRUE_POSITIVE
    prediction: TriageCategory = TriageCategory.TRUE_POSITIVE
    confidence: float = 0.0
    latency_ms: int = 0
    tokens_input: int = 0
    tokens_output: int = 0
    mode_used: InferenceMode = InferenceMode.DETERMINISTIC
    model_version: str = ""
    timestamp: str = field(default_factory=lambda: datetime.utcnow().isoformat())


@dataclass
class TriageDecision:
    """Stable analyst-facing decision artifact."""

    decision_id: str = field(default_factory=lambda: str(uuid4()))
    alert_id: str = ""
    classification: TriageCategory = TriageCategory.NEEDS_INVESTIGATION
    confidence: float = 0.0
    severity_override: Optional[str] = None
    evidence_trace: list[EvidenceItem] = field(default_factory=list)
    tool_invocations: list[ToolInvocation] = field(default_factory=list)
    rationale_summary: str = ""
    correlated_events: list[str] = field(default_factory=list)
    mitre_techniques: list[str] = field(default_factory=list)
    playbook_id: Optional[str] = None
    processing_time_ms: int = 0
    mode_used: InferenceMode = InferenceMode.DETERMINISTIC
    model_version: str = ""
    override_record: Optional[OverrideRecord] = None
    created_at: str = field(default_factory=lambda: datetime.utcnow().isoformat())
