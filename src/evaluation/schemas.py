"""Evaluation and triage decision schemas for the scoped Hades v1 prototype."""

from __future__ import annotations

import json
from dataclasses import asdict, dataclass, field
from datetime import UTC, datetime
from enum import Enum
from typing import Any, Self
from uuid import uuid4


class TriageCategory(Enum):
    TRUE_POSITIVE = "true_positive"
    FALSE_POSITIVE = "false_positive"
    NEEDS_INVESTIGATION = "needs_investigation"
    ESCALATE = "escalate"


class InferenceMode(Enum):
    DETERMINISTIC = "deterministic"
    RETRIEVAL_AUGMENTED = "retrieval_augmented"


@dataclass(slots=True)
class EvalResult:
    """Single evaluation result for one alert against ground truth."""

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
    timestamp: str = field(
        default_factory=lambda: datetime.now(UTC).isoformat()
    )

    @property
    def correct(self) -> bool:
        return self.ground_truth == self.prediction

    def to_dict(self) -> dict[str, Any]:
        d = asdict(self)
        d["ground_truth"] = self.ground_truth.value
        d["prediction"] = self.prediction.value
        d["mode_used"] = self.mode_used.value
        return d

    def to_json(self) -> str:
        return json.dumps(self.to_dict())

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> Self:
        return cls(
            eval_id=data.get("eval_id", str(uuid4())),
            config_id=data.get("config_id", ""),
            dataset_name=data.get("dataset_name", data.get("dataset", "")),
            dataset_split=data.get("dataset_split", "test"),
            transform_version=data.get("transform_version", "alert_projection_v1"),
            annotation_protocol=data.get("annotation_protocol", "benchmark_label_v1"),
            alert_id=data.get("alert_id", ""),
            ground_truth=TriageCategory(data["ground_truth"]) if "ground_truth" in data else TriageCategory.TRUE_POSITIVE,
            prediction=TriageCategory(data["prediction"]) if "prediction" in data else TriageCategory.TRUE_POSITIVE,
            confidence=data.get("confidence", 0.0),
            latency_ms=data.get("latency_ms", 0),
            tokens_input=data.get("tokens_input", 0),
            tokens_output=data.get("tokens_output", 0),
            mode_used=InferenceMode(data["mode_used"]) if "mode_used" in data else InferenceMode.DETERMINISTIC,
            model_version=data.get("model_version", ""),
            timestamp=data.get("timestamp", datetime.now(UTC).isoformat()),
        )


@dataclass(slots=True)
class EvidenceItem:
    """Evidence surfaced to the analyst and audit layer."""

    source_type: str = ""
    source_ref: str = ""
    summary: str = ""
    score: float | None = None


@dataclass(slots=True)
class ToolInvocation:
    """Stable record of a tool or retrieval call."""

    tool_name: str = ""
    arguments: dict[str, Any] = field(default_factory=dict)
    status: str = "not_run"
    duration_ms: int | None = None


@dataclass(slots=True)
class OverrideRecord:
    """Analyst override applied to an automated decision."""

    actor: str = ""
    reason: str = ""
    previous_classification: str | None = None
    new_classification: str | None = None
    overridden_at: str = field(default_factory=lambda: datetime.now(UTC).isoformat())


@dataclass(slots=True)
class TriageDecision:
    """Stable analyst-facing triage decision artifact."""

    decision_id: str = field(default_factory=lambda: str(uuid4()))
    alert_id: str = ""
    classification: TriageCategory = TriageCategory.NEEDS_INVESTIGATION
    confidence: float = 0.0
    severity_override: str | None = None
    evidence_trace: list[EvidenceItem] = field(default_factory=list)
    tool_invocations: list[ToolInvocation] = field(default_factory=list)
    rationale_summary: str = ""
    correlated_events: list[str] = field(default_factory=list)
    mitre_techniques: list[str] = field(default_factory=list)
    playbook_id: str | None = None
    processing_time_ms: int = 0
    mode_used: InferenceMode = InferenceMode.DETERMINISTIC
    model_version: str = ""
    override_record: OverrideRecord | None = None
    created_at: str = field(
        default_factory=lambda: datetime.now(UTC).isoformat()
    )

    def to_dict(self) -> dict[str, Any]:
        d = asdict(self)
        d["classification"] = self.classification.value
        d["mode_used"] = self.mode_used.value
        return d

    def to_json(self) -> str:
        return json.dumps(self.to_dict())

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> Self:
        evidence_trace = [
            item if isinstance(item, EvidenceItem) else EvidenceItem(**item)
            for item in data.get("evidence_trace", [])
        ]
        tool_invocations = [
            item if isinstance(item, ToolInvocation) else ToolInvocation(**item)
            for item in data.get("tool_invocations", [])
        ]
        override_data = data.get("override_record")
        override_record = (
            override_data
            if isinstance(override_data, OverrideRecord)
            else OverrideRecord(**override_data)
            if override_data
            else None
        )

        return cls(
            decision_id=data.get("decision_id", str(uuid4())),
            alert_id=data.get("alert_id", ""),
            classification=TriageCategory(data["classification"]) if "classification" in data else TriageCategory.NEEDS_INVESTIGATION,
            confidence=data.get("confidence", 0.0),
            severity_override=data.get("severity_override"),
            evidence_trace=evidence_trace,
            tool_invocations=tool_invocations,
            rationale_summary=data.get("rationale_summary", ""),
            correlated_events=data.get("correlated_events", []),
            mitre_techniques=data.get("mitre_techniques", []),
            playbook_id=data.get("playbook_id"),
            processing_time_ms=data.get("processing_time_ms", 0),
            mode_used=InferenceMode(data["mode_used"]) if "mode_used" in data else InferenceMode.DETERMINISTIC,
            model_version=data.get("model_version", ""),
            override_record=override_record,
            created_at=data.get("created_at", datetime.now(UTC).isoformat()),
        )
