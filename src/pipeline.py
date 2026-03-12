"""Prototype alert triage pipeline."""

from __future__ import annotations

import time
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path
from typing import TYPE_CHECKING, Any

from src.evaluation.schemas import (
    EvidenceItem,
    InferenceMode,
    ToolInvocation,
    TriageCategory,
    TriageDecision,
)

if TYPE_CHECKING:
    from src.agents import ClassifierAgent
    from src.agents.base import AgentResult
    from src.ingestion.schema import UnifiedAlert


@dataclass(slots=True)
class PipelineRunResult:
    """Summary and artifacts produced by one pipeline run."""

    decisions: list[TriageDecision] = field(default_factory=list)
    total_alerts: int = 0
    classification_counts: dict[str, int] = field(default_factory=dict)
    total_processing_ms: int = 0
    wall_clock_ms: int = 0
    output_path: str = ""
    started_at: str = field(
        default_factory=lambda: datetime.now(UTC).isoformat()
    )
    finished_at: str | None = None

    @property
    def avg_latency_ms(self) -> float:
        if self.total_alerts == 0:
            return 0.0
        return self.total_processing_ms / self.total_alerts


class TriagePipeline:
    """Minimal async pipeline for classifying unified alerts."""

    def __init__(self, classifier: ClassifierAgent) -> None:
        self.classifier = classifier

    async def run(
        self,
        alerts: list[UnifiedAlert],
        output_path: str | Path,
    ) -> PipelineRunResult:
        """Classify alerts, emit decisions, and write them to JSONL."""
        destination = Path(output_path)
        destination.parent.mkdir(parents=True, exist_ok=True)

        run_result = PipelineRunResult(
            total_alerts=len(alerts),
            output_path=str(destination),
        )

        started = time.monotonic()
        with destination.open("w", encoding="utf-8") as handle:
            for alert in alerts:
                decision = await self._classify_alert(alert)
                run_result.decisions.append(decision)
                run_result.total_processing_ms += decision.processing_time_ms
                classification = decision.classification.value
                run_result.classification_counts[classification] = (
                    run_result.classification_counts.get(classification, 0) + 1
                )
                handle.write(f"{decision.to_json()}\n")

        run_result.wall_clock_ms = int((time.monotonic() - started) * 1000)
        run_result.finished_at = datetime.now(UTC).isoformat()
        return run_result

    async def _classify_alert(self, alert: UnifiedAlert) -> TriageDecision:
        result = await self.classifier.run(alert)
        classification = _coerce_classification(result)
        confidence = _coerce_confidence(result.data.get("confidence"))
        rationale = (
            result.data.get("reasoning")
            or result.error
            or "Classifier returned no reasoning."
        )

        return TriageDecision(
            alert_id=alert.alert_id,
            classification=classification,
            confidence=confidence,
            evidence_trace=[
                EvidenceItem(
                    source_type="alert",
                    source_ref=f"alert:{alert.alert_id}",
                    summary=_build_evidence_summary(alert),
                    score=confidence if result.success else None,
                ),
            ],
            tool_invocations=[
                ToolInvocation(
                    tool_name=self.classifier.name,
                    arguments={
                        "alert_id": alert.alert_id,
                        "event_type": alert.event_type or "",
                    },
                    status="success" if result.success else "error",
                    duration_ms=result.latency_ms,
                ),
            ],
            rationale_summary=rationale,
            correlated_events=[],
            mitre_techniques=_coerce_string_list(
                result.data.get("mitre_techniques"),
            ),
            processing_time_ms=result.latency_ms,
            mode_used=InferenceMode.DETERMINISTIC,
            model_version=_resolve_model_version(self.classifier.config),
        )


def _coerce_classification(result: AgentResult) -> TriageCategory:
    if not result.success:
        return TriageCategory.ESCALATE

    raw_value = result.data.get("classification")
    if isinstance(raw_value, TriageCategory):
        return raw_value
    if isinstance(raw_value, str):
        try:
            return TriageCategory(raw_value)
        except ValueError:
            return TriageCategory.NEEDS_INVESTIGATION
    return TriageCategory.NEEDS_INVESTIGATION


def _coerce_confidence(value: Any) -> float:
    try:
        return float(value)
    except (TypeError, ValueError):
        return 0.0


def _coerce_string_list(value: Any) -> list[str]:
    if not isinstance(value, list):
        return []
    return [str(item) for item in value]


def _resolve_model_version(config: dict[str, Any]) -> str:
    value = config.get("model_version") or config.get("model") or ""
    return str(value)


def _build_evidence_summary(alert: UnifiedAlert) -> str:
    parts = [
        alert.signature or alert.event_type or "Unknown alert",
        f"severity={alert.severity.value}",
    ]
    if alert.src_ip and alert.dst_ip:
        parts.append(f"flow={alert.src_ip}->{alert.dst_ip}")
    return ", ".join(parts)


__all__ = ["PipelineRunResult", "TriagePipeline"]
