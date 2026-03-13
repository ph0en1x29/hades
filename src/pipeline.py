"""Multi-agent alert triage pipeline.

Pipeline stages:
  1. Classification — single-alert triage via LLM
  2. Behavioral invariant check — output-level injection detection
  3. Correlation — multi-alert campaign detection (optional)
  4. Playbook generation — NIST SP 800-61 response (optional)

The correlator and playbook agents are optional; when provided the
pipeline produces richer decisions with campaign context and response
guidance.
"""

from __future__ import annotations

import time
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path
from typing import TYPE_CHECKING, Any

from src.evaluation.behavioral_invariants import run_invariant_checks
from src.evaluation.schemas import (
    EvidenceItem,
    InferenceMode,
    OverrideRecord,
    ToolInvocation,
    TriageCategory,
    TriageDecision,
)

if TYPE_CHECKING:
    from src.agents import ClassifierAgent
    from src.agents.base import AgentResult
    from src.agents.correlator import CorrelatorAgent
    from src.agents.playbook import PlaybookAgent
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
    campaigns_detected: int = 0
    playbooks_generated: int = 0
    invariant_escalations: int = 0
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
    """Multi-agent async pipeline for classifying and correlating alerts."""

    def __init__(
        self,
        classifier: ClassifierAgent,
        correlator: CorrelatorAgent | None = None,
        playbook: PlaybookAgent | None = None,
    ) -> None:
        self.classifier = classifier
        self.correlator = correlator
        self.playbook = playbook

    async def run(
        self,
        alerts: list[UnifiedAlert],
        output_path: str | Path,
    ) -> PipelineRunResult:
        """Classify alerts, correlate, generate playbooks, and write JSONL."""
        destination = Path(output_path)
        destination.parent.mkdir(parents=True, exist_ok=True)

        run_result = PipelineRunResult(
            total_alerts=len(alerts),
            output_path=str(destination),
        )

        # Pre-load all alerts into correlator for cross-alert lookups
        if self.correlator is not None:
            self.correlator.load_alerts(alerts)

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
                if decision.override_record is not None:
                    run_result.invariant_escalations += 1
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

        evidence_trace = [
            EvidenceItem(
                source_type="alert",
                source_ref=f"alert:{alert.alert_id}",
                summary=_build_evidence_summary(alert),
                score=confidence if result.success else None,
            ),
        ]
        tool_invocations = [
            ToolInvocation(
                tool_name=self.classifier.name,
                arguments={
                    "alert_id": alert.alert_id,
                    "event_type": alert.event_type or "",
                },
                status="success" if result.success else "error",
                duration_ms=result.latency_ms,
            ),
        ]

        override_record = None
        alert_dict = alert.to_dict()
        decision_dict = {
            "severity": result.data.get("severity") or alert.severity.value.upper(),
            "classification": classification.value,
            "confidence": confidence,
            "reasoning": rationale,
            "summary": result.data.get("summary") or "",
        }
        invariant_result = run_invariant_checks(alert_dict, decision_dict)
        tool_invocations.append(
            ToolInvocation(
                tool_name="behavioral_invariants",
                arguments={
                    "alert_id": alert.alert_id,
                    "checks_run": invariant_result.checks_run,
                },
                status="flagged" if invariant_result.injection_suspected else "clean",
                duration_ms=0,
            )
        )
        if invariant_result.violations:
            evidence_trace.append(
                EvidenceItem(
                    source_type="invariant",
                    source_ref=f"invariants:{alert.alert_id}",
                    summary=(
                        "Behavioral invariant violations: "
                        + ", ".join(
                            f"{v.invariant_id}[{v.severity}]"
                            for v in invariant_result.violations
                        )
                    ),
                    score=float(invariant_result.violation_count),
                )
            )
        if invariant_result.injection_suspected:
            previous_classification = classification.value
            classification = TriageCategory.ESCALATE
            rationale = (
                rationale
                + "\n\n[HADES SAFETY LAYER] Escalated due to behavioral invariant violations "
                + ", ".join(v.invariant_id for v in invariant_result.violations)
                + "."
            )
            override_record = OverrideRecord(
                actor="system:behavioral_invariants",
                reason=(
                    "Potential indirect prompt injection detected via behavioral "
                    "invariant violations"
                ),
                previous_classification=previous_classification,
                new_classification=classification.value,
            )

        # --- Stage 3: Correlation (optional) ---
        correlated_events: list[dict[str, Any]] = []
        campaign_context: dict[str, Any] = {}
        if self.correlator is not None:
            corr_result = await self.correlator.run(alert)
            if corr_result.success:
                correlated_events = corr_result.data.get("correlated_events", [])
                campaign_context = {
                    "campaign_detected": corr_result.data.get("campaign_detected", False),
                    "campaign_confidence": corr_result.data.get("campaign_confidence", 0),
                    "attack_chains": corr_result.data.get("attack_chains", []),
                    "affected_hosts": corr_result.data.get("affected_hosts", []),
                }
                tool_invocations.append(
                    ToolInvocation(
                        tool_name="correlator",
                        arguments={
                            "alert_id": alert.alert_id,
                            "events_found": corr_result.data.get("event_count", 0),
                            "chains_found": corr_result.data.get("chain_count", 0),
                        },
                        status="campaign" if corr_result.data.get("campaign_detected") else "no_campaign",
                        duration_ms=corr_result.latency_ms,
                    )
                )
                if correlated_events:
                    evidence_trace.append(
                        EvidenceItem(
                            source_type="correlation",
                            source_ref=f"correlator:{alert.alert_id}",
                            summary=(
                                f"{len(correlated_events)} correlated events, "
                                f"{corr_result.data.get('chain_count', 0)} attack chains"
                            ),
                            score=corr_result.data.get("campaign_confidence", 0),
                        )
                    )

        # --- Stage 4: Playbook generation (optional) ---
        playbook_data: dict[str, Any] = {}
        if self.playbook is not None:
            pb_context: dict[str, Any] = {
                "classification": classification.value,
                "confidence": confidence,
                "campaign": campaign_context,
            }
            pb_result = await self.playbook.run(alert, context=pb_context)
            if pb_result.success:
                playbook_data = pb_result.data
                tool_invocations.append(
                    ToolInvocation(
                        tool_name="playbook_generator",
                        arguments={"alert_id": alert.alert_id},
                        status="generated",
                        duration_ms=pb_result.latency_ms,
                    )
                )

        return TriageDecision(
            alert_id=alert.alert_id,
            classification=classification,
            confidence=confidence,
            evidence_trace=evidence_trace,
            tool_invocations=tool_invocations,
            rationale_summary=rationale,
            correlated_events=[
                ev.get("alert_id", "") if isinstance(ev, dict) else str(ev)
                for ev in correlated_events
            ],
            mitre_techniques=_coerce_string_list(
                result.data.get("mitre_techniques"),
            ),
            processing_time_ms=result.latency_ms,
            mode_used=InferenceMode.DETERMINISTIC,
            model_version=_resolve_model_version(self.classifier.config),
            override_record=override_record,
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
