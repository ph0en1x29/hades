"""Alert Classifier Agent — First-pass triage classification.

Classifies incoming alerts into:
  - True Positive: confirmed threat requiring response
  - False Positive: benign activity, no action needed
  - Needs Investigation: ambiguous, requires correlator enrichment
  - Escalate: beyond automated capability, route to human analyst
"""

from __future__ import annotations

import time
from typing import TYPE_CHECKING, Any

from src.agents.base import AgentResult, BaseAgent
from src.evaluation.schemas import TriageCategory

if TYPE_CHECKING:
    from src.ingestion.schema import UnifiedAlert

# Few-shot classification prompt template
CLASSIFIER_SYSTEM_PROMPT = """\
You are a SOC analyst performing alert triage. Classify the following \
SIEM alert into exactly one category:

- TRUE_POSITIVE: Confirmed malicious activity requiring incident response.
- FALSE_POSITIVE: Benign activity that triggered a false alarm.
- NEEDS_INVESTIGATION: Ambiguous — requires additional log correlation.
- ESCALATE: Complex or critical — requires human analyst review.

Respond with a JSON object:
{
  "classification": "<category>",
  "confidence": <0.0-1.0>,
  "reasoning": "<brief explanation>",
  "mitre_techniques": ["<T-code>", ...] or []
}
"""


class ClassifierAgent(BaseAgent):
    """First-pass alert classifier using LLM inference."""

    @property
    def name(self) -> str:
        return "classifier"

    async def run(
        self,
        alert: UnifiedAlert,
        context: dict[str, Any] | None = None,
    ) -> AgentResult:
        """Classify an alert into a triage category.

        If confidence < threshold, the pipeline should route
        to the Log Correlator for enrichment before re-classifying.
        """
        start = time.monotonic()

        # TODO: Replace with actual LLM inference via the chosen runtime adapter
        # For now, return a placeholder that exercises the full schema
        try:
            # Build prompt from alert data
            alert_context = (
                f"Signature: {alert.signature}\n"
                f"Source: {alert.src_ip}:{alert.src_port} → "
                f"{alert.dst_ip}:{alert.dst_port}\n"
                f"Protocol: {alert.protocol}\n"
                f"Severity: {alert.severity.value}\n"
                f"Raw log: {alert.raw_log[:500]}"
            )

            if context and "correlated_events" in context:
                alert_context += (
                    f"\n\nCorrelated events ({len(context['correlated_events'])}):\n"
                    + "\n".join(
                        str(e) for e in context["correlated_events"][:5]
                    )
                )

            if context and "rag_results" in context:
                alert_context += (
                    "\n\nThreat intelligence:\n"
                    + "\n".join(
                        r.get("content", "")[:200]
                        for r in context["rag_results"][:3]
                    )
                )

            # --- LLM call goes here ---
            # response = await self.llm.generate(
            #     system=CLASSIFIER_SYSTEM_PROMPT,
            #     user=alert_context,
            # )
            # parsed = json.loads(response.text)
            # ---

            elapsed_ms = int((time.monotonic() - start) * 1000)

            return AgentResult(
                agent_name=self.name,
                success=True,
                data={
                    "classification": TriageCategory.NEEDS_INVESTIGATION.value,
                    "confidence": 0.0,
                    "reasoning": "LLM inference not yet connected",
                    "mitre_techniques": [],
                    "needs_correlation": True,
                    "prompt_tokens": len(alert_context.split()),
                },
                latency_ms=elapsed_ms,
            )

        except Exception as exc:
            elapsed_ms = int((time.monotonic() - start) * 1000)
            return AgentResult(
                agent_name=self.name,
                success=False,
                error=str(exc),
                latency_ms=elapsed_ms,
            )
