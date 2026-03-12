"""Alert Classifier Agent — first-pass triage via local OpenAI-compatible LLM.

Classifies incoming alerts into:
  - True Positive: confirmed threat requiring response
  - False Positive: benign activity, no action needed
  - Needs Investigation: ambiguous, requires correlator enrichment
  - Escalate: beyond automated capability, route to human analyst
"""

from __future__ import annotations

import asyncio
import time
from typing import TYPE_CHECKING, Any

from src.agents.base import AgentResult, BaseAgent
from src.agents.triage_parser import parse_triage_response
from src.agents.triage_prompt import (
    SYSTEM_INSTRUCTION,
    estimate_prompt_tokens,
    format_alert_for_triage,
)
from src.evaluation.schemas import TriageCategory
from src.runtime.openai_compat import OpenAICompatChatClient, OpenAICompatError

if TYPE_CHECKING:
    from src.ingestion.schema import UnifiedAlert

# Prompt source unified with the dedicated triage prompt module.
CLASSIFIER_SYSTEM_PROMPT = SYSTEM_INSTRUCTION


def _map_decision_to_category(
    llm_classification: str,
    llm_severity: str,
) -> TriageCategory:
    normalized_class = (llm_classification or "").strip().lower()
    normalized_severity = (llm_severity or "").strip().lower()

    if normalized_class in {"true_positive", TriageCategory.TRUE_POSITIVE.value}:
        return TriageCategory.TRUE_POSITIVE
    if normalized_class in {"false_positive", TriageCategory.FALSE_POSITIVE.value}:
        return TriageCategory.FALSE_POSITIVE
    if normalized_class in {"needs_investigation", TriageCategory.NEEDS_INVESTIGATION.value}:
        return TriageCategory.NEEDS_INVESTIGATION
    if normalized_class in {"escalate", TriageCategory.ESCALATE.value}:
        return TriageCategory.ESCALATE

    if normalized_severity == "critical":
        return TriageCategory.ESCALATE
    if normalized_severity in {"high", "medium"}:
        return TriageCategory.TRUE_POSITIVE
    if normalized_severity == "low":
        return TriageCategory.NEEDS_INVESTIGATION
    if normalized_severity == "info":
        return TriageCategory.FALSE_POSITIVE
    return TriageCategory.NEEDS_INVESTIGATION


class ClassifierAgent(BaseAgent):
    """First-pass alert classifier using local LLM inference."""

    def __init__(self, config: dict[str, Any]) -> None:
        super().__init__(config)
        self.client = OpenAICompatChatClient(
            base_url=str(config.get("base_url") or ""),
            api_key=str(config.get("api_key") or ""),
            timeout_seconds=int(config.get("timeout_seconds", 90)),
        )
        self._retriever: Any = None
        self._rag_enabled = bool(config.get("rag_enabled", False))
        self._rag_config = dict(config.get("rag") or {})

    @property
    def name(self) -> str:
        return "classifier"

    def _get_retriever(self) -> Any | None:
        if not self._rag_enabled:
            return None
        if self._retriever is not None:
            return self._retriever

        try:
            from src.rag import Retriever, VectorStore

            store = VectorStore(self._rag_config)
            store.initialize()
            self._retriever = Retriever(store, self._rag_config)
            return self._retriever
        except Exception:
            return None

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

        try:
            system_prompt, user_prompt = format_alert_for_triage(
                alert,
                use_structured=bool(self.config.get("use_structured_prompt", False)),
                include_raw_log=bool(self.config.get("include_raw_log", True)),
                max_raw_log_chars=int(self.config.get("max_raw_log_chars", 2000)),
            )

            if context and "correlated_events" in context:
                correlated = context["correlated_events"][:5]
                user_prompt += (
                    f"\n\nCorrelated events ({len(correlated)}):\n"
                    + "\n".join(str(event) for event in correlated)
                )

            rag_items = []
            if context and "rag_results" in context:
                rag_items = list(context["rag_results"][:3])
            elif alert.benchmark.mitre_techniques:
                retriever = self._get_retriever()
                if retriever is not None:
                    seen_ids: set[str] = set()
                    for technique_id in alert.benchmark.mitre_techniques[:3]:
                        for item in retriever.query_mitre(str(technique_id), top_k=2):
                            candidate_id = str(item.get("metadata", {}).get("technique_id", ""))
                            key = candidate_id or str(item.get("content", ""))[:80]
                            if key and key not in seen_ids:
                                seen_ids.add(key)
                                rag_items.append(item)
                            if len(rag_items) >= 3:
                                break
                        if len(rag_items) >= 3:
                            break

            if rag_items:
                user_prompt += (
                    "\n\nRetrieved threat intelligence:\n"
                    + "\n".join(str(item.get("content", ""))[:300] for item in rag_items)
                )

            model_name = str(
                self.config.get("model")
                or self.config.get("model_name")
                or self.config.get("model_version")
                or "moonshotai/Kimi-K2.5"
            )
            temperature = float(self.config.get("temperature", 0.0))
            max_tokens = int(self.config.get("max_tokens", 512))
            seed = self.config.get("seed")

            completion = await asyncio.to_thread(
                self.client.chat_completion,
                model=model_name,
                system=system_prompt,
                user=user_prompt,
                temperature=temperature,
                max_tokens=max_tokens,
                seed=int(seed) if seed is not None else None,
                response_format={"type": "json_object"},
            )
            parsed = parse_triage_response(completion.content)

            classification = _map_decision_to_category(parsed.classification, parsed.severity)
            elapsed_ms = int((time.monotonic() - start) * 1000)

            return AgentResult(
                agent_name=self.name,
                success=parsed.parse_success,
                data={
                    "classification": classification.value,
                    "confidence": parsed.confidence,
                    "reasoning": parsed.reasoning or parsed.parse_error or "No reasoning returned",
                    "mitre_techniques": parsed.mitre_techniques,
                    "recommended_actions": parsed.recommended_actions,
                    "evidence": parsed.evidence,
                    "llm_severity": parsed.severity,
                    "llm_classification": parsed.classification,
                    "prompt_tokens": completion.prompt_tokens or estimate_prompt_tokens(system_prompt, user_prompt),
                    "completion_tokens": completion.completion_tokens,
                    "total_tokens": completion.total_tokens,
                    "finish_reason": completion.finish_reason,
                    "model_version": completion.model,
                },
                error=parsed.parse_error,
                latency_ms=elapsed_ms,
                tokens_used=completion.total_tokens,
            )

        except OpenAICompatError as exc:
            elapsed_ms = int((time.monotonic() - start) * 1000)
            return AgentResult(
                agent_name=self.name,
                success=False,
                data={
                    "classification": TriageCategory.NEEDS_INVESTIGATION.value,
                    "confidence": 0.0,
                    "reasoning": "Model server unavailable; falling back to safe investigation state",
                    "mitre_techniques": alert.benchmark.mitre_techniques,
                    "fallback": True,
                },
                error=str(exc),
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
