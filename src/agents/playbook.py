"""Playbook Generator Agent — Produces incident response playbooks.

Based on NIST SP 800-61 incident response lifecycle:
  1. Preparation
  2. Detection & Analysis
  3. Containment, Eradication & Recovery
  4. Post-Incident Activity
"""

from __future__ import annotations

import time
from typing import Any
from uuid import uuid4

from src.agents.base import AgentResult, BaseAgent
from src.ingestion.schema import UnifiedAlert

PLAYBOOK_SYSTEM_PROMPT = """\
You are a SOC incident response specialist. Given a classified alert \
with correlated evidence, generate a step-by-step incident response \
playbook following NIST SP 800-61.

Structure your response as JSON:
{
  "playbook_id": "<uuid>",
  "title": "<incident type> Response Playbook",
  "severity": "<critical|high|medium|low>",
  "steps": [
    {
      "phase": "containment|eradication|recovery|post_incident",
      "action": "<specific action>",
      "priority": <1-5>,
      "automated": <true|false>
    }
  ],
  "iocs": [{"type": "ip|domain|hash|url", "value": "<indicator>"}],
  "escalation": "<when and who to escalate to>",
  "references": ["<MITRE technique URLs>"]
}
"""


class PlaybookAgent(BaseAgent):
    """Generates structured incident response playbooks."""

    @property
    def name(self) -> str:
        return "playbook"

    async def run(
        self,
        alert: UnifiedAlert,
        context: dict[str, Any] | None = None,
    ) -> AgentResult:
        """Generate an incident response playbook.

        Uses the classification result and correlated events to
        produce a NIST 800-61 playbook with actionable steps,
        IOC extraction, and escalation guidance.
        """
        start = time.monotonic()

        try:
            classification = (context or {}).get("classification", "unknown")
            mitre_techniques = (context or {}).get("mitre_techniques", [])
            correlated_events = (context or {}).get("correlated_events", [])

            playbook_id = str(uuid4())

            # TODO: Replace with actual LLM generation via OpenClaw
            # Build context string from classification + events + RAG
            # and generate the playbook

            # --- LLM call goes here ---
            # response = await self.llm.generate(
            #     system=PLAYBOOK_SYSTEM_PROMPT,
            #     user=playbook_context,
            # )
            # ---

            elapsed_ms = int((time.monotonic() - start) * 1000)

            return AgentResult(
                agent_name=self.name,
                success=True,
                data={
                    "playbook_id": playbook_id,
                    "title": f"Response Playbook for {alert.signature}",
                    "classification": classification,
                    "mitre_techniques": mitre_techniques,
                    "steps": [],  # Populated by LLM
                    "iocs": [
                        {"type": "ip", "value": alert.src_ip},
                        {"type": "ip", "value": alert.dst_ip},
                    ],
                    "correlated_event_count": len(correlated_events),
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
