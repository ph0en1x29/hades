"""Log Correlator Agent — Pulls related events for context enrichment.

Correlates by:
  - Time window (±15 min default)
  - Source/destination IP grouping
  - Session reconstruction (same flow)
  - Signature family matching
"""

from __future__ import annotations

import time
from typing import Any

from src.agents.base import AgentResult, BaseAgent
from src.ingestion.schema import UnifiedAlert


class CorrelatorAgent(BaseAgent):
    """Enriches ambiguous alerts by pulling related log events."""

    @property
    def name(self) -> str:
        return "correlator"

    async def run(
        self,
        alert: UnifiedAlert,
        context: dict[str, Any] | None = None,
    ) -> AgentResult:
        """Find correlated events for the given alert.

        Searches the SIEM index (or local log store) for events
        matching the alert's IPs, signature family, and time window.
        Returns a timeline of related events for the classifier to
        re-evaluate.
        """
        start = time.monotonic()
        window_minutes = self.config.get("time_window_minutes", 15)

        try:
            # TODO: Replace with actual SIEM/log query via OpenClaw tool
            # Correlation strategies (all applied, results merged):
            #   1. Same src_ip within ±window
            #   2. Same dst_ip within ±window
            #   3. Same src_ip → dst_ip pair (session)
            #   4. Same signature family

            correlated_events: list[dict[str, Any]] = []
            related_alerts: list[str] = []

            # --- SIEM query goes here ---
            # events = await self.siem_tool.query(
            #     query_type="ip_lookup",
            #     value=alert.src_ip,
            #     time_window_minutes=window_minutes,
            # )
            # ---

            elapsed_ms = int((time.monotonic() - start) * 1000)

            return AgentResult(
                agent_name=self.name,
                success=True,
                data={
                    "correlated_events": correlated_events,
                    "related_alerts": related_alerts,
                    "time_window_minutes": window_minutes,
                    "src_ip": alert.src_ip,
                    "dst_ip": alert.dst_ip,
                    "event_count": len(correlated_events),
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
