"""Log Correlator Agent — Correlates alerts into attack chains.

Strategies:
  1. IP-based clustering (same src/dst within time window)
  2. Technique chain detection (recon → access → lateral → exfil)
  3. Session reconstruction (same src→dst pair across events)
  4. Temporal burst detection (spike in alerts from same source)

Operates entirely on in-memory alert sets — no external SIEM needed.
This is what separates "alert classifier" from "campaign detector."
"""

from __future__ import annotations

import time
from collections import defaultdict
from dataclasses import asdict, dataclass, field
from datetime import datetime, timedelta
from typing import TYPE_CHECKING, Any

from src.agents.base import AgentResult, BaseAgent

if TYPE_CHECKING:
    from src.ingestion.schema import UnifiedAlert


# === MITRE ATT&CK Kill Chain Ordering ===
# Used for technique chain detection — attacks progress through these phases

TACTIC_ORDER: dict[str, int] = {
    "TA0043": 0,   # Reconnaissance
    "TA0042": 1,   # Resource Development
    "TA0001": 2,   # Initial Access
    "TA0002": 3,   # Execution
    "TA0003": 4,   # Persistence
    "TA0004": 5,   # Privilege Escalation
    "TA0005": 6,   # Defense Evasion
    "TA0006": 7,   # Credential Access
    "TA0007": 8,   # Discovery
    "TA0008": 9,   # Lateral Movement
    "TA0009": 10,  # Collection
    "TA0011": 11,  # Command and Control
    "TA0010": 12,  # Exfiltration
    "TA0040": 13,  # Impact
}

# Technique prefix → primary tactic
TECHNIQUE_TO_TACTIC: dict[str, str] = {
    "T1003": "TA0006", "T1021": "TA0008", "T1027": "TA0005",
    "T1036": "TA0005", "T1047": "TA0002", "T1053": "TA0003",
    "T1055": "TA0005", "T1059": "TA0002", "T1071": "TA0011",
    "T1078": "TA0001", "T1087": "TA0007", "T1105": "TA0011",
    "T1110": "TA0006", "T1218": "TA0005", "T1547": "TA0003",
    "T1569": "TA0002", "T1048": "TA0010", "T1190": "TA0001",
    "T1566": "TA0001", "T1068": "TA0004", "T1098": "TA0003",
    "T1136": "TA0003", "T1486": "TA0040", "T1490": "TA0040",
}

# Known multi-stage attack patterns (sequences of tactics)
ATTACK_PATTERNS: dict[str, list[str]] = {
    "ransomware_campaign": [
        "TA0001", "TA0002", "TA0003", "TA0006", "TA0008", "TA0040",
    ],
    "data_exfiltration": [
        "TA0001", "TA0002", "TA0007", "TA0009", "TA0010",
    ],
    "credential_theft": [
        "TA0001", "TA0006", "TA0008", "TA0007",
    ],
    "lateral_movement_campaign": [
        "TA0006", "TA0008", "TA0007", "TA0002",
    ],
    "persistence_establishment": [
        "TA0001", "TA0002", "TA0003", "TA0005",
    ],
}


@dataclass
class CorrelatedEvent:
    """A single event related to the anchor alert."""
    alert_id: str
    timestamp: str
    src_ip: str | None
    dst_ip: str | None
    technique: str
    tactic: str
    severity: str
    correlation_type: str  # 'ip_cluster', 'technique_chain', 'session', 'temporal_burst'
    relevance_score: float  # 0.0–1.0


@dataclass
class AttackChain:
    """A detected multi-stage attack sequence."""
    chain_id: str
    pattern_name: str  # e.g., 'ransomware_campaign', 'credential_theft'
    tactics_observed: list[str]
    tactics_expected: list[str]
    coverage: float  # fraction of expected tactics observed
    alert_ids: list[str] = field(default_factory=list)
    confidence: float = 0.0
    description: str = ""


@dataclass
class TemporalBurst:
    """A detected spike in alerts from a single source."""
    src_ip: str
    alert_count: int
    window_minutes: int
    alert_ids: list[str] = field(default_factory=list)
    burst_score: float = 0.0  # alerts/minute normalized


@dataclass
class CorrelationResult:
    """Full correlation output."""
    anchor_alert_id: str
    correlated_events: list[CorrelatedEvent] = field(default_factory=list)
    attack_chains: list[AttackChain] = field(default_factory=list)
    temporal_bursts: list[TemporalBurst] = field(default_factory=list)
    session_groups: dict[str, list[str]] = field(default_factory=dict)
    campaign_detected: bool = False
    campaign_confidence: float = 0.0
    affected_hosts: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


class AlertStore:
    """In-memory store for alert correlation lookups.

    Indexes alerts by IP, technique, and timestamp for fast correlation.
    In production this would wrap a SIEM query interface.
    """

    def __init__(self) -> None:
        self._alerts: dict[str, "UnifiedAlert"] = {}
        self._by_src_ip: dict[str, list[str]] = defaultdict(list)
        self._by_dst_ip: dict[str, list[str]] = defaultdict(list)
        self._by_technique: dict[str, list[str]] = defaultdict(list)
        self._by_session: dict[str, list[str]] = defaultdict(list)

    def ingest(self, alerts: list["UnifiedAlert"]) -> None:
        """Index a batch of alerts for correlation lookups."""
        for alert in alerts:
            self._alerts[alert.alert_id] = alert
            if alert.src_ip:
                self._by_src_ip[alert.src_ip].append(alert.alert_id)
            if alert.dst_ip:
                self._by_dst_ip[alert.dst_ip].append(alert.alert_id)
            # Index by technique
            for tech in (alert.benchmark.mitre_techniques or []):
                prefix = tech.split(".")[0] if "." in tech else tech
                self._by_technique[prefix].append(alert.alert_id)
            # Index by session (src→dst pair)
            if alert.src_ip and alert.dst_ip:
                session_key = f"{alert.src_ip}->{alert.dst_ip}"
                self._by_session[session_key].append(alert.alert_id)

    def get(self, alert_id: str) -> "UnifiedAlert | None":
        return self._alerts.get(alert_id)

    def by_src_ip(self, ip: str) -> list[str]:
        return self._by_src_ip.get(ip, [])

    def by_dst_ip(self, ip: str) -> list[str]:
        return self._by_dst_ip.get(ip, [])

    def by_technique(self, technique_prefix: str) -> list[str]:
        return self._by_technique.get(technique_prefix, [])

    def by_session(self, src_ip: str, dst_ip: str) -> list[str]:
        return self._by_session.get(f"{src_ip}->{dst_ip}", [])

    def all_alerts(self) -> list["UnifiedAlert"]:
        return list(self._alerts.values())

    @property
    def count(self) -> int:
        return len(self._alerts)


def _parse_timestamp(ts: str | None) -> datetime | None:
    """Best-effort timestamp parsing."""
    if not ts:
        return None
    for fmt in ("%Y-%m-%dT%H:%M:%S.%f%z", "%Y-%m-%dT%H:%M:%S%z",
                "%Y-%m-%dT%H:%M:%S.%f", "%Y-%m-%dT%H:%M:%S",
                "%Y-%m-%d %H:%M:%S.%f", "%Y-%m-%d %H:%M:%S"):
        try:
            return datetime.strptime(ts, fmt)
        except ValueError:
            continue
    return None


def _get_tactic(alert: "UnifiedAlert") -> str:
    """Get primary tactic for an alert."""
    for tech in (alert.benchmark.mitre_techniques or []):
        prefix = tech.split(".")[0] if "." in tech else tech
        tactic = TECHNIQUE_TO_TACTIC.get(prefix)
        if tactic:
            return tactic
    return ""


def _get_technique_prefix(alert: "UnifiedAlert") -> str:
    """Get primary technique prefix (e.g., T1003)."""
    for tech in (alert.benchmark.mitre_techniques or []):
        return tech.split(".")[0] if "." in tech else tech
    return ""


def correlate_alerts(
    anchor: "UnifiedAlert",
    store: AlertStore,
    *,
    window_minutes: int = 15,
    min_chain_coverage: float = 0.4,
    burst_threshold: int = 5,
) -> CorrelationResult:
    """Correlate an anchor alert against the alert store.

    This is the core correlation engine. It runs four strategies:
    1. IP clustering — find alerts sharing src/dst IPs
    2. Technique chain — detect MITRE ATT&CK kill chain progression
    3. Session reconstruction — group by src→dst pairs
    4. Temporal burst — detect alert volume spikes

    Returns a CorrelationResult with attack chains, bursts, and
    campaign assessment.
    """
    result = CorrelationResult(anchor_alert_id=anchor.alert_id)
    seen_ids: set[str] = {anchor.alert_id}
    anchor_ts = _parse_timestamp(anchor.timestamp)

    # --- Strategy 1: IP Clustering ---
    related_by_ip: set[str] = set()
    if anchor.src_ip:
        related_by_ip.update(store.by_src_ip(anchor.src_ip))
    if anchor.dst_ip:
        related_by_ip.update(store.by_dst_ip(anchor.dst_ip))
        # Also check reverse — our dst might be someone else's src
        related_by_ip.update(store.by_src_ip(anchor.dst_ip))

    for aid in related_by_ip:
        if aid in seen_ids:
            continue
        related = store.get(aid)
        if not related:
            continue
        # Time window filter
        if anchor_ts:
            related_ts = _parse_timestamp(related.timestamp)
            if related_ts and abs((related_ts - anchor_ts).total_seconds()) > window_minutes * 60:
                continue
        seen_ids.add(aid)
        result.correlated_events.append(CorrelatedEvent(
            alert_id=aid,
            timestamp=related.timestamp or "",
            src_ip=related.src_ip,
            dst_ip=related.dst_ip,
            technique=_get_technique_prefix(related),
            tactic=_get_tactic(related),
            severity=related.severity.value,
            correlation_type="ip_cluster",
            relevance_score=0.7,
        ))

    # --- Strategy 2: Technique Chain Detection ---
    # Collect all tactics observed across anchor + correlated events
    all_tactics: set[str] = set()
    tactic_alerts: dict[str, list[str]] = defaultdict(list)

    anchor_tactic = _get_tactic(anchor)
    if anchor_tactic:
        all_tactics.add(anchor_tactic)
        tactic_alerts[anchor_tactic].append(anchor.alert_id)

    for ev in result.correlated_events:
        if ev.tactic:
            all_tactics.add(ev.tactic)
            tactic_alerts[ev.tactic].append(ev.alert_id)

    # Also scan technique-related alerts not yet found by IP
    for tech in (anchor.benchmark.mitre_techniques or []):
        prefix = tech.split(".")[0] if "." in tech else tech
        for aid in store.by_technique(prefix):
            if aid in seen_ids:
                continue
            related = store.get(aid)
            if not related:
                continue
            tactic = _get_tactic(related)
            if tactic:
                all_tactics.add(tactic)
                tactic_alerts[tactic].append(aid)
            seen_ids.add(aid)
            result.correlated_events.append(CorrelatedEvent(
                alert_id=aid,
                timestamp=related.timestamp or "",
                src_ip=related.src_ip,
                dst_ip=related.dst_ip,
                technique=_get_technique_prefix(related),
                tactic=tactic,
                severity=related.severity.value,
                correlation_type="technique_chain",
                relevance_score=0.8,
            ))

    # Match observed tactics against known attack patterns
    for pattern_name, expected_tactics in ATTACK_PATTERNS.items():
        observed = [t for t in expected_tactics if t in all_tactics]
        coverage = len(observed) / len(expected_tactics) if expected_tactics else 0
        if coverage >= min_chain_coverage:
            chain_alerts = []
            for t in observed:
                chain_alerts.extend(tactic_alerts.get(t, []))
            result.attack_chains.append(AttackChain(
                chain_id=f"chain-{pattern_name}-{anchor.alert_id[:8]}",
                pattern_name=pattern_name,
                tactics_observed=observed,
                tactics_expected=expected_tactics,
                coverage=coverage,
                alert_ids=list(dict.fromkeys(chain_alerts)),  # dedup preserving order
                confidence=min(coverage * 1.2, 1.0),  # scale up slightly
                description=(
                    f"Detected {pattern_name.replace('_', ' ')} pattern: "
                    f"{len(observed)}/{len(expected_tactics)} tactics observed "
                    f"({', '.join(observed)})"
                ),
            ))

    # --- Strategy 3: Session Reconstruction ---
    if anchor.src_ip and anchor.dst_ip:
        session_alerts = store.by_session(anchor.src_ip, anchor.dst_ip)
        if len(session_alerts) > 1:
            result.session_groups[f"{anchor.src_ip}->{anchor.dst_ip}"] = session_alerts
            for aid in session_alerts:
                if aid in seen_ids:
                    continue
                related = store.get(aid)
                if not related:
                    continue
                seen_ids.add(aid)
                result.correlated_events.append(CorrelatedEvent(
                    alert_id=aid,
                    timestamp=related.timestamp or "",
                    src_ip=related.src_ip,
                    dst_ip=related.dst_ip,
                    technique=_get_technique_prefix(related),
                    tactic=_get_tactic(related),
                    severity=related.severity.value,
                    correlation_type="session",
                    relevance_score=0.9,
                ))

    # --- Strategy 4: Temporal Burst Detection ---
    if anchor.src_ip:
        src_alerts = store.by_src_ip(anchor.src_ip)
        if len(src_alerts) >= burst_threshold:
            # Check if they cluster within the window
            timestamps = []
            for aid in src_alerts:
                a = store.get(aid)
                if a:
                    ts = _parse_timestamp(a.timestamp)
                    if ts:
                        timestamps.append(ts)
            if timestamps:
                timestamps.sort()
                # Sliding window — find max alerts within window_minutes
                max_in_window = 0
                for i, ts_start in enumerate(timestamps):
                    window_end = ts_start + timedelta(minutes=window_minutes)
                    count = sum(1 for t in timestamps[i:] if t <= window_end)
                    max_in_window = max(max_in_window, count)

                if max_in_window >= burst_threshold:
                    result.temporal_bursts.append(TemporalBurst(
                        src_ip=anchor.src_ip,
                        alert_count=max_in_window,
                        window_minutes=window_minutes,
                        alert_ids=src_alerts,
                        burst_score=max_in_window / window_minutes,
                    ))

    # --- Campaign Assessment ---
    result.affected_hosts = sorted({
        ip for ev in result.correlated_events
        for ip in (ev.src_ip, ev.dst_ip) if ip
    })
    result.campaign_detected = (
        len(result.attack_chains) > 0
        or len(result.temporal_bursts) > 0
        or len(result.correlated_events) >= 10
    )
    if result.campaign_detected:
        chain_conf = max((c.confidence for c in result.attack_chains), default=0)
        burst_conf = min(max((b.burst_score / 5 for b in result.temporal_bursts), default=0), 1.0)
        volume_conf = min(len(result.correlated_events) / 20, 1.0)
        result.campaign_confidence = max(chain_conf, burst_conf, volume_conf)

    return result


class CorrelatorAgent(BaseAgent):
    """Enriches alerts by correlating against an in-memory alert store.

    In production, the AlertStore would be backed by a SIEM query interface.
    For evaluation, we pre-load the benchmark alert set so the correlator
    can find cross-alert relationships.
    """

    def __init__(self, config: dict[str, Any], store: AlertStore | None = None) -> None:
        super().__init__(config)
        self.store = store or AlertStore()

    @property
    def name(self) -> str:
        return "correlator"

    def load_alerts(self, alerts: list["UnifiedAlert"]) -> None:
        """Pre-load alerts into the store for correlation."""
        self.store.ingest(alerts)

    async def run(
        self,
        alert: "UnifiedAlert",
        context: dict[str, Any] | None = None,
    ) -> AgentResult:
        """Correlate an alert against the store and return enrichment."""
        start = time.monotonic()
        window = self.config.get("time_window_minutes", 15)

        try:
            correlation = correlate_alerts(
                anchor=alert,
                store=self.store,
                window_minutes=window,
                min_chain_coverage=self.config.get("min_chain_coverage", 0.4),
                burst_threshold=self.config.get("burst_threshold", 5),
            )
            elapsed_ms = int((time.monotonic() - start) * 1000)

            return AgentResult(
                agent_name=self.name,
                success=True,
                data={
                    "correlated_events": [asdict(e) for e in correlation.correlated_events],
                    "attack_chains": [asdict(c) for c in correlation.attack_chains],
                    "temporal_bursts": [asdict(b) for b in correlation.temporal_bursts],
                    "session_groups": correlation.session_groups,
                    "campaign_detected": correlation.campaign_detected,
                    "campaign_confidence": correlation.campaign_confidence,
                    "affected_hosts": correlation.affected_hosts,
                    "event_count": len(correlation.correlated_events),
                    "chain_count": len(correlation.attack_chains),
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
