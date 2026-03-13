"""SOC-Bench Output Adapter.

Converts Hades TriageDecision outputs into SOC-Bench-compatible JSON
formats, specifically targeting Task Fox (campaign detection / alert triage)
and Task Tiger (attribution / TTP reporting).

SOC-Bench Design Principles (Dr. Liu):
  DP1: Loyalty to existing SOCs — reflect what SOC observes, not attacker sequence
  DP2: Be exclusive — each task focuses on one SOC function
  DP3: Based on real-world ransomware — don't generalize

Ring Scoring Model:
  Bullseye = 3 pts (exact match)
  Inner    = 2 pts (correct category, minor detail diff)
  Outer    = 1 pt  (partially relevant)
  Miss     = 0 pts

Penalty Rules:
  Wrong assertion:    -1
  No evidence:        -1
  Contradiction:      -2
  Stage leakage:      -2
  Spam/over-submit:   penalty
"""

from __future__ import annotations

import json
from dataclasses import asdict, dataclass, field
from datetime import UTC, datetime
from typing import Any

from src.evaluation.schemas import TriageCategory, TriageDecision

# === SOC-Bench Fox Output Schemas ===


@dataclass
class FoxO1CampaignAssessment:
    """O1: Campaign-scale assessment (39 pts).
    Identifies whether alerts form a coordinated campaign or isolated events.
    """

    stage_id: str
    timestamp: str
    campaign_detected: bool
    campaign_confidence: float  # 0.0 – 1.0
    campaign_scope: str  # 'isolated', 'targeted', 'widespread'
    affected_hosts: list[str] = field(default_factory=list)
    affected_subnets: list[str] = field(default_factory=list)
    evidence_ids: list[str] = field(default_factory=list)
    reasoning: str = ""


@dataclass
class FoxO2ActivityReasoning:
    """O2: Activity-type reasoning (39 pts).
    Classifies and explains the type of malicious activity.
    """

    stage_id: str
    timestamp: str
    activity_type: str  # e.g., 'credential_access', 'lateral_movement', 'exfiltration'
    mitre_techniques: list[str] = field(default_factory=list)
    kill_chain_phase: str = ""  # 'reconnaissance', 'weaponization', 'delivery', 'exploitation', 'installation', 'c2', 'actions'
    confidence: float = 0.0
    evidence_ids: list[str] = field(default_factory=list)
    reasoning: str = ""


@dataclass
class FoxO3TriageBundle:
    """O3: Cross-stage alert triage bundle (22 pts).
    Groups related alerts into coherent bundles with priority.
    """

    stage_id: str
    timestamp: str
    bundle_id: str
    alert_ids: list[str] = field(default_factory=list)
    priority: str = "medium"  # 'critical', 'high', 'medium', 'low', 'informational'
    triage_decision: str = ""  # 'true_positive', 'false_positive', 'needs_investigation'
    recommended_actions: list[str] = field(default_factory=list)
    evidence_ids: list[str] = field(default_factory=list)


@dataclass
class FoxStageOutput:
    """Complete Fox output for a single 30-minute stage."""

    stage_id: str
    stage_timestamp: str
    o1_campaign: FoxO1CampaignAssessment
    o2_activity: FoxO2ActivityReasoning
    o3_triage: FoxO3TriageBundle

    def to_json(self) -> str:
        return json.dumps(asdict(self), indent=2)


# === SOC-Bench Tiger Output Schemas ===


@dataclass
class TigerO1DataRelationship:
    """O1: Data source relationships (JSON)."""

    source_a: str
    source_b: str
    relationship_type: str  # 'corroborates', 'contradicts', 'extends', 'precedes'
    evidence_ids: list[str] = field(default_factory=list)
    confidence: float = 0.0


@dataclass
class TigerThreatNode:
    """Node in threat graph."""

    node_id: str
    node_type: str  # 'host', 'ip', 'user', 'process', 'file', 'service'
    label: str
    properties: dict[str, Any] = field(default_factory=dict)
    evidence_ids: list[str] = field(default_factory=list)


@dataclass
class TigerThreatEdge:
    """Edge in threat graph."""

    source_id: str
    target_id: str
    edge_type: str  # 'accessed', 'spawned', 'connected_to', 'authenticated_as', 'wrote', 'read'
    timestamp: str = ""
    evidence_ids: list[str] = field(default_factory=list)


@dataclass
class TigerO2ThreatGraph:
    """O2: Threat graph with nodes/edges/vulnerabilities."""

    nodes: list[TigerThreatNode] = field(default_factory=list)
    edges: list[TigerThreatEdge] = field(default_factory=list)
    vulnerabilities: list[str] = field(default_factory=list)
    mitre_techniques: list[str] = field(default_factory=list)


@dataclass
class TigerStageOutput:
    """Complete Tiger output for a single stage."""

    stage_id: str
    o1_relationships: list[TigerO1DataRelationship]
    o2_threat_graph: TigerO2ThreatGraph
    o3_entrypoint_statement: str  # one-paragraph prose

    def to_json(self) -> str:
        return json.dumps(asdict(self), indent=2)


# === SOC-Bench Panda (Containment) ===


@dataclass
class PandaBLUFReport:
    """Panda BLUF (Bottom Line Up Front) report per stage.
    Max 100 pts per stage, min -80.
      Containment actions:  20 pts
      Action targets:       40 pts
      Reasoning/evidence:   40 pts
    """

    stage_timestamp: str
    containment_actions: list[str] = field(default_factory=list)
    action_targets: dict[str, list[str]] = field(
        default_factory=lambda: {
            "hosts": [],
            "ips": [],
            "subnets": [],
            "user_accounts": [],
            "user_groups": [],
            "services": [],
            "other": [],
        }
    )
    reasoning_evidence: str = ""
    # Reasoning must include:
    #   (I) action justification with SOC trade-offs
    #   (II) current situation assessment with concrete evidence
    #   (III) predicted impact of inaction

    def to_json(self) -> str:
        return json.dumps(asdict(self), indent=2)


# === Adapter: Hades → SOC-Bench ===


def triage_decisions_to_fox_stage(
    decisions: list[TriageDecision],
    stage_id: str = "S1",
    stage_timestamp: str | None = None,
    alerts: list[Any] | None = None,
) -> FoxStageOutput:
    """Convert a batch of Hades TriageDecisions into a SOC-Bench Fox stage output.

    This is the key adapter — it transforms our flat triage classifications
    into the richer, evidence-backed, campaign-aware format SOC-Bench expects.

    Args:
        decisions: Triage decisions from pipeline
        stage_id: SOC-Bench stage identifier
        stage_timestamp: ISO timestamp for the stage
        alerts: Optional list of UnifiedAlert objects for IP extraction
    """
    if stage_timestamp is None:
        stage_timestamp = datetime.now(UTC).isoformat()

    # Build alert lookup by ID for IP extraction
    alert_map: dict[str, Any] = {}
    if alerts:
        for a in alerts:
            alert_map[a.alert_id] = a

    # Classify decisions
    true_positives = [d for d in decisions if d.classification == TriageCategory.TRUE_POSITIVE]
    escalations = [d for d in decisions if d.classification == TriageCategory.ESCALATE]
    critical = true_positives + escalations

    # Collect evidence
    all_evidence = []
    all_techniques = []
    affected_ips = set()
    for d in decisions:
        for ev in d.evidence_trace or []:
            all_evidence.append(ev.evidence_id if hasattr(ev, "evidence_id") else str(ev))
        for t in d.mitre_techniques or []:
            if t not in all_techniques:
                all_techniques.append(t)
        # Try to get IPs from alert object (if attached) or alert map
        alert = getattr(d, "alert", None) or alert_map.get(d.alert_id)
        if alert:
            if getattr(alert, "src_ip", None):
                affected_ips.add(alert.src_ip)
            if getattr(alert, "dst_ip", None):
                affected_ips.add(alert.dst_ip)

    # O1: Campaign assessment
    campaign_detected = len(critical) >= 3  # threshold: 3+ related true positives
    scope = (
        "widespread"
        if len(affected_ips) > 10
        else "targeted"
        if len(affected_ips) > 3
        else "isolated"
    )
    o1 = FoxO1CampaignAssessment(
        stage_id=stage_id,
        timestamp=stage_timestamp,
        campaign_detected=campaign_detected,
        campaign_confidence=min(len(critical) / max(len(decisions), 1), 1.0),
        campaign_scope=scope,
        affected_hosts=sorted(affected_ips)[:20],
        evidence_ids=all_evidence[:10],
        reasoning=f"Identified {len(critical)} critical alerts across {len(affected_ips)} hosts",
    )

    # O2: Activity reasoning
    activity = _infer_activity_type(all_techniques)
    o2 = FoxO2ActivityReasoning(
        stage_id=stage_id,
        timestamp=stage_timestamp,
        activity_type=activity,
        mitre_techniques=all_techniques[:10],
        kill_chain_phase=_techniques_to_kill_chain(all_techniques),
        confidence=sum(d.confidence for d in decisions) / max(len(decisions), 1),
        evidence_ids=all_evidence[:10],
        reasoning=f"Techniques {', '.join(all_techniques[:5])} indicate {activity}",
    )

    # O3: Triage bundle
    priority = (
        "critical" if len(escalations) > 0 else "high" if len(true_positives) > 0 else "medium"
    )
    o3 = FoxO3TriageBundle(
        stage_id=stage_id,
        timestamp=stage_timestamp,
        bundle_id=f"B-{stage_id}-{datetime.now(UTC).strftime('%H%M%S')}",
        alert_ids=[d.alert_id for d in decisions[:50] if hasattr(d, "alert_id")],
        priority=priority,
        triage_decision=decisions[0].classification.value if decisions else "needs_investigation",
        recommended_actions=_generate_recommendations(all_techniques, critical),
        evidence_ids=all_evidence[:10],
    )

    return FoxStageOutput(
        stage_id=stage_id,
        stage_timestamp=stage_timestamp,
        o1_campaign=o1,
        o2_activity=o2,
        o3_triage=o3,
    )


# === Helpers ===

# MITRE tactic → activity type mapping
_TACTIC_ACTIVITY = {
    "TA0001": "initial_access",
    "TA0002": "execution",
    "TA0003": "persistence",
    "TA0004": "privilege_escalation",
    "TA0005": "defense_evasion",
    "TA0006": "credential_access",
    "TA0007": "discovery",
    "TA0008": "lateral_movement",
    "TA0009": "collection",
    "TA0010": "exfiltration",
    "TA0011": "command_and_control",
    "TA0040": "impact",
}

# Technique prefix → tactic (simplified)
_TECHNIQUE_TACTIC = {
    "T1003": "TA0006",
    "T1021": "TA0008",
    "T1027": "TA0005",
    "T1036": "TA0005",
    "T1053": "TA0003",
    "T1055": "TA0005",
    "T1059": "TA0002",
    "T1071": "TA0011",
    "T1078": "TA0001",
    "T1087": "TA0007",
    "T1105": "TA0011",
    "T1110": "TA0006",
    "T1218": "TA0005",
    "T1547": "TA0003",
    "T1569": "TA0002",
}


def _infer_activity_type(techniques: list[str]) -> str:
    """Infer the primary activity type from MITRE techniques."""
    if not techniques:
        return "unknown"
    tactic_counts: dict[str, int] = {}
    for t in techniques:
        prefix = t.split(".")[0] if "." in t else t
        tactic = _TECHNIQUE_TACTIC.get(prefix, "")
        if tactic:
            tactic_counts[tactic] = tactic_counts.get(tactic, 0) + 1
    if not tactic_counts:
        return "unknown"
    primary = max(tactic_counts, key=tactic_counts.get)  # type: ignore
    return _TACTIC_ACTIVITY.get(primary, "unknown")


def _techniques_to_kill_chain(techniques: list[str]) -> str:
    """Map techniques to Lockheed Martin kill chain phase."""
    if not techniques:
        return ""
    phase_map = {
        "TA0001": "delivery",
        "TA0002": "exploitation",
        "TA0003": "installation",
        "TA0004": "exploitation",
        "TA0005": "installation",
        "TA0006": "exploitation",
        "TA0007": "reconnaissance",
        "TA0008": "actions",
        "TA0009": "actions",
        "TA0010": "actions",
        "TA0011": "c2",
    }
    for t in techniques:
        prefix = t.split(".")[0] if "." in t else t
        tactic = _TECHNIQUE_TACTIC.get(prefix, "")
        if tactic in phase_map:
            return phase_map[tactic]
    return ""


def _generate_recommendations(
    techniques: list[str],
    critical: list[TriageDecision],
) -> list[str]:
    """Generate actionable recommendations based on findings."""
    recs = []
    technique_set = set(t.split(".")[0] for t in techniques)
    if "T1003" in technique_set:
        recs.append("Rotate credentials for affected accounts; enable LSA protection")
    if "T1021" in technique_set:
        recs.append("Restrict SMB/RDP lateral movement; review admin share access")
    if "T1071" in technique_set:
        recs.append("Block identified C2 domains/IPs at perimeter firewall")
    if "T1110" in technique_set:
        recs.append("Enable account lockout policies; investigate brute-force source IPs")
    if "T1059" in technique_set:
        recs.append("Review PowerShell execution policy; enable script block logging")
    if "T1547" in technique_set or "T1053" in technique_set:
        recs.append("Audit startup/scheduled task persistence mechanisms")
    if len(critical) > 5:
        recs.append("Escalate to Incident Response team — multiple high-severity indicators")
    if not recs:
        recs.append("Continue monitoring; no immediate action required")
    return recs
