"""SOC-Bench Fox Task Scorer.

Implements the ring-based scoring model from SOC-Bench [Cai et al., 2026]
for evaluating Hades triage outputs against ground truth.

Ring Scoring Model:
  Bullseye = 3 pts  (exact match — technique, severity, and reasoning correct)
  Inner    = 2 pts  (correct tactic, minor sub-technique or severity offset)
  Outer    = 1 pt   (partially relevant — right kill chain phase, wrong specifics)
  Miss     = 0 pts  (completely wrong or no response)

Penalty Rules (from SOC-Bench §5):
  Wrong assertion with confidence:     -1 pt
  No evidence provided:                -1 pt
  Contradiction (conflicting claims):  -2 pts
  Stage leakage (future knowledge):    -2 pts
  Spam/over-submission:                -0.5 per excess

Fox Outcomes:
  O1: Campaign-scale assessment  (39 pts max)
  O2: Activity-type reasoning    (39 pts max)
  O3: Cross-stage triage bundle  (22 pts max)
  Total: 100 pts per stage
"""

from __future__ import annotations

import json
from dataclasses import asdict, dataclass, field
from datetime import UTC, datetime
from typing import Any

from src.evaluation.socbench_adapter import (
    FoxO1CampaignAssessment,
    FoxO2ActivityReasoning,
    FoxO3TriageBundle,
    FoxStageOutput,
)

# === Ring Scoring ===


class Ring:
    BULLSEYE = 3
    INNER = 2
    OUTER = 1
    MISS = 0


@dataclass
class ScoredItem:
    """A single scored comparison between prediction and ground truth."""

    dimension: str  # what was scored (e.g., "campaign_detected", "technique_T1003")
    ring: int  # 0-3
    ring_label: str  # "bullseye", "inner", "outer", "miss"
    max_points: float
    earned_points: float
    reasoning: str = ""


@dataclass
class PenaltyItem:
    """A penalty applied during scoring."""

    penalty_type: str  # "wrong_assertion", "no_evidence", "contradiction", "stage_leakage", "spam"
    points: float  # negative
    description: str


@dataclass
class OutcomeScore:
    """Score for a single Fox outcome (O1, O2, or O3)."""

    outcome: str  # "O1", "O2", "O3"
    max_points: float
    raw_points: float
    penalties: float
    final_points: float
    items: list[ScoredItem] = field(default_factory=list)
    penalty_items: list[PenaltyItem] = field(default_factory=list)


@dataclass
class FoxStageScore:
    """Complete score for a Fox stage."""

    stage_id: str
    o1_score: OutcomeScore
    o2_score: OutcomeScore
    o3_score: OutcomeScore
    total_raw: float
    total_penalties: float
    total_final: float
    timestamp: str = ""

    def to_json(self) -> str:
        return json.dumps(asdict(self), indent=2)


# === Ground Truth Schema ===


@dataclass
class FoxGroundTruth:
    """Ground truth for scoring a Fox stage."""

    stage_id: str
    # O1 ground truth
    campaign_present: bool
    campaign_scope: str  # 'isolated', 'targeted', 'widespread'
    affected_hosts: list[str] = field(default_factory=list)
    # O2 ground truth
    primary_activity: str = ""
    mitre_techniques: list[str] = field(default_factory=list)
    kill_chain_phase: str = ""
    # O3 ground truth
    true_positive_alert_ids: list[str] = field(default_factory=list)
    false_positive_alert_ids: list[str] = field(default_factory=list)
    expected_priority: str = "medium"


# === Scoring Functions ===


def _ring_label(ring: int) -> str:
    return {3: "bullseye", 2: "inner", 1: "outer", 0: "miss"}[ring]


def _score_ring(ring: int, max_points: float) -> float:
    """Convert ring to points proportionally."""
    return (ring / 3.0) * max_points


def score_o1_campaign(
    prediction: FoxO1CampaignAssessment,
    ground_truth: FoxGroundTruth,
) -> OutcomeScore:
    """Score O1: Campaign-scale assessment (39 pts max).

    Scoring dimensions:
    - Campaign detection (bool): 13 pts
    - Campaign scope (enum): 13 pts
    - Affected hosts coverage: 13 pts
    """
    items: list[ScoredItem] = []
    penalties: list[PenaltyItem] = []

    # 1. Campaign detection (13 pts)
    if prediction.campaign_detected == ground_truth.campaign_present:
        ring = Ring.BULLSEYE
    else:
        ring = Ring.MISS
    pts = _score_ring(ring, 13.0)
    items.append(
        ScoredItem(
            "campaign_detected",
            ring,
            _ring_label(ring),
            13.0,
            pts,
            f"predicted={prediction.campaign_detected}, truth={ground_truth.campaign_present}",
        )
    )

    # 2. Campaign scope (13 pts)
    if prediction.campaign_scope == ground_truth.campaign_scope:
        ring = Ring.BULLSEYE
    elif _scope_adjacent(prediction.campaign_scope, ground_truth.campaign_scope):
        ring = Ring.INNER
    else:
        ring = Ring.MISS
    pts = _score_ring(ring, 13.0)
    items.append(
        ScoredItem(
            "campaign_scope",
            ring,
            _ring_label(ring),
            13.0,
            pts,
            f"predicted={prediction.campaign_scope}, truth={ground_truth.campaign_scope}",
        )
    )

    # 3. Affected hosts coverage (13 pts)
    if ground_truth.affected_hosts:
        pred_set = set(prediction.affected_hosts)
        truth_set = set(ground_truth.affected_hosts)
        if pred_set == truth_set:
            ring = Ring.BULLSEYE
        elif len(pred_set & truth_set) >= len(truth_set) * 0.7:
            ring = Ring.INNER
        elif len(pred_set & truth_set) > 0:
            ring = Ring.OUTER
        else:
            ring = Ring.MISS
    else:
        ring = Ring.BULLSEYE if not prediction.affected_hosts else Ring.INNER
    pts = _score_ring(ring, 13.0)
    items.append(ScoredItem("affected_hosts", ring, _ring_label(ring), 13.0, pts))

    # Penalties
    if not prediction.evidence_ids:
        penalties.append(PenaltyItem("no_evidence", -1.0, "O1: no evidence_ids provided"))

    if prediction.campaign_confidence > 0.9 and not ground_truth.campaign_present:
        penalties.append(
            PenaltyItem(
                "wrong_assertion",
                -1.0,
                f"High confidence ({prediction.campaign_confidence:.2f}) on false campaign",
            )
        )

    raw = sum(i.earned_points for i in items)
    pen = sum(p.points for p in penalties)
    return OutcomeScore(
        "O1", 39.0, round(raw, 2), round(pen, 2), round(max(raw + pen, 0), 2), items, penalties
    )


def score_o2_activity(
    prediction: FoxO2ActivityReasoning,
    ground_truth: FoxGroundTruth,
) -> OutcomeScore:
    """Score O2: Activity-type reasoning (39 pts max).

    Scoring dimensions:
    - Activity type (13 pts)
    - MITRE technique accuracy (13 pts)
    - Kill chain phase (13 pts)
    """
    items: list[ScoredItem] = []
    penalties: list[PenaltyItem] = []

    # 1. Activity type (13 pts)
    if prediction.activity_type == ground_truth.primary_activity:
        ring = Ring.BULLSEYE
    elif _activity_related(prediction.activity_type, ground_truth.primary_activity):
        ring = Ring.INNER
    else:
        ring = Ring.MISS
    pts = _score_ring(ring, 13.0)
    items.append(
        ScoredItem(
            "activity_type",
            ring,
            _ring_label(ring),
            13.0,
            pts,
            f"predicted={prediction.activity_type}, truth={ground_truth.primary_activity}",
        )
    )

    # 2. MITRE technique accuracy (13 pts) — ring based on overlap
    if ground_truth.mitre_techniques:
        pred_set = set(prediction.mitre_techniques)
        truth_set = set(ground_truth.mitre_techniques)
        # Check exact technique match
        exact_overlap = pred_set & truth_set
        # Check tactic-level match (T1003 matches T1003.001)
        pred_parents = {t.split(".")[0] for t in pred_set}
        truth_parents = {t.split(".")[0] for t in truth_set}
        parent_overlap = pred_parents & truth_parents

        if exact_overlap == truth_set and len(pred_set - truth_set) <= 1:
            ring = Ring.BULLSEYE
        elif len(exact_overlap) > 0 or len(parent_overlap) >= len(truth_parents) * 0.5:
            ring = Ring.INNER
        elif len(parent_overlap) > 0:
            ring = Ring.OUTER
        else:
            ring = Ring.MISS
    else:
        ring = Ring.BULLSEYE if not prediction.mitre_techniques else Ring.INNER
    pts = _score_ring(ring, 13.0)
    items.append(ScoredItem("mitre_techniques", ring, _ring_label(ring), 13.0, pts))

    # 3. Kill chain phase (13 pts)
    if prediction.kill_chain_phase == ground_truth.kill_chain_phase:
        ring = Ring.BULLSEYE
    elif _phase_adjacent(prediction.kill_chain_phase, ground_truth.kill_chain_phase):
        ring = Ring.INNER
    else:
        ring = Ring.MISS if ground_truth.kill_chain_phase else Ring.BULLSEYE
    pts = _score_ring(ring, 13.0)
    items.append(ScoredItem("kill_chain_phase", ring, _ring_label(ring), 13.0, pts))

    # Penalties
    if not prediction.evidence_ids:
        penalties.append(PenaltyItem("no_evidence", -1.0, "O2: no evidence_ids provided"))

    # Check for technique spam
    if len(prediction.mitre_techniques) > len(ground_truth.mitre_techniques) * 3 + 5:
        excess = len(prediction.mitre_techniques) - (len(ground_truth.mitre_techniques) * 3 + 5)
        penalties.append(
            PenaltyItem(
                "spam",
                -0.5 * excess,
                f"Over-submission: {len(prediction.mitre_techniques)} techniques",
            )
        )

    raw = sum(i.earned_points for i in items)
    pen = sum(p.points for p in penalties)
    return OutcomeScore(
        "O2", 39.0, round(raw, 2), round(pen, 2), round(max(raw + pen, 0), 2), items, penalties
    )


def score_o3_triage(
    prediction: FoxO3TriageBundle,
    ground_truth: FoxGroundTruth,
) -> OutcomeScore:
    """Score O3: Cross-stage triage bundle (22 pts max).

    Scoring dimensions:
    - Alert classification accuracy (8 pts)
    - Priority assessment (7 pts)
    - Actionability of recommendations (7 pts)
    """
    items: list[ScoredItem] = []
    penalties: list[PenaltyItem] = []

    # 1. Alert classification (8 pts)
    if ground_truth.true_positive_alert_ids:
        pred_set = set(prediction.alert_ids)
        tp_set = set(ground_truth.true_positive_alert_ids)
        fp_set = set(ground_truth.false_positive_alert_ids)
        correct_tp = pred_set & tp_set
        included_fp = pred_set & fp_set

        if correct_tp == tp_set and not included_fp:
            ring = Ring.BULLSEYE
        elif len(correct_tp) >= len(tp_set) * 0.7 and len(included_fp) <= 1:
            ring = Ring.INNER
        elif len(correct_tp) > 0:
            ring = Ring.OUTER
        else:
            ring = Ring.MISS
    else:
        ring = Ring.BULLSEYE  # no ground truth to compare
    pts = _score_ring(ring, 8.0)
    items.append(ScoredItem("alert_classification", ring, _ring_label(ring), 8.0, pts))

    # 2. Priority assessment (7 pts)
    priority_order = ["informational", "low", "medium", "high", "critical"]
    pred_idx = (
        priority_order.index(prediction.priority) if prediction.priority in priority_order else 2
    )
    truth_idx = (
        priority_order.index(ground_truth.expected_priority)
        if ground_truth.expected_priority in priority_order
        else 2
    )

    diff = abs(pred_idx - truth_idx)
    if diff == 0:
        ring = Ring.BULLSEYE
    elif diff == 1:
        ring = Ring.INNER
    elif diff == 2:
        ring = Ring.OUTER
    else:
        ring = Ring.MISS
    pts = _score_ring(ring, 7.0)
    items.append(
        ScoredItem(
            "priority",
            ring,
            _ring_label(ring),
            7.0,
            pts,
            f"predicted={prediction.priority}, truth={ground_truth.expected_priority}",
        )
    )

    # 3. Actionability (7 pts) — scored on recommendation quality
    if prediction.recommended_actions:
        # At least 1 specific, actionable recommendation = inner
        # Generic "continue monitoring" only = outer
        specific = [
            a
            for a in prediction.recommended_actions
            if any(
                kw in a.lower()
                for kw in [
                    "block",
                    "isolate",
                    "rotate",
                    "restrict",
                    "disable",
                    "enable",
                    "review",
                    "audit",
                    "escalate",
                    "investigate",
                ]
            )
        ]
        if len(specific) >= 2:
            ring = Ring.BULLSEYE
        elif len(specific) >= 1:
            ring = Ring.INNER
        elif prediction.recommended_actions:
            ring = Ring.OUTER
        else:
            ring = Ring.MISS
    else:
        ring = Ring.MISS
    pts = _score_ring(ring, 7.0)
    items.append(ScoredItem("actionability", ring, _ring_label(ring), 7.0, pts))

    # Penalties
    if not prediction.evidence_ids:
        penalties.append(PenaltyItem("no_evidence", -1.0, "O3: no evidence_ids provided"))

    raw = sum(i.earned_points for i in items)
    pen = sum(p.points for p in penalties)
    return OutcomeScore(
        "O3", 22.0, round(raw, 2), round(pen, 2), round(max(raw + pen, 0), 2), items, penalties
    )


def score_fox_stage(
    prediction: FoxStageOutput,
    ground_truth: FoxGroundTruth,
) -> FoxStageScore:
    """Score a complete Fox stage output against ground truth.

    Returns a FoxStageScore with O1 (39 pts), O2 (39 pts), O3 (22 pts) = 100 pts max.
    """
    o1 = score_o1_campaign(prediction.o1_campaign, ground_truth)
    o2 = score_o2_activity(prediction.o2_activity, ground_truth)
    o3 = score_o3_triage(prediction.o3_triage, ground_truth)

    total_raw = o1.raw_points + o2.raw_points + o3.raw_points
    total_pen = o1.penalties + o2.penalties + o3.penalties
    total_final = o1.final_points + o2.final_points + o3.final_points

    return FoxStageScore(
        stage_id=prediction.stage_id,
        o1_score=o1,
        o2_score=o2,
        o3_score=o3,
        total_raw=round(total_raw, 2),
        total_penalties=round(total_pen, 2),
        total_final=round(total_final, 2),
        timestamp=datetime.now(UTC).isoformat(),
    )


# === Helper Functions ===

_SCOPE_ORDER = ["isolated", "targeted", "widespread"]


def _scope_adjacent(a: str, b: str) -> bool:
    """Check if scopes are one step apart."""
    try:
        return abs(_SCOPE_ORDER.index(a) - _SCOPE_ORDER.index(b)) == 1
    except ValueError:
        return False


# Related activity pairs (same kill chain phase or commonly co-occurring)
_RELATED_ACTIVITIES = {
    ("credential_access", "lateral_movement"),
    ("lateral_movement", "credential_access"),
    ("execution", "persistence"),
    ("persistence", "execution"),
    ("defense_evasion", "execution"),
    ("execution", "defense_evasion"),
    ("command_and_control", "exfiltration"),
    ("exfiltration", "command_and_control"),
    ("initial_access", "execution"),
    ("execution", "initial_access"),
    ("discovery", "lateral_movement"),
    ("lateral_movement", "discovery"),
    ("privilege_escalation", "credential_access"),
    ("credential_access", "privilege_escalation"),
}


def _activity_related(a: str, b: str) -> bool:
    return (a, b) in _RELATED_ACTIVITIES


_PHASE_ORDER = [
    "reconnaissance",
    "weaponization",
    "delivery",
    "exploitation",
    "installation",
    "c2",
    "actions",
]


def _phase_adjacent(a: str, b: str) -> bool:
    try:
        return abs(_PHASE_ORDER.index(a) - _PHASE_ORDER.index(b)) <= 1
    except ValueError:
        return False


# === Convenience: Score from JSON ===


def score_fox_from_json(
    prediction_json: dict[str, Any],
    ground_truth_json: dict[str, Any],
) -> FoxStageScore:
    """Score Fox output from raw JSON dicts."""
    pred = FoxStageOutput(
        stage_id=prediction_json["stage_id"],
        stage_timestamp=prediction_json["stage_timestamp"],
        o1_campaign=FoxO1CampaignAssessment(**prediction_json["o1_campaign"]),
        o2_activity=FoxO2ActivityReasoning(**prediction_json["o2_activity"]),
        o3_triage=FoxO3TriageBundle(**prediction_json["o3_triage"]),
    )
    gt = FoxGroundTruth(
        stage_id=ground_truth_json["stage_id"],
        campaign_present=ground_truth_json["campaign_present"],
        campaign_scope=ground_truth_json["campaign_scope"],
        affected_hosts=ground_truth_json.get("affected_hosts", []),
        primary_activity=ground_truth_json.get("primary_activity", ""),
        mitre_techniques=ground_truth_json.get("mitre_techniques", []),
        kill_chain_phase=ground_truth_json.get("kill_chain_phase", ""),
        true_positive_alert_ids=ground_truth_json.get("true_positive_alert_ids", []),
        false_positive_alert_ids=ground_truth_json.get("false_positive_alert_ids", []),
        expected_priority=ground_truth_json.get("expected_priority", "medium"),
    )
    return score_fox_stage(pred, gt)


def print_fox_score(score: FoxStageScore) -> str:
    """Format a Fox stage score for display."""
    lines = [
        f"FOX Stage {score.stage_id} — {score.total_final:.1f}/100 pts",
        f"  O1 Campaign:  {score.o1_score.final_points:5.1f}/39  (raw {score.o1_score.raw_points:.1f}, pen {score.o1_score.penalties:.1f})",
        f"  O2 Activity:  {score.o2_score.final_points:5.1f}/39  (raw {score.o2_score.raw_points:.1f}, pen {score.o2_score.penalties:.1f})",
        f"  O3 Triage:    {score.o3_score.final_points:5.1f}/22  (raw {score.o3_score.raw_points:.1f}, pen {score.o3_score.penalties:.1f})",
        "",
    ]

    for outcome in [score.o1_score, score.o2_score, score.o3_score]:
        lines.append(f"  {outcome.outcome} Details:")
        for item in outcome.items:
            icon = {"bullseye": "🎯", "inner": "🟡", "outer": "🟠", "miss": "❌"}[item.ring_label]
            lines.append(
                f"    {icon} {item.dimension}: {item.earned_points:.1f}/{item.max_points:.1f} ({item.ring_label})"
            )
            if item.reasoning:
                lines.append(f"       {item.reasoning}")
        for pen in outcome.penalty_items:
            lines.append(f"    ⚠️  {pen.penalty_type}: {pen.points:+.1f} — {pen.description}")
        lines.append("")

    return "\n".join(lines)
