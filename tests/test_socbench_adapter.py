#!/usr/bin/env python3
"""Tests for SOC-Bench output adapter.

Validates that Hades TriageDecision outputs can be correctly transformed
into SOC-Bench-compatible formats (Fox O1-O3).
"""

from __future__ import annotations

import json
import sys
from datetime import UTC, datetime
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from src.evaluation.schemas import (
    TriageCategory,
    TriageDecision,
    EvidenceItem,
)
from src.evaluation.socbench_adapter import (
    FoxO1CampaignAssessment,
    FoxO2ActivityReasoning,
    FoxO3TriageBundle,
    FoxStageOutput,
    triage_decisions_to_fox_stage,
)

passed = 0
failed = 0


def ok(name: str):
    global passed
    passed += 1
    print(f"  ✅ {name}")


def fail(name: str, reason: str):
    global failed
    failed += 1
    print(f"  ❌ {name}: {reason}")


def make_triage_decision(
    alert_id: str = "test-001",
    classification: TriageCategory = TriageCategory.TRUE_POSITIVE,
    confidence: float = 0.85,
    mitre_techniques: list[str] | None = None,
    rationale: str = "Test reasoning",
    correlated_events: list[str] | None = None,
) -> TriageDecision:
    """Helper to create triage decisions for testing."""
    return TriageDecision(
        alert_id=alert_id,
        classification=classification,
        confidence=confidence,
        mitre_techniques=mitre_techniques or ["T1003.001"],
        rationale_summary=rationale,
        evidence_trace=[EvidenceItem(source_type="test", source_ref="ref-001", summary="test evidence")],
        correlated_events=correlated_events or [],
    )


def main():
    print("=" * 70)
    print("  HADES — SOC-Bench Adapter Validation")
    print("=" * 70)

    # === Fox Stage Output: Single Isolated Alert ===
    print("\n─── Fox Stage: Isolated Alert ───")

    isolated_decision = make_triage_decision(
        alert_id="alert-001",
        correlated_events=[],
    )
    fox_isolated = triage_decisions_to_fox_stage(
        [isolated_decision],
        stage_id="S1",
    )
    
    assert isinstance(fox_isolated, FoxStageOutput), "Should return FoxStageOutput"
    assert fox_isolated.stage_id == "S1"
    assert not fox_isolated.o1_campaign.campaign_detected, "Single alert should not be campaign"
    assert fox_isolated.o1_campaign.campaign_scope == "isolated"
    ok(f"isolated alert: scope={fox_isolated.o1_campaign.campaign_scope}")

    # === Fox Stage Output: Campaign Detection ===
    print("\n─── Fox Stage: Campaign Detection ───")

    # Create 4 correlated decisions (threshold is 3+ for campaign)
    campaign_decisions = [
        make_triage_decision(
            alert_id=f"alert-{i:03d}",
            mitre_techniques=["T1003.001"],
            correlated_events=[f"alert-{j:03d}" for j in range(1, 5) if j != i],
        )
        for i in range(1, 5)
    ]
    fox_campaign = triage_decisions_to_fox_stage(
        campaign_decisions,
        stage_id="S2",
    )
    
    # With 4 correlated true positives, campaign should be detected
    assert fox_campaign.o1_campaign.campaign_detected, "4 true positives should trigger campaign"
    assert len(fox_campaign.o3_triage.alert_ids) == 4
    ok(f"campaign detected: {len(fox_campaign.o3_triage.alert_ids)} alerts bundled")

    # === Fox O2: Activity Reasoning ===
    print("\n─── Fox O2: Activity Reasoning ───")

    cred_decision = make_triage_decision(
        alert_id="cred-001",
        mitre_techniques=["T1003.001", "T1003.003"],
        rationale="LSASS memory access detected indicating credential dumping attempt",
    )
    fox_cred = triage_decisions_to_fox_stage([cred_decision], stage_id="S3")
    
    # O2 should have activity type inferred from techniques
    assert fox_cred.o2_activity.activity_type != "", "Should infer activity type"
    assert "T1003.001" in fox_cred.o2_activity.mitre_techniques
    ok(f"credential access: type={fox_cred.o2_activity.activity_type}")

    # Lateral movement
    lateral_decision = make_triage_decision(
        alert_id="lat-001",
        mitre_techniques=["T1021.002"],
        rationale="SMB admin shares used for lateral movement",
    )
    fox_lat = triage_decisions_to_fox_stage([lateral_decision], stage_id="S3b")
    ok(f"lateral movement: type={fox_lat.o2_activity.activity_type}")

    # === Fox O3: Triage Bundle Priority ===
    print("\n─── Fox O3: Triage Bundle Priority ───")

    escalate_decision = make_triage_decision(
        alert_id="escalate-001",
        classification=TriageCategory.ESCALATE,
    )
    fox_escalate = triage_decisions_to_fox_stage([escalate_decision], stage_id="S4")
    
    # Escalation should result in critical priority
    assert fox_escalate.o3_triage.priority == "critical", \
        f"Escalation should have critical priority, got {fox_escalate.o3_triage.priority}"
    ok(f"escalation: priority={fox_escalate.o3_triage.priority}")

    # True positive should be high priority
    tp_decision = make_triage_decision(
        alert_id="tp-001",
        classification=TriageCategory.TRUE_POSITIVE,
    )
    fox_tp = triage_decisions_to_fox_stage([tp_decision], stage_id="S4b")
    assert fox_tp.o3_triage.priority == "high", \
        f"True positive should have high priority, got {fox_tp.o3_triage.priority}"
    ok(f"true positive: priority={fox_tp.o3_triage.priority}")

    # === Empty Input Handling ===
    print("\n─── Edge Cases ───")

    fox_empty = triage_decisions_to_fox_stage([], stage_id="S5")
    assert fox_empty.stage_id == "S5"
    assert len(fox_empty.o3_triage.alert_ids) == 0
    assert fox_empty.o3_triage.priority == "medium"
    ok("handles empty decision list")

    # False positive handling
    fp_decision = make_triage_decision(
        alert_id="fp-001",
        classification=TriageCategory.FALSE_POSITIVE,
    )
    fox_fp = triage_decisions_to_fox_stage([fp_decision], stage_id="S6")
    assert not fox_fp.o1_campaign.campaign_detected
    assert fox_fp.o3_triage.priority == "medium"  # FP doesn't trigger true_positive path
    ok("handles false positive classification")

    # Needs investigation handling
    ni_decision = make_triage_decision(
        alert_id="ni-001",
        classification=TriageCategory.NEEDS_INVESTIGATION,
    )
    fox_ni = triage_decisions_to_fox_stage([ni_decision], stage_id="S6b")
    assert fox_ni.o3_triage.triage_decision == "needs_investigation"
    ok("handles needs_investigation classification")

    # === JSON Serialization ===
    print("\n─── JSON Serialization ───")

    json_str = fox_campaign.to_json()
    parsed = json.loads(json_str)
    
    assert "stage_id" in parsed
    assert "o1_campaign" in parsed
    assert "o2_activity" in parsed
    assert "o3_triage" in parsed
    assert "campaign_detected" in parsed["o1_campaign"]
    ok(f"Fox output serializes to valid JSON ({len(json_str)} chars)")

    # Round-trip through JSON
    reparsed = json.loads(json_str)
    assert reparsed["o1_campaign"]["campaign_detected"] == fox_campaign.o1_campaign.campaign_detected
    ok("JSON round-trip preserves data")

    # === Kill Chain Phase Inference ===
    print("\n─── Kill Chain Phase Inference ───")

    # C2 technique
    c2_decision = make_triage_decision(
        alert_id="c2-001",
        mitre_techniques=["T1071.001"],
    )
    fox_c2 = triage_decisions_to_fox_stage([c2_decision], stage_id="S8")
    ok(f"command & control: phase={fox_c2.o2_activity.kill_chain_phase}")

    # Execution technique
    exec_decision = make_triage_decision(
        alert_id="exec-001",
        mitre_techniques=["T1059.001"],
    )
    fox_exec = triage_decisions_to_fox_stage([exec_decision], stage_id="S8b")
    ok(f"execution: phase={fox_exec.o2_activity.kill_chain_phase}")

    # === Multiple Techniques Aggregation ===
    print("\n─── Technique Aggregation ───")

    multi_tech_decisions = [
        make_triage_decision(
            alert_id=f"multi-{i}",
            mitre_techniques=[f"T100{i}.001"],
        )
        for i in range(1, 5)
    ]
    fox_multi = triage_decisions_to_fox_stage(multi_tech_decisions, stage_id="S9")
    
    # Should aggregate techniques across all decisions
    total_techniques = len(fox_multi.o2_activity.mitre_techniques)
    assert total_techniques == 4, f"Expected 4 techniques, got {total_techniques}"
    ok(f"aggregated {total_techniques} techniques from {len(multi_tech_decisions)} decisions")

    # === Confidence Aggregation ===
    print("\n─── Confidence Aggregation ───")

    mixed_conf_decisions = [
        make_triage_decision(alert_id=f"conf-{i}", confidence=c)
        for i, c in enumerate([0.9, 0.8, 0.7, 0.6])
    ]
    fox_conf = triage_decisions_to_fox_stage(mixed_conf_decisions, stage_id="S10")
    
    # Should average confidence
    expected_avg = (0.9 + 0.8 + 0.7 + 0.6) / 4
    assert abs(fox_conf.o2_activity.confidence - expected_avg) < 0.01, \
        f"Expected avg confidence {expected_avg}, got {fox_conf.o2_activity.confidence}"
    ok(f"confidence averaged: {fox_conf.o2_activity.confidence:.2f}")

    # === Stage Timestamp Handling ===
    print("\n─── Stage Timestamp ───")

    custom_ts = "2026-03-13T12:00:00Z"
    fox_ts = triage_decisions_to_fox_stage(
        [isolated_decision],
        stage_id="S11",
        stage_timestamp=custom_ts,
    )
    assert fox_ts.stage_timestamp == custom_ts
    ok("custom stage timestamp preserved")

    # Auto-generated timestamp
    fox_auto_ts = triage_decisions_to_fox_stage([isolated_decision], stage_id="S12")
    assert fox_auto_ts.stage_timestamp != ""
    assert "T" in fox_auto_ts.stage_timestamp  # ISO format
    ok("auto-generates ISO timestamp")

    print()
    print("=" * 70)
    total = passed + failed
    print(f"  RESULTS: {passed}/{total} passed")
    print("=" * 70)
    sys.exit(0 if failed == 0 else 1)


if __name__ == "__main__":
    main()
