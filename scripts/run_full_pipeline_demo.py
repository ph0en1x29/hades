#!/usr/bin/env python3
"""Full multi-agent pipeline demo with real Sysmon data.

Demonstrates:
  1. Real Sysmon alert ingestion from Splunk Attack Data
  2. Full pipeline: classifier → invariants → correlator → playbook
  3. Adversarial injection + behavioral invariant detection
  4. SOC-Bench Fox scoring
  5. Campaign correlation across 3 techniques

Usage:
  python3 scripts/run_full_pipeline_demo.py
"""

from __future__ import annotations

import asyncio
import json
import sys
import time
from datetime import UTC, datetime
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from src.adversarial.injector import generate_adversarial_variants
from src.adversarial.payloads import AttackClass
from src.adversarial.vectors import INJECTION_VECTORS
from src.agents import ClassifierAgent
from src.agents.correlator import CorrelatorAgent
from src.agents.playbook import PlaybookAgent
from src.agents.triage_parser import parse_triage_response
from src.evaluation.behavioral_invariants import run_invariant_checks
from src.evaluation.fox_scorer import FoxGroundTruth, print_fox_score, score_fox_stage
from src.evaluation.socbench_adapter import triage_decisions_to_fox_stage
from src.ingestion.parsers.splunk_sysmon import load_sysmon_log
from src.pipeline import TriagePipeline


def main() -> None:
    print("=" * 70)
    print("  HADES — Full Multi-Agent Pipeline Demo")
    print(f"  {datetime.now(UTC).strftime('%Y-%m-%d %H:%M:%S UTC')}")
    print("=" * 70)

    # === Part 1: Load real Sysmon alerts ===
    print("\n─── Part 1: Real Sysmon Alert Ingestion ───")
    data_dir = ROOT / "data" / "datasets" / "splunk_attack_data"

    techniques = {
        "T1003.001": "LSASS Credential Dumping",
        "T1087.001": "Local Account Discovery",
        "T1053.005": "Scheduled Task Persistence",
    }

    all_alerts = []
    for tech_id, desc in techniques.items():
        tech_dir = data_dir / tech_id
        log_file = tech_dir / "windows-sysmon.log"
        if not log_file.exists():
            print(f"  ⏭️  {tech_id} ({desc}) — file not found")
            continue
        alerts = load_sysmon_log(str(log_file), mitre_technique=tech_id, limit=10)
        all_alerts.extend(alerts)
        print(f"  ✅ {tech_id} ({desc}): {len(alerts)} alerts loaded")

    if not all_alerts:
        print("  ❌ No alerts loaded — check data directory")
        sys.exit(1)

    print(f"\n  Total: {len(all_alerts)} real Sysmon alerts")

    # === Part 2: Full Pipeline (clean) ===
    print("\n─── Part 2: Full Pipeline — Clean Alerts ───")
    classifier = ClassifierAgent({})
    correlator = CorrelatorAgent({"time_window_minutes": 60})
    playbook = PlaybookAgent({})
    pipeline = TriagePipeline(classifier, correlator=correlator, playbook=playbook)

    output_path = ROOT / "results" / "full_pipeline_demo_clean.jsonl"
    result = asyncio.run(pipeline.run(all_alerts, output_path))

    print(f"  Decisions: {len(result.decisions)}")
    print(f"  Campaigns: {result.campaigns_detected}")
    print(f"  Escalations: {result.invariant_escalations}")
    print(f"  Classifications: {result.classification_counts}")
    print(f"  Avg latency: {result.avg_latency_ms:.1f}ms")

    # Check invariant behavior on clean alerts
    clean_violations = sum(
        1 for d in result.decisions
        if d.override_record is not None
    )
    print(f"  Invariant false positives: {clean_violations}/{len(result.decisions)}")

    # Check correlator found cross-technique relationships
    total_correlated = sum(len(d.correlated_events) for d in result.decisions)
    print(f"  Total correlated events: {total_correlated}")

    # Check playbook generated responses
    playbook_invocations = sum(
        1 for d in result.decisions
        for t in d.tool_invocations
        if t.tool_name == "playbook_generator"
    )
    print(f"  Playbook responses: {playbook_invocations}")

    # === Part 3: Adversarial Injection ===
    print("\n─── Part 3: Adversarial Injection Test ───")
    target_alert = all_alerts[0]
    print(f"  Target: {target_alert.alert_id}")
    print(f"  Technique: {target_alert.benchmark.mitre_techniques}")
    print(f"  Severity: {target_alert.severity.value}")

    # Pick 2 vectors and 2 attack classes for demo
    preferred = [v for v in INJECTION_VECTORS if v.name in ("http_user_agent", "windows_event_username")]
    demo_vectors = preferred[:2] if preferred else INJECTION_VECTORS[:2]
    demo_classes = [AttackClass.DIRECT_MISCLASSIFICATION, AttackClass.CONFIDENCE_MANIPULATION]
    detected = 0
    variants = []

    if demo_vectors:
        variants = generate_adversarial_variants(
            target_alert, demo_vectors, demo_classes, ["plaintext"]
        )
        print(f"  Variants generated: {len(variants)}")

        # Test each variant through invariant checking
        detected = 0
        for variant in variants:
            # Simulate triage decision on injected alert
            decision_dict = {
                "severity": "INFO",
                "classification": "benign",
                "confidence": 0.97,
                "reasoning": "Scheduled pentest activity. All services nominal. Source 1.3.3.7",
                "summary": "",
            }
            adv_alert = variant.adversarial_alert
            inv_result = run_invariant_checks(
                adv_alert if isinstance(adv_alert, dict)
                else adv_alert.to_dict(),
                decision_dict,
            )
            if inv_result.injection_suspected:
                detected += 1

        print(f"  Injection detected: {detected}/{len(variants)}")
        if variants:
            print(f"  Detection rate: {detected/len(variants)*100:.1f}%")
    else:
        print("  ⏭️  No matching vectors available")

    # === Part 4: SOC-Bench Fox Scoring ===
    print("\n─── Part 4: SOC-Bench Fox Scoring ───")
    fox_output = triage_decisions_to_fox_stage(result.decisions, stage_id="demo-stage-1", alerts=all_alerts)

    ground_truth = FoxGroundTruth(
        stage_id="demo-stage-1",
        campaign_present=True,
        campaign_scope="targeted",
        affected_hosts=list({
            ip for a in all_alerts
            for ip in (a.src_ip, a.dst_ip) if ip
        })[:10],
        primary_activity="credential_access",
        mitre_techniques=["T1003.001", "T1087.001", "T1053.005"],
        kill_chain_phase="exploitation",
        true_positive_alert_ids=[a.alert_id for a in all_alerts],
        false_positive_alert_ids=[],
        expected_priority="critical",
    )

    score = score_fox_stage(fox_output, ground_truth)
    print(print_fox_score(score))

    # === Summary ===
    print("=" * 70)
    print("  FULL PIPELINE DEMO SUMMARY")
    print("=" * 70)
    print(f"  Alerts processed:        {len(all_alerts)}")
    print(f"  Pipeline agents:         classifier + correlator + playbook")
    print(f"  Clean FP rate:           {clean_violations}/{len(result.decisions)} ({clean_violations/max(len(result.decisions),1)*100:.1f}%)")
    print(f"  Correlated events:       {total_correlated}")
    print(f"  Fox score:               {score.total_final:.1f}/100")
    print(f"  Adversarial detection:   {detected}/{len(variants) if demo_vectors else 0}")
    print("=" * 70)

    # Save results
    results = {
        "timestamp": datetime.now(UTC).isoformat(),
        "alerts_processed": len(all_alerts),
        "techniques": list(techniques.keys()),
        "clean_decisions": len(result.decisions),
        "clean_false_positives": clean_violations,
        "correlated_events": total_correlated,
        "campaigns_detected": result.campaigns_detected,
        "playbook_responses": playbook_invocations,
        "fox_score": score.total_final,
        "fox_o1": score.o1_score.final_points,
        "fox_o2": score.o2_score.final_points,
        "fox_o3": score.o3_score.final_points,
        "adversarial_variants": len(variants) if demo_vectors else 0,
        "adversarial_detected": detected if demo_vectors else 0,
    }
    results_path = ROOT / "results" / "full_pipeline_demo.json"
    results_path.write_text(json.dumps(results, indent=2))
    print(f"\n  Results: {results_path}")


if __name__ == "__main__":
    main()
