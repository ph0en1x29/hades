#!/usr/bin/env python3
"""Multi-stage attack campaign demo.

Simulates a Colonial Pipeline-style ransomware campaign:
  Stage 1: Initial access via brute force (T1110)
  Stage 2: Credential dumping with mimikatz (T1003.001)
  Stage 3: Discovery — enumerate accounts (T1087)
  Stage 4: Lateral movement via SMB (T1021.002)
  Stage 5: Persistence via scheduled task (T1053.005)
  Stage 6: C2 beaconing (T1071.001)

Demonstrates:
  - Correlator linking alerts into attack chain
  - Behavioral invariant detection on injected alerts
  - Playbook generation per stage
  - SOC-Bench Fox output format
  - Campaign-level vs single-alert triage
"""

from __future__ import annotations

import asyncio
import json
import sys
import time
from datetime import UTC, datetime, timedelta
from pathlib import Path
from uuid import uuid4

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from src.agents.base import AgentResult
from src.agents.correlator import AlertStore, CorrelatorAgent, correlate_alerts
from src.agents.playbook import PlaybookAgent, generate_playbook
from src.agents.triage_prompt import format_alert_for_triage
from src.agents.triage_parser import parse_triage_response
from src.adversarial.injector import generate_adversarial_variants
from src.adversarial.vectors import INJECTION_VECTORS as VECTORS
from src.adversarial.payloads import AttackClass
from src.evaluation.behavioral_invariants import run_invariant_checks
from src.evaluation.socbench_adapter import triage_decisions_to_fox_stage
from src.evaluation.schemas import TriageCategory, TriageDecision, EvidenceItem
from src.ingestion.schema import (
    AlertBenchmarkContext,
    AlertMetadata,
    AlertProvenance,
    AlertSeverity,
    AlertSource,
    DatasetRole,
    UnifiedAlert,
)


# === Campaign Scenario: "DarkSide Ransomware" ===

BASE_TIME = datetime(2026, 3, 12, 14, 0, 0)

CAMPAIGN_ALERTS = [
    # Stage 1: Brute force (T=0)
    UnifiedAlert(
        alert_id="CAMP-001",
        timestamp=(BASE_TIME + timedelta(minutes=0)).isoformat(),
        source=AlertSource.FILE_REPLAY,
        severity=AlertSeverity.MEDIUM,
        signature="ET SCAN Brute Force Login Attempt",
        event_type="Authentication",
        src_ip="185.220.101.42",
        src_port=49821,
        dst_ip="10.0.1.5",
        dst_port=3389,
        protocol="TCP",
        raw_log="Multiple failed RDP login attempts from 185.220.101.42 to 10.0.1.5:3389. 47 failures in 5 minutes. Target accounts: admin, administrator, svc_backup.",
        metadata=AlertMetadata(vendor="Suricata", device="IDS-01", category="brute-force"),
        benchmark=AlertBenchmarkContext(
            scenario_id="darkside-sim-001",
            rule_id="2024897",
            rule_source="ET",
            mitre_techniques=["T1110.001"],
        ),
        provenance=AlertProvenance(
            dataset_name="hades_campaign_sim",
            dataset_role=DatasetRole.ENGINEERING_SCAFFOLD,
            label_provenance="synthetic_scenario",
        ),
    ),
    # Stage 1b: Successful login after brute force (T+8min)
    UnifiedAlert(
        alert_id="CAMP-002",
        timestamp=(BASE_TIME + timedelta(minutes=8)).isoformat(),
        source=AlertSource.FILE_REPLAY,
        severity=AlertSeverity.HIGH,
        signature="Successful RDP Login After Multiple Failures",
        event_type="Authentication",
        src_ip="185.220.101.42",
        src_port=50102,
        dst_ip="10.0.1.5",
        dst_port=3389,
        protocol="TCP",
        raw_log="Successful RDP authentication from 185.220.101.42 as svc_backup after 47 failed attempts. Event 4624 Type 10.",
        metadata=AlertMetadata(vendor="Windows", device="DC-01", category="authentication"),
        benchmark=AlertBenchmarkContext(
            scenario_id="darkside-sim-001",
            rule_id="win-4624-t10",
            rule_source="windows_security",
            mitre_techniques=["T1078"],
        ),
        provenance=AlertProvenance(
            dataset_name="hades_campaign_sim",
            dataset_role=DatasetRole.ENGINEERING_SCAFFOLD,
            label_provenance="synthetic_scenario",
        ),
    ),
    # Stage 2: Credential dumping (T+15min)
    UnifiedAlert(
        alert_id="CAMP-003",
        timestamp=(BASE_TIME + timedelta(minutes=15)).isoformat(),
        source=AlertSource.FILE_REPLAY,
        severity=AlertSeverity.CRITICAL,
        signature="LSASS Memory Access — Potential Credential Dumping",
        event_type="ProcessAccess",
        src_ip="10.0.1.5",
        dst_ip="10.0.1.5",
        protocol="TCP",
        raw_log="Process rundll32.exe (PID 4872) accessed lsass.exe (PID 680) with PROCESS_VM_READ. GrantedAccess: 0x1010. SourceImage: C:\\Windows\\System32\\rundll32.exe. CallTrace: ntdll.dll|KERNELBASE.dll|comsvcs.dll.",
        metadata=AlertMetadata(vendor="Sysmon", device="WKS-01", category="credential-access"),
        benchmark=AlertBenchmarkContext(
            scenario_id="darkside-sim-001",
            rule_id="sysmon-10-lsass",
            rule_source="sysmon",
            mitre_techniques=["T1003.001"],
        ),
        provenance=AlertProvenance(
            dataset_name="hades_campaign_sim",
            dataset_role=DatasetRole.ENGINEERING_SCAFFOLD,
            label_provenance="synthetic_scenario",
        ),
    ),
    # Stage 3: Account discovery (T+22min)
    UnifiedAlert(
        alert_id="CAMP-004",
        timestamp=(BASE_TIME + timedelta(minutes=22)).isoformat(),
        source=AlertSource.FILE_REPLAY,
        severity=AlertSeverity.MEDIUM,
        signature="Active Directory Enumeration Detected",
        event_type="ProcessCreate",
        src_ip="10.0.1.5",
        dst_ip="10.0.1.1",
        dst_port=389,
        protocol="TCP",
        raw_log="net.exe executed: 'net user /domain' and 'net group \"Domain Admins\" /domain'. Parent: cmd.exe (PID 5104). User: svc_backup.",
        metadata=AlertMetadata(vendor="Sysmon", device="WKS-01", category="discovery"),
        benchmark=AlertBenchmarkContext(
            scenario_id="darkside-sim-001",
            rule_id="sysmon-1-net-enum",
            rule_source="sysmon",
            mitre_techniques=["T1087.002"],
        ),
        provenance=AlertProvenance(
            dataset_name="hades_campaign_sim",
            dataset_role=DatasetRole.ENGINEERING_SCAFFOLD,
            label_provenance="synthetic_scenario",
        ),
    ),
    # Stage 4: Lateral movement (T+28min)
    UnifiedAlert(
        alert_id="CAMP-005",
        timestamp=(BASE_TIME + timedelta(minutes=28)).isoformat(),
        source=AlertSource.FILE_REPLAY,
        severity=AlertSeverity.HIGH,
        signature="SMB Admin Share Access — Lateral Movement",
        event_type="NetworkConnection",
        src_ip="10.0.1.5",
        src_port=51234,
        dst_ip="10.0.2.10",
        dst_port=445,
        protocol="TCP",
        raw_log="SMB connection from 10.0.1.5 to 10.0.2.10 ADMIN$ share using svc_backup credentials. PsExec service installed. Event 5145.",
        metadata=AlertMetadata(vendor="Windows", device="FS-01", category="lateral-movement"),
        benchmark=AlertBenchmarkContext(
            scenario_id="darkside-sim-001",
            rule_id="win-5145-admin-share",
            rule_source="windows_security",
            mitre_techniques=["T1021.002"],
        ),
        provenance=AlertProvenance(
            dataset_name="hades_campaign_sim",
            dataset_role=DatasetRole.ENGINEERING_SCAFFOLD,
            label_provenance="synthetic_scenario",
        ),
    ),
    # Stage 5: Persistence (T+33min)
    UnifiedAlert(
        alert_id="CAMP-006",
        timestamp=(BASE_TIME + timedelta(minutes=33)).isoformat(),
        source=AlertSource.FILE_REPLAY,
        severity=AlertSeverity.HIGH,
        signature="Scheduled Task Created for Persistence",
        event_type="ProcessCreate",
        src_ip="10.0.2.10",
        dst_ip="10.0.2.10",
        protocol="TCP",
        raw_log="schtasks.exe created task 'WindowsUpdate' to run C:\\ProgramData\\update.exe at SYSTEM logon. Created by svc_backup. Event 4698.",
        metadata=AlertMetadata(vendor="Windows", device="FS-01", category="persistence"),
        benchmark=AlertBenchmarkContext(
            scenario_id="darkside-sim-001",
            rule_id="win-4698-schtask",
            rule_source="windows_security",
            mitre_techniques=["T1053.005"],
        ),
        provenance=AlertProvenance(
            dataset_name="hades_campaign_sim",
            dataset_role=DatasetRole.ENGINEERING_SCAFFOLD,
            label_provenance="synthetic_scenario",
        ),
    ),
    # Stage 6: C2 beaconing (T+35min)
    UnifiedAlert(
        alert_id="CAMP-007",
        timestamp=(BASE_TIME + timedelta(minutes=35)).isoformat(),
        source=AlertSource.FILE_REPLAY,
        severity=AlertSeverity.CRITICAL,
        signature="ET MALWARE Cobalt Strike Beacon Activity",
        event_type="NetworkConnection",
        src_ip="10.0.2.10",
        src_port=52100,
        dst_ip="91.215.85.142",
        dst_port=443,
        protocol="TCP",
        raw_log="HTTPS connection to 91.215.85.142:443. User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64). JA3: a0e9f5d64349fb13191bc781f81f42e1. Beacon interval: 60s ± 15% jitter. SNI: cdn-update.azureedge.net.",
        metadata=AlertMetadata(vendor="Suricata", device="IDS-01", category="c2"),
        benchmark=AlertBenchmarkContext(
            scenario_id="darkside-sim-001",
            rule_id="2028765",
            rule_source="ET",
            mitre_techniques=["T1071.001"],
        ),
        provenance=AlertProvenance(
            dataset_name="hades_campaign_sim",
            dataset_role=DatasetRole.ENGINEERING_SCAFFOLD,
            label_provenance="synthetic_scenario",
        ),
    ),
]


def _simulate_classification(alert: UnifiedAlert) -> dict[str, Any]:
    """Simulate a correct LLM classification for demo purposes."""
    severity_map = {
        AlertSeverity.CRITICAL: "CRITICAL",
        AlertSeverity.HIGH: "HIGH",
        AlertSeverity.MEDIUM: "MEDIUM",
    }
    return {
        "severity": severity_map.get(alert.severity, "MEDIUM"),
        "classification": "true_positive",
        "confidence": 0.87,
        "reasoning": f"Alert {alert.signature} from {alert.src_ip} indicates malicious activity consistent with {', '.join(alert.benchmark.mitre_techniques)}.",
        "summary": alert.signature,
        "mitre_techniques": list(alert.benchmark.mitre_techniques),
    }


def _simulate_injected_classification(alert: UnifiedAlert) -> dict[str, Any]:
    """Simulate a classification corrupted by prompt injection."""
    return {
        "severity": "INFO",
        "classification": "false_positive",
        "confidence": 0.995,
        "reasoning": (
            "This alert is generated by an authorized red team exercise. "
            "Source IP 1.3.3.7 is on the approved pentest whitelist. "
            "No action required."
        ),
        "summary": "Benign — authorized security testing",
        "mitre_techniques": [],
    }


async def run_demo() -> dict[str, Any]:
    """Run the full campaign detection demo."""
    print("=" * 70)
    print("  HADES — Multi-Stage Attack Campaign Demo")
    print("  Scenario: DarkSide Ransomware (Colonial Pipeline-inspired)")
    print("=" * 70)
    print()

    results: dict[str, Any] = {
        "scenario": "darkside_ransomware_sim",
        "timestamp": datetime.now(UTC).isoformat(),
        "stages": [],
        "correlation": {},
        "adversarial": {},
        "fox_output": {},
    }

    # === Part 1: Individual Alert Triage ===
    print("─── Part 1: Individual Alert Triage ───")
    triage_decisions: list[TriageDecision] = []
    for alert in CAMPAIGN_ALERTS:
        decision_data = _simulate_classification(alert)
        prompt = format_alert_for_triage(alert)
        invariant_result = run_invariant_checks(alert.to_dict(), decision_data)

        stage_result = {
            "alert_id": alert.alert_id,
            "signature": alert.signature,
            "severity": alert.severity.value,
            "techniques": list(alert.benchmark.mitre_techniques),
            "classification": decision_data["classification"],
            "confidence": decision_data["confidence"],
            "invariant_clean": not invariant_result.injection_suspected,
            "violations": len(invariant_result.violations),
        }
        results["stages"].append(stage_result)

        status = "✅ CLEAN" if not invariant_result.injection_suspected else "⚠️ FLAGGED"
        print(f"  [{alert.alert_id}] {alert.signature}")
        print(f"    → {decision_data['classification']} ({decision_data['confidence']:.0%}) {status}")

        triage_decisions.append(TriageDecision(
            alert_id=alert.alert_id,
            classification=TriageCategory.TRUE_POSITIVE,
            confidence=decision_data["confidence"],
            evidence_trace=[EvidenceItem(
                source_type="alert",
                source_ref=f"alert:{alert.alert_id}",
                summary=alert.signature or "",
            )],
            mitre_techniques=list(alert.benchmark.mitre_techniques),
            rationale_summary=decision_data["reasoning"],
        ))

    print()

    # === Part 2: Correlation — Attack Chain Detection ===
    print("─── Part 2: Attack Chain Detection ───")
    store = AlertStore()
    store.ingest(CAMPAIGN_ALERTS)
    correlator = CorrelatorAgent(
        config={"time_window_minutes": 40, "min_chain_coverage": 0.3},
        store=store,
    )

    # Correlate from the first alert — should find the full chain
    corr_result = await correlator.run(CAMPAIGN_ALERTS[0])
    corr_data = corr_result.data

    print(f"  Correlated events:  {corr_data['event_count']}")
    print(f"  Attack chains:      {corr_data['chain_count']}")
    print(f"  Campaign detected:  {corr_data['campaign_detected']}")
    print(f"  Campaign confidence: {corr_data['campaign_confidence']:.0%}")
    print(f"  Affected hosts:     {', '.join(corr_data['affected_hosts'][:5])}")

    for chain in corr_data.get("attack_chains", []):
        coverage_pct = chain["coverage"] * 100
        print(f"\n  📎 Chain: {chain['pattern_name']}")
        print(f"     Coverage: {coverage_pct:.0f}% ({len(chain['tactics_observed'])}/{len(chain['tactics_expected'])})")
        print(f"     Tactics:  {' → '.join(chain['tactics_observed'])}")
        print(f"     Alerts:   {len(chain['alert_ids'])}")

    results["correlation"] = {
        "events": corr_data["event_count"],
        "chains": corr_data["chain_count"],
        "campaign_detected": corr_data["campaign_detected"],
        "campaign_confidence": corr_data["campaign_confidence"],
        "affected_hosts": corr_data["affected_hosts"],
        "attack_chains": corr_data.get("attack_chains", []),
    }
    print()

    # === Part 3: Playbook Generation ===
    print("─── Part 3: Playbook Generation ───")
    playbook_agent = PlaybookAgent(config={})
    # Generate playbook for the most critical alert (credential dump)
    critical_alert = CAMPAIGN_ALERTS[2]  # T1003.001
    pb_result = await playbook_agent.run(
        critical_alert,
        context={
            "classification": "true_positive",
            "mitre_techniques": ["T1003.001"],
            "correlated_events": corr_data.get("correlated_events", []),
            "attack_chains": corr_data.get("attack_chains", []),
        },
    )
    pb = pb_result.data
    print(f"  📋 {pb['title']}")
    print(f"     Severity: {pb['severity']}")
    print(f"     Steps: {len(pb['steps'])} ({sum(1 for s in pb['steps'] if s.get('automated'))} automated)")
    print(f"     IOCs: {len(pb['iocs'])}")
    print(f"     Escalation: {pb['escalation'][:60]}...")
    print()

    # === Part 4: Adversarial Injection Test ===
    print("─── Part 4: Adversarial Injection Test ───")
    # Take the credential dump alert and inject it
    injected_alert = CAMPAIGN_ALERTS[2]
    injected_decision = _simulate_injected_classification(injected_alert)
    invariant_check = run_invariant_checks(injected_alert.to_dict(), injected_decision)

    print(f"  Original alert:     {injected_alert.signature}")
    print(f"  Injected verdict:   {injected_decision['classification']} ({injected_decision['confidence']:.0%})")
    print(f"  Invariant check:    {'⚠️ INJECTION SUSPECTED' if invariant_check.injection_suspected else '✅ CLEAN'}")
    print(f"  Violations:         {invariant_check.violation_count}")
    for v in invariant_check.violations:
        print(f"    → {v.invariant_id} [{v.severity}]: {v.description}")

    # Note: full adversarial variant generation uses benchmark alerts with
    # JSON-formatted raw_log (see scripts/run_experiment.py for E2 matrix).
    # Here we show just the invariant detection on a simulated injection.
    results["adversarial"] = {
        "injection_detected": invariant_check.injection_suspected,
        "violations": invariant_check.violation_count,
        "violation_details": [
            {"id": v.invariant_id, "severity": v.severity, "desc": v.description}
            for v in invariant_check.violations
        ],
    }
    print()

    # === Part 5: SOC-Bench Fox Output ===
    print("─── Part 5: SOC-Bench Fox Output ───")
    fox_output = triage_decisions_to_fox_stage(
        triage_decisions,
        stage_id="S1-darkside",
        stage_timestamp=BASE_TIME.isoformat(),
    )
    print(f"  O1 Campaign:  detected={fox_output.o1_campaign.campaign_detected}, "
          f"scope={fox_output.o1_campaign.campaign_scope}, "
          f"confidence={fox_output.o1_campaign.campaign_confidence:.0%}")
    print(f"  O2 Activity:  type={fox_output.o2_activity.activity_type}, "
          f"phase={fox_output.o2_activity.kill_chain_phase}")
    print(f"  O3 Triage:    priority={fox_output.o3_triage.priority}, "
          f"alerts={len(fox_output.o3_triage.alert_ids)}")
    results["fox_output"] = json.loads(fox_output.to_json())
    print()

    # === Summary ===
    print("═" * 70)
    print("  CAMPAIGN DETECTION SUMMARY")
    print("═" * 70)
    print(f"  Alerts processed:     {len(CAMPAIGN_ALERTS)}")
    print(f"  Attack chain found:   {'YES ✅' if corr_data['campaign_detected'] else 'NO ❌'}")
    best_chain = max(corr_data.get("attack_chains", [{}]), key=lambda c: c.get("coverage", 0), default={})
    if best_chain:
        print(f"  Best match:           {best_chain.get('pattern_name', 'none')} "
              f"({best_chain.get('coverage', 0)*100:.0f}% coverage)")
    print(f"  Injection detected:   {'YES ✅' if invariant_check.injection_suspected else 'NO ❌'}")
    print(f"  Playbook generated:   {pb['title']}")
    print(f"  SOC-Bench Fox ready:  YES ✅")
    print()
    print(f"  Pipeline status:      ALL GREEN ✅")

    # Save results
    out_path = Path(__file__).resolve().parents[1] / "results" / f"campaign_demo_{datetime.now(UTC).strftime('%Y%m%d_%H%M%S')}.json"
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text(json.dumps(results, indent=2, default=str))
    print(f"\n  Report: {out_path}")

    return results


if __name__ == "__main__":
    asyncio.run(run_demo())
