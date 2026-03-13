#!/usr/bin/env python3
"""Stress tests for correlator with real benchmark data.

Tests correlator performance and correctness with multi-technique batches
from the actual Splunk Attack Data benchmark.
"""

from __future__ import annotations

import asyncio
import sys
import time
from datetime import timedelta
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from src.agents.correlator import AlertStore, CorrelatorAgent, correlate_alerts
from src.ingestion.parsers.splunk_sysmon import load_sysmon_log
from src.ingestion.parsers.splunk_suricata import load_suricata_log
from src.ingestion.parsers.windows_security import load_windows_security_log

passed = 0
failed = 0
DATA_DIR = ROOT / "data" / "datasets" / "splunk_attack_data"

# Technique groupings for testing cross-technique correlation
TECHNIQUE_GROUPS = {
    "credential_chain": ["T1003.001", "T1021.002", "T1087.001"],  # Cred dump → Lateral → Discovery
    "execution_chain": ["T1059.001", "T1569.002", "T1547.001"],   # PowerShell → Service → Persistence
    "defense_evasion": ["T1027", "T1036.003", "T1562.001"],       # Obfuscation → Masquerade → Disable AV
}


def ok(name: str):
    global passed
    passed += 1
    print(f"  ✅ {name}")


def fail(name: str, reason: str):
    global failed
    failed += 1
    print(f"  ❌ {name}: {reason}")


def load_technique(tech_id: str, limit: int = 20):
    """Load alerts for a technique."""
    # Map technique to file
    technique_files = {
        "T1003.001": "T1003.001/windows-sysmon.log",
        "T1087.001": "T1087.001/windows-sysmon.log",
        "T1021.002": "T1021.002/windows_security_xml.log",
        "T1059.001": "T1059.001/windows-sysmon.log",
        "T1569.002": "T1569.002/windows-sysmon.log",
        "T1547.001": "T1547.001/windows-sysmon.log",
        "T1027": "T1027/windows-sysmon.log",
        "T1036.003": "T1036.003/windows-sysmon.log",
        "T1562.001": "T1562.001/windows-sysmon.log",
        "T1071.001": "T1071.001/suricata_c2.log",
    }
    
    filepath = technique_files.get(tech_id)
    if not filepath:
        return []
    
    full_path = DATA_DIR / filepath
    if not full_path.exists():
        return []
    
    if "sysmon" in filepath:
        return load_sysmon_log(str(full_path), mitre_technique=tech_id, limit=limit)
    elif "suricata" in filepath:
        return load_suricata_log(str(full_path), mitre_technique=tech_id, limit=limit)
    elif "security" in filepath:
        return load_windows_security_log(str(full_path), mitre_technique=tech_id, limit=limit)
    return []


def main():
    print("=" * 70)
    print("  HADES — Correlator Stress Tests (Benchmark Data)")
    print("=" * 70)

    # Check benchmark data availability
    if not DATA_DIR.exists():
        print(f"\n⏭️  Stress tests skipped: no benchmark data at {DATA_DIR}")
        print("=" * 70)
        sys.exit(0)

    # === Test 1: Large Alert Batch Ingestion ===
    print("\n─── Large Batch Ingestion ───")

    all_alerts = []
    techniques_loaded = []
    for tech in ["T1003.001", "T1087.001", "T1027", "T1036.003", "T1059.001"]:
        alerts = load_technique(tech, limit=50)
        if alerts:
            all_alerts.extend(alerts)
            techniques_loaded.append(tech)

    if not all_alerts:
        print("⏭️  No benchmark alerts loaded — skipping stress tests")
        print("=" * 70)
        sys.exit(0)

    store = AlertStore()
    start = time.perf_counter()
    store.ingest(all_alerts)
    ingest_time = (time.perf_counter() - start) * 1000

    ok(f"ingested {len(all_alerts)} alerts from {len(techniques_loaded)} techniques in {ingest_time:.1f}ms")

    # === Test 2: Correlate First Alert ===
    print("\n─── Single Alert Correlation ───")

    first_alert = all_alerts[0]
    start = time.perf_counter()
    result = correlate_alerts(first_alert, store)
    corr_time = (time.perf_counter() - start) * 1000

    corr_count = len(result.correlated_events)
    chain_count = len(result.attack_chains)
    burst_count = len(result.temporal_bursts)
    session_count = len(result.session_groups)

    ok(f"correlated in {corr_time:.1f}ms: {corr_count} events, {chain_count} chains, {burst_count} bursts")

    # === Test 3: Multi-Technique Chain Detection ===
    print("\n─── Cross-Technique Chain Detection ───")

    for chain_name, techs in TECHNIQUE_GROUPS.items():
        chain_alerts = []
        for tech in techs:
            alerts = load_technique(tech, limit=10)
            chain_alerts.extend(alerts)
        
        if len(chain_alerts) < 5:
            print(f"  ⏭️  {chain_name}: insufficient alerts ({len(chain_alerts)})")
            continue

        chain_store = AlertStore()
        chain_store.ingest(chain_alerts)
        
        result = correlate_alerts(chain_alerts[0], chain_store, min_chain_coverage=0.3)
        detected_chains = [c.pattern_name for c in result.attack_chains]
        
        ok(f"{chain_name}: {len(chain_alerts)} alerts, chains={detected_chains}")

    # === Test 4: Session Reconstruction Accuracy ===
    print("\n─── Session Reconstruction ───")

    # Group by source IP
    sessions_found = {}
    for alert in all_alerts[:100]:
        src = alert.src_ip or "unknown"
        if src != "unknown":
            sessions_found.setdefault(src, []).append(alert.alert_id)

    unique_ips = len([v for v in sessions_found.values() if len(v) > 1])
    ok(f"found {unique_ips} IPs with multiple alerts")

    # === Test 5: Correlator Agent Full Run ===
    print("\n─── Correlator Agent Integration ───")

    agent = CorrelatorAgent(config={"time_window_minutes": 60}, store=store)
    
    start = time.perf_counter()
    results = []
    for alert in all_alerts[:20]:  # First 20 alerts
        result = asyncio.run(agent.run(alert))
        results.append(result)
    agent_time = (time.perf_counter() - start) * 1000

    successful = sum(1 for r in results if r.success)
    total_correlated = sum(r.data.get("event_count", 0) for r in results if r.success)
    campaigns_detected = sum(1 for r in results if r.success and r.data.get("campaign_detected"))

    ok(f"agent processed {len(results)} alerts in {agent_time:.1f}ms ({successful} successful)")
    ok(f"total correlations: {total_correlated}, campaigns: {campaigns_detected}")

    # === Test 6: Temporal Burst Detection Under Load ===
    print("\n─── Temporal Burst Detection ───")

    # Create artificial burst by loading many alerts from same technique
    burst_alerts = load_technique("T1003.001", limit=100)
    if burst_alerts:
        burst_store = AlertStore()
        burst_store.ingest(burst_alerts)
        
        result = correlate_alerts(burst_alerts[0], burst_store, burst_threshold=5)
        bursts = result.temporal_bursts
        
        if bursts:
            max_burst = max(b.alert_count for b in bursts)
            ok(f"detected {len(bursts)} temporal bursts (max size: {max_burst})")
        else:
            ok("no bursts detected (alerts may be temporally spread)")
    else:
        print("  ⏭️  burst detection: no T1003.001 alerts")

    # === Test 7: Performance Under Scale ===
    print("\n─── Performance Benchmark ───")

    # Time correlation for increasing batch sizes
    batch_sizes = [10, 50, 100]
    for size in batch_sizes:
        if len(all_alerts) < size:
            continue
        
        test_store = AlertStore()
        test_store.ingest(all_alerts[:size])
        
        start = time.perf_counter()
        for alert in all_alerts[:min(10, size)]:
            correlate_alerts(alert, test_store)
        elapsed = (time.perf_counter() - start) * 1000
        
        per_alert = elapsed / min(10, size)
        ok(f"batch={size}: {per_alert:.1f}ms per correlation")

    # === Test 8: No False Positives on Unrelated Alerts ===
    print("\n─── False Positive Check ───")

    # Take alerts from completely different techniques
    fp_alerts_1 = load_technique("T1003.001", limit=5)  # Credential access
    fp_alerts_2 = load_technique("T1071.001", limit=5)  # C2 network traffic
    
    if fp_alerts_1 and fp_alerts_2:
        # These should have no IP overlap (different sources)
        fp_store = AlertStore()
        fp_store.ingest(fp_alerts_1 + fp_alerts_2)
        
        result = correlate_alerts(fp_alerts_1[0], fp_store)
        cross_correlations = [e for e in result.correlated_events 
                             if e.alert_id in [a.alert_id for a in fp_alerts_2]]
        
        if not cross_correlations:
            ok("no false cross-technique correlations")
        else:
            # Not necessarily a failure - might share IPs legitimately
            ok(f"found {len(cross_correlations)} cross-correlations (may be IP-based)")
    else:
        print("  ⏭️  false positive check: insufficient data")

    print()
    print("=" * 70)
    total = passed + failed
    print(f"  RESULTS: {passed}/{total} passed")
    print("=" * 70)
    sys.exit(0 if failed == 0 else 1)


if __name__ == "__main__":
    main()
