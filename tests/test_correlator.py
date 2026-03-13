"""Tests for the correlator agent and attack chain detection."""

from __future__ import annotations

import asyncio
import sys
from datetime import timedelta
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from src.agents.correlator import AlertStore, CorrelatorAgent, correlate_alerts
from src.ingestion.schema import (
    AlertBenchmarkContext,
    AlertSeverity,
    UnifiedAlert,
)

BASE = "2026-03-12T14:00:00"


def _alert(aid: str, src: str, dst: str, tech: str, minutes: int = 0) -> UnifiedAlert:
    from datetime import datetime

    ts = datetime.fromisoformat(BASE) + timedelta(minutes=minutes)
    return UnifiedAlert(
        alert_id=aid,
        timestamp=ts.isoformat(),
        severity=AlertSeverity.HIGH,
        src_ip=src,
        dst_ip=dst,
        benchmark=AlertBenchmarkContext(mitre_techniques=[tech]),
    )


def test_ip_clustering():
    store = AlertStore()
    a1 = _alert("A1", "10.0.1.5", "10.0.2.10", "T1003.001", 0)
    a2 = _alert("A2", "10.0.1.5", "10.0.2.10", "T1021.002", 5)
    a3 = _alert("A3", "192.168.1.1", "172.16.0.1", "T1110", 3)
    store.ingest([a1, a2, a3])
    result = correlate_alerts(a1, store)
    corr_ids = {e.alert_id for e in result.correlated_events}
    assert "A2" in corr_ids, "Same IP pair should correlate"
    assert "A3" not in corr_ids, "Different IPs should not correlate"


def test_attack_chain_detection():
    store = AlertStore()
    alerts = [
        _alert("C1", "10.0.1.5", "10.0.1.1", "T1078", 0),  # Initial Access
        _alert("C2", "10.0.1.5", "10.0.1.5", "T1003.001", 10),  # Credential Access
        _alert("C3", "10.0.1.5", "10.0.2.10", "T1021.002", 20),  # Lateral Movement
        _alert("C4", "10.0.1.5", "10.0.1.1", "T1087.002", 25),  # Discovery
    ]
    store.ingest(alerts)
    result = correlate_alerts(alerts[0], store, min_chain_coverage=0.3)
    chain_names = {c.pattern_name for c in result.attack_chains}
    assert "credential_theft" in chain_names, f"Should detect credential_theft, got {chain_names}"
    assert result.campaign_detected, "Campaign should be detected"


def test_session_reconstruction():
    store = AlertStore()
    a1 = _alert("S1", "10.0.1.5", "10.0.2.10", "T1021.002", 0)
    a2 = _alert("S2", "10.0.1.5", "10.0.2.10", "T1059.001", 2)
    store.ingest([a1, a2])
    result = correlate_alerts(a1, store)
    assert "10.0.1.5->10.0.2.10" in result.session_groups


def test_temporal_burst():
    store = AlertStore()
    alerts = [_alert(f"B{i}", "10.0.1.5", "10.0.2.10", "T1110.001", i) for i in range(8)]
    store.ingest(alerts)
    result = correlate_alerts(alerts[0], store, burst_threshold=5)
    assert len(result.temporal_bursts) > 0, "Should detect temporal burst"
    assert result.temporal_bursts[0].alert_count >= 5


def test_correlator_agent():
    store = AlertStore()
    alerts = [
        _alert("AG1", "10.0.1.5", "10.0.1.1", "T1078", 0),
        _alert("AG2", "10.0.1.5", "10.0.1.5", "T1003.001", 5),
    ]
    store.ingest(alerts)
    agent = CorrelatorAgent(config={"time_window_minutes": 15}, store=store)
    result = asyncio.run(agent.run(alerts[0]))
    assert result.success
    assert result.data["event_count"] >= 1


def test_no_false_correlations():
    store = AlertStore()
    a1 = _alert("N1", "10.0.1.5", "10.0.2.10", "T1003.001", 0)
    a2 = _alert("N2", "192.168.1.1", "172.16.0.1", "T1110", 100)  # Different IPs, far apart
    store.ingest([a1, a2])
    result = correlate_alerts(a1, store, window_minutes=15)
    corr_ids = {e.alert_id for e in result.correlated_events}
    assert "N2" not in corr_ids, "Unrelated alerts should not correlate"


if __name__ == "__main__":
    tests = [
        test_ip_clustering,
        test_attack_chain_detection,
        test_session_reconstruction,
        test_temporal_burst,
        test_correlator_agent,
        test_no_false_correlations,
    ]
    passed = 0
    for t in tests:
        try:
            t()
            print(f"  ✅ {t.__name__}")
            passed += 1
        except Exception as e:
            print(f"  ❌ {t.__name__}: {e}")
    print(f"\n{passed}/{len(tests)} passed")
