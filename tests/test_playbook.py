"""Tests for the playbook generator agent."""

from __future__ import annotations

import asyncio
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from src.agents.playbook import PlaybookAgent, generate_playbook
from src.ingestion.schema import AlertBenchmarkContext, AlertSeverity, UnifiedAlert


def _alert(tech: str, severity: AlertSeverity = AlertSeverity.HIGH) -> UnifiedAlert:
    return UnifiedAlert(
        alert_id="PB-001",
        severity=severity,
        src_ip="10.0.1.5",
        dst_ip="10.0.2.10",
        signature=f"Test alert for {tech}",
        benchmark=AlertBenchmarkContext(mitre_techniques=[tech]),
        raw_log="Test raw log data",
    )


def test_credential_dump_playbook():
    pb = generate_playbook(
        _alert("T1003.001"),
        classification="true_positive",
        mitre_techniques=["T1003.001"],
    )
    assert pb["title"] == "Credential Dumping Response"
    assert pb["severity"] in ("critical", "high")
    assert len(pb["steps"]) > 5
    phases = {s["phase"] for s in pb["steps"]}
    assert "containment" in phases
    assert "eradication" in phases
    assert "recovery" in phases
    assert "post_incident" in phases


def test_c2_playbook():
    pb = generate_playbook(
        _alert("T1071.001", AlertSeverity.CRITICAL),
        classification="true_positive",
        mitre_techniques=["T1071.001"],
    )
    assert pb["title"] == "Application Layer C2 Protocol Response"
    assert any("C2" in s["action"] or "firewall" in s["action"].lower() for s in pb["steps"])


def test_unknown_technique_fallback():
    pb = generate_playbook(
        _alert("T9999"),
        classification="unknown",
        mitre_techniques=["T9999"],
    )
    assert pb["title"] == "Unknown Technique Response"
    assert len(pb["steps"]) >= 3


def test_severity_escalation_with_chains():
    pb = generate_playbook(
        _alert("T1087.002", AlertSeverity.MEDIUM),
        classification="true_positive",
        mitre_techniques=["T1087.002"],
        attack_chains=[{"pattern_name": "credential_theft", "coverage": 0.75}],
    )
    assert pb["severity"] == "critical", "Chain presence should escalate severity"
    assert any("chain" in s["action"].lower() for s in pb["steps"])


def test_ioc_extraction():
    pb = generate_playbook(
        _alert("T1110.001"),
        classification="true_positive",
        mitre_techniques=["T1110.001"],
    )
    assert len(pb["iocs"]) >= 2
    ip_iocs = [i for i in pb["iocs"] if i["type"] == "ip"]
    assert len(ip_iocs) >= 2


def test_playbook_agent():
    agent = PlaybookAgent(config={})
    alert = _alert("T1003.001")
    result = asyncio.run(
        agent.run(
            alert,
            context={
                "classification": "true_positive",
                "mitre_techniques": ["T1003.001"],
            },
        )
    )
    assert result.success
    assert result.data["title"] == "Credential Dumping Response"


if __name__ == "__main__":
    tests = [
        test_credential_dump_playbook,
        test_c2_playbook,
        test_unknown_technique_fallback,
        test_severity_escalation_with_chains,
        test_ioc_extraction,
        test_playbook_agent,
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
