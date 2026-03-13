"""Integration test: full multi-agent pipeline with correlator + playbook."""

from __future__ import annotations

import asyncio
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from src.agents import ClassifierAgent
from src.agents.correlator import CorrelatorAgent
from src.agents.playbook import PlaybookAgent
from src.ingestion.schema import (
    AlertBenchmarkContext,
    AlertMetadata,
    AlertProvenance,
    AlertSeverity,
    AlertSource,
    DatasetRole,
    UnifiedAlert,
)
from src.pipeline import TriagePipeline


def _make_alert(
    alert_id: str,
    src_ip: str = "10.0.0.5",
    dst_ip: str = "10.0.0.100",
    technique: str = "T1003.001",
    severity: AlertSeverity = AlertSeverity.HIGH,
) -> UnifiedAlert:
    return UnifiedAlert(
        alert_id=alert_id,
        timestamp="2026-03-12T14:00:00Z",
        source=AlertSource.FILE_REPLAY,
        severity=severity,
        signature=f"Test alert {alert_id}",
        event_type="process_access",
        src_ip=src_ip,
        dst_ip=dst_ip,
        raw_log='{"EventID": "10", "SourceImage": "mimikatz.exe"}',
        metadata=AlertMetadata(),
        benchmark=AlertBenchmarkContext(
            scenario_id="test-full-pipeline",
            rule_id="rule-test-001",
            rule_source="test",
            rule_name="Test Rule",
            mitre_techniques=[technique],
        ),
        provenance=AlertProvenance(
            dataset_name="test",
            dataset_role=DatasetRole.ENGINEERING_SCAFFOLD,
            source_path="test",
            parser_version="test",
            label_provenance="test",
        ),
    )


def test_full_pipeline_with_all_agents() -> None:
    """Pipeline runs with classifier + correlator + playbook."""
    alerts = [
        _make_alert("fp-001", technique="T1003.001"),  # credential access
        _make_alert("fp-002", technique="T1087.001"),  # discovery
        _make_alert("fp-003", technique="T1021.002"),  # lateral movement
    ]

    classifier = ClassifierAgent({})
    correlator = CorrelatorAgent({"time_window_minutes": 60})
    playbook = PlaybookAgent({})

    pipeline = TriagePipeline(classifier, correlator=correlator, playbook=playbook)

    import tempfile

    with tempfile.NamedTemporaryFile(suffix=".jsonl", delete=False) as f:
        output = Path(f.name)

    result = asyncio.run(pipeline.run(alerts, output))

    assert result.total_alerts == 3
    assert len(result.decisions) == 3
    assert result.wall_clock_ms >= 0

    # Every decision should have correlator + playbook tool invocations
    for decision in result.decisions:
        tool_names = [t.tool_name for t in decision.tool_invocations]
        assert "classifier" in tool_names
        assert "behavioral_invariants" in tool_names
        assert "correlator" in tool_names
        assert "playbook_generator" in tool_names

    # At least some decisions should have correlated events
    total_correlated = sum(len(d.correlated_events) for d in result.decisions)
    assert total_correlated > 0, "Correlator should find cross-alert relationships"

    output.unlink(missing_ok=True)


def test_pipeline_without_optional_agents() -> None:
    """Pipeline works with classifier only (backward compat)."""
    alerts = [_make_alert("fp-solo")]
    classifier = ClassifierAgent({})
    pipeline = TriagePipeline(classifier)

    import tempfile

    with tempfile.NamedTemporaryFile(suffix=".jsonl", delete=False) as f:
        output = Path(f.name)

    result = asyncio.run(pipeline.run(alerts, output))

    assert result.total_alerts == 1
    assert len(result.decisions) == 1

    tool_names = [t.tool_name for t in result.decisions[0].tool_invocations]
    assert "classifier" in tool_names
    assert "behavioral_invariants" in tool_names
    assert "correlator" not in tool_names
    assert "playbook_generator" not in tool_names

    output.unlink(missing_ok=True)


if __name__ == "__main__":
    test_full_pipeline_with_all_agents()
    print("✅ test_full_pipeline_with_all_agents")
    test_pipeline_without_optional_agents()
    print("✅ test_pipeline_without_optional_agents")
    print("All full pipeline tests passed.")
