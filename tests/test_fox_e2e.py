"""End-to-end test: pipeline → SOC-Bench Fox adapter → ring scorer."""

from __future__ import annotations

import asyncio
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from src.agents import ClassifierAgent
from src.agents.correlator import CorrelatorAgent
from src.agents.playbook import PlaybookAgent
from src.evaluation.fox_scorer import FoxGroundTruth, print_fox_score, score_fox_stage
from src.evaluation.socbench_adapter import triage_decisions_to_fox_stage
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


def _darkside_scenario() -> list[UnifiedAlert]:
    """7 synthetic alerts mimicking a DarkSide ransomware campaign."""
    base = dict(
        source=AlertSource.FILE_REPLAY,
        raw_log='{"EventID": "1"}',
        metadata=AlertMetadata(),
        provenance=AlertProvenance(
            dataset_name="darkside_synthetic",
            dataset_role=DatasetRole.ENGINEERING_SCAFFOLD,
            source_path="synthetic",
            parser_version="test",
            label_provenance="manual",
        ),
    )

    return [
        UnifiedAlert(
            alert_id="ds-001",
            timestamp="2026-03-12T14:00:00Z",
            severity=AlertSeverity.HIGH,
            signature="Phishing email with malicious attachment",
            event_type="email_alert",
            src_ip="203.0.113.50",
            dst_ip="10.10.1.15",
            benchmark=AlertBenchmarkContext(
                scenario_id="darkside",
                rule_id="r-001",
                rule_source="test",
                rule_name="Phishing",
                mitre_techniques=["T1566.001"],
            ),
            **base,
        ),
        UnifiedAlert(
            alert_id="ds-002",
            timestamp="2026-03-12T14:05:00Z",
            severity=AlertSeverity.HIGH,
            signature="PowerShell encoded command execution",
            event_type="process_create",
            src_ip="10.10.1.15",
            dst_ip="10.10.1.15",
            benchmark=AlertBenchmarkContext(
                scenario_id="darkside",
                rule_id="r-002",
                rule_source="test",
                rule_name="Execution",
                mitre_techniques=["T1059.001"],
            ),
            **base,
        ),
        UnifiedAlert(
            alert_id="ds-003",
            timestamp="2026-03-12T14:08:00Z",
            severity=AlertSeverity.CRITICAL,
            signature="LSASS memory access by non-system process",
            event_type="process_access",
            src_ip="10.10.1.15",
            dst_ip="10.10.1.20",
            benchmark=AlertBenchmarkContext(
                scenario_id="darkside",
                rule_id="r-003",
                rule_source="test",
                rule_name="Credential Dump",
                mitre_techniques=["T1003.001"],
            ),
            **base,
        ),
        UnifiedAlert(
            alert_id="ds-004",
            timestamp="2026-03-12T14:12:00Z",
            severity=AlertSeverity.HIGH,
            signature="SMB admin share connection from workstation",
            event_type="network_connection",
            src_ip="10.10.1.15",
            dst_ip="10.10.1.20",
            benchmark=AlertBenchmarkContext(
                scenario_id="darkside",
                rule_id="r-004",
                rule_source="test",
                rule_name="Lateral Movement",
                mitre_techniques=["T1021.002"],
            ),
            **base,
        ),
        UnifiedAlert(
            alert_id="ds-005",
            timestamp="2026-03-12T14:15:00Z",
            severity=AlertSeverity.MEDIUM,
            signature="Account enumeration detected",
            event_type="process_create",
            src_ip="10.10.1.20",
            dst_ip="10.10.1.20",
            benchmark=AlertBenchmarkContext(
                scenario_id="darkside",
                rule_id="r-005",
                rule_source="test",
                rule_name="Discovery",
                mitre_techniques=["T1087.001"],
            ),
            **base,
        ),
        UnifiedAlert(
            alert_id="ds-006",
            timestamp="2026-03-12T14:20:00Z",
            severity=AlertSeverity.CRITICAL,
            signature="Scheduled task created for persistence",
            event_type="task_create",
            src_ip="10.10.1.20",
            dst_ip="10.10.1.20",
            benchmark=AlertBenchmarkContext(
                scenario_id="darkside",
                rule_id="r-006",
                rule_source="test",
                rule_name="Persistence",
                mitre_techniques=["T1053.005"],
            ),
            **base,
        ),
        UnifiedAlert(
            alert_id="ds-007",
            timestamp="2026-03-12T14:25:00Z",
            severity=AlertSeverity.CRITICAL,
            signature="Ransomware file encryption detected",
            event_type="file_modify",
            src_ip="10.10.1.20",
            dst_ip="10.10.1.20",
            benchmark=AlertBenchmarkContext(
                scenario_id="darkside",
                rule_id="r-007",
                rule_source="test",
                rule_name="Impact",
                mitre_techniques=["T1486"],
            ),
            **base,
        ),
    ]


def _ground_truth() -> FoxGroundTruth:
    return FoxGroundTruth(
        stage_id="darkside-stage-1",
        campaign_present=True,
        campaign_scope="targeted",
        affected_hosts=["10.10.1.15", "10.10.1.20", "203.0.113.50"],
        primary_activity="lateral_movement",
        mitre_techniques=[
            "T1566.001",
            "T1059.001",
            "T1003.001",
            "T1021.002",
            "T1087.001",
            "T1053.005",
            "T1486",
        ],
        kill_chain_phase="exploitation",
        true_positive_alert_ids=[
            "ds-001",
            "ds-002",
            "ds-003",
            "ds-004",
            "ds-005",
            "ds-006",
            "ds-007",
        ],
        false_positive_alert_ids=[],
        expected_priority="critical",
    )


def test_fox_e2e_pipeline() -> None:
    """Run full pipeline → Fox adapter → scorer on DarkSide scenario."""
    alerts = _darkside_scenario()
    gt = _ground_truth()

    # Build full pipeline
    classifier = ClassifierAgent({})
    correlator = CorrelatorAgent({"time_window_minutes": 60})
    playbook = PlaybookAgent({})
    pipeline = TriagePipeline(classifier, correlator=correlator, playbook=playbook)

    with tempfile.NamedTemporaryFile(suffix=".jsonl", delete=False) as f:
        output = Path(f.name)

    result = asyncio.run(pipeline.run(alerts, output))
    assert len(result.decisions) == 7

    # Convert to Fox format
    fox_output = triage_decisions_to_fox_stage(
        result.decisions, stage_id="darkside-stage-1", alerts=alerts
    )
    assert fox_output.stage_id == "darkside-stage-1"

    # Score against ground truth
    score = score_fox_stage(fox_output, gt)
    report = print_fox_score(score)
    print(report)

    # Assertions
    assert score.total_final >= 0, "Score should be non-negative"
    assert score.total_final <= 100, "Score should not exceed 100"
    assert score.o1_score.final_points >= 0
    assert score.o2_score.final_points >= 0
    assert score.o3_score.final_points >= 0

    # The mock classifier won't get perfect scores but should score
    # something via the correlator's campaign detection
    print(f"\nTotal: {score.total_final}/100")

    output.unlink(missing_ok=True)


if __name__ == "__main__":
    test_fox_e2e_pipeline()
    print("\n✅ test_fox_e2e_pipeline passed")
