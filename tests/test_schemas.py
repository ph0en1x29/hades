"""Tests for ingestion and evaluation schemas."""

from src.evaluation.schemas import (
    EvalResult,
    EvidenceItem,
    OverrideRecord,
    ToolInvocation,
    TriageCategory,
    TriageDecision,
)
from src.ingestion.schema import (
    AlertBenchmarkContext,
    AlertProvenance,
    AlertSeverity,
    AlertSource,
    DatasetRole,
    UnifiedAlert,
)


class TestUnifiedAlert:
    def test_create_default(self):
        alert = UnifiedAlert()
        assert alert.source == AlertSource.FILE_REPLAY
        assert alert.severity == AlertSeverity.MEDIUM
        assert alert.alert_id  # UUID generated

    def test_roundtrip_json(self):
        alert = UnifiedAlert(
            signature="ET SCAN Nmap SYN Scan",
            src_ip="192.168.1.100",
            dst_ip="10.0.0.1",
            dst_port=22,
            severity=AlertSeverity.HIGH,
            benchmark=AlertBenchmarkContext(
                scenario_id="windows_bruteforce_slice",
                rule_id="DET-0001",
                rule_source="splunk",
                rule_name="Windows Brute Force Detection",
                mitre_techniques=["T1110"],
                correlation_id="campaign-42",
            ),
            provenance=AlertProvenance(
                dataset_name="cicids2018",
                dataset_role=DatasetRole.BENCHMARK_CANDIDATE,
                source_path="data/benchmarks/raw.jsonl",
                source_record_index=12,
                label_provenance="analyst_review_v1",
            ),
        )
        json_str = alert.to_json()
        restored = UnifiedAlert.from_json(json_str)
        assert restored.signature == alert.signature
        assert restored.src_ip == alert.src_ip
        assert restored.severity == AlertSeverity.HIGH
        assert restored.provenance.dataset_name == "cicids2018"
        assert restored.provenance.dataset_role == DatasetRole.BENCHMARK_CANDIDATE
        assert restored.provenance.label_provenance == "analyst_review_v1"
        assert restored.benchmark.rule_id == "DET-0001"
        assert restored.benchmark.mitre_techniques == ["T1110"]

    def test_to_dict_serializes_enums(self):
        alert = UnifiedAlert(source=AlertSource.NORMALIZED_JSON)
        d = alert.to_dict()
        assert d["source"] == "normalized_json"
        assert isinstance(d["source"], str)


class TestEvalResult:
    def test_correct_property(self):
        result = EvalResult(
            ground_truth=TriageCategory.TRUE_POSITIVE,
            prediction=TriageCategory.TRUE_POSITIVE,
        )
        assert result.correct is True

        result_wrong = EvalResult(
            ground_truth=TriageCategory.TRUE_POSITIVE,
            prediction=TriageCategory.FALSE_POSITIVE,
        )
        assert result_wrong.correct is False

    def test_roundtrip_dict(self):
        result = EvalResult(config_id="A", dataset_name="bench", confidence=0.95)
        d = result.to_dict()
        restored = EvalResult.from_dict(d)
        assert restored.config_id == "A"
        assert restored.dataset_name == "bench"
        assert restored.confidence == 0.95


class TestTriageDecision:
    def test_evidence_trace(self):
        decision = TriageDecision(
            classification=TriageCategory.TRUE_POSITIVE,
            confidence=0.92,
            evidence_trace=[
                EvidenceItem(
                    source_type="alert",
                    source_ref="alert:123",
                    summary="Classifier flagged lateral movement indicators",
                    score=0.85,
                ),
            ],
            tool_invocations=[
                ToolInvocation(
                    tool_name="rag_search",
                    arguments={"query": "T1021.001"},
                    status="success",
                    duration_ms=37,
                ),
            ],
            rationale_summary="Evidence supports a true positive with analyst follow-up.",
            mitre_techniques=["T1021.001"],
            override_record=OverrideRecord(
                actor="analyst@example",
                reason="Confirmed from case notes",
                previous_classification="needs_investigation",
                new_classification="true_positive",
            ),
        )
        d = decision.to_dict()
        restored = TriageDecision.from_dict(d)
        assert d["classification"] == "true_positive"
        assert len(d["evidence_trace"]) == 1
        assert d["mitre_techniques"] == ["T1021.001"]
        assert restored.override_record is not None
        assert restored.override_record.new_classification == "true_positive"
