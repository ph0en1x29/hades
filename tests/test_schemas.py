"""Tests for ingestion and evaluation schemas."""

import json

from src.ingestion.schema import AlertSeverity, AlertSource, UnifiedAlert
from src.evaluation.schemas import EvalResult, TriageCategory, TriageDecision, ReasoningStep


class TestUnifiedAlert:
    def test_create_default(self):
        alert = UnifiedAlert()
        assert alert.source == AlertSource.FILE
        assert alert.severity == AlertSeverity.MEDIUM
        assert alert.alert_id  # UUID generated

    def test_roundtrip_json(self):
        alert = UnifiedAlert(
            signature="ET SCAN Nmap SYN Scan",
            src_ip="192.168.1.100",
            dst_ip="10.0.0.1",
            dst_port=22,
            severity=AlertSeverity.HIGH,
        )
        json_str = alert.to_json()
        restored = UnifiedAlert.from_json(json_str)
        assert restored.signature == alert.signature
        assert restored.src_ip == alert.src_ip
        assert restored.severity == AlertSeverity.HIGH

    def test_to_dict_serializes_enums(self):
        alert = UnifiedAlert(source=AlertSource.SPLUNK)
        d = alert.to_dict()
        assert d["source"] == "splunk"
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
        result = EvalResult(config_id="A", confidence=0.95)
        d = result.to_dict()
        restored = EvalResult.from_dict(d)
        assert restored.config_id == "A"
        assert restored.confidence == 0.95


class TestTriageDecision:
    def test_reasoning_chain(self):
        decision = TriageDecision(
            classification=TriageCategory.TRUE_POSITIVE,
            confidence=0.92,
            reasoning_chain=[
                ReasoningStep(step=1, agent="classifier", action="classify", result="TP (0.85)"),
                ReasoningStep(step=2, agent="correlator", action="correlate", result="3 events"),
            ],
            mitre_techniques=["T1021.001"],
        )
        d = decision.to_dict()
        assert d["classification"] == "true_positive"
        assert len(d["reasoning_chain"]) == 2
        assert d["mitre_techniques"] == ["T1021.001"]
