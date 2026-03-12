"""Tests for dataset-gate contract and config validation."""

from __future__ import annotations

from pathlib import Path

from src.evaluation.dataset_gate import (
    benchmark_contract_issues,
    validate_benchmark_config,
    validate_loaded_alerts,
)
from src.ingestion.parsers.cicids2018 import parse_cicids2018_row
from src.ingestion.schema import (
    AlertBenchmarkContext,
    AlertMetadata,
    AlertProvenance,
    DatasetRole,
    UnifiedAlert,
)


class TestBenchmarkContract:
    def test_benchmark_ready_alert_has_no_contract_issues(self) -> None:
        alert = UnifiedAlert(
            signature="Windows brute force detected",
            metadata=AlertMetadata(message="Repeated failed logins detected by rule"),
            benchmark=AlertBenchmarkContext(
                scenario_id="windows_bruteforce_slice",
                rule_id="DET-0001",
                rule_source="splunk_security_content",
                rule_name="Windows Brute Force Detection",
                mitre_techniques=["T1110"],
                correlation_id="campaign-1",
            ),
            provenance=AlertProvenance(
                dataset_name="splunk_attack_data",
                dataset_role=DatasetRole.BENCHMARK_OF_RECORD,
                source_path="data/benchmarks/public/windows_bruteforce.jsonl",
                label_provenance="splunk_detection_label_v1",
            ),
        )

        assert benchmark_contract_issues(alert) == []

    def test_cicids_scaffold_fails_benchmark_contract(self) -> None:
        alert = parse_cicids2018_row(
            {
                "Src IP": "10.0.0.15",
                "Dst IP": "172.16.0.10",
                "Dst Port": "443",
                "Protocol": "6",
                "Label": "Brute Force",
            },
            source_path="data/datasets/sample.csv",
            source_record_index=3,
        )

        issues = benchmark_contract_issues(alert)

        assert "engineering scaffold sources cannot serve as benchmark-of-record" in issues
        assert "missing detection rule association" in issues
        assert "missing MITRE mapping" in issues


class TestBenchmarkConfigValidation:
    def test_config_rejects_engineering_scaffold_as_benchmark(self) -> None:
        config = {
            "dataset_preparation": {
                "raw_sources": [
                    {
                        "name": "cicids2018",
                        "dataset_role": "engineering_scaffold",
                        "benchmark_eligible": False,
                    },
                ],
                "benchmark_of_record": {
                    "source": "cicids2018",
                    "manifest": "",
                    "rule_pack_source": "sigma_rules",
                    "label_provenance_policy": "dataset_flow_label",
                },
            },
        }

        try:
            validate_benchmark_config(config)
        except ValueError as exc:
            assert "engineering_scaffold" in str(exc)
        else:
            raise AssertionError("engineering scaffold benchmark should be rejected")

    def test_config_accepts_public_benchmark_of_record(self) -> None:
        repo_root = Path(__file__).resolve().parent.parent

        config = {
            "dataset_preparation": {
                "raw_sources": [
                    {
                        "name": "splunk_attack_data",
                        "dataset_role": "benchmark_of_record",
                        "benchmark_eligible": True,
                    },
                ],
                "benchmark_of_record": {
                    "source": "splunk_attack_data",
                    "manifest": "data/manifests/public_benchmark_of_record.yaml",
                    "rule_pack_source": "splunk_security_content",
                    "label_provenance_policy": "splunk_detection_label_v1",
                },
            },
        }

        validate_benchmark_config(config, base_dir=repo_root)


class TestLoadedAlertValidation:
    def test_runtime_rejects_invalid_benchmark_candidate(self) -> None:
        alert = UnifiedAlert(
            provenance=AlertProvenance(
                dataset_name="splunk_attack_data",
                dataset_role=DatasetRole.BENCHMARK_CANDIDATE,
            ),
        )

        try:
            validate_loaded_alerts([alert])
        except ValueError as exc:
            assert "failed dataset gate" in str(exc)
        else:
            raise AssertionError("invalid benchmark candidate should be rejected")

    def test_runtime_allows_engineering_scaffold_with_warning(self) -> None:
        alert = parse_cicids2018_row(
            {
                "Src IP": "10.0.0.15",
                "Dst IP": "172.16.0.10",
                "Dst Port": "443",
                "Protocol": "6",
                "Label": "Brute Force",
            },
            source_path="data/datasets/sample.csv",
            source_record_index=3,
        )

        warnings = validate_loaded_alerts([alert])

        assert len(warnings) == 1
        assert "engineering_scaffold" in warnings[0]
