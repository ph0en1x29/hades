"""Tests for dataset-specific parsers."""

from __future__ import annotations

import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

import json

from src.ingestion.parsers.cicids2018 import (
    load_cicids2018_csv,
    parse_cicids2018_row,
)
from src.ingestion.parsers.splunk_attack_data import (
    load_splunk_attack_data_jsonl,
    parse_splunk_attack_data_record,
)
from src.ingestion.schema import AlertSeverity, DatasetRole


class TestCicids2018Parser:
    def test_parse_row_maps_core_fields(self) -> None:
        row = {
            "Src IP": "10.0.0.15",
            "Src Port": "51514",
            "Dst IP": "172.16.0.10",
            "Dst Port": "443",
            "Protocol": "6",
            "Timestamp": "14/02/2018 08:31:12",
            "Flow Duration": "112233",
            "Tot Fwd Pkts": "11",
            "Tot Bwd Pkts": "9",
            "Label": "Brute Force",
        }

        alert = parse_cicids2018_row(
            row,
            source_path="data/datasets/sample.csv",
            source_record_index=7,
        )

        assert alert.timestamp == "2018-02-14T08:31:12"
        assert alert.event_type == "Brute Force"
        assert alert.protocol == "TCP"
        assert alert.dst_port == 443
        assert alert.src_ip == "10.0.0.15"
        assert alert.severity == AlertSeverity.HIGH
        assert alert.provenance.dataset_name == "cicids2018"
        assert alert.provenance.dataset_role == DatasetRole.ENGINEERING_SCAFFOLD
        assert alert.provenance.label_provenance == "cicids2018_flow_label"
        assert alert.provenance.source_record_index == 7
        assert alert.benchmark.rule_id == ""

        raw_log = json.loads(alert.raw_log)
        assert raw_log["source_record_index"] == 7
        assert raw_log["flow_features"]["Flow Duration"] == 112233
        assert raw_log["flow_features"]["Tot Fwd Pkts"] == 11

    def test_load_csv_builds_unified_alerts(self, tmp_path) -> None:
        csv_path = tmp_path / "cicids2018_sample.csv"
        csv_path.write_text(
            "\n".join(
                [
                    "Src IP,Src Port,Dst IP,Dst Port,Protocol,Timestamp,Flow Duration,Tot Fwd Pkts,Tot Bwd Pkts,Label",
                    "10.1.1.5,53001,192.0.2.25,80,6,2018-02-14 08:35:00,3000,6,5,Benign",
                    "198.51.100.10,53,10.0.0.20,8080,17,2018-02-14 08:36:00,7000,200,10,DDoS",
                ]
            ),
            encoding="utf-8",
        )

        alerts = load_cicids2018_csv(csv_path)

        assert len(alerts) == 2
        assert alerts[0].event_type == "Benign"
        assert alerts[0].severity == AlertSeverity.INFO
        assert alerts[1].event_type == "DDoS"
        assert alerts[1].severity == AlertSeverity.CRITICAL
        assert alerts[1].protocol == "UDP"
        assert alerts[1].provenance.source_record_index == 1


class TestSplunkAttackDataParser:
    def test_parse_record_maps_benchmark_metadata(self) -> None:
        record = {
            "record_id": "sad-001",
            "scenario_id": "windows_credential_access",
            "event": {
                "timestamp": "2026-03-12T10:00:00Z",
                "event_type": "credential_access",
                "message": "Multiple failed logons followed by successful logon",
                "src_ip": "198.51.100.50",
                "dst_ip": "10.0.0.15",
                "dst_port": 445,
                "protocol": "TCP",
                "log_source": "sysmon",
            },
            "detection": {
                "rule_id": "DET-1001",
                "rule_source": "splunk_security_content",
                "rule_name": "Windows Brute Force Detection",
                "severity": "high",
                "category": "credential_access",
                "mitre_techniques": ["T1110"],
            },
            "label": {"provenance": "splunk_detection_label_v1"},
        }

        alert = parse_splunk_attack_data_record(record, source_path="data/benchmarks/public/slice.jsonl")

        assert alert.signature == "Windows Brute Force Detection"
        assert alert.severity == AlertSeverity.HIGH
        assert alert.benchmark.rule_id == "DET-1001"
        assert alert.benchmark.rule_source == "splunk_security_content"
        assert alert.benchmark.scenario_id == "windows_credential_access"
        assert alert.benchmark.mitre_techniques == ["T1110"]
        assert alert.provenance.dataset_role == DatasetRole.BENCHMARK_OF_RECORD
        assert alert.provenance.label_provenance == "splunk_detection_label_v1"

    def test_load_jsonl_builds_benchmark_alerts(self, tmp_path) -> None:
        jsonl_path = tmp_path / "splunk_attack_data_slice.jsonl"
        jsonl_path.write_text(
            "\n".join(
                [
                    json.dumps(
                        {
                            "record_id": "sad-001",
                            "scenario_id": "windows_credential_access",
                            "event": {
                                "timestamp": "2026-03-12T10:00:00Z",
                                "event_type": "credential_access",
                                "message": "Multiple failed logons followed by successful logon",
                                "src_ip": "198.51.100.50",
                                "dst_ip": "10.0.0.15",
                                "dst_port": 445,
                                "protocol": "TCP",
                                "log_source": "sysmon",
                            },
                            "detection": {
                                "rule_id": "DET-1001",
                                "rule_source": "splunk_security_content",
                                "rule_name": "Windows Brute Force Detection",
                                "severity": "high",
                                "category": "credential_access",
                                "mitre_techniques": ["T1110"],
                            },
                            "label": {"provenance": "splunk_detection_label_v1"},
                        }
                    ),
                    json.dumps(
                        {
                            "record_id": "sad-002",
                            "scenario_id": "windows_discovery",
                            "event": {
                                "timestamp": "2026-03-12T10:05:00Z",
                                "event_type": "discovery",
                                "message": "Suspicious system discovery commands",
                                "src_ip": "10.0.0.21",
                                "dst_ip": "10.0.0.21",
                                "protocol": "TCP",
                                "log_source": "windows_security",
                            },
                            "detection": {
                                "rule_id": "DET-1002",
                                "rule_source": "splunk_security_content",
                                "rule_name": "Windows Discovery Commands",
                                "severity": "medium",
                                "category": "discovery",
                                "mitre_techniques": ["T1087"],
                            },
                            "label": {"provenance": "splunk_detection_label_v1"},
                        }
                    ),
                ]
            ),
            encoding="utf-8",
        )

        alerts = load_splunk_attack_data_jsonl(jsonl_path)

        assert len(alerts) == 2
        assert alerts[0].benchmark.rule_id == "DET-1001"
        assert alerts[1].benchmark.rule_id == "DET-1002"
        assert alerts[0].provenance.dataset_role == DatasetRole.BENCHMARK_OF_RECORD
