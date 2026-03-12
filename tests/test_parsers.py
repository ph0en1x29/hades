"""Tests for dataset-specific parsers."""

from __future__ import annotations

import json
from pathlib import Path

from src.ingestion.parsers.cicids2018 import (
    load_cicids2018_csv,
    parse_cicids2018_row,
)
from src.ingestion.schema import AlertSeverity


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
        assert alert.provenance.source_record_index == 7

        raw_log = json.loads(alert.raw_log)
        assert raw_log["source_record_index"] == 7
        assert raw_log["flow_features"]["Flow Duration"] == 112233
        assert raw_log["flow_features"]["Tot Fwd Pkts"] == 11

    def test_load_csv_builds_unified_alerts(self, tmp_path: Path) -> None:
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
