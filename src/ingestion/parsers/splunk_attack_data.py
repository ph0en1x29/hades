"""Splunk Attack Data JSONL normalization helpers."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from src.ingestion.schema import (
    AlertBenchmarkContext,
    AlertMetadata,
    AlertProvenance,
    AlertSeverity,
    DatasetRole,
    UnifiedAlert,
)

SEVERITY_MAP = {
    "critical": AlertSeverity.CRITICAL,
    "high": AlertSeverity.HIGH,
    "medium": AlertSeverity.MEDIUM,
    "low": AlertSeverity.LOW,
    "info": AlertSeverity.INFO,
}


def load_splunk_attack_data_jsonl(
    path: str | Path,
    *,
    dataset_name: str = "splunk_attack_data",
) -> list[UnifiedAlert]:
    """Load a Splunk Attack Data benchmark slice from JSONL."""
    jsonl_path = Path(path)
    with jsonl_path.open("r", encoding="utf-8") as handle:
        return [
            parse_splunk_attack_data_record(
                json.loads(line),
                source_path=str(jsonl_path),
                source_record_index=index,
                dataset_name=dataset_name,
            )
            for index, line in enumerate(handle)
            if line.strip()
        ]


def parse_splunk_attack_data_record(
    record: dict[str, Any],
    *,
    source_path: str = "",
    source_record_index: int = 0,
    dataset_name: str = "splunk_attack_data",
) -> UnifiedAlert:
    """Convert one Splunk Attack Data record into a UnifiedAlert."""
    event = _as_dict(record.get("event"))
    detection = _as_dict(record.get("detection"))
    label = _as_dict(record.get("label"))

    severity_text = str(detection.get("severity", "medium")).lower()
    severity = SEVERITY_MAP.get(severity_text, AlertSeverity.MEDIUM)

    signature = _coerce_str(detection.get("rule_name")) or _coerce_str(
        event.get("message"),
    )
    event_type = _coerce_str(event.get("event_type")) or signature or "splunk_alert"

    source_record_id = _coerce_str(record.get("record_id"))
    correlation_id = _coerce_str(record.get("correlation_id")) or _coerce_str(
        event.get("correlation_id"),
    )

    return UnifiedAlert(
        timestamp=_coerce_str(event.get("timestamp")),
        severity=severity,
        signature=signature,
        signature_id=_coerce_str(detection.get("rule_id")),
        event_type=event_type,
        src_ip=_coerce_str(event.get("src_ip")),
        src_port=_coerce_int(event.get("src_port")),
        dst_ip=_coerce_str(event.get("dst_ip")),
        dst_port=_coerce_int(event.get("dst_port")),
        protocol=_coerce_str(event.get("protocol")),
        raw_log=json.dumps(record, sort_keys=True),
        metadata=AlertMetadata(
            vendor="Splunk Attack Data",
            device=_coerce_str(event.get("log_source")) or "splunk",
            category=_coerce_str(detection.get("category")) or "splunk_detection",
            message=_coerce_str(event.get("message")) or signature or "",
        ),
        benchmark=AlertBenchmarkContext(
            scenario_id=_coerce_str(record.get("scenario_id")) or "",
            rule_id=_coerce_str(detection.get("rule_id")) or "",
            rule_source=_coerce_str(detection.get("rule_source")) or "",
            rule_name=_coerce_str(detection.get("rule_name")) or "",
            mitre_techniques=_coerce_string_list(detection.get("mitre_techniques")),
            correlation_id=correlation_id,
        ),
        provenance=AlertProvenance(
            dataset_name=dataset_name,
            dataset_role=DatasetRole.BENCHMARK_OF_RECORD,
            source_path=source_path,
            source_record_id=source_record_id,
            source_record_index=source_record_index,
            original_format="jsonl",
            parser_version="splunk_attack_data_jsonl_v1",
            transform_version="alert_projection_v2",
            label_provenance=_coerce_str(label.get("provenance")) or "",
        ),
    )


def _as_dict(value: Any) -> dict[str, Any]:
    return value if isinstance(value, dict) else {}


def _coerce_str(value: Any) -> str | None:
    if value is None:
        return None
    text = str(value).strip()
    return text or None


def _coerce_int(value: Any) -> int | None:
    if value is None:
        return None
    try:
        return int(value)
    except (TypeError, ValueError):
        return None


def _coerce_string_list(value: Any) -> list[str]:
    if not isinstance(value, list):
        return []
    return [str(item) for item in value if str(item).strip()]


__all__ = ["load_splunk_attack_data_jsonl", "parse_splunk_attack_data_record"]
