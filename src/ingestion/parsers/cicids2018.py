"""CIC-IDS2018 CSV normalization helpers."""

from __future__ import annotations

import csv
import json
import math
from datetime import datetime
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

PROTOCOL_MAP = {
    "1": "ICMP",
    "6": "TCP",
    "17": "UDP",
}

TIMESTAMP_FORMATS = (
    "%d/%m/%Y %H:%M:%S",
    "%d/%m/%Y %H:%M",
    "%m/%d/%Y %H:%M:%S",
    "%m/%d/%Y %H:%M",
    "%m/%d/%Y %I:%M:%S %p",
    "%m/%d/%Y %I:%M %p",
    "%Y-%m-%d %H:%M:%S",
    "%Y-%m-%dT%H:%M:%S",
)


def load_cicids2018_csv(
    path: str | Path,
    *,
    dataset_name: str = "cicids2018",
) -> list[UnifiedAlert]:
    """Load a CIC-IDS2018 CSV file into normalized alerts."""
    csv_path = Path(path)
    with csv_path.open("r", encoding="utf-8-sig", newline="") as handle:
        reader = csv.DictReader(handle)
        return [
            parse_cicids2018_row(
                row,
                source_path=str(csv_path),
                source_record_index=index,
                dataset_name=dataset_name,
            )
            for index, row in enumerate(reader)
        ]


def parse_cicids2018_row(
    row: dict[str, str | None],
    *,
    source_path: str = "",
    source_record_index: int = 0,
    dataset_name: str = "cicids2018",
) -> UnifiedAlert:
    """Convert one CIC-IDS2018 CSV row into a UnifiedAlert."""
    event_type = _clean_str(_get_first(row, ("Label",))) or "Unknown"
    protocol_value = _clean_str(_get_first(row, ("Protocol",)))

    raw_payload = {
        "dataset_name": dataset_name,
        "source_record_index": source_record_index,
        "flow_features": {
            key: _coerce_value(value) for key, value in row.items() if key is not None
        },
    }

    return UnifiedAlert(
        timestamp=_normalize_timestamp(_get_first(row, ("Timestamp",))),
        severity=_map_label_to_severity(event_type),
        signature=_build_signature(event_type),
        event_type=event_type,
        src_ip=_clean_str(_get_first(row, ("Src IP", "Source IP"))),
        src_port=_parse_int(_get_first(row, ("Src Port", "Source Port"))),
        dst_ip=_clean_str(_get_first(row, ("Dst IP", "Destination IP"))),
        dst_port=_parse_int(_get_first(row, ("Dst Port", "Destination Port"))),
        protocol=_map_protocol(protocol_value),
        raw_log=json.dumps(raw_payload, sort_keys=True),
        metadata=AlertMetadata(
            vendor="CIC-IDS2018",
            device="cicflowmeter",
            category=event_type.lower().replace(" ", "_"),
            message=f"CIC-IDS2018 labeled flow: {event_type}",
        ),
        benchmark=AlertBenchmarkContext(),
        provenance=AlertProvenance(
            dataset_name=dataset_name,
            dataset_role=DatasetRole.ENGINEERING_SCAFFOLD,
            source_path=source_path,
            source_record_index=source_record_index,
            original_format="csv",
            parser_version="cicids2018_csv_v1",
            label_provenance="cicids2018_flow_label",
        ),
    )


def _get_first(
    row: dict[str, str | None],
    keys: tuple[str, ...],
) -> str | None:
    for key in keys:
        if key in row:
            return row[key]
    return None


def _clean_str(value: str | None) -> str | None:
    if value is None:
        return None
    cleaned = value.strip()
    return cleaned or None


def _parse_int(value: str | None) -> int | None:
    cleaned = _clean_str(value)
    if cleaned is None:
        return None
    try:
        return int(float(cleaned))
    except ValueError:
        return None


def _coerce_value(value: str | None) -> Any:
    cleaned = _clean_str(value)
    if cleaned is None:
        return None

    normalized = cleaned.lower()
    if normalized in {"nan", "inf", "-inf", "infinity", "-infinity"}:
        return None

    try:
        integer_value = int(cleaned)
    except ValueError:
        pass
    else:
        return integer_value

    try:
        float_value = float(cleaned)
    except ValueError:
        return cleaned

    if math.isfinite(float_value):
        return float_value
    return None


def _normalize_timestamp(value: str | None) -> str | None:
    cleaned = _clean_str(value)
    if cleaned is None:
        return None

    try:
        return datetime.fromisoformat(cleaned).isoformat()
    except ValueError:
        pass

    for fmt in TIMESTAMP_FORMATS:
        try:
            return datetime.strptime(cleaned, fmt).isoformat()
        except ValueError:
            continue

    return cleaned


def _map_protocol(value: str | None) -> str | None:
    cleaned = _clean_str(value)
    if cleaned is None:
        return None
    return PROTOCOL_MAP.get(cleaned, cleaned.upper())


def _map_label_to_severity(label: str) -> AlertSeverity:
    normalized = label.strip().lower()

    if normalized == "benign":
        return AlertSeverity.INFO
    if "ddos" in normalized or "dos" in normalized:
        return AlertSeverity.CRITICAL
    if (
        "infilteration" in normalized
        or "infiltration" in normalized
        or "brute force" in normalized
        or "bruteforce" in normalized
        or "patator" in normalized
        or "web attack" in normalized
        or "sql injection" in normalized
        or "xss" in normalized
        or "bot" in normalized
    ):
        return AlertSeverity.HIGH
    if "scan" in normalized or "recon" in normalized:
        return AlertSeverity.MEDIUM
    return AlertSeverity.MEDIUM


def _build_signature(label: str) -> str:
    if label.strip().lower() == "benign":
        return "CIC-IDS2018 benign network flow"
    return f"CIC-IDS2018 {label} network flow"


__all__ = ["load_cicids2018_csv", "parse_cicids2018_row"]
