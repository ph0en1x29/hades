"""BETH dataset parser.

Parses BETH honeypot process and DNS logs into UnifiedAlert objects.
The parser is intentionally schema-flexible because BETH appears in a few
slightly different exported layouts (Kaggle mirrors, SQL extracts, CSVs).

Supported sources:
- process logs (kernel / process execution / file activity style rows)
- DNS logs

This parser is primarily for engineering-scaffold ingestion and cross-dataset
comparison; BETH does not provide SIEM rule associations equivalent to Splunk
Attack Data, so it should not be treated as the benchmark of record.
"""

from __future__ import annotations

import csv
import json
from datetime import UTC, datetime
from pathlib import Path
from typing import Any
from uuid import uuid4

from src.ingestion.schema import (
    AlertBenchmarkContext,
    AlertMetadata,
    AlertProvenance,
    AlertSeverity,
    AlertSource,
    DatasetRole,
    UnifiedAlert,
)

PROCESS_TIME_FIELDS = [
    "timestamp",
    "ts",
    "time",
    "event_time",
]

PROCESS_NAME_FIELDS = [
    "process_name",
    "process",
    "procname",
    "exe",
    "path",
    "command",
    "cmdline",
]

PROCESS_USER_FIELDS = [
    "username",
    "user",
    "uid_name",
]

DNS_QUERY_FIELDS = [
    "dnsquery",
    "dnsquerynames",
    "query",
    "rrname",
]

DNS_ANSWER_FIELDS = [
    "dnsanswer",
    "answer",
]

SRC_IP_FIELDS = [
    "sourceip",
    "src_ip",
    "srcip",
    "hostip",
]

DST_IP_FIELDS = [
    "destinationip",
    "dst_ip",
    "dstip",
]

LABEL_FIELDS = [
    "label",
    "class",
    "sus",
    "evil",
]


def _first_present(row: dict[str, Any], field_names: list[str]) -> str | None:
    for name in field_names:
        value = row.get(name)
        if value not in (None, ""):
            return str(value)
    return None


def _parse_timestamp(value: str | None) -> str:
    if not value:
        return datetime.now(UTC).isoformat()

    candidates = [
        "%Y-%m-%d %H:%M:%S",
        "%Y-%m-%d %H:%M:%S.%f",
        "%Y-%m-%dT%H:%M:%S",
        "%Y-%m-%dT%H:%M:%S.%f",
    ]
    for fmt in candidates:
        try:
            return datetime.strptime(value, fmt).replace(tzinfo=UTC).isoformat()
        except ValueError:
            continue

    try:
        return datetime.fromisoformat(value.replace("Z", "+00:00")).isoformat()
    except ValueError:
        return datetime.now(UTC).isoformat()


def _severity_from_label(row: dict[str, Any]) -> AlertSeverity:
    evil = str(row.get("evil", "0")).strip().lower()
    sus = str(row.get("sus", "0")).strip().lower()
    label = (_first_present(row, LABEL_FIELDS) or "").strip().lower()

    if evil in {"1", "true", "yes"} or label in {"evil", "malicious", "attack"}:
        return AlertSeverity.HIGH
    if sus in {"1", "true", "yes"} or label in {"sus", "suspicious", "anomaly"}:
        return AlertSeverity.MEDIUM
    return AlertSeverity.INFO


def parse_beth_dns_row(
    row: dict[str, Any],
    *,
    source_path: str,
    row_index: int,
    dataset_name: str = "beth",
) -> UnifiedAlert:
    query = _first_present(row, DNS_QUERY_FIELDS) or "unknown_query"
    answer = _first_present(row, DNS_ANSWER_FIELDS) or ""
    src_ip = _first_present(row, SRC_IP_FIELDS)
    dst_ip = _first_present(row, DST_IP_FIELDS)
    severity = _severity_from_label(row)

    summary = f"BETH DNS {query}"
    if answer:
        summary += f" -> {answer}"

    return UnifiedAlert(
        alert_id=f"beth-dns-{row_index}-{uuid4().hex[:8]}",
        timestamp=_parse_timestamp(_first_present(row, PROCESS_TIME_FIELDS)),
        source=AlertSource.FILE_REPLAY,
        severity=severity,
        signature=summary,
        signature_id=str(row.get("sensorid", "beth_dns")),
        event_type="beth_dns",
        src_ip=src_ip,
        src_port=None,
        dst_ip=dst_ip,
        dst_port=53,
        protocol="dns",
        raw_log=json.dumps(row),
        metadata=AlertMetadata(
            vendor="BETH",
            device="honeypot",
            category="dns",
            message=summary,
        ),
        benchmark=AlertBenchmarkContext(
            scenario_id=f"{dataset_name}:dns:{source_path}",
            rule_id="beth_dns_behavior",
            rule_source="beth_labels",
            rule_name="BETH DNS Behavioral Label",
            mitre_techniques=[],
            correlation_id=None,
        ),
        provenance=AlertProvenance(
            dataset_name=dataset_name,
            dataset_role=DatasetRole.ENGINEERING_SCAFFOLD,
            source_path=source_path,
            source_record_id=None,
            source_record_index=row_index,
            original_format="csv",
            parser_version="beth_dns_v1",
            transform_version="1.0",
            label_provenance="beth_honeypot_labels",
            collected_at=None,
        ),
    )


def parse_beth_process_row(
    row: dict[str, Any],
    *,
    source_path: str,
    row_index: int,
    dataset_name: str = "beth",
) -> UnifiedAlert:
    process_name = _first_present(row, PROCESS_NAME_FIELDS) or "unknown_process"
    user = _first_present(row, PROCESS_USER_FIELDS)
    src_ip = _first_present(row, SRC_IP_FIELDS)
    severity = _severity_from_label(row)

    summary = f"BETH Process {process_name}"
    if user:
        summary += f" user={user}"

    return UnifiedAlert(
        alert_id=f"beth-proc-{row_index}-{uuid4().hex[:8]}",
        timestamp=_parse_timestamp(_first_present(row, PROCESS_TIME_FIELDS)),
        source=AlertSource.FILE_REPLAY,
        severity=severity,
        signature=summary,
        signature_id=str(row.get("event_id", "beth_process")),
        event_type="beth_process",
        src_ip=src_ip,
        src_port=None,
        dst_ip=None,
        dst_port=None,
        protocol=None,
        raw_log=json.dumps(row),
        metadata=AlertMetadata(
            vendor="BETH",
            device="honeypot",
            category="process",
            message=summary,
        ),
        benchmark=AlertBenchmarkContext(
            scenario_id=f"{dataset_name}:process:{source_path}",
            rule_id="beth_process_behavior",
            rule_source="beth_labels",
            rule_name="BETH Process Behavioral Label",
            mitre_techniques=[],
            correlation_id=None,
        ),
        provenance=AlertProvenance(
            dataset_name=dataset_name,
            dataset_role=DatasetRole.ENGINEERING_SCAFFOLD,
            source_path=source_path,
            source_record_id=None,
            source_record_index=row_index,
            original_format="csv",
            parser_version="beth_process_v1",
            transform_version="1.0",
            label_provenance="beth_honeypot_labels",
            collected_at=None,
        ),
    )


def _detect_beth_mode(headers: list[str]) -> str:
    lowered = {header.strip().lower() for header in headers}
    if lowered & {field.lower() for field in DNS_QUERY_FIELDS}:
        return "dns"
    return "process"


def load_beth_csv(
    path: str | Path,
    *,
    limit: int | None = None,
    mode: str | None = None,
    dataset_name: str = "beth",
) -> list[UnifiedAlert]:
    csv_path = Path(path)
    alerts: list[UnifiedAlert] = []

    with csv_path.open("r", encoding="utf-8", errors="replace", newline="") as handle:
        reader = csv.DictReader(handle)
        if reader.fieldnames is None:
            return []

        inferred_mode = mode or _detect_beth_mode(reader.fieldnames)
        for row_index, row in enumerate(reader, start=1):
            if inferred_mode == "dns":
                alert = parse_beth_dns_row(
                    row,
                    source_path=str(csv_path),
                    row_index=row_index,
                    dataset_name=dataset_name,
                )
            else:
                alert = parse_beth_process_row(
                    row,
                    source_path=str(csv_path),
                    row_index=row_index,
                    dataset_name=dataset_name,
                )
            alerts.append(alert)
            if limit is not None and len(alerts) >= limit:
                break

    return alerts


__all__ = [
    "load_beth_csv",
    "parse_beth_dns_row",
    "parse_beth_process_row",
]
