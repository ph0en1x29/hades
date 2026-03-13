"""Splunk Attack Data / Suricata JSON parser.

Parses Suricata eve.json-style logs from Splunk Attack Data into
UnifiedAlert objects. These logs contain HTTP, DNS, TLS, and alert
events with full network context — critical for injection vector research.

Format: JSONL (one JSON object per line)
Source: https://github.com/splunk/attack_data
"""

from __future__ import annotations

import json
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from src.ingestion.schema import (
    AlertBenchmarkContext,
    AlertMetadata,
    AlertProvenance,
    AlertSeverity,
    AlertSource,
    DatasetRole,
    UnifiedAlert,
)

# Suricata severity mapping
SURICATA_SEVERITY: dict[int, AlertSeverity] = {
    1: AlertSeverity.HIGH,
    2: AlertSeverity.MEDIUM,
    3: AlertSeverity.LOW,
}

# Event type → base severity (when no alert severity present)
EVENT_TYPE_SEVERITY: dict[str, AlertSeverity] = {
    "alert": AlertSeverity.HIGH,
    "http": AlertSeverity.MEDIUM,
    "dns": AlertSeverity.LOW,
    "tls": AlertSeverity.LOW,
    "fileinfo": AlertSeverity.MEDIUM,
    "flow": AlertSeverity.LOW,
    "stats": AlertSeverity.INFO,
}


def parse_suricata_event(
    record: dict[str, Any],
    *,
    mitre_technique: str,
    rule_name: str = "",
    rule_source: str = "splunk_security_content",
    dataset_name: str = "splunk_attack_data",
) -> UnifiedAlert | None:
    """Parse a single Suricata JSON record into a UnifiedAlert."""
    event_type = record.get("event_type", "")
    timestamp_str = record.get("timestamp", "")

    # Parse timestamp
    try:
        ts = datetime.fromisoformat(timestamp_str.replace("+0000", "+00:00"))
    except (ValueError, TypeError):
        ts = datetime.now(UTC)

    # Extract network fields
    src_ip = record.get("src_ip")
    src_port = record.get("src_port")
    dst_ip = record.get("dest_ip")
    dst_port = record.get("dest_port")
    proto = record.get("proto", "")

    # Build signature from event content
    signature_parts = []
    http = record.get("http", {})
    alert_data = record.get("alert", {})
    dns = record.get("dns", {})
    tls = record.get("tls", {})

    if alert_data:
        signature_parts.append(alert_data.get("signature", "Suricata Alert"))
        severity_num = alert_data.get("severity", 2)
        severity = SURICATA_SEVERITY.get(severity_num, AlertSeverity.MEDIUM)
    elif http:
        method = http.get("http_method", "")
        url = http.get("url", "")[:100]
        ua = http.get("http_user_agent", "")[:80]
        signature_parts.append(f"HTTP {method} {url}")
        if ua:
            signature_parts.append(f"UA: {ua}")
        severity = EVENT_TYPE_SEVERITY.get("http", AlertSeverity.MEDIUM)
    elif dns:
        query = dns.get("query", dns.get("rrname", ""))
        qtype = dns.get("rrtype", dns.get("type", ""))
        signature_parts.append(f"DNS {qtype} {query}")
        severity = EVENT_TYPE_SEVERITY.get("dns", AlertSeverity.LOW)
    elif tls:
        sni = tls.get("sni", "")
        cn = tls.get("subject", "")
        signature_parts.append(f"TLS SNI={sni}")
        if cn:
            signature_parts.append(f"CN={cn[:60]}")
        severity = EVENT_TYPE_SEVERITY.get("tls", AlertSeverity.LOW)
    else:
        signature_parts.append(f"Suricata {event_type}")
        severity = EVENT_TYPE_SEVERITY.get(event_type, AlertSeverity.LOW)

    signature = " | ".join(signature_parts)

    if not rule_name:
        rule_name = f"Suricata_{event_type}_{mitre_technique}"

    return UnifiedAlert(
        alert_id=f"suricata-{record.get('flow_id', '')}-{timestamp_str}",
        timestamp=ts.isoformat(),
        source=AlertSource.FILE_REPLAY,
        severity=severity,
        signature=signature,
        signature_id=str(alert_data.get("signature_id", "")),
        event_type=f"suricata_{event_type}",
        src_ip=src_ip,
        src_port=src_port,
        dst_ip=dst_ip,
        dst_port=dst_port,
        protocol=proto,
        raw_log=json.dumps(record),
        metadata=AlertMetadata(
            vendor="Suricata",
            device="IDS/IPS",
            category=event_type,
            message=signature,
        ),
        provenance=AlertProvenance(
            dataset_name=dataset_name,
            dataset_role=DatasetRole.BENCHMARK_OF_RECORD,
            parser_version="splunk_suricata_v1",
            transform_version="1.0",
            label_provenance=f"splunk_attack_data:{mitre_technique}",
        ),
        benchmark=AlertBenchmarkContext(
            scenario_id=f"{dataset_name}:{mitre_technique}",
            rule_id=alert_data.get("signature_id", f"suricata-{event_type}-{mitre_technique}"),
            rule_source=rule_source,
            rule_name=rule_name,
            mitre_techniques=[mitre_technique],
        ),
    )


def load_suricata_log(
    path: str | Path,
    *,
    mitre_technique: str,
    rule_name: str = "",
    limit: int | None = None,
    event_types: set[str] | None = None,
) -> list[UnifiedAlert]:
    """Load a Suricata JSONL log file and parse into UnifiedAlerts.

    Args:
        path: Path to the JSONL file
        mitre_technique: MITRE ATT&CK technique ID
        rule_name: Detection rule name
        limit: Max events to parse
        event_types: Filter to specific event types (e.g. {"http", "alert"})
    """
    path = Path(path)
    alerts: list[UnifiedAlert] = []
    if not path.exists() or path.stat().st_size == 0:
        return alerts

    with path.open(encoding="utf-8", errors="replace") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue

            try:
                record = json.loads(line)
            except json.JSONDecodeError:
                continue

            # Filter by event type if specified
            if event_types and record.get("event_type") not in event_types:
                continue

            alert = parse_suricata_event(
                record,
                mitre_technique=mitre_technique,
                rule_name=rule_name,
            )
            if alert is not None:
                alerts.append(alert)

            if limit and len(alerts) >= limit:
                break

    return alerts
