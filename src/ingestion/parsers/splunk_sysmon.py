"""Splunk Attack Data / Windows Sysmon XML parser.

Parses raw Sysmon XML event logs from Splunk Attack Data repository into
UnifiedAlert objects with full benchmark context (rule association, MITRE
technique mapping, provenance chain).

Format: concatenated <Event> XML elements (no root wrapper).
Source: https://github.com/splunk/attack_data
"""

from __future__ import annotations

import xml.etree.ElementTree as ET
from datetime import datetime, UTC
from pathlib import Path

from src.ingestion.schema import (
    AlertBenchmarkContext,
    AlertMetadata,
    AlertProvenance,
    AlertSeverity,
    AlertSource,
    DatasetRole,
    UnifiedAlert,
)

import json

# Sysmon EventID → human-readable description
SYSMON_EVENT_TYPES: dict[int, str] = {
    1: "Process Creation",
    2: "File Creation Time Changed",
    3: "Network Connection",
    4: "Sysmon Service State Changed",
    5: "Process Terminated",
    6: "Driver Loaded",
    7: "Image Loaded",
    8: "CreateRemoteThread",
    9: "RawAccessRead",
    10: "ProcessAccess",
    11: "FileCreate",
    12: "Registry Event (Create/Delete)",
    13: "Registry Value Set",
    14: "Registry Key/Value Rename",
    15: "FileCreateStreamHash",
    17: "PipeEvent (Created)",
    18: "PipeEvent (Connected)",
    22: "DNSEvent (Query)",
    23: "FileDelete (Archived)",
    24: "ClipboardChange",
    25: "ProcessTampering",
    26: "FileDeleteDetected",
}

# Sysmon EventID → severity mapping for triage
SYSMON_SEVERITY: dict[int, str] = {
    1: "medium",    # Process creation — context dependent
    3: "low",       # Network connection — very common
    8: "high",      # Remote thread — common in injection
    10: "high",     # Process access — credential dumping indicator
    11: "low",      # File create — very common
    22: "low",      # DNS query — very common
}

NS = {"ev": "http://schemas.microsoft.com/win/2004/08/events/event"}


def _parse_event_xml(event_str: str) -> dict | None:
    """Parse a single <Event> XML string into a structured dict."""
    try:
        root = ET.fromstring(event_str)
    except ET.ParseError:
        return None

    system = root.find("ev:System", NS)
    if system is None:
        return None

    event_id_el = system.find("ev:EventID", NS)
    event_id = int(event_id_el.text) if event_id_el is not None and event_id_el.text else 0

    time_el = system.find("ev:TimeCreated", NS)
    timestamp = time_el.get("SystemTime", "") if time_el is not None else ""

    computer_el = system.find("ev:Computer", NS)
    computer = computer_el.text if computer_el is not None and computer_el.text else ""

    provider_el = system.find("ev:Provider", NS)
    provider = provider_el.get("Name", "") if provider_el is not None else ""

    # Parse EventData key-value pairs
    event_data: dict[str, str] = {}
    data_section = root.find("ev:EventData", NS)
    if data_section is not None:
        for data_el in data_section.findall("ev:Data", NS):
            name = data_el.get("Name", "")
            value = data_el.text or ""
            if name:
                event_data[name] = value

    return {
        "event_id": event_id,
        "timestamp": timestamp,
        "computer": computer,
        "provider": provider,
        "event_data": event_data,
    }


def _extract_source_dest(event_data: dict[str, str], event_id: int) -> tuple[str, str, int | None, int | None]:
    """Extract source/dest IPs and ports from Sysmon event data."""
    src_ip = event_data.get("SourceIp", "")
    dst_ip = event_data.get("DestinationIp", "")
    src_port = None
    dst_port = None

    if "SourcePort" in event_data:
        try:
            src_port = int(event_data["SourcePort"])
        except (ValueError, TypeError):
            pass
    if "DestinationPort" in event_data:
        try:
            dst_port = int(event_data["DestinationPort"])
        except (ValueError, TypeError):
            pass

    # For process events, use Computer as source
    if not src_ip and event_id in (1, 5, 8, 10):
        src_ip = "local"

    return src_ip, dst_ip, src_port, dst_port


def parse_sysmon_event(
    event_str: str,
    *,
    mitre_technique: str,
    rule_name: str = "",
    rule_source: str = "splunk_security_content",
    dataset_name: str = "splunk_attack_data",
) -> UnifiedAlert | None:
    """Parse a single Sysmon XML event into a UnifiedAlert."""
    parsed = _parse_event_xml(event_str)
    if parsed is None:
        return None

    event_id = parsed["event_id"]
    event_data = parsed["event_data"]
    src_ip, dst_ip, src_port, dst_port = _extract_source_dest(event_data, event_id)

    # Build readable signature
    event_type = SYSMON_EVENT_TYPES.get(event_id, f"EventID {event_id}")
    process_name = event_data.get("Image", event_data.get("SourceImage", ""))
    if process_name:
        process_name = process_name.rsplit("\\", 1)[-1]  # Just the filename
    signature = f"Sysmon {event_type}: {process_name}" if process_name else f"Sysmon {event_type}"

    # Parse timestamp
    try:
        ts = datetime.fromisoformat(parsed["timestamp"].rstrip("Z") + "+00:00") if parsed["timestamp"] else datetime.now(UTC)
    except (ValueError, TypeError):
        ts = datetime.now(UTC)

    severity_str = SYSMON_SEVERITY.get(event_id, "medium")
    severity = AlertSeverity(severity_str)

    # Auto-generate rule name if not provided
    if not rule_name:
        rule_name = f"Sysmon_{event_type.replace(' ', '_')}_{mitre_technique}"

    return UnifiedAlert(
        alert_id=f"splunk-{dataset_name}-{parsed['timestamp']}-{event_id}",
        timestamp=ts.isoformat(),
        source=AlertSource.FILE_REPLAY,
        severity=severity,
        signature=signature,
        event_type=f"sysmon_{event_id}",
        src_ip=src_ip or None,
        src_port=src_port,
        dst_ip=dst_ip or None,
        dst_port=dst_port,
        protocol=event_data.get("Protocol", ""),
        raw_log=json.dumps(event_data),
        metadata=AlertMetadata(
            vendor="Microsoft",
            device="Sysmon",
            category=event_type,
            message=signature,
        ),
        provenance=AlertProvenance(
            dataset_name=dataset_name,
            dataset_role=DatasetRole.BENCHMARK_OF_RECORD,
            parser_version="splunk_sysmon_v1",
            transform_version="1.0",
            label_provenance=f"splunk_attack_data:{mitre_technique}",
        ),
        benchmark=AlertBenchmarkContext(
            scenario_id=f"{dataset_name}:{mitre_technique}",
            rule_id=f"sysmon-{event_id}-{mitre_technique}",
            rule_source=rule_source,
            rule_name=rule_name,
            mitre_techniques=[mitre_technique],
        ),
    )


def load_sysmon_log(
    path: str | Path,
    *,
    mitre_technique: str,
    rule_name: str = "",
    limit: int | None = None,
) -> list[UnifiedAlert]:
    """Load a Sysmon XML log file and parse all events into UnifiedAlerts.

    Splunk Attack Data logs are concatenated <Event> elements with no root wrapper.
    We split on '</Event>' boundaries and parse each.
    """
    path = Path(path)
    content = path.read_text(encoding="utf-8", errors="replace")

    # Split on event boundaries
    raw_events = content.split("</Event>")
    alerts: list[UnifiedAlert] = []

    for i, raw in enumerate(raw_events):
        raw = raw.strip()
        if not raw or "<Event" not in raw:
            continue

        # Re-add the closing tag
        event_str = raw + "</Event>"

        alert = parse_sysmon_event(
            event_str,
            mitre_technique=mitre_technique,
            rule_name=rule_name,
        )
        if alert is not None:
            alerts.append(alert)

        if limit and len(alerts) >= limit:
            break

    return alerts
