"""Windows Security Event Log parser.

Parses XML-formatted Windows Security Event logs (e.g., Event IDs 4688, 4698,
4624, 4625, 4672, etc.) into UnifiedAlert objects.

Handles:
  - Process creation (4688) with command line auditing
  - Scheduled task creation (4698) with embedded task XML
  - Logon events (4624), failed logons (4625), privilege assignment (4672)
  - Single-line XML format from Splunk Attack Data exports
"""

from __future__ import annotations

import json
import xml.etree.ElementTree as ET
from datetime import UTC, datetime
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

# Windows Security Event namespace
NS = {"ev": "http://schemas.microsoft.com/win/2004/08/events/event"}

# Event ID → severity mapping
EVENT_SEVERITY = {
    4625: AlertSeverity.HIGH,  # Failed logon
    4688: AlertSeverity.MEDIUM,  # Process creation
    4698: AlertSeverity.HIGH,  # Scheduled task created
    4672: AlertSeverity.MEDIUM,  # Special privileges assigned
    4624: AlertSeverity.INFO,  # Successful logon
    4720: AlertSeverity.HIGH,  # User account created
    4732: AlertSeverity.HIGH,  # Member added to security group
}

# Event ID → signature description
EVENT_SIGNATURES = {
    4625: "Failed Logon Attempt",
    4688: "Process Creation with Command Line",
    4698: "Scheduled Task Created",
    4672: "Special Privileges Assigned to New Logon",
    4624: "Account Logon",
    4720: "User Account Created",
    4732: "Member Added to Security-Enabled Local Group",
}


def parse_windows_security_xml(
    xml_line: str,
    *,
    mitre_technique: str = "",
    rule_name: str = "",
    dataset_name: str = "splunk_attack_data",
    source_path: str = "",
    record_index: int = 0,
) -> UnifiedAlert | None:
    """Parse a single Windows Security Event XML line into a UnifiedAlert."""
    try:
        root = ET.fromstring(xml_line.strip())
    except ET.ParseError:
        return None

    # Extract System elements
    system = root.find("ev:System", NS)
    if system is None:
        return None

    event_id_elem = system.find("ev:EventID", NS)
    event_id = int(event_id_elem.text) if event_id_elem is not None and event_id_elem.text else 0

    time_elem = system.find("ev:TimeCreated", NS)
    timestamp_str = time_elem.get("SystemTime", "") if time_elem is not None else ""

    computer_elem = system.find("ev:Computer", NS)
    computer = computer_elem.text if computer_elem is not None else "unknown"

    record_id_elem = system.find("ev:EventRecordID", NS)
    record_id = record_id_elem.text if record_id_elem is not None else str(record_index)

    # Parse timestamp
    try:
        # Handle various timestamp formats
        ts_clean = timestamp_str.rstrip("Z").split(".")[0]
        timestamp = datetime.fromisoformat(ts_clean).replace(tzinfo=UTC)
    except (ValueError, IndexError):
        timestamp = datetime.now(UTC)

    # Extract EventData fields
    event_data: dict[str, str] = {}
    data_section = root.find("ev:EventData", NS)
    if data_section is not None:
        for data_elem in data_section.findall("ev:Data", NS):
            name = data_elem.get("Name", "")
            value = data_elem.text or ""
            if name:
                event_data[name] = value

    # Build signature
    severity = EVENT_SEVERITY.get(event_id, AlertSeverity.MEDIUM)
    signature = EVENT_SIGNATURES.get(event_id, f"Windows Security Event {event_id}")

    # Extract network info where available
    src_ip = event_data.get("IpAddress", "")
    src_port = event_data.get("IpPort", "")
    if src_ip in ("-", "", "::1", "127.0.0.1"):
        src_ip = "local"

    # Build meaningful alert ID
    alert_id = f"winsec-{dataset_name}-{timestamp.isoformat()}-{record_id}"

    # Build raw_log as JSON-like string for LLM consumption
    raw_fields = {
        "EventID": event_id,
        "Computer": computer,
        "TimeCreated": timestamp_str,
    }
    raw_fields.update(event_data)
    raw_log = json.dumps(raw_fields)

    return UnifiedAlert(
        alert_id=alert_id,
        timestamp=timestamp.isoformat(),
        source=AlertSource.FILE_REPLAY,
        severity=severity,
        signature=signature,
        signature_id=f"WinSec_{event_id}",
        event_type=f"winsec_{event_id}",
        src_ip=src_ip if src_ip != "local" else "",
        src_port=int(src_port) if src_port and src_port.isdigit() else None,
        dst_ip=computer,
        dst_port=None,
        protocol="N/A",
        raw_log=raw_log,
        metadata=AlertMetadata(
            vendor="Microsoft",
            device=computer or "",
            category=f"Windows Security Event {event_id}",
            message=event_data.get("CommandLine", event_data.get("TaskName", "")),
        ),
        benchmark=AlertBenchmarkContext(
            scenario_id=f"splunk_{mitre_technique}_{event_id}",
            rule_id=f"WinSec_{event_id}_{mitre_technique}",
            rule_source="windows_security_auditing",
            rule_name=rule_name or signature,
            mitre_techniques=[mitre_technique] if mitre_technique else [],
        ),
        provenance=AlertProvenance(
            dataset_name=dataset_name,
            dataset_role=DatasetRole.BENCHMARK_OF_RECORD,
            source_path=source_path,
            source_record_index=record_index,
            original_format="windows_security_xml",
            parser_version="1.0.0",
            label_provenance="mitre_technique_mapping",
        ),
    )


def load_windows_security_log(
    filepath: str,
    *,
    mitre_technique: str = "",
    rule_name: str = "",
    dataset_name: str = "splunk_attack_data",
    limit: int | None = None,
) -> list[UnifiedAlert]:
    """Load and parse a Windows Security Event Log file.

    Each line should be a complete XML Event element.
    """
    alerts: list[UnifiedAlert] = []
    path = Path(filepath)

    if not path.exists() or path.stat().st_size == 0:
        return alerts

    content = path.read_text(encoding="utf-8", errors="replace")

    # Split on Event boundaries — handles both single-line and multi-line XML
    # Find all <Event ...>...</Event> blocks
    import re as _re

    event_pattern = _re.compile(r"<Event\s[^>]*>.*?</Event>", _re.DOTALL)

    for i, match in enumerate(event_pattern.finditer(content)):
        xml_text = match.group()

        alert = parse_windows_security_xml(
            xml_text,
            mitre_technique=mitre_technique,
            rule_name=rule_name,
            dataset_name=dataset_name,
            source_path=str(filepath),
            record_index=i,
        )
        if alert:
            alerts.append(alert)

        if limit and len(alerts) >= limit:
            break

    return alerts
