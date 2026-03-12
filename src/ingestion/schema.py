"""Unified Alert Schema v1 — Normalizes SIEM alerts from multiple vendors."""

from __future__ import annotations

import json
from dataclasses import asdict, dataclass, field
from datetime import UTC, datetime
from enum import Enum
from typing import Optional, Self
from uuid import uuid4


class AlertSeverity(Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


class AlertSource(Enum):
    SPLUNK = "splunk"
    ELASTIC = "elastic"
    QRADAR = "qradar"
    FILE = "file"


@dataclass(frozen=True, slots=True)
class AlertMetadata:
    """Vendor-specific metadata attached to an alert."""

    vendor: str = ""
    device: str = ""
    category: str = ""


@dataclass(slots=True)
class UnifiedAlert:
    """Normalized alert for downstream processing.

    All SIEM connectors produce this format, regardless of vendor.
    Immutable after ingestion — downstream agents reference by alert_id.
    """

    alert_id: str = field(default_factory=lambda: str(uuid4()))
    timestamp: str = ""
    source: AlertSource = AlertSource.FILE
    severity: AlertSeverity = AlertSeverity.MEDIUM
    signature: str = ""
    signature_id: str = ""
    src_ip: str = ""
    src_port: Optional[int] = None
    dst_ip: str = ""
    dst_port: Optional[int] = None
    protocol: str = "TCP"
    raw_log: str = ""
    metadata: AlertMetadata = field(default_factory=AlertMetadata)
    ingested_at: str = field(
        default_factory=lambda: datetime.now(UTC).isoformat()
    )

    def to_dict(self) -> dict:
        """Serialize to plain dict (JSON-safe)."""
        d = asdict(self)
        d["source"] = self.source.value
        d["severity"] = self.severity.value
        return d

    def to_json(self) -> str:
        """Serialize to JSON string."""
        return json.dumps(self.to_dict())

    @classmethod
    def from_dict(cls, data: dict) -> Self:
        """Deserialize from a plain dict."""
        return cls(
            alert_id=data.get("alert_id", str(uuid4())),
            timestamp=data.get("timestamp", ""),
            source=AlertSource(data["source"]) if "source" in data else AlertSource.FILE,
            severity=AlertSeverity(data["severity"]) if "severity" in data else AlertSeverity.MEDIUM,
            signature=data.get("signature", ""),
            signature_id=data.get("signature_id", ""),
            src_ip=data.get("src_ip", ""),
            src_port=data.get("src_port"),
            dst_ip=data.get("dst_ip", ""),
            dst_port=data.get("dst_port"),
            protocol=data.get("protocol", "TCP"),
            raw_log=data.get("raw_log", ""),
            metadata=AlertMetadata(**data.get("metadata", {})),
            ingested_at=data.get("ingested_at", datetime.now(UTC).isoformat()),
        )

    @classmethod
    def from_json(cls, raw: str) -> Self:
        """Deserialize from a JSON string."""
        return cls.from_dict(json.loads(raw))
