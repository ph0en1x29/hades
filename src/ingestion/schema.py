"""Unified Alert Schema v1 — Normalizes SIEM alerts from multiple vendors."""

from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import Optional
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


@dataclass
class AlertMetadata:
    vendor: str = ""
    device: str = ""
    category: str = ""


@dataclass
class UnifiedAlert:
    """Normalized alert schema for downstream processing."""

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
    ingested_at: str = field(default_factory=lambda: datetime.utcnow().isoformat())

    def to_dict(self) -> dict:
        return {
            "alert_id": self.alert_id,
            "timestamp": self.timestamp,
            "source": self.source.value,
            "severity": self.severity.value,
            "signature": self.signature,
            "signature_id": self.signature_id,
            "src_ip": self.src_ip,
            "src_port": self.src_port,
            "dst_ip": self.dst_ip,
            "dst_port": self.dst_port,
            "protocol": self.protocol,
            "raw_log": self.raw_log,
            "metadata": {
                "vendor": self.metadata.vendor,
                "device": self.metadata.device,
                "category": self.metadata.category,
            },
            "ingested_at": self.ingested_at,
        }
