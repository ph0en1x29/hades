"""Unified alert schema for the Hades v1 prototype."""

from dataclasses import asdict, dataclass, field
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
    FILE_REPLAY = "file_replay"
    NORMALIZED_JSON = "normalized_json"
    NORMALIZED_JSONL = "normalized_jsonl"


@dataclass
class AlertMetadata:
    vendor: str = ""
    device: str = ""
    category: str = ""
    message: str = ""


@dataclass
class AlertProvenance:
    dataset_name: str = ""
    source_path: str = ""
    source_record_id: Optional[str] = None
    source_record_index: Optional[int] = None
    original_format: str = ""
    parser_version: str = "alert_normalization_v1"
    transform_version: str = "alert_projection_v1"
    collected_at: str = field(default_factory=lambda: datetime.utcnow().isoformat())


@dataclass
class UnifiedAlert:
    """Normalized alert object used by the deterministic triage path."""

    alert_id: str = field(default_factory=lambda: str(uuid4()))
    timestamp: Optional[str] = None
    source: AlertSource = AlertSource.FILE_REPLAY
    severity: AlertSeverity = AlertSeverity.MEDIUM
    signature: Optional[str] = None
    signature_id: Optional[str] = None
    event_type: Optional[str] = None
    src_ip: Optional[str] = None
    src_port: Optional[int] = None
    dst_ip: Optional[str] = None
    dst_port: Optional[int] = None
    protocol: Optional[str] = None
    raw_log: str = ""
    metadata: AlertMetadata = field(default_factory=AlertMetadata)
    provenance: AlertProvenance = field(default_factory=AlertProvenance)
    ingested_at: str = field(default_factory=lambda: datetime.utcnow().isoformat())

    def to_dict(self) -> dict:
        payload = asdict(self)
        payload["source"] = self.source.value
        payload["severity"] = self.severity.value
        return payload
