"""Unified alert schema for the scoped Hades v1 prototype."""

from __future__ import annotations

import json
from dataclasses import asdict, dataclass, field
from datetime import UTC, datetime
from enum import Enum
from typing import Any, Self
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


@dataclass(frozen=True, slots=True)
class AlertMetadata:
    """Vendor-specific metadata attached to an alert."""

    vendor: str = ""
    device: str = ""
    category: str = ""
    message: str = ""


@dataclass(frozen=True, slots=True)
class AlertProvenance:
    """Information needed to trace a normalized alert back to its origin."""

    dataset_name: str = ""
    source_path: str = ""
    source_record_id: str | None = None
    source_record_index: int | None = None
    original_format: str = ""
    parser_version: str = "alert_normalization_v1"
    transform_version: str = "alert_projection_v1"
    collected_at: str = field(default_factory=lambda: datetime.now(UTC).isoformat())


@dataclass(slots=True)
class UnifiedAlert:
    """Normalized alert for the deterministic triage pipeline."""

    alert_id: str = field(default_factory=lambda: str(uuid4()))
    timestamp: str | None = None
    source: AlertSource = AlertSource.FILE_REPLAY
    severity: AlertSeverity = AlertSeverity.MEDIUM
    signature: str | None = None
    signature_id: str | None = None
    event_type: str | None = None
    src_ip: str | None = None
    src_port: int | None = None
    dst_ip: str | None = None
    dst_port: int | None = None
    protocol: str | None = None
    raw_log: str = ""
    metadata: AlertMetadata = field(default_factory=AlertMetadata)
    provenance: AlertProvenance = field(default_factory=AlertProvenance)
    ingested_at: str = field(
        default_factory=lambda: datetime.now(UTC).isoformat()
    )

    def to_dict(self) -> dict[str, Any]:
        """Serialize to plain dict (JSON-safe)."""
        d = asdict(self)
        d["source"] = self.source.value
        d["severity"] = self.severity.value
        return d

    def to_json(self) -> str:
        """Serialize to JSON string."""
        return json.dumps(self.to_dict())

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> Self:
        """Deserialize from a plain dict."""
        return cls(
            alert_id=data.get("alert_id", str(uuid4())),
            timestamp=data.get("timestamp"),
            source=AlertSource(data["source"]) if "source" in data else AlertSource.FILE_REPLAY,
            severity=AlertSeverity(data["severity"]) if "severity" in data else AlertSeverity.MEDIUM,
            signature=data.get("signature"),
            signature_id=data.get("signature_id"),
            event_type=data.get("event_type"),
            src_ip=data.get("src_ip"),
            src_port=data.get("src_port"),
            dst_ip=data.get("dst_ip"),
            dst_port=data.get("dst_port"),
            protocol=data.get("protocol"),
            raw_log=data.get("raw_log", ""),
            metadata=AlertMetadata(**data.get("metadata", {})),
            provenance=AlertProvenance(**data.get("provenance", {})),
            ingested_at=data.get("ingested_at", datetime.now(UTC).isoformat()),
        )

    @classmethod
    def from_json(cls, raw: str) -> Self:
        """Deserialize from a JSON string."""
        return cls.from_dict(json.loads(raw))
