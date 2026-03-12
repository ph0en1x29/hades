"""Hades data ingestion — SIEM normalization layer."""

from src.ingestion.schema import AlertMetadata, AlertSeverity, AlertSource, UnifiedAlert

__all__ = ["AlertMetadata", "AlertSeverity", "AlertSource", "UnifiedAlert"]
