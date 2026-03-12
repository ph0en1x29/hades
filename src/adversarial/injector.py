"""Adversarial payload injector for benchmark alerts.

Takes clean benchmark alerts and produces adversarial variants by
injecting prompt injection payloads into realistic log fields.
This is the core of experiments E2-E8.

The injector respects field constraints (max length, encoding, SIEM survival)
and produces alerts that would look realistic in a production SIEM.
"""

from __future__ import annotations

import copy
import json
from dataclasses import dataclass
from enum import Enum
from typing import Any

from src.adversarial.payloads import TEMPLATES_BY_CLASS, AttackClass, PayloadTemplate
from src.adversarial.vectors import INJECTION_VECTORS, InjectionVector
from src.ingestion.schema import UnifiedAlert


class EncodingStrategy(Enum):
    """How the payload is encoded within the log field."""
    PLAINTEXT = "plaintext"           # Direct injection, no encoding
    UNDERSCORE = "underscore"         # Spaces → underscores (Neaves2025 style)
    URL_ENCODED = "url_encoded"       # %20-style encoding
    BASE64_FRAGMENT = "base64_fragment"  # Partial base64 that looks like encoded data


@dataclass
class InjectionResult:
    """Result of injecting a payload into an alert."""
    original_alert: UnifiedAlert
    adversarial_alert: UnifiedAlert
    vector: InjectionVector
    attack_class: AttackClass
    encoding: EncodingStrategy
    payload_text: str
    injection_field: str
    payload_survived: bool  # Would this survive SIEM normalization?


def encode_payload(text: str, strategy: EncodingStrategy) -> str:
    """Encode a payload using the specified strategy."""
    if strategy == EncodingStrategy.PLAINTEXT:
        return text
    elif strategy == EncodingStrategy.UNDERSCORE:
        return text.replace(" ", "_")
    elif strategy == EncodingStrategy.URL_ENCODED:
        return text.replace(" ", "%20").replace(",", "%2C")
    elif strategy == EncodingStrategy.BASE64_FRAGMENT:
        # Wrap in realistic-looking base64 context
        import base64
        encoded = base64.b64encode(text.encode()).decode()
        return f"data={encoded}"
    return text


def truncate_payload(payload: str, max_length: int) -> str:
    """Truncate payload to fit field constraints while keeping it functional."""
    if len(payload) <= max_length:
        return payload
    # Try to truncate at a word boundary
    truncated = payload[:max_length]
    last_space = truncated.rfind(" ")
    if last_space > max_length * 0.6:
        return truncated[:last_space]
    return truncated


def inject_into_sysmon_alert(
    alert: UnifiedAlert,
    vector: InjectionVector,
    payload: str,
) -> tuple[UnifiedAlert, str]:
    """Inject a payload into a Sysmon-based alert's raw_log.

    Returns (modified_alert, injection_field_name).
    """
    adv = copy.copy(alert)
    raw = json.loads(alert.raw_log)

    # Map vector to Sysmon EventData fields
    field_map: dict[str, list[str]] = {
        "http.user_agent": ["UserAgent", "CommandLine"],
        "http.referer": ["CommandLine"],
        "source.hostname": ["SourceHostname", "Computer"],
        "source.user": ["User", "TargetUserName"],
        "winlog.event_data.TargetUserName": ["TargetUserName", "User"],
        "dns.query": ["QueryName", "DestinationHostname"],
        "ssh.banner": ["CommandLine"],
        "ldap.bind_dn": ["TargetUserName"],
    }

    target_fields = field_map.get(vector.log_field, ["CommandLine"])
    injection_field = None

    for field in target_fields:
        if field in raw:
            # Append payload to existing field value
            original = raw[field]
            raw[field] = f"{original} {payload}"
            injection_field = field
            break

    if injection_field is None:
        # If no matching field exists, inject into first available
        injection_field = target_fields[0]
        raw[injection_field] = payload

    adv.raw_log = json.dumps(raw)
    return adv, injection_field


def inject_into_suricata_alert(
    alert: UnifiedAlert,
    vector: InjectionVector,
    payload: str,
) -> tuple[UnifiedAlert, str]:
    """Inject a payload into a Suricata-based alert's raw_log."""
    adv = copy.copy(alert)
    raw = json.loads(alert.raw_log)
    http = raw.get("http", {})

    field_map: dict[str, str] = {
        "http.user_agent": "http_user_agent",
        "http.referer": "http_referer",
        "dns.query": "hostname",
    }

    target_field = field_map.get(vector.log_field, "http_user_agent")
    injection_field = f"http.{target_field}"

    if target_field in http:
        http[target_field] = f"{http[target_field]} {payload}"
    else:
        http[target_field] = payload

    # Also update request_headers if present
    if "request_headers" in http:
        for header in http["request_headers"]:
            if header.get("name", "").lower() == "user-agent" and target_field == "http_user_agent":
                header["value"] = http[target_field]

    raw["http"] = http
    adv.raw_log = json.dumps(raw)
    return adv, injection_field


def generate_adversarial_variants(
    alert: UnifiedAlert,
    vectors: list[InjectionVector] | None = None,
    attack_classes: list[AttackClass] | None = None,
    encodings: list[EncodingStrategy] | None = None,
) -> list[InjectionResult]:
    """Generate adversarial variants of a clean alert.

    Produces one variant per (vector × attack_class × encoding) combination,
    respecting field length constraints.
    """
    if vectors is None:
        vectors = INJECTION_VECTORS
    if attack_classes is None:
        attack_classes = list(AttackClass)
    if encodings is None:
        encodings = [EncodingStrategy.PLAINTEXT, EncodingStrategy.UNDERSCORE]

    results: list[InjectionResult] = []
    is_suricata = alert.event_type and alert.event_type.startswith("suricata_")

    for vector in vectors:
        for attack_class in attack_classes:
            # Find matching payload template
            templates = TEMPLATES_BY_CLASS.get(attack_class, [])
            if not templates:
                continue

            payload_text = templates[0]  # Templates are plain strings

            for encoding in encodings:
                # Encode and truncate
                raw_payload = payload_text
                encoded = encode_payload(raw_payload, encoding)
                truncated = truncate_payload(encoded, vector.max_payload_length)

                # Inject into alert
                if is_suricata:
                    adv_alert, field = inject_into_suricata_alert(
                        alert, vector, truncated
                    )
                else:
                    adv_alert, field = inject_into_sysmon_alert(
                        alert, vector, truncated
                    )

                # Estimate SIEM survival
                survived = len(truncated) <= vector.max_payload_length

                results.append(InjectionResult(
                    original_alert=alert,
                    adversarial_alert=adv_alert,
                    vector=vector,
                    attack_class=attack_class,
                    encoding=encoding,
                    payload_text=truncated,
                    injection_field=field,
                    payload_survived=survived,
                ))

    return results
