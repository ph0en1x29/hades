"""Defense mechanisms against adversarial injection in LLM triage."""

from __future__ import annotations

import re
import secrets
from abc import ABC, abstractmethod
from copy import deepcopy
from dataclasses import dataclass, field
from typing import Any


@dataclass
class DefenseResult:
    """Result of applying a defense mechanism to an alert."""

    defense_name: str
    alert_modified: bool
    fields_sanitized: list[str] = field(default_factory=list)
    injection_detected: bool = False
    confidence: float = 0.0
    notes: str = ""


class Defense(ABC):
    """Base class for defense mechanisms."""

    name: str

    @abstractmethod
    def apply(self, alert: dict[str, Any]) -> tuple[dict[str, Any], DefenseResult]:
        """Apply defense to an alert. Returns (modified_alert, result)."""
        ...


class SanitizationDefense(Defense):
    """D1 — Input sanitization: strip suspicious patterns from log fields."""

    name = "sanitization"

    # Patterns that may indicate prompt injection
    SUSPICIOUS_PATTERNS = [
        r"(?i)ignore\s+(previous|above|prior)\s+(instructions?|context)",
        r"(?i)classify\s+as\s+(benign|safe|harmless|false.positive)",
        r"(?i)confidence\s*[:=]\s*0?\.\d{2,}",
        r"(?i)no\s+action\s+required",
        r"(?i)severity\s*[:=]\s*(none|low|info)",
        r"(?i)system\s+note\s*:",
        r"(?i)pre-screening\s+result",
        r"(?i)authorized\s+(scanner|audit|pentest)",
        r"(?i)whitelist|approved.list",
        r"(?i)override|overrule",
    ]

    # Fields that originate from network traffic (attacker-controllable)
    UNTRUSTED_FIELDS = [
        "http.user_agent",
        "http.referer",
        "http.x_forwarded_for",
        "dns.query",
        "source.hostname",
        "snmp.community",
        "email.subject",
        "email.from",
        "tls.server.cn",
        "tls.server.san",
        "ssh.banner",
        "ldap.bind_dn",
        "url.full",
        "url.path",
    ]

    def __init__(self, level: str = "moderate") -> None:
        """Level: strict (truncate), moderate (flag+strip), permissive (flag only)."""
        self.level = level

    def apply(self, alert: dict[str, Any]) -> tuple[dict[str, Any], DefenseResult]:
        sanitized = deepcopy(alert)
        result = DefenseResult(defense_name=self.name, alert_modified=False)

        for field_path in self.UNTRUSTED_FIELDS:
            value = self._get_nested(sanitized, field_path)
            if not isinstance(value, str):
                continue

            for pattern in self.SUSPICIOUS_PATTERNS:
                if re.search(pattern, value):
                    result.injection_detected = True
                    result.fields_sanitized.append(field_path)
                    result.confidence = max(result.confidence, 0.8)

                    if self.level == "strict":
                        self._set_nested(sanitized, field_path, "[SANITIZED]")
                        result.alert_modified = True
                    elif self.level == "moderate":
                        cleaned = re.sub(pattern, "[REDACTED]", value)
                        self._set_nested(sanitized, field_path, cleaned)
                        result.alert_modified = True
                    break  # one match per field is enough

        return sanitized, result

    @staticmethod
    def _get_nested(d: dict[str, Any], path: str) -> Any:
        keys = path.split(".")
        for k in keys:
            if isinstance(d, dict) and k in d:
                d = d[k]
            else:
                return None
        return d

    @staticmethod
    def _set_nested(d: dict[str, Any], path: str, value: Any) -> None:
        keys = path.split(".")
        for k in keys[:-1]:
            if k not in d:
                return
            d = d[k]
        d[keys[-1]] = value


class StructuredPromptDefense(Defense):
    """D2 — Structured prompt architecture: separate data from instructions."""

    name = "structured_prompt"

    def apply(self, alert: dict[str, Any]) -> tuple[dict[str, Any], DefenseResult]:
        """Wrap string leaves with field markers while preserving alert structure."""
        result = DefenseResult(defense_name=self.name, alert_modified=True)
        structured = self._structure_value(alert, path="", result=result)
        return structured, result

    def _structure_value(
        self,
        value: Any,
        *,
        path: str,
        result: DefenseResult,
    ) -> Any:
        if isinstance(value, dict):
            return {
                key: self._structure_value(
                    item,
                    path=self._join_path(path, key),
                    result=result,
                )
                for key, item in value.items()
            }

        if isinstance(value, list):
            return [
                self._structure_value(
                    item,
                    path=f"{path}[{index}]",
                    result=result,
                )
                for index, item in enumerate(value)
            ]

        if isinstance(value, str):
            field_path = path or "root"
            result.fields_sanitized.append(field_path)
            return f"[FIELD:{field_path}] {value} [/FIELD]"

        return value

    @staticmethod
    def _join_path(prefix: str, key: str) -> str:
        return f"{prefix}.{key}" if prefix else key


class CanaryDefense(Defense):
    """D5 — Canary token detection: detect cross-boundary influence."""

    name = "canary_token"

    CANARY_PREFIX = "CANARY_"
    CANARY_FIELD = "prompt_boundary_canary"

    def __init__(self, canary_id: str | None = None) -> None:
        self.canary_id = canary_id or f"{self.CANARY_PREFIX}{secrets.token_hex(4)}"

    def apply(self, alert: dict[str, Any]) -> tuple[dict[str, Any], DefenseResult]:
        """Inject a canary into alert metadata so output leakage can be detected."""
        instrumented = deepcopy(alert)
        metadata = instrumented.get("metadata")
        metadata_copy = dict(metadata) if isinstance(metadata, dict) else {}
        metadata_copy[self.CANARY_FIELD] = self.canary_id
        instrumented["metadata"] = metadata_copy

        result = DefenseResult(
            defense_name=self.name,
            alert_modified=True,
            fields_sanitized=[f"metadata.{self.CANARY_FIELD}"],
            notes=(
                "Canary inserted into alert data boundary. "
                f"Check model output for leaked token {self.canary_id}."
            ),
        )
        return instrumented, result

    def check_output(self, model_output: str) -> bool:
        """Check if model output references the canary (indicates cross-boundary influence)."""
        return self.canary_id in model_output
