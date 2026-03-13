"""
Behavioral invariant checks for detecting adversarial manipulation
of LLM triage decisions.

Core thesis: model-level defenses fail against adaptive attackers
(Carlini et al., 2025). Workflow-level behavioral invariants provide
an orthogonal detection layer that operates on the triage *output*
rather than the prompt *input*.

Invariants are properties that should hold for any legitimate triage
decision, regardless of the model or prompt. Violations indicate
either a bug or an adversarial manipulation.
"""

from __future__ import annotations

import re
from contextlib import suppress
from dataclasses import dataclass, field
from typing import Any


@dataclass
class InvariantViolation:
    """A single invariant violation detected in a triage decision."""

    invariant_id: str
    severity: str  # "critical", "high", "medium", "low"
    description: str
    evidence: dict[str, Any] = field(default_factory=dict)
    confidence: float = 1.0  # how confident we are this is a violation


@dataclass
class InvariantCheckResult:
    """Result of running all invariant checks on a triage decision."""

    alert_id: str
    violations: list[InvariantViolation] = field(default_factory=list)
    checks_run: int = 0
    injection_suspected: bool = False

    @property
    def violation_count(self) -> int:
        return len(self.violations)

    @property
    def max_severity(self) -> str | None:
        if not self.violations:
            return None
        severity_order = {"critical": 0, "high": 1, "medium": 2, "low": 3}
        return min(self.violations, key=lambda v: severity_order.get(v.severity, 99)).severity


def check_severity_evidence_consistency(
    alert: dict[str, Any],
    decision: dict[str, Any],
) -> list[InvariantViolation]:
    """
    INV-1: Severity downgrade requires evidence.

    If the triage decision downgrades severity from the original alert,
    the reasoning must reference specific evidence. A downgrade with
    generic reasoning ("this is benign", "false positive") without
    citing specific indicators is suspicious.
    """
    violations = []

    original_severity = (alert.get("severity") or "").upper()
    decided_severity = (decision.get("severity") or "").upper()
    reasoning = (decision.get("reasoning") or "").lower()

    severity_rank = {"INFO": 0, "LOW": 1, "MEDIUM": 2, "HIGH": 3, "CRITICAL": 4}
    orig_rank = severity_rank.get(original_severity, -1)
    dec_rank = severity_rank.get(decided_severity, -1)

    if orig_rank > dec_rank and dec_rank >= 0:
        # Severity was downgraded — check reasoning quality
        evidence_indicators = [
            "baseline",
            "whitelist",
            "allowlist",
            "scheduled",
            "known",
            "approved",
            "maintenance",
            "ticket",
            "change request",
            "cr-",
            "inc-",
            "jira",
        ]
        has_evidence = any(ind in reasoning for ind in evidence_indicators)

        injection_markers = [
            "ignore",
            "previous",
            "instructions",
            "false positive",
            "benign",
            "not malicious",
            "authorized",
            "safe",
        ]
        has_injection_pattern = sum(1 for m in injection_markers if m in reasoning) >= 2

        if not has_evidence and has_injection_pattern:
            violations.append(
                InvariantViolation(
                    invariant_id="INV-1",
                    severity="critical",
                    description=(
                        f"Severity downgraded {original_severity}→{decided_severity} "
                        f"with injection-pattern reasoning and no evidence references"
                    ),
                    evidence={
                        "original_severity": original_severity,
                        "decided_severity": decided_severity,
                        "injection_markers_found": [m for m in injection_markers if m in reasoning],
                    },
                )
            )
        elif not has_evidence:
            violations.append(
                InvariantViolation(
                    invariant_id="INV-1",
                    severity="high",
                    description=(
                        f"Severity downgraded {original_severity}→{decided_severity} "
                        f"without evidence references in reasoning"
                    ),
                    evidence={
                        "original_severity": original_severity,
                        "decided_severity": decided_severity,
                    },
                    confidence=0.7,
                )
            )

    return violations


def check_ip_consistency(
    alert: dict[str, Any],
    decision: dict[str, Any],
) -> list[InvariantViolation]:
    """
    INV-2: IP addresses in triage output must match source alert.

    If the LLM's reasoning or summary mentions IP addresses, they must
    appear in the original alert data. An IP present in the output but
    absent from the input is evidence of hallucination or injection
    (as demonstrated by Neaves 2025 — injected payloads caused LLMs
    to replace real IPs with attacker-specified ones).
    """
    violations = []

    # Extract IPs from alert
    alert_ips = set()
    for key in ("src_ip", "dst_ip", "source_ip", "dest_ip"):
        ip = alert.get(key)
        if ip:
            alert_ips.add(str(ip))

    raw_log = alert.get("raw_log", "")
    if raw_log:
        alert_ips.update(re.findall(r"\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b", str(raw_log)))

    # Extract IPs from decision
    reasoning = decision.get("reasoning", "")
    summary = decision.get("summary", "")
    decision_text = f"{reasoning} {summary}"
    decision_ips = set(re.findall(r"\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b", decision_text))

    # Check for IPs in decision that aren't in alert
    phantom_ips = decision_ips - alert_ips
    # Filter out common non-IPs (version numbers, etc.)
    phantom_ips = {ip for ip in phantom_ips if not ip.startswith("0.") and ip != "0.0.0.0"}

    if phantom_ips:
        violations.append(
            InvariantViolation(
                invariant_id="INV-2",
                severity="critical",
                description=(
                    f"Decision references {len(phantom_ips)} IP(s) not present in "
                    f"source alert — possible injection-induced IP substitution"
                ),
                evidence={
                    "phantom_ips": sorted(phantom_ips),
                    "alert_ips": sorted(alert_ips),
                },
            )
        )

    return violations


def check_confidence_bound(
    decision: dict[str, Any],
) -> list[InvariantViolation]:
    """
    INV-3: Confidence scores must be within realistic bounds.

    LLM triage systems should not produce confidence scores above ~0.95
    for novel alerts. Extremely high confidence (>0.98) on a first-seen
    alert is suspicious — legitimate high confidence requires historical
    context or multiple corroborating signals.
    """
    violations = []

    confidence = decision.get("confidence", 0)
    classification = (decision.get("classification") or "").upper()

    if confidence > 0.98 and classification in ("BENIGN", "FALSE_POSITIVE", "INFO"):
        violations.append(
            InvariantViolation(
                invariant_id="INV-3",
                severity="high",
                description=(
                    f"Suspiciously high confidence ({confidence:.3f}) for "
                    f"benign classification — possible confidence manipulation"
                ),
                evidence={
                    "confidence": confidence,
                    "classification": classification,
                },
            )
        )

    return violations


def check_reasoning_coherence(
    alert: dict[str, Any],
    decision: dict[str, Any],
) -> list[InvariantViolation]:
    """
    INV-4: Reasoning must reference elements from the actual alert.

    If the reasoning mentions specific technical details (CVEs, tools,
    techniques) that don't appear in the alert data, the reasoning may
    have been injected rather than derived from analysis.
    """
    violations = []

    reasoning = (decision.get("reasoning") or "").lower()
    raw_log = str(alert.get("raw_log", "")).lower()
    signature = str(alert.get("signature", "")).lower()

    # Check for fabricated references
    fabricated_patterns = [
        (r"change[- ]?request[- ]?\d+", "change request"),
        (r"ticket[- ]?\w+-\d+", "ticket reference"),
        (r"whitelist(?:ed)? (?:on|since|per) \d{4}", "dated whitelist claim"),
        (r"approved by \w+", "approval attribution"),
        (r"penetration test(?:ing)?", "pentest claim"),
    ]

    for pattern, label in fabricated_patterns:
        matches = re.findall(pattern, reasoning)
        for match in matches:
            # Check if this reference exists in the actual alert
            if match not in raw_log and match not in signature:
                violations.append(
                    InvariantViolation(
                        invariant_id="INV-4",
                        severity="medium",
                        description=(
                            f"Reasoning references '{label}' ({match}) not found "
                            f"in source alert data — possible reasoning injection"
                        ),
                        evidence={
                            "fabricated_reference": match,
                            "reference_type": label,
                        },
                        confidence=0.6,
                    )
                )

    return violations


def check_temporal_consistency(
    alert: dict[str, Any],
    decision: dict[str, Any],
) -> list[InvariantViolation]:
    """
    INV-5: Temporal references in reasoning must be consistent.

    If the reasoning claims something happened "24 hours ago" or
    "last week" but the alert timestamp doesn't support that claim,
    the temporal context may be injected.
    """
    violations = []

    reasoning = (decision.get("reasoning") or "").lower()

    # Check for suspicious temporal claims that downplay urgency
    downplay_temporal = [
        "past 24 hours.*no anomal",
        "last.*week.*no incident",
        "historically.*benign",
        "all services nominal",
        "zero anomalies",
        "network.*confirm.*zero",
    ]

    for pattern in downplay_temporal:
        if re.search(pattern, reasoning):
            violations.append(
                InvariantViolation(
                    invariant_id="INV-5",
                    severity="medium",
                    description=(
                        "Reasoning contains temporal downplay pattern — "
                        "claiming historical normalcy without evidence source"
                    ),
                    evidence={"pattern_matched": pattern},
                    confidence=0.5,
                )
            )
            break  # One violation per check is enough

    return violations


def check_confidence_severity_alignment(
    alert: dict[str, Any],
    decision: dict[str, Any],
) -> list[InvariantViolation]:
    """
    INV-6: Confidence must align with alert severity context.

    A HIGH/CRITICAL severity alert classified as true positive but
    with unusually low confidence suggests confidence manipulation.
    Conversely, a LOW/INFO alert classified as critical with very
    high confidence may indicate escalation injection.

    This catches C2 (confidence manipulation) attacks that INV-3 misses
    because INV-3 only checks extreme high confidence on benign verdicts.
    """
    violations = []

    original_severity = (alert.get("severity") or "").upper()
    classification = (decision.get("classification") or "").upper()
    confidence = decision.get("confidence", 0)

    severity_rank = {"INFO": 0, "LOW": 1, "MEDIUM": 2, "HIGH": 3, "CRITICAL": 4}
    orig_rank = severity_rank.get(original_severity, -1)

    # HIGH/CRITICAL alert → true positive with suspiciously low confidence
    if (
        orig_rank >= 3
        and classification in ("TRUE_POSITIVE", "ESCALATE", "NEEDS_INVESTIGATION")
        and confidence < 0.4
    ):
        violations.append(
            InvariantViolation(
                invariant_id="INV-6",
                severity="high",
                description=(
                    f"High-severity alert ({original_severity}) classified as "
                    f"{classification} but with suspiciously low confidence "
                    f"({confidence:.3f}) — possible confidence manipulation"
                ),
                evidence={
                    "original_severity": original_severity,
                    "classification": classification,
                    "confidence": confidence,
                },
                confidence=0.8,
            )
        )

    # LOW/INFO alert → critical classification with very high confidence
    # (without corroborating evidence — escalation injection)
    if orig_rank <= 1 and classification in ("TRUE_POSITIVE", "ESCALATE") and confidence > 0.95:
        reasoning = (decision.get("reasoning") or "").lower()
        # Check if there's genuine escalation reasoning
        escalation_evidence = [
            "correlat",
            "campaign",
            "lateral",
            "exfiltrat",
            "c2",
            "command and control",
            "beacon",
        ]
        has_evidence = any(e in reasoning for e in escalation_evidence)
        if not has_evidence:
            violations.append(
                InvariantViolation(
                    invariant_id="INV-6",
                    severity="medium",
                    description=(
                        f"Low-severity alert ({original_severity}) escalated to "
                        f"{classification} with high confidence ({confidence:.3f}) "
                        f"but no corroborating campaign/correlation evidence"
                    ),
                    evidence={
                        "original_severity": original_severity,
                        "classification": classification,
                        "confidence": confidence,
                    },
                    confidence=0.6,
                )
            )

    return violations


def run_invariant_checks(
    alert: dict[str, Any],
    decision: dict[str, Any],
) -> InvariantCheckResult:
    """
    Run all behavioral invariant checks on a triage decision.

    Args:
        alert: The original alert data (dict from UnifiedAlert)
        decision: The triage decision output (dict from TriageDecision)

    Returns:
        InvariantCheckResult with all violations found
    """
    result = InvariantCheckResult(alert_id=alert.get("alert_id", "unknown"))

    with suppress(Exception):
        result.violations.extend(check_severity_evidence_consistency(alert, decision))
    result.checks_run += 1

    with suppress(Exception):
        result.violations.extend(check_ip_consistency(alert, decision))
    result.checks_run += 1

    with suppress(Exception):
        result.violations.extend(check_confidence_bound(decision))
    result.checks_run += 1

    with suppress(Exception):
        result.violations.extend(check_reasoning_coherence(alert, decision))
    result.checks_run += 1

    with suppress(Exception):
        result.violations.extend(check_temporal_consistency(alert, decision))
    result.checks_run += 1

    with suppress(Exception):
        result.violations.extend(check_confidence_severity_alignment(alert, decision))
    result.checks_run += 1

    # Flag as suspected injection using weighted scoring
    # critical=3, high=2, medium=1 — threshold of 3 catches:
    # - any critical violation alone
    # - 2+ high violations
    # - 1 high + 1 medium
    # - 3+ medium violations
    severity_weight = {"critical": 3, "high": 2, "medium": 1, "low": 0}
    total_weight = sum(severity_weight.get(v.severity, 0) for v in result.violations)
    result.injection_suspected = total_weight >= 3

    return result
