"""Playbook Generator Agent — Produces incident response playbooks.

Based on NIST SP 800-61 incident response lifecycle:
  1. Preparation
  2. Detection & Analysis
  3. Containment, Eradication & Recovery
  4. Post-Incident Activity

Generates structured, actionable playbooks from classification results
and correlated evidence. Rule-based generation with optional LLM
enhancement when model server is available.
"""

from __future__ import annotations

import time
from typing import TYPE_CHECKING, Any
from uuid import uuid4

from src.agents.base import AgentResult, BaseAgent

if TYPE_CHECKING:
    from src.ingestion.schema import UnifiedAlert


# === Technique-specific response knowledge base ===

RESPONSE_KB: dict[str, dict[str, Any]] = {
    "T1003": {
        "title": "Credential Dumping Response",
        "severity": "critical",
        "containment": [
            {"action": "Isolate affected host from network", "priority": 1, "automated": True},
            {"action": "Force password reset for all accounts on compromised host", "priority": 1, "automated": True},
            {"action": "Revoke Kerberos TGTs for affected domain", "priority": 2, "automated": False},
            {"action": "Enable LSA protection (RunAsPPL) on domain controllers", "priority": 2, "automated": True},
        ],
        "eradication": [
            {"action": "Scan for credential harvesting tools (mimikatz, secretsdump)", "priority": 1, "automated": True},
            {"action": "Audit LSASS access patterns across all endpoints", "priority": 2, "automated": True},
            {"action": "Review scheduled tasks and services for persistence", "priority": 2, "automated": False},
        ],
        "recovery": [
            {"action": "Reset KRBTGT password (twice, 12hr apart)", "priority": 1, "automated": False},
            {"action": "Rotate all service account credentials", "priority": 1, "automated": False},
            {"action": "Re-image compromised host from known-good baseline", "priority": 2, "automated": False},
        ],
        "ioc_types": ["process_name", "hash", "ip"],
        "escalation": "Immediate — Tier 3 + IR team. Potential domain compromise.",
    },
    "T1021": {
        "title": "Lateral Movement via Remote Services",
        "severity": "high",
        "containment": [
            {"action": "Block SMB/RDP between compromised segments", "priority": 1, "automated": True},
            {"action": "Disable admin shares (C$, ADMIN$) on non-critical hosts", "priority": 2, "automated": True},
            {"action": "Enable network-level authentication for RDP", "priority": 2, "automated": True},
        ],
        "eradication": [
            {"action": "Audit lateral movement artifacts (Event 4648, 4624 Type 3)", "priority": 1, "automated": True},
            {"action": "Hunt for PsExec/SMBExec/WMIExec artifacts", "priority": 1, "automated": True},
        ],
        "recovery": [
            {"action": "Re-segment network to limit lateral paths", "priority": 1, "automated": False},
            {"action": "Deploy host-based firewall rules blocking unnecessary SMB", "priority": 2, "automated": True},
        ],
        "ioc_types": ["ip", "process_name", "hash"],
        "escalation": "Tier 2 — Active lateral movement indicates post-compromise stage.",
    },
    "T1059": {
        "title": "Command and Scripting Interpreter Response",
        "severity": "high",
        "containment": [
            {"action": "Enable Constrained Language Mode for PowerShell", "priority": 1, "automated": True},
            {"action": "Block script execution via AppLocker/WDAC", "priority": 1, "automated": True},
            {"action": "Kill suspicious interpreter processes on affected host", "priority": 1, "automated": True},
        ],
        "eradication": [
            {"action": "Review PowerShell script block logs (Event 4104)", "priority": 1, "automated": True},
            {"action": "Analyze command history for data staging or exfiltration", "priority": 2, "automated": False},
        ],
        "recovery": [
            {"action": "Deploy PowerShell transcription logging fleet-wide", "priority": 2, "automated": True},
            {"action": "Harden execution policy via Group Policy", "priority": 2, "automated": True},
        ],
        "ioc_types": ["hash", "domain", "url"],
        "escalation": "Tier 2 — Script-based execution often precedes data exfiltration.",
    },
    "T1071": {
        "title": "Application Layer C2 Protocol Response",
        "severity": "critical",
        "containment": [
            {"action": "Block identified C2 domains/IPs at perimeter firewall", "priority": 1, "automated": True},
            {"action": "DNS sinkhole known C2 domains", "priority": 1, "automated": True},
            {"action": "Isolate beaconing hosts", "priority": 1, "automated": True},
        ],
        "eradication": [
            {"action": "Extract and analyze C2 beacon configuration", "priority": 1, "automated": False},
            {"action": "Hunt for similar User-Agent strings across proxy logs", "priority": 2, "automated": True},
            {"action": "Check for scheduled beaconing patterns (jitter analysis)", "priority": 2, "automated": True},
        ],
        "recovery": [
            {"action": "Update IDS/IPS signatures for identified C2 patterns", "priority": 1, "automated": True},
            {"action": "Deploy JA3/JA4 fingerprint blocklists", "priority": 2, "automated": True},
        ],
        "ioc_types": ["domain", "ip", "url", "user_agent"],
        "escalation": "Immediate — Active C2 channel. Attacker has persistent access.",
    },
    "T1110": {
        "title": "Brute Force Response",
        "severity": "high",
        "containment": [
            {"action": "Enable account lockout after 5 failed attempts", "priority": 1, "automated": True},
            {"action": "Block source IPs at WAF/firewall", "priority": 1, "automated": True},
            {"action": "Enable CAPTCHA on targeted authentication endpoints", "priority": 2, "automated": True},
        ],
        "eradication": [
            {"action": "Verify no accounts were successfully compromised", "priority": 1, "automated": True},
            {"action": "Audit authentication logs for successful logins from brute-force IPs", "priority": 1, "automated": True},
        ],
        "recovery": [
            {"action": "Force password reset for any successfully accessed accounts", "priority": 1, "automated": True},
            {"action": "Deploy MFA on all external-facing services", "priority": 1, "automated": False},
        ],
        "ioc_types": ["ip", "username"],
        "escalation": "Tier 1 — Standard unless successful compromise detected, then Tier 2.",
    },
    "T1547": {
        "title": "Boot/Logon Autostart Persistence Response",
        "severity": "high",
        "containment": [
            {"action": "Disable identified autostart entries (Run keys, services)", "priority": 1, "automated": True},
            {"action": "Quarantine persistence payload files", "priority": 1, "automated": True},
        ],
        "eradication": [
            {"action": "Scan all endpoints for similar persistence mechanisms", "priority": 1, "automated": True},
            {"action": "Audit Startup folders, Run/RunOnce keys, scheduled tasks", "priority": 2, "automated": True},
            {"action": "Check for DLL search order hijacking", "priority": 2, "automated": False},
        ],
        "recovery": [
            {"action": "Deploy Sysmon or equivalent to monitor registry modifications", "priority": 2, "automated": True},
            {"action": "Harden autostart locations via Group Policy", "priority": 2, "automated": True},
        ],
        "ioc_types": ["hash", "file_path", "registry_key"],
        "escalation": "Tier 2 — Persistence means attacker intends to maintain access.",
    },
    "T1087": {
        "title": "Account Discovery Response",
        "severity": "medium",
        "containment": [
            {"action": "Monitor for subsequent credential access or lateral movement", "priority": 1, "automated": True},
            {"action": "Restrict LDAP/AD enumeration from non-admin accounts", "priority": 2, "automated": True},
        ],
        "eradication": [
            {"action": "Audit who queried AD user/group information", "priority": 1, "automated": True},
            {"action": "Review source process for legitimacy", "priority": 2, "automated": False},
        ],
        "recovery": [
            {"action": "Implement tiered admin model (PAW/PAM)", "priority": 2, "automated": False},
            {"action": "Deploy advanced AD auditing (4662, 4661 events)", "priority": 2, "automated": True},
        ],
        "ioc_types": ["process_name", "username"],
        "escalation": "Tier 1 — Reconnaissance activity; watch for escalation to credential access.",
    },
}

# Generic fallback for unknown techniques
GENERIC_RESPONSE: dict[str, Any] = {
    "title": "Unknown Technique Response",
    "severity": "medium",
    "containment": [
        {"action": "Isolate affected host for investigation", "priority": 1, "automated": True},
        {"action": "Capture volatile memory and disk image", "priority": 2, "automated": False},
    ],
    "eradication": [
        {"action": "Analyze alert context for IOCs", "priority": 1, "automated": False},
        {"action": "Cross-reference with threat intelligence feeds", "priority": 2, "automated": True},
    ],
    "recovery": [
        {"action": "Monitor for recurrence of same alert pattern", "priority": 2, "automated": True},
    ],
    "ioc_types": ["ip", "hash"],
    "escalation": "Tier 1 — Assess severity based on context and escalate as needed.",
}


def _extract_iocs(alert: "UnifiedAlert", ioc_types: list[str]) -> list[dict[str, str]]:
    """Extract IOCs from alert based on expected types."""
    iocs: list[dict[str, str]] = []
    if "ip" in ioc_types:
        if alert.src_ip:
            iocs.append({"type": "ip", "value": alert.src_ip, "role": "source"})
        if alert.dst_ip:
            iocs.append({"type": "ip", "value": alert.dst_ip, "role": "destination"})
    if "domain" in ioc_types and alert.signature:
        iocs.append({"type": "signature", "value": alert.signature, "role": "detection"})
    if "hash" in ioc_types and alert.raw_log:
        # Extract SHA256-like patterns from raw log
        import re
        hashes = re.findall(r"[A-Fa-f0-9]{64}", alert.raw_log)
        for h in hashes[:3]:
            iocs.append({"type": "sha256", "value": h, "role": "artifact"})
    return iocs


def _determine_severity(
    classification: str,
    alert_severity: str,
    chain_count: int,
) -> str:
    """Determine playbook severity from classification + context."""
    if classification in ("true_positive", "escalate") and chain_count > 0:
        return "critical"
    if classification in ("true_positive", "escalate"):
        return "high"
    if alert_severity in ("critical", "high"):
        return "high"
    return "medium"


def generate_playbook(
    alert: "UnifiedAlert",
    classification: str = "unknown",
    mitre_techniques: list[str] | None = None,
    correlated_events: list[dict[str, Any]] | None = None,
    attack_chains: list[dict[str, Any]] | None = None,
) -> dict[str, Any]:
    """Generate a NIST 800-61 incident response playbook.

    This is the rule-based generator. It maps techniques to known
    response procedures and adapts severity based on correlation context.
    """
    techniques = mitre_techniques or []
    events = correlated_events or []
    chains = attack_chains or []
    playbook_id = str(uuid4())

    # Find best matching technique KB entry
    kb_entry = GENERIC_RESPONSE
    for tech in techniques:
        prefix = tech.split(".")[0] if "." in tech else tech
        if prefix in RESPONSE_KB:
            kb_entry = RESPONSE_KB[prefix]
            break

    severity = _determine_severity(
        classification,
        alert.severity.value,
        len(chains),
    )

    # Build step list from KB phases
    steps: list[dict[str, Any]] = []
    for phase_name in ("containment", "eradication", "recovery"):
        for step in kb_entry.get(phase_name, []):
            steps.append({
                "phase": phase_name,
                "action": step["action"],
                "priority": step["priority"],
                "automated": step.get("automated", False),
            })

    # Add post-incident steps
    steps.append({
        "phase": "post_incident",
        "action": "Document incident timeline and response actions",
        "priority": 1,
        "automated": False,
    })
    steps.append({
        "phase": "post_incident",
        "action": "Update detection rules based on observed TTPs",
        "priority": 2,
        "automated": False,
    })
    if chains:
        steps.append({
            "phase": "post_incident",
            "action": f"Review {len(chains)} detected attack chain(s) for coverage gaps",
            "priority": 1,
            "automated": False,
        })

    # Extract IOCs
    iocs = _extract_iocs(alert, kb_entry.get("ioc_types", ["ip"]))

    # Build MITRE references
    references = [
        f"https://attack.mitre.org/techniques/{t.replace('.', '/')}/"
        for t in techniques[:5]
    ]

    return {
        "playbook_id": playbook_id,
        "title": kb_entry["title"],
        "severity": severity,
        "classification": classification,
        "mitre_techniques": techniques,
        "steps": steps,
        "iocs": iocs,
        "escalation": kb_entry.get("escalation", "Assess and escalate as needed."),
        "correlated_event_count": len(events),
        "attack_chain_count": len(chains),
        "references": references,
    }


class PlaybookAgent(BaseAgent):
    """Generates structured incident response playbooks.

    Uses technique-specific knowledge base for rule-based generation.
    When a model server is available, can optionally enhance with
    LLM-generated context-aware recommendations.
    """

    @property
    def name(self) -> str:
        return "playbook"

    async def run(
        self,
        alert: "UnifiedAlert",
        context: dict[str, Any] | None = None,
    ) -> AgentResult:
        """Generate an incident response playbook."""
        start = time.monotonic()

        try:
            ctx = context or {}
            playbook = generate_playbook(
                alert=alert,
                classification=ctx.get("classification", "unknown"),
                mitre_techniques=ctx.get("mitre_techniques", []),
                correlated_events=ctx.get("correlated_events", []),
                attack_chains=ctx.get("attack_chains", []),
            )
            elapsed_ms = int((time.monotonic() - start) * 1000)

            return AgentResult(
                agent_name=self.name,
                success=True,
                data=playbook,
                latency_ms=elapsed_ms,
            )

        except Exception as exc:
            elapsed_ms = int((time.monotonic() - start) * 1000)
            return AgentResult(
                agent_name=self.name,
                success=False,
                error=str(exc),
                latency_ms=elapsed_ms,
            )
