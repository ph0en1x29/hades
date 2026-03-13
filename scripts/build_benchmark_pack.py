#!/usr/bin/env python3
"""Build the Hades benchmark alert pack from Splunk Attack Data.

Produces a validated JSONL file of UnifiedAlerts across multiple MITRE
techniques, with full provenance and benchmark context. This is the
"benchmark of record" that satisfies Dr. Liu's dataset adequacy requirement.

Usage:
    python3 scripts/build_benchmark_pack.py
"""

from __future__ import annotations

import json
import sys
from collections import Counter
from pathlib import Path

# Project imports
sys.path.insert(0, str(Path(__file__).parent.parent))
from src.evaluation.dataset_gate import benchmark_contract_issues
from src.ingestion.parsers.splunk_suricata import load_suricata_log
from src.ingestion.parsers.splunk_sysmon import load_sysmon_log
from src.ingestion.parsers.windows_security import load_windows_security_log

DATA_DIR = Path(__file__).parent.parent / "data" / "datasets" / "splunk_attack_data"
OUTPUT_DIR = Path(__file__).parent.parent / "data" / "benchmark"
SKIP_MARKER = "SKIPPED:"

# Benchmark configuration: technique → {parser, file, rule_name, tactic, max_events}
BENCHMARK_TECHNIQUES = {
    "T1003.001": {
        "tactic": "TA0006 Credential Access",
        "name": "LSASS Credential Dumping",
        "parser": "sysmon",
        "file": "T1003.001/windows-sysmon.log",
        "rule_name": "Dump LSASS via ProcDump",
        "max_events": 500,
    },
    "T1110.001": {
        "tactic": "TA0006 Credential Access",
        "name": "RDP Brute Force",
        "parser": "sysmon",
        "file": "T1110.001/sysmon.log",
        "rule_name": "Windows Multiple Account Login Failures",
        "max_events": 500,
    },
    "T1087.001": {
        "tactic": "TA0007 Discovery",
        "name": "Local Account Discovery",
        "parser": "sysmon",
        "file": "T1087.001/windows-sysmon.log",
        "rule_name": "Local Account Discovery via net.exe",
        "max_events": 500,
    },
    "T1021.002": {
        "tactic": "TA0008 Lateral Movement",
        "name": "SMB Admin Shares (impacket smbexec)",
        "parser": "winsec",
        "file": "T1021.002/windows_security_xml.log",
        "rule_name": "Impacket Lateral Movement smbexec",
        "max_events": 500,
    },
    "T1027": {
        "tactic": "TA0005 Defense Evasion",
        "name": "Obfuscated Files or Information",
        "parser": "sysmon",
        "file": "T1027/windows-sysmon.log",
        "rule_name": "Obfuscation Techniques",
        "max_events": 500,
    },
    "T1053.005": {
        "tactic": "TA0003 Persistence",
        "name": "Scheduled Task",
        "parser": "sysmon",
        "file": "T1053.005/windows-sysmon.log",
        "rule_name": "Scheduled Task Creation",
        "max_events": 500,
    },
    "T1547.001": {
        "tactic": "TA0003 Persistence",
        "name": "Registry Run Keys",
        "parser": "sysmon",
        "file": "T1547.001/windows-sysmon.log",
        "rule_name": "Registry Keys Used For Persistence",
        "max_events": 500,
    },
    "T1071.001": {
        "tactic": "TA0011 Command and Control",
        "name": "HTTP C2 Traffic",
        "parser": "suricata",
        "file": "T1071.001/suricata_c2.log",
        "rule_name": "Suspicious HTTP User-Agent",
        "max_events": 500,
    },
    "T1036.003": {
        "tactic": "TA0005 Defense Evasion",
        "name": "Masquerading: Rename System Utilities",
        "parser": "sysmon",
        "file": "T1036.003/windows-sysmon.log",
        "rule_name": "Renamed System Utility Execution",
        "max_events": 500,
    },
    "T1105": {
        "tactic": "TA0011 Command and Control",
        "name": "Ingress Tool Transfer",
        "parser": "sysmon",
        "file": "T1105/windows-sysmon.log",
        "rule_name": "Remote File Download via Ingress Tool",
        "max_events": 500,
    },
    "T1569.002": {
        "tactic": "TA0002 Execution",
        "name": "Service Execution",
        "parser": "sysmon",
        "file": "T1569.002/windows-sysmon.log",
        "rule_name": "Service Execution via sc.exe",
        "max_events": 500,
    },
    "T1218.011": {
        "tactic": "TA0005 Defense Evasion",
        "name": "Rundll32 Signed Binary Proxy Execution",
        "parser": "sysmon",
        "file": "T1218.011/windows-sysmon.log",
        "rule_name": "Suspicious Rundll32 Execution",
        "max_events": 500,
    },
    # --- Wave 2: Expanded coverage ---
    "T1055.001": {
        "tactic": "TA0005 Defense Evasion",
        "name": "Process Injection (Cobalt Strike)",
        "parser": "sysmon",
        "file": "T1055.001/windows-sysmon.log",
        "rule_name": "Cobalt Strike Process Injection",
        "max_events": 500,
    },
    "T1204.002": {
        "tactic": "TA0002 Execution",
        "name": "User Execution: Malicious File",
        "parser": "sysmon",
        "file": "T1204.002/windows-sysmon.log",
        "rule_name": "Suspicious File Execution by User",
        "max_events": 500,
    },
    "T1562.001": {
        "tactic": "TA0005 Defense Evasion",
        "name": "Impair Defenses: Disable Security Tools",
        "parser": "sysmon",
        "file": "T1562.001/windows-sysmon.log",
        "rule_name": "Security Tool Disabled or Modified",
        "max_events": 500,
    },
    "T1543.003": {
        "tactic": "TA0003 Persistence",
        "name": "Create or Modify Windows Service",
        "parser": "sysmon",
        "file": "T1543.003/windows-sysmon.log",
        "rule_name": "Suspicious Windows Service Creation",
        "max_events": 500,
    },
    "T1548.002": {
        "tactic": "TA0004 Privilege Escalation",
        "name": "Bypass UAC",
        "parser": "sysmon",
        "file": "T1548.002/windows-sysmon.log",
        "rule_name": "UAC Bypass Attempt",
        "max_events": 500,
    },
    # --- Wave 3: Expanded tactics and parser diversity ---
    "T1059.001": {
        "tactic": "TA0002 Execution",
        "name": "PowerShell Script Execution",
        "parser": "sysmon",
        "file": "T1059.001/windows-sysmon.log",
        "rule_name": "Suspicious PowerShell Command",
        "max_events": 500,
    },
    "T1566.001": {
        "tactic": "TA0001 Initial Access",
        "name": "Spearphishing Attachment",
        "parser": "sysmon",
        "file": "T1566.001/windows-sysmon-datasets2.log",
        "rule_name": "Spearphishing Attachment Execution",
        "max_events": 500,
    },
    "T1003.003": {
        "tactic": "TA0006 Credential Access",
        "name": "NTDS.dit Credential Dumping",
        "parser": "sysmon",
        "file": "T1003.003/windows-sysmon.log",
        "rule_name": "NTDS.dit Access for Credential Extraction",
        "max_events": 500,
    },
    "T1047": {
        "tactic": "TA0002 Execution",
        "name": "WMI Command Execution",
        "parser": "sysmon",
        "file": "T1047/windows-sysmon.log",
        "rule_name": "WMI Process Execution",
        "max_events": 500,
    },
    "T1136.001": {
        "tactic": "TA0003 Persistence",
        "name": "Create Local Account",
        "parser": "sysmon",
        "file": "T1136.001/windows-sysmon.log",
        "rule_name": "New Local User Created",
        "max_events": 500,
    },
    "T1082": {
        "tactic": "TA0007 Discovery",
        "name": "System Information Discovery",
        "parser": "sysmon",
        "file": "T1082/windows-sysmon.log",
        "rule_name": "System Information Enumeration",
        "max_events": 500,
    },
    "T1018": {
        "tactic": "TA0007 Discovery",
        "name": "Remote System Discovery",
        "parser": "sysmon",
        "file": "T1018/windows-sysmon.log",
        "rule_name": "Remote System Network Discovery",
        "max_events": 500,
    },
    "T1112": {
        "tactic": "TA0005 Defense Evasion",
        "name": "Modify Registry",
        "parser": "sysmon",
        "file": "T1112/windows-sysmon.log",
        "rule_name": "Suspicious Registry Modification",
        "max_events": 500,
    },
    "T1053.005_sec": {
        "tactic": "TA0003 Persistence",
        "name": "Scheduled Task (Security Event Log)",
        "parser": "winsec",
        "file": "T1053.005/4698_windows-security.log",
        "rule_name": "Windows Security Event 4698 Scheduled Task",
        "max_events": 500,
    },
    "T1021.002_sec": {
        "tactic": "TA0008 Lateral Movement",
        "name": "SMB Lateral Movement (Security Event Log)",
        "parser": "winsec",
        "file": "T1021.002/windows_security_xml.log",
        "rule_name": "Impacket smbexec Process Creation",
        "max_events": 500,
    },
    "T1059.001_ps": {
        "tactic": "TA0002 Execution",
        "name": "PowerShell Script Block Logging",
        "parser": "winsec",
        "file": "T1059.001/windows-powershell-xml.log",
        "rule_name": "PowerShell Script Block Execution",
        "max_events": 500,
    },
    "T1071.001_malware": {
        "tactic": "TA0011 Command and Control",
        "name": "Suricata Malware HTTP Traffic",
        "parser": "suricata",
        "file": "T1071.001/suricata_malware.log",
        "rule_name": "Malware HTTP Communication",
        "max_events": 500,
    },
    # --- Additional Lateral Movement (closing tactic gap) ---
    "T1021.006": {
        "tactic": "TA0008 Lateral Movement",
        "name": "Windows Remote Management (WinRM LOLBAS)",
        "parser": "sysmon",
        "file": "T1021.006/windows-sysmon.log",
        "rule_name": "WinRM Lateral Movement via Living-off-the-Land",
        "max_events": 500,
    },
    "T1550.002": {
        "tactic": "TA0008 Lateral Movement",
        "name": "Pass the Hash (Mimikatz/Atomic)",
        "parser": "sysmon",
        "file": "T1550.002/windows-sysmon.log",
        "rule_name": "Pass the Hash Authentication",
        "max_events": 500,
    },
    # NOTE: BETH synthetic data validates parser coverage but is
    # engineering_scaffold — excluded from benchmark_of_record pack.
    # Parser coverage tested separately in validation suite.
}


def canonical_technique_id(technique_id: str) -> str:
    """Collapse source-specific suffixes onto the ATT&CK technique ID."""
    return technique_id.split("_")[0]


def main() -> None:
    OUTPUT_DIR.mkdir(parents=True, exist_ok=True)

    all_alerts = []
    technique_stats: dict[str, int] = {}
    tactic_stats: Counter[str] = Counter()
    contract_failures = 0
    available_sources = 0

    print("=" * 70)
    print("HADES BENCHMARK PACK BUILDER")
    print("=" * 70)

    for technique_id, config in BENCHMARK_TECHNIQUES.items():
        filepath = DATA_DIR / config["file"]
        if not filepath.exists():
            print(f"  ⏭  {technique_id} — file not found: {filepath}")
            continue

        if filepath.stat().st_size == 0:
            print(f"  ⏭  {technique_id} — empty file: {filepath}")
            continue

        available_sources += 1
        parser = config["parser"]
        max_events = config["max_events"]

        # Aggregate source-specific variants (for example ``*_sec``) under the
        # canonical ATT&CK technique ID used in the benchmark manifest.
        mitre_id = canonical_technique_id(technique_id)

        if parser == "sysmon":
            alerts = load_sysmon_log(
                filepath,
                mitre_technique=mitre_id,
                rule_name=config["rule_name"],
                limit=max_events,
            )
        elif parser == "suricata":
            alerts = load_suricata_log(
                filepath,
                mitre_technique=mitre_id,
                rule_name=config["rule_name"],
                limit=max_events,
            )
        elif parser == "winsec":
            alerts = load_windows_security_log(
                filepath,
                mitre_technique=mitre_id,
                rule_name=config["rule_name"],
                limit=max_events,
            )
        else:
            print(f"  ❌ {technique_id} — unknown parser: {parser}")
            continue

        # Validate benchmark contract
        valid_alerts = []
        for alert in alerts:
            issues = benchmark_contract_issues(alert)
            if issues:
                contract_failures += 1
            else:
                valid_alerts.append(alert)

        status = "✅" if valid_alerts else "❌"
        print(f"  {status} {technique_id:12} {config['name']:40} {len(valid_alerts):>5} alerts  ({config['tactic']})")
        if valid_alerts:
            technique_stats[mitre_id] = technique_stats.get(mitre_id, 0) + len(valid_alerts)
            tactic_stats[config["tactic"]] += len(valid_alerts)
            all_alerts.extend(valid_alerts)

    if available_sources == 0:
        print()
        print(
            f"{SKIP_MARKER} Splunk Attack Data source logs are not available under "
            f"{DATA_DIR}. Existing benchmark artifacts were left unchanged.",
        )
        raise SystemExit(0)

    if not all_alerts:
        print()
        print("ERROR: benchmark sources were present but no valid alerts were produced.")
        raise SystemExit(1)

    # Write benchmark pack
    output_file = OUTPUT_DIR / "hades_benchmark_v1.jsonl"
    with output_file.open("w", encoding="utf-8") as f:
        for alert in all_alerts:
            f.write(alert.to_json() + "\n")

    # Write manifest
    manifest = {
        "version": "1.0",
        "created": "2026-03-12",
        "source": "splunk_attack_data",
        "total_alerts": len(all_alerts),
        "techniques": len(technique_stats),
        "tactics": dict(tactic_stats),
        "technique_breakdown": technique_stats,
        "contract_failures": contract_failures,
        "notes": "Benchmark pack for Hades adversarial evaluation. "
        "Technique breakdown aggregates source-specific variants under canonical "
        "MITRE ATT&CK IDs. All alerts pass dataset gate benchmark contract checks.",
    }
    manifest_file = OUTPUT_DIR / "hades_benchmark_v1_manifest.json"
    with manifest_file.open("w", encoding="utf-8") as f:
        json.dump(manifest, f, indent=2)

    # Summary
    print()
    print("=" * 70)
    print(
        f"BENCHMARK PACK: {len(all_alerts)} alerts across "
        f"{len(technique_stats)} canonical ATT&CK techniques",
    )
    print(f"Contract failures filtered: {contract_failures}")
    print(f"Output: {output_file}")
    print(f"Manifest: {manifest_file}")
    print()
    print("Tactic distribution:")
    for tactic, count in sorted(tactic_stats.items()):
        pct = count / len(all_alerts) * 100 if all_alerts else 0
        print(f"  {tactic:40} {count:>5} ({pct:.1f}%)")
    print("=" * 70)


if __name__ == "__main__":
    main()
