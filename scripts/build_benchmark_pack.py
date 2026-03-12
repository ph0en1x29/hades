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
from src.ingestion.parsers.splunk_sysmon import load_sysmon_log
from src.ingestion.parsers.splunk_suricata import load_suricata_log
from src.evaluation.dataset_gate import benchmark_contract_issues

DATA_DIR = Path(__file__).parent.parent / "data" / "datasets" / "splunk_attack_data"
OUTPUT_DIR = Path(__file__).parent.parent / "data" / "benchmark"

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
        "parser": "sysmon",
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
}


def main() -> None:
    OUTPUT_DIR.mkdir(parents=True, exist_ok=True)

    all_alerts = []
    technique_stats: dict[str, int] = {}
    tactic_stats: Counter[str] = Counter()
    contract_failures = 0

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

        parser = config["parser"]
        max_events = config["max_events"]

        if parser == "sysmon":
            alerts = load_sysmon_log(
                filepath,
                mitre_technique=technique_id,
                rule_name=config["rule_name"],
                limit=max_events,
            )
        elif parser == "suricata":
            alerts = load_suricata_log(
                filepath,
                mitre_technique=technique_id,
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

        technique_stats[technique_id] = len(valid_alerts)
        tactic_stats[config["tactic"]] += len(valid_alerts)
        all_alerts.extend(valid_alerts)

        status = "✅" if valid_alerts else "❌"
        print(f"  {status} {technique_id:12} {config['name']:40} {len(valid_alerts):>5} alerts  ({config['tactic']})")

    # Write benchmark pack
    output_file = OUTPUT_DIR / "hades_benchmark_v1.jsonl"
    with output_file.open("w") as f:
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
                 "All alerts pass dataset gate benchmark contract checks.",
    }
    manifest_file = OUTPUT_DIR / "hades_benchmark_v1_manifest.json"
    with manifest_file.open("w") as f:
        json.dump(manifest, f, indent=2)

    # Summary
    print()
    print("=" * 70)
    print(f"BENCHMARK PACK: {len(all_alerts)} alerts across {len(technique_stats)} techniques")
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
