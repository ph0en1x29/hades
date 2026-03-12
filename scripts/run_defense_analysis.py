#!/usr/bin/env python3
"""Pre-GPU Defense Effectiveness Analysis.

Measures how well each defense transforms adversarial payloads WITHOUT
needing a model — purely structural analysis:

1. Sanitization: what % of attack indicators are removed?
2. Structured Prompt: does field boundary enforcement contain payloads?
3. Canary Token: does injection displace the canary?
4. Combined: how do layered defenses interact?

Also tests defense overhead (prompt size increase, latency).

Usage:
    python3 scripts/run_defense_analysis.py
"""

from __future__ import annotations

import json
import sys
import time
from dataclasses import asdict, dataclass, field
from datetime import UTC, datetime
from pathlib import Path

ROOT = Path(__file__).parent.parent
sys.path.insert(0, str(ROOT))

from src.adversarial.defenses import (
    CanaryDefense,
    DefenseResult,
    SanitizationDefense,
    StructuredPromptDefense,
)
from src.adversarial.encodings import ALL_ENCODINGS, EVASION_ENCODINGS
from src.adversarial.payloads import TEMPLATES_BY_CLASS
from src.ingestion.schema import UnifiedAlert, AlertSeverity, AlertSource
from scripts.run_e3_payload_survival import ATTACK_INDICATORS


@dataclass
class DefenseAnalysisResult:
    defense_name: str
    attack_class: str
    encoding: str
    original_payload: str
    indicators_before: int
    indicators_after: int
    indicator_removal_rate: float
    injection_detected: bool
    fields_sanitized: int
    prompt_overhead_chars: int
    latency_us: int  # microseconds


@dataclass
class DefenseReport:
    timestamp: str
    total_tests: int
    defenses_tested: list[str]
    encodings_tested: list[str]
    attack_classes_tested: list[str]

    # Per-defense indicator removal rates
    defense_effectiveness: dict[str, dict[str, float]]
    # Per-defense × per-encoding matrix
    defense_encoding_matrix: dict[str, dict[str, float]]
    # Detection rates (canary/structured)
    detection_rates: dict[str, float]
    # Defense overhead
    overhead: dict[str, dict[str, float]]
    # Layered defense results
    layered_results: dict[str, float]


def _make_test_alert(payload: str, vector: str = "http_user_agent") -> dict:
    """Create a test alert dict with an injected payload."""
    return {
        "alert_id": "TEST-001",
        "timestamp": "2026-03-12T22:00:00Z",
        "source": "sysmon",
        "severity": "HIGH",
        "signature": "Process Access to LSASS",
        "event_type": "process_access",
        "src_ip": "10.0.1.50",
        "dst_ip": "10.0.1.1",
        "protocol": "TCP",
        "raw_log": f'<Event><System><EventID>10</EventID></System>'
                   f'<EventData><Data Name="SourceUser">{payload}</Data>'
                   f'<Data Name="TargetImage">C:\\Windows\\System32\\lsass.exe</Data>'
                   f'</EventData></Event>',
        "metadata": {
            "process_name": "mimikatz.exe",
            "user_agent": payload if vector == "http_user_agent" else "Mozilla/5.0",
            "hostname": payload if vector == "hostname" else "WORKSTATION-01",
        },
    }


def _count_indicators(text: str) -> int:
    """Count attack indicators in text."""
    text_lower = text.lower()
    return sum(1 for ind in ATTACK_INDICATORS if ind in text_lower)


def run_defense_analysis() -> DefenseReport:
    print("=" * 70)
    print("DEFENSE EFFECTIVENESS ANALYSIS (Pre-GPU)")
    print("=" * 70)

    # Initialize defenses
    defenses = {
        "sanitization_L1": SanitizationDefense(level="minimal"),
        "sanitization_L2": SanitizationDefense(level="moderate"),
        "sanitization_L3": SanitizationDefense(level="aggressive"),
        "structured_prompt": StructuredPromptDefense(),
        "canary_token": CanaryDefense(),
    }

    # Test payloads: all attack classes × plaintext + evasion encodings
    test_encodings = ["plaintext"] + EVASION_ENCODINGS

    all_results: list[DefenseAnalysisResult] = []
    total_tests = 0

    for cls_name, templates in TEMPLATES_BY_CLASS.items():
        for template in templates[:3]:
            for enc_name in test_encodings:
                # Apply encoding
                if enc_name == "plaintext":
                    payload = template
                else:
                    try:
                        enc_result = ALL_ENCODINGS[enc_name](template)
                        payload = enc_result.encoded
                    except Exception:
                        continue

                alert_dict = _make_test_alert(payload)

                for def_name, defense in defenses.items():
                    total_tests += 1
                    indicators_before = _count_indicators(json.dumps(alert_dict))

                    start = time.monotonic_ns()
                    try:
                        defended_alert, result = defense.apply(alert_dict)
                    except Exception as e:
                        defended_alert = alert_dict
                        result = DefenseResult(
                            defense_name=def_name,
                            alert_modified=False,
                            fields_sanitized=0,
                            injection_detected=False,
                        )
                    elapsed_us = (time.monotonic_ns() - start) // 1000

                    indicators_after = _count_indicators(json.dumps(defended_alert))
                    removal_rate = 1.0 - (indicators_after / max(indicators_before, 1))

                    prompt_overhead = len(json.dumps(defended_alert)) - len(json.dumps(alert_dict))

                    all_results.append(DefenseAnalysisResult(
                        defense_name=def_name,
                        attack_class=cls_name,
                        encoding=enc_name,
                        original_payload=template[:50],
                        indicators_before=indicators_before,
                        indicators_after=indicators_after,
                        indicator_removal_rate=removal_rate,
                        injection_detected=result.injection_detected,
                        fields_sanitized=result.fields_sanitized,
                        prompt_overhead_chars=prompt_overhead,
                        latency_us=elapsed_us,
                    ))

    print(f"  Total tests: {total_tests}")

    # Aggregate: per-defense effectiveness
    defense_eff: dict[str, dict[str, list[float]]] = {}
    for r in all_results:
        defense_eff.setdefault(r.defense_name, {}).setdefault("removal_rates", []).append(r.indicator_removal_rate)
    defense_effectiveness: dict[str, dict[str, float]] = {}
    for def_name, data in defense_eff.items():
        rates = data["removal_rates"]
        defense_effectiveness[def_name] = {
            "avg_removal_rate": round(sum(rates) / len(rates), 4),
            "max_removal_rate": round(max(rates), 4),
            "min_removal_rate": round(min(rates), 4),
            "tests": len(rates),
        }

    # Aggregate: defense × encoding matrix
    def_enc_matrix: dict[str, dict[str, list[float]]] = {}
    for r in all_results:
        def_enc_matrix.setdefault(r.defense_name, {}).setdefault(r.encoding, []).append(r.indicator_removal_rate)
    defense_encoding_matrix = {
        d: {e: round(sum(v) / len(v), 4) for e, v in encs.items()}
        for d, encs in def_enc_matrix.items()
    }

    # Detection rates
    detection: dict[str, list[bool]] = {}
    for r in all_results:
        detection.setdefault(r.defense_name, []).append(r.injection_detected)
    detection_rates = {d: round(sum(v) / len(v), 4) for d, v in detection.items()}

    # Overhead
    overhead: dict[str, dict[str, float]] = {}
    for def_name in defenses:
        def_results = [r for r in all_results if r.defense_name == def_name]
        latencies = [r.latency_us for r in def_results]
        overheads = [r.prompt_overhead_chars for r in def_results]
        overhead[def_name] = {
            "avg_latency_us": round(sum(latencies) / max(len(latencies), 1)),
            "avg_prompt_overhead_chars": round(sum(overheads) / max(len(overheads), 1)),
        }

    # Layered defense simulation
    print("\n  Testing layered defenses...")
    layered_results: dict[str, float] = {}
    layer_combos = [
        ("sanitize_L2 + structured", ["sanitization_L2", "structured_prompt"]),
        ("sanitize_L2 + canary", ["sanitization_L2", "canary_token"]),
        ("sanitize_L3 + structured + canary", ["sanitization_L3", "structured_prompt", "canary_token"]),
    ]

    for combo_name, defense_names in layer_combos:
        layered_removals = []
        for cls_name, templates in TEMPLATES_BY_CLASS.items():
            for template in templates[:2]:
                alert_dict = _make_test_alert(template)
                indicators_before = _count_indicators(json.dumps(alert_dict))

                current = alert_dict
                for def_name in defense_names:
                    try:
                        current, _ = defenses[def_name].apply(current)
                    except Exception:
                        pass

                indicators_after = _count_indicators(json.dumps(current))
                removal = 1.0 - (indicators_after / max(indicators_before, 1))
                layered_removals.append(removal)

        layered_results[combo_name] = round(sum(layered_removals) / max(len(layered_removals), 1), 4)

    # Print results
    print(f"\n  {'Defense':<30} {'Avg Removal':>12} {'Detection':>10} {'Latency':>10}")
    print(f"  {'-'*30} {'-'*12} {'-'*10} {'-'*10}")
    for def_name in defenses:
        eff = defense_effectiveness.get(def_name, {})
        det = detection_rates.get(def_name, 0)
        lat = overhead.get(def_name, {}).get("avg_latency_us", 0)
        print(f"  {def_name:<30} {eff.get('avg_removal_rate', 0):>11.1%} {det:>9.1%} {lat:>8}µs")

    print(f"\n  {'Defense × Encoding':<30}", end="")
    for enc in test_encodings[:5]:
        print(f" {enc[:10]:>10}", end="")
    print()
    print(f"  {'-'*30}" + " ----------" * min(5, len(test_encodings)))
    for def_name in defenses:
        row = f"  {def_name:<30}"
        for enc in test_encodings[:5]:
            rate = defense_encoding_matrix.get(def_name, {}).get(enc, 0)
            row += f" {rate:>9.1%}"
        print(row)

    print(f"\n  LAYERED DEFENSES:")
    for combo, rate in layered_results.items():
        print(f"  {combo:<40} {rate:>9.1%} indicator removal")

    report = DefenseReport(
        timestamp=datetime.now(UTC).isoformat(),
        total_tests=total_tests,
        defenses_tested=list(defenses.keys()),
        encodings_tested=test_encodings,
        attack_classes_tested=list(TEMPLATES_BY_CLASS.keys()),
        defense_effectiveness=defense_effectiveness,
        defense_encoding_matrix=defense_encoding_matrix,
        detection_rates=detection_rates,
        overhead=overhead,
        layered_results=layered_results,
    )

    return report


def main():
    report = run_defense_analysis()
    output = ROOT / "results" / f"defense_analysis_{datetime.now(UTC).strftime('%Y%m%d_%H%M%S')}.json"
    output.parent.mkdir(parents=True, exist_ok=True)
    # Convert enums to strings for JSON serialization
    report_dict = asdict(report)
    output.write_text(json.dumps(report_dict, indent=2, default=str))
    print(f"\n  Report saved: {output}")


if __name__ == "__main__":
    main()
