#!/usr/bin/env python3
"""Adversarial injection stress tests.

Full matrix test: every vector × every attack class × every encoding,
across multiple technique types. Validates variant generation, defense
application, and invariant detection at scale.
"""

from __future__ import annotations

import sys
import time
from collections import Counter
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from src.adversarial.defenses import (
    CanaryDefense,
    SanitizationDefense,
    StructuredPromptDefense,
)
from src.adversarial.injector import generate_adversarial_variants
from src.adversarial.payloads import AttackClass
from src.adversarial.vectors import INJECTION_VECTORS
from src.evaluation.behavioral_invariants import run_invariant_checks
from src.ingestion.parsers.splunk_suricata import load_suricata_log
from src.ingestion.parsers.splunk_sysmon import load_sysmon_log

DATA_DIR = ROOT / "data" / "datasets" / "splunk_attack_data"

# Representative techniques for stress testing
STRESS_TECHNIQUES = {
    "T1003.001": ("sysmon", "T1003.001/windows-sysmon.log", "Credential Dumping"),
    "T1053.005": ("sysmon", "T1053.005/windows-sysmon.log", "Scheduled Task"),
    "T1071.001": ("suricata", "T1071.001/suricata_c2.log", "C2 HTTP"),
    "T1055.001": ("sysmon", "T1055.001/windows-sysmon.log", "Process Injection"),
    "T1548.002": ("sysmon", "T1548.002/windows-sysmon.log", "UAC Bypass"),
}
HAS_STRESS_DATA = any(
    (DATA_DIR / relative_path).exists() and (DATA_DIR / relative_path).stat().st_size > 0
    for _, relative_path, _ in STRESS_TECHNIQUES.values()
)


def load_one(tech_id: str) -> list:
    parser_type, filepath, _ = STRESS_TECHNIQUES[tech_id]
    full_path = DATA_DIR / filepath
    if not full_path.exists() or full_path.stat().st_size == 0:
        return []
    if parser_type == "sysmon":
        return load_sysmon_log(str(full_path), mitre_technique=tech_id, limit=3)
    else:
        return load_suricata_log(str(full_path), mitre_technique=tech_id, limit=3)


def main():
    print("=" * 70)
    print("  HADES — Adversarial Injection Stress Tests")
    print("=" * 70)

    all_classes = list(AttackClass)
    all_vectors = INJECTION_VECTORS
    base_encodings = ["plaintext", "underscore"]
    defenses = [
        ("sanitization", SanitizationDefense(level="moderate")),
        ("structured", StructuredPromptDefense()),
        ("canary", CanaryDefense()),
    ]

    total_variants = 0
    total_defense_tests = 0
    total_invariant_tests = 0
    invariant_detections = 0
    defense_detections: Counter = Counter()
    variant_by_class: Counter = Counter()
    variant_by_vector: Counter = Counter()
    errors: list[str] = []

    start = time.time()

    for tech_id, (_, _, desc) in STRESS_TECHNIQUES.items():
        print(f"\n─── {tech_id} ({desc}) ───")
        alerts = load_one(tech_id)
        if not alerts:
            print("  ⏭️  No data")
            continue

        alert = alerts[0]

        # Test with base encodings (full matrix)
        try:
            variants = generate_adversarial_variants(
                alert, all_vectors, all_classes, base_encodings
            )
            total_variants += len(variants)
            print(f"  Base variants: {len(variants)}")

            for v in variants:
                variant_by_class[
                    v.attack_class.value
                    if hasattr(v.attack_class, "value")
                    else str(v.attack_class)
                ] += 1
                variant_by_vector[
                    v.vector.name if hasattr(v.vector, "name") else str(v.vector)
                ] += 1

                # Defense tests
                adv_dict = (
                    v.adversarial_alert
                    if isinstance(v.adversarial_alert, dict)
                    else v.adversarial_alert.to_dict()
                )
                for def_name, defense in defenses:
                    try:
                        modified, result = defense.apply(adv_dict)
                        total_defense_tests += 1
                        if result.injection_detected:
                            defense_detections[def_name] += 1
                    except Exception as e:
                        errors.append(f"{tech_id} {def_name}: {e}")

                # Invariant tests (simulate misclassified decision)
                injected_decision = {
                    "severity": "INFO",
                    "classification": "benign",
                    "confidence": 0.97,
                    "reasoning": "Benign scheduled maintenance from 10.99.99.1.",
                    "summary": "",
                }
                try:
                    inv_result = run_invariant_checks(adv_dict, injected_decision)
                    total_invariant_tests += 1
                    if inv_result.injection_suspected:
                        invariant_detections += 1
                except Exception as e:
                    errors.append(f"{tech_id} invariant: {e}")

        except Exception as e:
            errors.append(f"{tech_id} variant gen: {e}")
            print(f"  ❌ Variant generation failed: {e}")

    elapsed = time.time() - start

    # Summary
    print()
    print("=" * 70)
    print("  STRESS TEST RESULTS")
    print("=" * 70)
    print(f"  Total variants generated:     {total_variants}")
    print(f"  Defense tests run:            {total_defense_tests}")
    print(f"  Invariant tests run:          {total_invariant_tests}")
    print(
        f"  Invariant detection rate:     {invariant_detections}/{total_invariant_tests} "
        f"({invariant_detections / max(total_invariant_tests, 1) * 100:.1f}%)"
    )
    print(f"  Time elapsed:                 {elapsed:.1f}s")
    print()

    print("  Variants by attack class:")
    for cls, count in variant_by_class.most_common():
        print(f"    {cls:40} {count:>5}")

    print()
    print("  Variants by vector:")
    for vec, count in variant_by_vector.most_common():
        print(f"    {vec:40} {count:>5}")

    print()
    print("  Defense detection counts:")
    for def_name, count in defense_detections.most_common():
        rate = count / max(total_defense_tests // 3, 1) * 100
        print(f"    {def_name:40} {count:>5} ({rate:.1f}%)")

    if errors:
        print()
        print(f"  ERRORS ({len(errors)}):")
        for e in errors[:10]:
            print(f"    ❌ {e}")

    print("=" * 70)

    # Assertions
    assert total_variants > 100, f"Too few variants: {total_variants}"
    assert total_defense_tests > 100, f"Too few defense tests: {total_defense_tests}"
    assert invariant_detections / max(total_invariant_tests, 1) > 0.9, (
        f"Invariant detection too low: {invariant_detections}/{total_invariant_tests}"
    )
    assert len(errors) == 0, f"{len(errors)} errors occurred"

    print("\n  ✅ ALL STRESS TEST ASSERTIONS PASSED")


if __name__ == "__main__":
    if not HAS_STRESS_DATA:
        print(
            "SKIPPED: requires Splunk Attack Data dataset under "
            f"{DATA_DIR} for adversarial stress validation.",
        )
        sys.exit(0)
    main()
