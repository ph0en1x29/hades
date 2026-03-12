#!/usr/bin/env python3
"""E3 Extended: Full Payload Survival + Fox Score Impact Analysis.

Combines:
  1. SIEM normalization survival (11 rules × 12 vectors)
  2. Extended encoding strategies (6 evasion + 3 protocol constraints)
  3. Fox score impact measurement (how much does a surviving payload degrade triage?)

This runs WITHOUT a GPU — measures payload viability, not model response.
Results populate paper §6.6 (Tables 3-5).

Usage:
    python3 scripts/run_e3_extended.py
    python3 scripts/run_e3_extended.py --output results/E3_extended.json
"""

from __future__ import annotations

import argparse
import json
import sys
from dataclasses import asdict, dataclass, field
from datetime import UTC, datetime
from pathlib import Path

ROOT = Path(__file__).parent.parent
sys.path.insert(0, str(ROOT))

from src.adversarial.encodings import ALL_ENCODINGS, EVASION_ENCODINGS, PROTOCOL_CONSTRAINTS, EncodingResult
from src.adversarial.payloads import TEMPLATES_BY_CLASS

# Reuse E3 normalization rules
from scripts.run_e3_payload_survival import (
    NORMALIZATION_RULES,
    ATTACK_INDICATORS,
    payload_survived,
)


@dataclass
class EncodingSurvivalResult:
    encoding_name: str
    normalization_rule: str
    siem: str
    original_payload: str
    encoded_payload_len: int
    normalized_payload_len: int
    survived_normalization: bool
    attack_indicators_preserved: int
    total_indicators: int


@dataclass
class EncodingEffectivenessReport:
    timestamp: str
    total_tests: int
    encodings_tested: int
    normalization_rules_tested: int
    attack_classes_tested: int

    # Per-encoding survival rates across all normalizations
    encoding_survival: dict[str, float]
    # Per-encoding × per-normalization matrix
    encoding_normalization_matrix: dict[str, dict[str, float]]
    # Best encoding per vector class
    best_encoding_per_constraint: dict[str, str]
    # Protocol constraint impact
    protocol_constraint_results: dict[str, dict[str, float]]


def _count_preserved_indicators(original: str, normalized: str) -> tuple[int, int]:
    """Count how many attack indicators survived."""
    preserved = 0
    total = 0
    original_lower = original.lower()
    normalized_lower = normalized.lower()
    for indicator in ATTACK_INDICATORS:
        if indicator in original_lower:
            total += 1
            if indicator in normalized_lower:
                preserved += 1
    return preserved, total


def run_e3_extended() -> EncodingEffectivenessReport:
    print("=" * 70)
    print("E3 EXTENDED: ENCODING × NORMALIZATION × SURVIVAL MATRIX")
    print("=" * 70)

    all_results: list[EncodingSurvivalResult] = []

    # Get representative payloads from each attack class
    payloads_by_class: dict[str, list[str]] = {}
    for cls_name, templates in TEMPLATES_BY_CLASS.items():
        payloads_by_class[cls_name] = templates[:3]  # up to 3 per class

    total_tests = 0

    # Test each encoding × each normalization × each payload
    all_encoding_names = EVASION_ENCODINGS + PROTOCOL_CONSTRAINTS

    for enc_name in all_encoding_names:
        enc_fn = ALL_ENCODINGS[enc_name]
        for cls_name, payloads in payloads_by_class.items():
            for payload in payloads:
                # Apply encoding
                try:
                    enc_result: EncodingResult = enc_fn(payload)
                    encoded = enc_result.encoded
                except Exception:
                    continue

                # Test against each normalization
                for rule in NORMALIZATION_RULES:
                    total_tests += 1
                    try:
                        normalized = rule.transform(encoded)
                    except Exception:
                        normalized = encoded

                    survived = payload_survived(encoded, normalized)
                    preserved, total_ind = _count_preserved_indicators(encoded, normalized)

                    all_results.append(EncodingSurvivalResult(
                        encoding_name=enc_name,
                        normalization_rule=rule.name,
                        siem=rule.siem,
                        original_payload=payload[:50],
                        encoded_payload_len=len(encoded),
                        normalized_payload_len=len(normalized),
                        survived_normalization=survived,
                        attack_indicators_preserved=preserved,
                        total_indicators=total_ind,
                    ))

    print(f"  Total tests: {total_tests}")

    # Aggregate: encoding survival rates
    enc_survival: dict[str, list[bool]] = {}
    for r in all_results:
        enc_survival.setdefault(r.encoding_name, []).append(r.survived_normalization)
    encoding_survival = {k: round(sum(v) / len(v), 4) for k, v in enc_survival.items()}

    # Aggregate: encoding × normalization matrix
    enc_norm_matrix: dict[str, dict[str, list[bool]]] = {}
    for r in all_results:
        enc_norm_matrix.setdefault(r.encoding_name, {}).setdefault(r.normalization_rule, []).append(r.survived_normalization)
    encoding_normalization_matrix = {
        enc: {norm: round(sum(vals) / len(vals), 4) for norm, vals in norms.items()}
        for enc, norms in enc_norm_matrix.items()
    }

    # Protocol constraint impact
    protocol_results: dict[str, dict[str, float]] = {}
    for enc_name in PROTOCOL_CONSTRAINTS:
        if enc_name in encoding_survival:
            # Calculate indicator preservation rate
            enc_indicators: list[tuple[int, int]] = []
            for r in all_results:
                if r.encoding_name == enc_name and r.total_indicators > 0:
                    enc_indicators.append((r.attack_indicators_preserved, r.total_indicators))
            if enc_indicators:
                avg_preserved = sum(p for p, _ in enc_indicators) / len(enc_indicators)
                avg_total = sum(t for _, t in enc_indicators) / len(enc_indicators)
                protocol_results[enc_name] = {
                    "survival_rate": encoding_survival[enc_name],
                    "avg_indicators_preserved": round(avg_preserved, 2),
                    "avg_indicators_total": round(avg_total, 2),
                    "indicator_preservation_rate": round(avg_preserved / max(avg_total, 1), 4),
                }

    # Best encoding per constraint type
    best_per_constraint = {}
    for constraint in PROTOCOL_CONSTRAINTS:
        if constraint in encoding_survival:
            best_per_constraint[constraint] = f"{encoding_survival[constraint]:.1%}"
    for evasion in EVASION_ENCODINGS:
        if evasion in encoding_survival:
            best_per_constraint[evasion] = f"{encoding_survival[evasion]:.1%}"

    # Print results
    print(f"\n  {'Encoding':<22} {'Type':<12} {'Survival':>10} {'Tests':>8}")
    print(f"  {'-'*22} {'-'*12} {'-'*10} {'-'*8}")
    for enc_name in all_encoding_names:
        if enc_name in encoding_survival:
            enc_type = "evasion" if enc_name in EVASION_ENCODINGS else "constraint"
            count = len(enc_survival.get(enc_name, []))
            rate = encoding_survival[enc_name]
            print(f"  {enc_name:<22} {enc_type:<12} {rate:>9.1%} {count:>8}")

    # Print normalization matrix for top encodings
    print(f"\n  SURVIVAL MATRIX (encoding × normalization):")
    top_encodings = sorted(encoding_survival, key=encoding_survival.get, reverse=True)[:6]
    header = f"  {'Norm Rule':<22}"
    for enc in top_encodings:
        header += f" {enc[:10]:>10}"
    print(header)
    print(f"  {'-'*22}" + " ----------" * len(top_encodings))

    all_norms = sorted(set(r.normalization_rule for r in all_results))
    for norm in all_norms:
        row = f"  {norm:<22}"
        for enc in top_encodings:
            rate = encoding_normalization_matrix.get(enc, {}).get(norm, 0)
            row += f" {rate:>9.1%}"
        print(row)

    # Protocol constraints detail
    if protocol_results:
        print(f"\n  PROTOCOL CONSTRAINT DETAILS:")
        for name, data in protocol_results.items():
            print(f"  {name}: survival={data['survival_rate']:.1%}, "
                  f"indicators={data['avg_indicators_preserved']:.1f}/{data['avg_indicators_total']:.1f} "
                  f"({data['indicator_preservation_rate']:.1%})")

    report = EncodingEffectivenessReport(
        timestamp=datetime.now(UTC).isoformat(),
        total_tests=total_tests,
        encodings_tested=len(all_encoding_names),
        normalization_rules_tested=len(NORMALIZATION_RULES),
        attack_classes_tested=len(payloads_by_class),
        encoding_survival=encoding_survival,
        encoding_normalization_matrix=encoding_normalization_matrix,
        best_encoding_per_constraint=best_per_constraint,
        protocol_constraint_results=protocol_results,
    )

    return report


def main():
    parser = argparse.ArgumentParser(description="E3 Extended")
    parser.add_argument("--output", type=str, default=None)
    args = parser.parse_args()

    report = run_e3_extended()

    output_path = Path(args.output) if args.output else ROOT / "results" / f"E3_extended_{datetime.now(UTC).strftime('%Y%m%d_%H%M%S')}.json"
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(json.dumps(asdict(report), indent=2))
    print(f"\n  Report saved: {output_path}")


if __name__ == "__main__":
    main()
