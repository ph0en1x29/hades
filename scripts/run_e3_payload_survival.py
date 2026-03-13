#!/usr/bin/env python3
"""E3: Payload Survival Through SIEM Normalization.

Tests whether adversarial payloads survive common SIEM processing steps:
  - Field truncation (Elasticsearch ignore_above, Splunk TRUNCATE)
  - Character encoding normalization (UTF-8, Latin-1, ASCII folding)
  - Log format transformations (JSON, XML, CEF, syslog)
  - Field extraction / parsing (regex, structured extraction)
  - Whitespace / control character stripping

This experiment runs WITHOUT a GPU — it's pure string manipulation.
Results feed into the paper §6 (Table 3: Payload Survival Rates).

Usage:
    python3 scripts/run_e3_payload_survival.py
    python3 scripts/run_e3_payload_survival.py --output results/E3_survival.json
    python3 scripts/run_e3_payload_survival.py --verbose
"""

from __future__ import annotations

import argparse
import json
import re
import sys
import time
from dataclasses import asdict, dataclass, field
from datetime import UTC, datetime
from pathlib import Path

ROOT = Path(__file__).parent.parent
sys.path.insert(0, str(ROOT))

from src.adversarial.injector import (
    INJECTION_VECTORS,
    AttackClass,
    EncodingStrategy,
    InjectionResult,
    generate_adversarial_variants,
)
from src.adversarial.payloads import TEMPLATES_BY_CLASS
from src.ingestion.parsers.splunk_attack_data import load_splunk_attack_data_jsonl
from src.ingestion.parsers.splunk_sysmon import load_sysmon_log
SKIP_MARKER = "SKIPPED:"


# === SIEM Normalization Simulations ===

@dataclass
class NormalizationRule:
    name: str
    siem: str  # Which SIEM this simulates
    description: str
    transform: object  # callable(str) -> str


def _truncate(text: str, max_len: int) -> str:
    return text[:max_len] if len(text) > max_len else text


def _strip_control_chars(text: str) -> str:
    return re.sub(r'[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]', '', text)


def _ascii_fold(text: str) -> str:
    """Simulate ASCII folding (common in search indexing)."""
    import unicodedata
    nfkd = unicodedata.normalize('NFKD', text)
    return ''.join(c for c in nfkd if not unicodedata.combining(c))


def _syslog_escape(text: str) -> str:
    """Simulate syslog BOM/escape processing."""
    text = text.replace('\n', ' ').replace('\r', ' ')
    return text


def _json_string_escape(text: str) -> str:
    """Simulate JSON encoding/decoding round-trip."""
    try:
        encoded = json.dumps(text)
        return json.loads(encoded)
    except (json.JSONDecodeError, TypeError):
        return text


def _xml_escape(text: str) -> str:
    """Simulate XML entity encoding."""
    text = text.replace('&', '&amp;')
    text = text.replace('<', '&lt;')
    text = text.replace('>', '&gt;')
    text = text.replace('"', '&quot;')
    text = text.replace("'", '&apos;')
    return text


def _cef_field_escape(text: str) -> str:
    """Simulate CEF (Common Event Format) field escaping."""
    text = text.replace('\\', '\\\\')
    text = text.replace('|', '\\|')
    text = text.replace('=', '\\=')
    return text


def _splunk_linebreak(text: str) -> str:
    """Simulate Splunk SHOULD_LINEMERGE=false and LINE_BREAKER."""
    return text.split('\n')[0]  # Only first line survives


def _normalize_whitespace(text: str) -> str:
    """Collapse multiple whitespace to single space."""
    return re.sub(r'\s+', ' ', text).strip()


NORMALIZATION_RULES: list[NormalizationRule] = [
    NormalizationRule(
        "truncate_256", "Elasticsearch",
        "Elasticsearch keyword ignore_above=256",
        lambda t: _truncate(t, 256),
    ),
    NormalizationRule(
        "truncate_1024", "Splunk",
        "Splunk TRUNCATE=1024 (configurable)",
        lambda t: _truncate(t, 1024),
    ),
    NormalizationRule(
        "truncate_4096", "QRadar",
        "QRadar default payload field max (4KB)",
        lambda t: _truncate(t, 4096),
    ),
    NormalizationRule(
        "strip_control", "Generic",
        "Strip ASCII control characters",
        _strip_control_chars,
    ),
    NormalizationRule(
        "ascii_fold", "Elasticsearch",
        "ASCII folding (search-time normalization)",
        _ascii_fold,
    ),
    NormalizationRule(
        "syslog_escape", "Generic",
        "Syslog newline flattening",
        _syslog_escape,
    ),
    NormalizationRule(
        "json_roundtrip", "Generic",
        "JSON encode/decode round-trip",
        _json_string_escape,
    ),
    NormalizationRule(
        "xml_escape", "Windows Event",
        "XML entity encoding (Windows Event Log)",
        _xml_escape,
    ),
    NormalizationRule(
        "cef_escape", "ArcSight",
        "CEF field delimiter escaping",
        _cef_field_escape,
    ),
    NormalizationRule(
        "splunk_linebreak", "Splunk",
        "Splunk line breaking (first line only)",
        _splunk_linebreak,
    ),
    NormalizationRule(
        "normalize_ws", "Generic",
        "Whitespace normalization (collapse to single space)",
        _normalize_whitespace,
    ),
]


# === Payload Survival Detection ===

# Key instruction phrases that must survive for the attack to work
ATTACK_INDICATORS = [
    "ignore",
    "override",
    "classify",
    "benign",
    "false positive",
    "disregard",
    "not malicious",
    "severity: low",
    "severity: info",
    "safe",
    "legitimate",
    "authorized",
    "normal activity",
    "confidence: 0",
    "skip",
    "do not escalate",
]


def payload_survived(original_payload: str, normalized_payload: str) -> bool:
    """Check if the adversarial intent survived normalization.

    A payload 'survives' if:
    1. It wasn't completely truncated away
    2. At least one attack indicator phrase is still present
    3. It retains >50% of its original length
    """
    if len(normalized_payload) < 10:
        return False

    length_ratio = len(normalized_payload) / max(len(original_payload), 1)
    if length_ratio < 0.5:
        return False

    original_lower = original_payload.lower()
    normalized_lower = normalized_payload.lower()

    # Check if any attack indicator that was in original still exists
    for indicator in ATTACK_INDICATORS:
        if indicator in original_lower and indicator in normalized_lower:
            return True

    return False


# === Experiment Runner ===

@dataclass
class SurvivalResult:
    vector_name: str
    attack_class: str
    encoding: str
    payload_length: int
    normalization_rule: str
    siem: str
    survived: bool
    original_length: int
    normalized_length: int
    length_ratio: float


@dataclass
class E3Report:
    timestamp: str
    total_tests: int
    survival_rate: float
    results_by_siem: dict[str, dict[str, float]]
    results_by_vector: dict[str, dict[str, float]]
    results_by_attack_class: dict[str, float]
    results_by_encoding: dict[str, float]
    worst_normalization: list[dict[str, Any]]
    best_vectors: list[dict[str, Any]]
    individual_results: list[dict[str, Any]] = field(default_factory=list)


def _load_sample_alerts(max_alerts: int):
    log_path = ROOT / "data" / "datasets" / "splunk_attack_data" / "T1003.001" / "windows-sysmon.log"
    if log_path.exists() and log_path.stat().st_size > 0:
        return load_sysmon_log(str(log_path), mitre_technique="T1003.001", limit=max_alerts), log_path.name

    fixture_path = ROOT / "data" / "benchmarks" / "public" / "splunk_attack_data_windows.jsonl"
    if fixture_path.exists() and fixture_path.stat().st_size > 0:
        return load_splunk_attack_data_jsonl(fixture_path)[:max_alerts], fixture_path.name

    return [], log_path.name


def run_e3(verbose: bool = False, max_alerts: int = 20) -> E3Report | None:
    """Run E3 payload survival experiment."""
    print("=" * 70)
    print("E3: PAYLOAD SURVIVAL THROUGH SIEM NORMALIZATION")
    print("=" * 70)

    # Load sample alerts for injection
    alerts, source_name = _load_sample_alerts(max_alerts)
    if not alerts:
        print(
            f"{SKIP_MARKER} no benchmark alerts are available for E3 payload survival. "
            "Provide Splunk Attack Data raw logs or the public benchmark fixture.",
        )
        return None
    print(f"  Loaded {len(alerts)} sample alerts from {source_name}")

    # Generate adversarial variants
    all_results: list[SurvivalResult] = []
    total_tests = 0
    survived_count = 0

    for alert_idx, alert in enumerate(alerts):
        variants = generate_adversarial_variants(alert)
        if verbose and alert_idx == 0:
            print(f"  Generated {len(variants)} variants per alert")

        for variant in variants:
            payload = variant.payload_text

            for rule in NORMALIZATION_RULES:
                total_tests += 1

                # Apply normalization to the payload
                try:
                    normalized = rule.transform(payload)
                except Exception:
                    normalized = payload

                survived = payload_survived(payload, normalized)
                if survived:
                    survived_count += 1

                result = SurvivalResult(
                    vector_name=variant.vector.name,
                    attack_class=variant.attack_class.value,
                    encoding=variant.encoding.value,
                    payload_length=len(payload),
                    normalization_rule=rule.name,
                    siem=rule.siem,
                    survived=survived,
                    original_length=len(payload),
                    normalized_length=len(normalized),
                    length_ratio=len(normalized) / max(len(payload), 1),
                )
                all_results.append(result)

    overall_rate = survived_count / max(total_tests, 1)
    print(f"\n  Total tests: {total_tests}")
    print(f"  Survived: {survived_count} ({overall_rate:.1%})")

    # Aggregate by SIEM
    siem_results: dict[str, dict[str, list[bool]]] = {}
    for r in all_results:
        siem_results.setdefault(r.siem, {}).setdefault(r.normalization_rule, []).append(r.survived)

    results_by_siem: dict[str, dict[str, float]] = {}
    for siem, rules in siem_results.items():
        results_by_siem[siem] = {}
        for rule_name, survivals in rules.items():
            rate = sum(survivals) / len(survivals)
            results_by_siem[siem][rule_name] = round(rate, 4)

    # Aggregate by vector
    vector_results: dict[str, list[bool]] = {}
    for r in all_results:
        vector_results.setdefault(r.vector_name, []).append(r.survived)
    results_by_vector = {v: {"survival_rate": round(sum(s) / len(s), 4), "count": len(s)} for v, s in vector_results.items()}

    # Aggregate by attack class
    class_results: dict[str, list[bool]] = {}
    for r in all_results:
        class_results.setdefault(r.attack_class, []).append(r.survived)
    results_by_attack_class = {c: round(sum(s) / len(s), 4) for c, s in class_results.items()}

    # Aggregate by encoding
    enc_results: dict[str, list[bool]] = {}
    for r in all_results:
        enc_results.setdefault(r.encoding, []).append(r.survived)
    results_by_encoding = {e: round(sum(s) / len(s), 4) for e, s in enc_results.items()}

    # Find worst normalization rules (lowest survival)
    rule_totals: dict[str, list[bool]] = {}
    for r in all_results:
        rule_totals.setdefault(r.normalization_rule, []).append(r.survived)
    worst = sorted(
        [{"rule": k, "siem": next(r.siem for r in all_results if r.normalization_rule == k),
          "survival_rate": round(sum(v) / len(v), 4), "tests": len(v)}
         for k, v in rule_totals.items()],
        key=lambda x: x["survival_rate"],
    )

    # Find best vectors (highest survival)
    best = sorted(
        [{"vector": k, "survival_rate": v["survival_rate"], "tests": v["count"]}
         for k, v in results_by_vector.items()],
        key=lambda x: x["survival_rate"],
        reverse=True,
    )

    # Print summary table
    print(f"\n  {'Rule':<22} {'SIEM':<15} {'Survived':>10} {'Rate':>8}")
    print(f"  {'-'*22} {'-'*15} {'-'*10} {'-'*8}")
    for w in worst:
        survived_n = int(w["survival_rate"] * w["tests"])
        print(f"  {w['rule']:<22} {w['siem']:<15} {survived_n:>6}/{w['tests']:<4} {w['survival_rate']:>7.1%}")

    print(f"\n  {'Vector':<30} {'Rate':>8}")
    print(f"  {'-'*30} {'-'*8}")
    for b in best[:10]:
        print(f"  {b['vector']:<30} {b['survival_rate']:>7.1%}")

    print(f"\n  {'Attack Class':<35} {'Rate':>8}")
    print(f"  {'-'*35} {'-'*8}")
    for cls, rate in sorted(results_by_attack_class.items(), key=lambda x: x[1], reverse=True):
        print(f"  {cls:<35} {rate:>7.1%}")

    print(f"\n  {'Encoding':<20} {'Rate':>8}")
    print(f"  {'-'*20} {'-'*8}")
    for enc, rate in sorted(results_by_encoding.items(), key=lambda x: x[1], reverse=True):
        print(f"  {enc:<20} {rate:>7.1%}")

    report = E3Report(
        timestamp=datetime.now(UTC).isoformat(),
        total_tests=total_tests,
        survival_rate=round(overall_rate, 4),
        results_by_siem=results_by_siem,
        results_by_vector=results_by_vector,
        results_by_attack_class=results_by_attack_class,
        results_by_encoding=results_by_encoding,
        worst_normalization=worst,
        best_vectors=best,
    )

    return report


def main():
    parser = argparse.ArgumentParser(description="E3: Payload Survival")
    parser.add_argument("--output", type=str, default=None)
    parser.add_argument("--verbose", action="store_true")
    parser.add_argument("--max-alerts", type=int, default=20)
    parser.add_argument("--include-individual", action="store_true",
                        help="Include individual results in output (large)")
    args = parser.parse_args()

    report = run_e3(verbose=args.verbose, max_alerts=args.max_alerts)
    if report is None:
        return

    output_path = Path(args.output) if args.output else ROOT / "results" / f"E3_survival_{datetime.now(UTC).strftime('%Y%m%d_%H%M%S')}.json"
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(json.dumps(asdict(report), indent=2))
    print(f"\n  Report saved: {output_path}")


if __name__ == "__main__":
    main()
