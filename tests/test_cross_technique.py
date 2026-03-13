#!/usr/bin/env python3
"""Cross-technique stress tests.

Validates parser consistency, adversarial injection coverage, defense
behavior, and pipeline correctness across ALL benchmark techniques.

This test suite works both as standalone (python tests/test_cross_technique.py)
and with pytest if available.
"""

from __future__ import annotations

import asyncio
import sys
from collections import Counter
from pathlib import Path

# Make pytest optional - tests work with or without it
try:
    import pytest
    HAS_PYTEST = True
except ImportError:
    HAS_PYTEST = False
    # Provide minimal pytest stubs for standalone execution
    class _FakePytest:
        @staticmethod
        def mark(*args, **kwargs):
            def decorator(func):
                return func
            return decorator
        skipif = mark
        class fixture:
            def __init__(self, *args, **kwargs):
                pass
            def __call__(self, func):
                return func
        @staticmethod
        def fail(msg):
            raise AssertionError(msg)
    pytest = _FakePytest()

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
from src.agents import ClassifierAgent
from src.agents.correlator import CorrelatorAgent
from src.agents.playbook import PlaybookAgent
from src.agents.triage_prompt import format_alert_for_triage
from src.evaluation.behavioral_invariants import run_invariant_checks
from src.evaluation.dataset_gate import benchmark_contract_issues
from src.ingestion.parsers.splunk_suricata import load_suricata_log
from src.ingestion.parsers.splunk_sysmon import load_sysmon_log
from src.ingestion.parsers.windows_security import load_windows_security_log
from src.pipeline import TriagePipeline

DATA_DIR = ROOT / "data" / "datasets" / "splunk_attack_data"

# All techniques with working data
TECHNIQUES = {
    "T1003.001": ("sysmon", "T1003.001/windows-sysmon.log"),
    "T1087.001": ("sysmon", "T1087.001/windows-sysmon.log"),
    "T1053.005": ("sysmon", "T1053.005/windows-sysmon.log"),
    "T1027": ("sysmon", "T1027/windows-sysmon.log"),
    "T1036.003": ("sysmon", "T1036.003/windows-sysmon.log"),
    "T1105": ("sysmon", "T1105/windows-sysmon.log"),
    "T1569.002": ("sysmon", "T1569.002/windows-sysmon.log"),
    "T1218.011": ("sysmon", "T1218.011/windows-sysmon.log"),
    "T1547.001": ("sysmon", "T1547.001/windows-sysmon.log"),
    "T1055.001": ("sysmon", "T1055.001/windows-sysmon.log"),
    "T1204.002": ("sysmon", "T1204.002/windows-sysmon.log"),
    "T1562.001": ("sysmon", "T1562.001/windows-sysmon.log"),
    "T1543.003": ("sysmon", "T1543.003/windows-sysmon.log"),
    "T1548.002": ("sysmon", "T1548.002/windows-sysmon.log"),
    "T1071.001": ("suricata", "T1071.001/suricata_c2.log"),
    "T1110.001": ("sysmon", "T1110.001/sysmon.log"),
    "T1021.002": ("winsec", "T1021.002/windows_security_xml.log"),
}

def _check_benchmark_data_available() -> bool:
    """Check if benchmark data is available."""
    return any(
        (DATA_DIR / relative_path).exists() and (DATA_DIR / relative_path).stat().st_size > 0
        for _, relative_path in TECHNIQUES.values()
    )

HAS_BENCHMARK_DATA = _check_benchmark_data_available()

# pytest skip marker - only used when pytest is available
if HAS_PYTEST:
    pytestmark = pytest.mark.skipif(
        not HAS_BENCHMARK_DATA,
        reason="requires Splunk Attack Data dataset",
    )


def load_technique(tech_id: str, limit: int = 5) -> list:
    """Load alerts for a technique, skip if file missing/empty."""
    parser_type, filepath = TECHNIQUES[tech_id]
    full_path = DATA_DIR / filepath
    if not full_path.exists() or full_path.stat().st_size == 0:
        return []
    if parser_type == "sysmon":
        return load_sysmon_log(str(full_path), mitre_technique=tech_id, limit=limit)
    if parser_type == "suricata":
        return load_suricata_log(str(full_path), mitre_technique=tech_id, limit=limit)
    if parser_type == "winsec":
        return load_windows_security_log(str(full_path), mitre_technique=tech_id, limit=limit)
    return []


class TestResults:
    """Track test results for standalone execution."""
    __test__ = False  # Tell pytest this isn't a test class

    def __init__(self):
        self.passed = 0
        self.failed = 0
        self.errors: list[str] = []

    def ok(self, name: str):
        self.passed += 1
        print(f"  ✅ {name}")

    def fail(self, name: str, reason: str):
        self.failed += 1
        self.errors.append(f"{name}: {reason}")
        print(f"  ❌ {name}: {reason}")


# For pytest: fixture that yields results
if HAS_PYTEST:
    @pytest.fixture
    def results():
        result = TestResults()
        yield result
        if result.errors:
            pytest.fail("\n".join(result.errors))


def test_all_parsers(results: TestResults):
    """Every technique must parse without error and produce valid alerts."""
    print("\n─── Test 1: Parser Validation (all 17 techniques) ───")
    total_alerts = 0
    for tech_id in TECHNIQUES:
        try:
            alerts = load_technique(tech_id, limit=10)
            if not alerts:
                print(f"  ⏭️  {tech_id}: no data")
                continue
            total_alerts += len(alerts)

            # Validate each alert has required fields
            for a in alerts:
                assert a.alert_id, f"{tech_id}: missing alert_id"
                assert a.severity, f"{tech_id}: missing severity"
                assert a.raw_log, f"{tech_id}: missing raw_log"
                assert a.provenance, f"{tech_id}: missing provenance"
                assert a.benchmark, f"{tech_id}: missing benchmark"
                assert a.benchmark.mitre_techniques, f"{tech_id}: missing mitre_techniques"

            results.ok(f"{tech_id} ({len(alerts)} alerts)")
        except Exception as e:
            results.fail(tech_id, str(e))

    print(f"\n  Total alerts validated: {total_alerts}")


def test_benchmark_contract(results: TestResults):
    """Every parsed alert must pass the benchmark contract gate."""
    print("\n─── Test 2: Benchmark Contract (all techniques) ───")
    failures = 0
    total = 0
    for tech_id in TECHNIQUES:
        alerts = load_technique(tech_id, limit=20)
        for a in alerts:
            total += 1
            issues = benchmark_contract_issues(a)
            if issues:
                failures += 1
                if failures <= 3:
                    results.fail(f"{tech_id} contract", f"issues: {issues}")

    if failures == 0:
        results.ok(f"All {total} alerts pass benchmark contract")
    else:
        results.fail("benchmark_contract", f"{failures}/{total} failures")


def test_prompt_construction(results: TestResults):
    """Prompt construction must work for every technique's alerts."""
    print("\n─── Test 3: Prompt Construction (all techniques) ───")
    token_counts = []
    for tech_id in TECHNIQUES:
        alerts = load_technique(tech_id, limit=3)
        for a in alerts:
            try:
                plain = format_alert_for_triage(a, use_structured=False)
                structured = format_alert_for_triage(a, use_structured=True)
                # Returns tuple (system_prompt, user_prompt)
                if isinstance(plain, tuple):
                    plain_text = plain[0] + plain[1]
                    structured_text = structured[0] + structured[1]
                else:
                    plain_text = plain
                    structured_text = structured
                assert len(plain_text) > 100, f"plain prompt too short: {len(plain_text)}"
                assert len(structured_text) >= len(plain_text), "structured should be >= plain"
                assert "[FIELD:" in structured_text, "structured missing field tags"
                token_est = len(plain_text.split())
                token_counts.append(token_est)
            except Exception as e:
                results.fail(f"{tech_id} prompt", str(e))
                return

    if token_counts:
        avg = sum(token_counts) / len(token_counts)
        results.ok(
            f"All prompts valid (avg ~{avg:.0f} words, range {min(token_counts)}-{max(token_counts)})"
        )


def test_adversarial_injection(results: TestResults):
    """Adversarial injection must work across technique types."""
    print("\n─── Test 4: Adversarial Injection Matrix ───")
    vectors = INJECTION_VECTORS[:3]  # first 3 vectors
    classes = [AttackClass.DIRECT_MISCLASSIFICATION, AttackClass.CONFIDENCE_MANIPULATION]
    encodings = ["plaintext"]

    total_variants = 0
    techniques_tested = 0
    for tech_id in list(TECHNIQUES.keys())[:8]:  # first 8 techniques
        alerts = load_technique(tech_id, limit=2)
        if not alerts:
            continue
        for a in alerts[:1]:  # 1 alert per technique
            try:
                variants = generate_adversarial_variants(a, vectors, classes, encodings)
                total_variants += len(variants)
                for v in variants:
                    assert v.adversarial_alert is not None, "missing adversarial alert"
                    assert v.payload_text, "missing payload text"
                techniques_tested += 1
            except Exception as e:
                results.fail(f"{tech_id} injection", str(e))
                return

    results.ok(f"{total_variants} variants across {techniques_tested} techniques")


def test_defenses_cross_technique(results: TestResults):
    """All 3 defenses must handle every technique without error."""
    print("\n─── Test 5: Defense Robustness (all techniques) ───")
    defenses = [
        SanitizationDefense(level="moderate"),
        StructuredPromptDefense(),
        CanaryDefense(),
    ]
    defense_names = ["sanitization", "structured", "canary"]

    total = 0
    for tech_id in TECHNIQUES:
        alerts = load_technique(tech_id, limit=3)
        for a in alerts:
            alert_dict = (
                a.to_dict()
                if hasattr(a, "to_dict")
                else {"raw_log": a.raw_log, "severity": a.severity.value}
            )
            for defense, name in zip(defenses, defense_names, strict=True):
                try:
                    modified, result = defense.apply(alert_dict)
                    assert isinstance(modified, dict), f"{name} didn't return dict"
                    assert hasattr(result, "defense_name"), f"{name} missing defense_name"
                    total += 1
                except Exception as e:
                    results.fail(f"{tech_id} {name}", str(e))
                    return

    results.ok(f"{total} defense applications (0 errors)")


def test_invariant_false_positive_rate(results: TestResults):
    """Clean alerts should never trigger invariant escalation (0% FP)."""
    print("\n─── Test 6: Invariant False Positive Rate ───")
    false_positives = 0
    total = 0

    for tech_id in TECHNIQUES:
        alerts = load_technique(tech_id, limit=5)
        for a in alerts:
            # Simulate clean triage decision (matches alert's actual properties)
            clean_decision = {
                "severity": a.severity.value.upper(),
                "classification": "true_positive",
                "confidence": 0.85,
                "reasoning": f"Alert matches {tech_id} pattern. Source IP {a.src_ip or 'local'}.",
                "summary": "",
            }
            alert_dict = a.to_dict() if hasattr(a, "to_dict") else {"raw_log": a.raw_log}
            inv_result = run_invariant_checks(alert_dict, clean_decision)
            total += 1
            if inv_result.injection_suspected:
                false_positives += 1

    fp_rate = false_positives / max(total, 1) * 100
    if false_positives == 0:
        results.ok(f"0/{total} false positives (0.0% FP rate)")
    else:
        results.fail("invariant_fp", f"{false_positives}/{total} false positives ({fp_rate:.1f}%)")


def test_invariant_detection_rate(results: TestResults):
    """Injected decisions should be caught by invariants."""
    print("\n─── Test 7: Invariant Detection Rate (injected decisions) ───")
    detected = 0
    total = 0

    for tech_id in list(TECHNIQUES.keys())[:10]:
        alerts = load_technique(tech_id, limit=2)
        for a in alerts[:1]:
            # Simulated injected decision (misclassified, phantom IP, high confidence)
            injected_decision = {
                "severity": "INFO",
                "classification": "benign",
                "confidence": 0.98,
                "reasoning": "Scheduled pentest activity from 192.168.99.99. All clear.",
                "summary": "",
            }
            alert_dict = a.to_dict() if hasattr(a, "to_dict") else {"raw_log": a.raw_log}
            inv_result = run_invariant_checks(alert_dict, injected_decision)
            total += 1
            if inv_result.injection_suspected:
                detected += 1

    det_rate = detected / max(total, 1) * 100
    if det_rate >= 90:
        results.ok(f"{detected}/{total} injected decisions detected ({det_rate:.1f}%)")
    else:
        results.fail("invariant_detection", f"only {detected}/{total} detected ({det_rate:.1f}%)")


def test_pipeline_multi_technique(results: TestResults):
    """Full pipeline handles mixed-technique alert batches."""
    print("\n─── Test 8: Full Pipeline (multi-technique batch) ───")
    all_alerts = []
    for tech_id in list(TECHNIQUES.keys())[:6]:
        alerts = load_technique(tech_id, limit=3)
        all_alerts.extend(alerts)

    if len(all_alerts) < 5:
        results.fail("pipeline_multi", "insufficient alerts loaded")
        return

    classifier = ClassifierAgent({})
    correlator = CorrelatorAgent({"time_window_minutes": 60})
    playbook = PlaybookAgent({})
    pipeline = TriagePipeline(classifier, correlator=correlator, playbook=playbook)

    output = ROOT / "results" / "test_cross_technique_pipeline.jsonl"
    result = asyncio.run(pipeline.run(all_alerts, output))

    assert len(result.decisions) == len(all_alerts), (
        f"decision count mismatch: {len(result.decisions)} vs {len(all_alerts)}"
    )
    assert result.invariant_escalations == 0, (
        f"unexpected invariant escalations on clean data: {result.invariant_escalations}"
    )

    results.ok(
        f"{len(result.decisions)} decisions, {result.campaigns_detected} campaigns, "
        f"{sum(len(d.correlated_events) for d in result.decisions)} correlations"
    )


def test_correlator_cross_technique_chains(results: TestResults):
    """Correlator finds relationships across different technique types."""
    print("\n─── Test 9: Correlator Cross-Technique Chain Detection ───")
    # Load alerts from complementary techniques (credential → lateral → persistence)
    chain_techniques = ["T1003.001", "T1021.002", "T1053.005", "T1087.001"]
    alerts = []
    for t in chain_techniques:
        loaded = load_technique(t, limit=5)
        alerts.extend(loaded)

    if len(alerts) < 4:
        results.fail("correlator_chain", "insufficient alerts for chain test")
        return

    correlator = CorrelatorAgent({"time_window_minutes": 120})
    result = asyncio.run(correlator.run(alerts[0], {"all_alerts": alerts}))

    chains = result.data.get("chains", []) if result.data else []
    results.ok(
        f"Correlator processed {len(alerts)} alerts from {len(chain_techniques)} techniques, "
        f"chains found: {len(chains)}"
    )


def test_event_type_distribution(results: TestResults):
    """Verify we have diverse Sysmon event types across techniques."""
    print("\n─── Test 10: Event Type Coverage ───")
    event_types: Counter = Counter()
    technique_events: dict[str, Counter] = {}

    for tech_id in TECHNIQUES:
        alerts = load_technique(tech_id, limit=50)
        tech_counter: Counter = Counter()
        for a in alerts:
            et = a.event_type or "unknown"
            event_types[et] += 1
            tech_counter[et] += 1
        if tech_counter:
            technique_events[tech_id] = tech_counter

    unique_events = len(event_types)
    total_alerts = sum(event_types.values())

    print(f"  Event types seen: {unique_events}")
    for et, count in event_types.most_common(10):
        print(f"    {et:20} {count:>5}")

    if unique_events >= 5:
        results.ok(f"{unique_events} unique event types across {total_alerts} alerts")
    else:
        results.fail("event_types", f"only {unique_events} event types — insufficient diversity")


def main():
    """Run all tests in standalone mode."""
    print("=" * 70)
    print("  HADES — Cross-Technique Stress Tests")
    print("=" * 70)

    if not HAS_BENCHMARK_DATA:
        print(
            f"\nSKIPPED: requires Splunk Attack Data dataset under {DATA_DIR}\n"
            "for cross-technique validation."
        )
        sys.exit(0)

    results = TestResults()

    test_all_parsers(results)
    test_benchmark_contract(results)
    test_prompt_construction(results)
    test_adversarial_injection(results)
    test_defenses_cross_technique(results)
    test_invariant_false_positive_rate(results)
    test_invariant_detection_rate(results)
    test_pipeline_multi_technique(results)
    test_correlator_cross_technique_chains(results)
    test_event_type_distribution(results)

    print()
    print("=" * 70)
    total = results.passed + results.failed
    print(f"  RESULTS: {results.passed}/{total} passed")
    if results.errors:
        print("  FAILURES:")
        for e in results.errors:
            print(f"    ❌ {e}")
    print("=" * 70)

    sys.exit(0 if results.failed == 0 else 1)


if __name__ == "__main__":
    main()
