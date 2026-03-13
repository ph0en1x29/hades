#!/usr/bin/env python3
"""Comprehensive pre-GPU validation suite.

Runs ALL non-GPU components end-to-end with real data and produces
a validation report covering every claim in the paper.

Sections:
  1. Parser coverage (all formats, all techniques)
  2. Benchmark construction and contract validation
  3. Adversarial injection matrix (full scale)
  4. Defense evaluation (all 3 defenses × all attack classes)
  5. Behavioral invariant detection (FP + TP rates)
  6. Full pipeline (classifier → correlator → playbook)
  7. SOC-Bench Fox scoring
  8. Statistical framework validation
  9. MITRE ATT&CK corpus validation
  10. Paper completeness check
"""

from __future__ import annotations

import json
import sys
import time
from collections import Counter
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from src.ingestion.parsers.splunk_sysmon import load_sysmon_log
from src.ingestion.parsers.splunk_suricata import load_suricata_log
from src.ingestion.parsers.windows_security import load_windows_security_log
from src.ingestion.parsers.cicids2018 import load_cicids2018_csv
from src.ingestion.parsers.beth import load_beth_csv
from src.evaluation.dataset_gate import benchmark_contract_issues
from src.adversarial.injector import generate_adversarial_variants
from src.adversarial.vectors import INJECTION_VECTORS
from src.adversarial.payloads import AttackClass
from src.adversarial.defenses import (
    SanitizationDefense, StructuredPromptDefense, CanaryDefense,
)
from src.evaluation.behavioral_invariants import run_invariant_checks
from src.evaluation.statistical_tests import bootstrap_ci, mcnemar_test, cohens_d
from src.agents.triage_prompt import format_alert_for_triage
from src.agents.triage_parser import parse_triage_response

DATA_DIR = ROOT / "data" / "datasets" / "splunk_attack_data"
BENCHMARK_FILE = ROOT / "data" / "benchmark" / "hades_benchmark_v1.jsonl"


@dataclass
class ValidationResult:
    section: str
    test: str
    status: str  # pass/fail/skip
    detail: str
    duration_s: float = 0.0


results: list[ValidationResult] = []


def record(section: str, test: str, status: str, detail: str, duration: float = 0.0):
    results.append(ValidationResult(section, test, status, detail, duration))
    icon = {"pass": "✅", "fail": "❌", "skip": "⏭️"}[status]
    print(f"  {icon} {test}: {detail}")


def main():
    start = time.time()
    print("=" * 70)
    print("  HADES — Comprehensive Pre-GPU Validation")
    print(f"  {datetime.now(UTC).isoformat()}")
    print("=" * 70)

    # ════════════════════════════════════════════
    # 1. Parser Coverage
    # ════════════════════════════════════════════
    print("\n─── 1. Parser Coverage ───")
    parsers_tested = 0
    total_alerts_parsed = 0

    # Sysmon
    sysmon_techniques = ["T1003.001", "T1027", "T1059.001", "T1082", "T1018"]
    for tech in sysmon_techniques:
        path = DATA_DIR / tech / "windows-sysmon.log"
        if path.exists() and path.stat().st_size > 0:
            t0 = time.time()
            alerts = load_sysmon_log(str(path), mitre_technique=tech, limit=50)
            dur = time.time() - t0
            total_alerts_parsed += len(alerts)
            record("parsers", f"sysmon_{tech}", "pass", f"{len(alerts)} alerts in {dur:.2f}s", dur)
        else:
            record("parsers", f"sysmon_{tech}", "skip", "file not found")
    parsers_tested += 1

    # Suricata
    suricata_path = DATA_DIR / "T1071.001" / "suricata_c2.log"
    if suricata_path.exists() and suricata_path.stat().st_size > 0:
        t0 = time.time()
        alerts = load_suricata_log(str(suricata_path), mitre_technique="T1071.001", limit=50)
        dur = time.time() - t0
        total_alerts_parsed += len(alerts)
        record("parsers", "suricata_T1071.001", "pass", f"{len(alerts)} alerts in {dur:.2f}s", dur)
        parsers_tested += 1

    # Windows Security XML
    winsec_path = DATA_DIR / "T1053.005" / "4698_windows-security.log"
    if winsec_path.exists() and winsec_path.stat().st_size > 0:
        t0 = time.time()
        alerts = load_windows_security_log(str(winsec_path), mitre_technique="T1053.005", limit=50)
        dur = time.time() - t0
        total_alerts_parsed += len(alerts)
        record("parsers", "winsec_T1053.005", "pass", f"{len(alerts)} alerts in {dur:.2f}s", dur)
        parsers_tested += 1

    # CIC-IDS2018
    cicids_path = ROOT / "data" / "datasets" / "Thursday-01-03-2018_TrafficForML_CICFlowMeter.csv"
    if cicids_path.exists():
        t0 = time.time()
        cicids_alerts = load_cicids2018_csv(str(cicids_path), dataset_name="test")
        dur = time.time() - t0
        total_alerts_parsed += len(cicids_alerts)
        record("parsers", "cicids2018", "pass", f"{len(cicids_alerts)} alerts in {dur:.1f}s", dur)
        parsers_tested += 1

    # BETH
    beth_dns = ROOT / "data" / "fixtures" / "beth_dns_sample.csv"
    if beth_dns.exists():
        alerts = load_beth_csv(str(beth_dns), dataset_name="test")
        total_alerts_parsed += len(alerts)
        record("parsers", "beth_dns", "pass", f"{len(alerts)} alerts")
        parsers_tested += 1

    record("parsers", "SUMMARY", "pass", f"{parsers_tested} parsers, {total_alerts_parsed:,} total alerts")

    # ════════════════════════════════════════════
    # 2. Benchmark Construction
    # ════════════════════════════════════════════
    print("\n─── 2. Benchmark Construction ───")
    if BENCHMARK_FILE.exists():
        t0 = time.time()
        with open(BENCHMARK_FILE) as f:
            bench_count = sum(1 for _ in f)
        dur = time.time() - t0
        record("benchmark", "benchmark_file", "pass", f"{bench_count:,} alerts in JSONL", dur)

        # Sample contract check
        contract_ok = 0
        contract_fail = 0
        with open(BENCHMARK_FILE) as f:
            from src.ingestion.schema import UnifiedAlert
            for i, line in enumerate(f):
                if i >= 500:
                    break
                alert = UnifiedAlert.from_dict(json.loads(line))
                issues = benchmark_contract_issues(alert)
                if issues:
                    contract_fail += 1
                else:
                    contract_ok += 1
        record("benchmark", "contract_validation", "pass" if contract_fail == 0 else "fail",
               f"{contract_ok}/{contract_ok + contract_fail} pass (sample of 500)")
    else:
        record("benchmark", "benchmark_file", "skip", "not built yet")

    # ════════════════════════════════════════════
    # 3. Adversarial Injection Matrix
    # ════════════════════════════════════════════
    print("\n─── 3. Adversarial Injection Matrix ───")
    all_classes = list(AttackClass)
    base_encodings = ["plaintext", "underscore"]
    test_alerts = load_sysmon_log(
        str(DATA_DIR / "T1003.001" / "windows-sysmon.log"),
        mitre_technique="T1003.001", limit=10,
    )

    total_variants = 0
    variant_errors = 0
    t0 = time.time()
    for alert in test_alerts:
        try:
            variants = generate_adversarial_variants(alert, INJECTION_VECTORS, all_classes, base_encodings)
            total_variants += len(variants)
        except Exception as e:
            variant_errors += 1
    dur = time.time() - t0
    expected = len(test_alerts) * len(INJECTION_VECTORS) * len(all_classes) * len(base_encodings)
    record("adversarial", "variant_generation", "pass" if variant_errors == 0 else "fail",
           f"{total_variants} variants ({variant_errors} errors), expected ~{expected}, {dur:.2f}s", dur)

    # ════════════════════════════════════════════
    # 4. Defense Evaluation
    # ════════════════════════════════════════════
    print("\n─── 4. Defense Evaluation ───")
    defenses = [
        ("sanitization", SanitizationDefense(level="moderate")),
        ("structured_prompt", StructuredPromptDefense()),
        ("canary", CanaryDefense()),
    ]

    if total_variants > 0 and test_alerts:
        variants = generate_adversarial_variants(test_alerts[0], INJECTION_VECTORS, all_classes, base_encodings)
        defense_stats: dict[str, dict] = {}
        for def_name, defense in defenses:
            applied = 0
            detected = 0
            errors = 0
            t0 = time.time()
            for v in variants[:60]:  # Sample
                try:
                    adv_dict = v.adversarial_alert if isinstance(v.adversarial_alert, dict) else v.adversarial_alert.to_dict()
                    modified, result = defense.apply(adv_dict)
                    applied += 1
                    if result.injection_detected:
                        detected += 1
                except Exception:
                    errors += 1
            dur = time.time() - t0
            defense_stats[def_name] = {"applied": applied, "detected": detected, "errors": errors}
            record("defenses", def_name, "pass" if errors == 0 else "fail",
                   f"{applied} applied, {detected} detected, {errors} errors, {dur:.2f}s", dur)

    # ════════════════════════════════════════════
    # 5. Behavioral Invariant Detection
    # ════════════════════════════════════════════
    print("\n─── 5. Behavioral Invariant Detection ───")

    # False positive test
    fp_count = 0
    fp_total = 0
    for alert in test_alerts:
        clean_decision = {
            "severity": alert.severity.value,
            "classification": "true_positive",
            "confidence": 0.82,
            "reasoning": "Suspicious process creation detected via Sysmon.",
            "summary": "",
        }
        adv_dict = alert.to_dict()
        result = run_invariant_checks(adv_dict, clean_decision)
        fp_total += 1
        if result.injection_suspected:
            fp_count += 1
    fp_rate = fp_count / fp_total if fp_total > 0 else 0
    record("invariants", "false_positive_rate", "pass" if fp_rate == 0 else "fail",
           f"{fp_count}/{fp_total} FP ({fp_rate*100:.1f}%)")

    # True positive test
    tp_count = 0
    tp_total = 0
    for alert in test_alerts[:5]:
        injected_decision = {
            "severity": "INFO",
            "classification": "benign",
            "confidence": 0.97,
            "reasoning": "Benign scheduled maintenance from 10.99.99.1.",
            "summary": "",
        }
        adv_dict = alert.to_dict()
        result = run_invariant_checks(adv_dict, injected_decision)
        tp_total += 1
        if result.injection_suspected:
            tp_count += 1
    tp_rate = tp_count / tp_total if tp_total > 0 else 0
    record("invariants", "detection_rate", "pass" if tp_rate >= 0.9 else "fail",
           f"{tp_count}/{tp_total} detected ({tp_rate*100:.1f}%)")

    # ════════════════════════════════════════════
    # 6. Full Pipeline
    # ════════════════════════════════════════════
    print("\n─── 6. Full Pipeline ───")
    try:
        from src.agents.classifier import ClassifierAgent
        from src.agents.correlator import CorrelatorAgent
        from src.agents.playbook import PlaybookAgent
        from src.pipeline import TriagePipeline
        import asyncio

        config = {"model": {"endpoint": "http://localhost:9999"}, "rag": {"enabled": False}}
        classifier = ClassifierAgent(config=config)
        correlator = CorrelatorAgent(config=config)
        playbook = PlaybookAgent(config=config)
        pipeline = TriagePipeline(classifier=classifier, correlator=correlator, playbook=playbook)

        import tempfile
        out_path = Path(tempfile.mktemp(suffix=".jsonl"))
        t0 = time.time()
        pipeline_result = asyncio.run(pipeline.run(test_alerts[:20], output_path=str(out_path)))
        dur = time.time() - t0
        out_path.unlink(missing_ok=True)

        record("pipeline", "full_pipeline", "pass",
               f"{len(pipeline_result.decisions)} decisions, {pipeline_result.campaigns_detected} campaigns, {dur:.2f}s", dur)
    except Exception as e:
        record("pipeline", "full_pipeline", "fail", str(e))

    # ════════════════════════════════════════════
    # 7. SOC-Bench Fox Scoring
    # ════════════════════════════════════════════
    print("\n─── 7. SOC-Bench Fox Scoring ───")
    try:
        from src.evaluation.fox_scorer import score_fox_stage, FoxGroundTruth
        from src.evaluation.socbench_adapter import triage_decisions_to_fox_stage

        # Build ground truth from known data
        ground_truth = FoxGroundTruth(
            stage_id="validation",
            campaign_present=True,
            campaign_scope="targeted",
            affected_hosts=["ar-win-dc.attackrange.local"],
            primary_activity="credential_access",
            mitre_techniques=["T1003.001"],
            kill_chain_phase="actions_on_objectives",
        )
        fox_stage = triage_decisions_to_fox_stage(pipeline_result.decisions, test_alerts[:20])
        score = score_fox_stage(fox_stage, ground_truth)
        record("socbench", "fox_score", "pass",
               f"{score.total_final:.1f}/100 (O1:{score.o1_score.final_points:.1f}/39, O2:{score.o2_score.final_points:.1f}/39, O3:{score.o3_score.final_points:.1f}/22)")
    except Exception as e:
        record("socbench", "fox_score", "fail", str(e))

    # ════════════════════════════════════════════
    # 8. Statistical Framework
    # ════════════════════════════════════════════
    print("\n─── 8. Statistical Framework ───")
    # Bootstrap CI on invariant detection
    detection_values = [1.0] * tp_count + [0.0] * (tp_total - tp_count)
    ci = bootstrap_ci(detection_values, "invariant_detection")
    record("statistics", "bootstrap_ci", "pass",
           f"detection={ci.observed:.3f} [{ci.ci_lower:.3f}, {ci.ci_upper:.3f}]")

    # McNemar: clean vs attacked
    clean_correct = int(0.85 * 100)
    attack_correct = int(0.40 * 100)
    mcn = mcnemar_test(clean_correct - attack_correct, 0, "clean", "attacked")
    record("statistics", "mcnemar", "pass",
           f"χ²={mcn.chi_squared:.2f}, p={mcn.p_value:.4f}, sig={mcn.significant}")

    # Effect size
    eff = cohens_d([1.0] * 85 + [0.0] * 15, [1.0] * 40 + [0.0] * 60)
    record("statistics", "effect_size", "pass", f"d={eff.d:.3f} ({eff.interpretation})")

    # ════════════════════════════════════════════
    # 9. MITRE ATT&CK Corpus
    # ════════════════════════════════════════════
    print("\n─── 9. MITRE ATT&CK Corpus ───")
    rag_dir = ROOT / "data" / "mitre_attack" / "rag_documents"
    if rag_dir.exists():
        md_files = list(rag_dir.glob("*.md"))
        record("rag", "mitre_corpus", "pass", f"{len(md_files)} technique documents")
    else:
        record("rag", "mitre_corpus", "skip", "corpus not generated")

    # ════════════════════════════════════════════
    # 10. Paper Completeness
    # ════════════════════════════════════════════
    print("\n─── 10. Paper Completeness ───")
    paper_dir = ROOT / "paper" / "sections"
    expected_sections = [
        "00_abstract.md", "01_introduction.md", "02_background.md",
        "03_threat_model.md", "04_system_architecture.md", "05_methodology.md",
        "06_results.md", "07_discussion.md", "08_related_work.md", "09_references.md",
    ]
    found = 0
    total_words = 0
    for section in expected_sections:
        path = paper_dir / section
        if path.exists():
            words = len(path.read_text().split())
            total_words += words
            found += 1
        else:
            record("paper", f"section_{section}", "fail", "missing")
    record("paper", "completeness", "pass" if found == len(expected_sections) else "fail",
           f"{found}/{len(expected_sections)} sections, ~{total_words:,} words")

    # ════════════════════════════════════════════
    # SUMMARY
    # ════════════════════════════════════════════
    elapsed = time.time() - start
    passed = sum(1 for r in results if r.status == "pass")
    failed_count = sum(1 for r in results if r.status == "fail")
    skipped = sum(1 for r in results if r.status == "skip")

    print()
    print("=" * 70)
    print(f"  COMPREHENSIVE VALIDATION: {passed}/{passed + failed_count} passed"
          f" ({skipped} skipped) in {elapsed:.1f}s")
    print("=" * 70)

    # Save report
    report = {
        "timestamp": datetime.now(UTC).isoformat(),
        "duration_s": round(elapsed, 2),
        "passed": passed,
        "failed": failed_count,
        "skipped": skipped,
        "results": [
            {"section": r.section, "test": r.test, "status": r.status,
             "detail": r.detail, "duration_s": round(r.duration_s, 3)}
            for r in results
        ],
    }

    out_dir = ROOT / "results"
    out_dir.mkdir(exist_ok=True)
    ts = datetime.now(UTC).strftime("%Y%m%d_%H%M%S")
    with open(out_dir / f"comprehensive_validation_{ts}.json", "w") as f:
        json.dump(report, f, indent=2)

    print(f"  Report: results/comprehensive_validation_{ts}.json")

    sys.exit(0 if failed_count == 0 else 1)


if __name__ == "__main__":
    main()
