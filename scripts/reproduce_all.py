#!/usr/bin/env python3
"""Reproducibility Package — Run all experiments and generate paper numbers.

Usage:
  python3 scripts/reproduce_all.py              # Non-GPU experiments only
  python3 scripts/reproduce_all.py --with-gpu   # Full suite (requires vLLM)

Generates:
  results/reproducibility_report.md   — Full markdown report
  results/reproducibility_report.json — Machine-readable results
"""

from __future__ import annotations

import json
import subprocess
import sys
import time
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
SKIP_MARKER = "SKIPPED:"

def _run_script(name: str, args: list[str] | None = None) -> tuple[str, str, float]:
    """Run a Python script and return (status, output, seconds)."""
    cmd = [sys.executable, str(ROOT / name)] + (args or [])
    start = time.monotonic()
    try:
        result = subprocess.run(
            cmd, capture_output=True, text=True, timeout=300, cwd=str(ROOT),
        )
        elapsed = time.monotonic() - start
        output = result.stdout + result.stderr
        if result.returncode == 0 and any(
            line.startswith(SKIP_MARKER) for line in output.splitlines()
        ):
            return "skipped", output, elapsed
        return ("pass" if result.returncode == 0 else "fail"), output, elapsed
    except subprocess.TimeoutExpired:
        return "fail", "TIMEOUT after 300s", time.monotonic() - start
    except Exception as e:
        return "fail", str(e), time.monotonic() - start


def _run_test(name: str) -> tuple[str, str, float]:
    """Run a standalone test or validation script."""
    return _run_script(name)


def _icon(status: str) -> str:
    return {"pass": "✅", "fail": "❌", "skipped": "⏭️"}[status]


def main():
    with_gpu = "--with-gpu" in sys.argv
    timestamp = datetime.now(UTC).strftime("%Y%m%d_%H%M%S")

    print("=" * 70)
    print("  HADES Reproducibility Package")
    print(f"  Timestamp: {timestamp}")
    print(f"  GPU mode:  {'ENABLED' if with_gpu else 'DISABLED (non-GPU only)'}")
    print("=" * 70)
    print()

    results: dict[str, Any] = {
        "timestamp": timestamp,
        "gpu_mode": with_gpu,
        "sections": {},
    }

    # === Section 1: Unit Tests ===
    print("─── Section 1: Unit Tests ───")
    test_files = [
        "tests/test_schemas.py",
        "tests/test_parsers.py",
        "tests/test_behavioral_invariants.py",
        "tests/test_pipeline_invariants.py",
        "tests/test_correlator.py",
        "tests/test_playbook.py",
        "tests/test_dataset_gate.py",
        "tests/test_beth_parser.py",
        "tests/test_full_pipeline.py",
        "tests/test_fox_e2e.py",
        "tests/test_parser_edge_cases.py",
        "tests/test_cross_technique.py",
        "tests/test_adversarial_stress.py",
        "tests/test_statistical_tests.py",
        "tests/test_adversarial_defenses.py",
        "tests/test_socbench_adapter.py",
        "tests/test_correlator_stress.py",
        "tests/test_rag_smoke.py",
    ]
    test_results = []
    for tf in test_files:
        if not (ROOT / tf).exists():
            print(f"  ⏭️  {tf} (not found, skipping)")
            test_results.append({"file": tf, "status": "skipped"})
            continue
        status, out, secs = _run_test(tf)
        print(f"  {_icon(status)} {tf} ({secs:.1f}s)")
        test_results.append({
            "file": tf, "status": status,
            "seconds": round(secs, 2), "output_tail": out[-200:] if status == "fail" else "",
        })
    results["sections"]["unit_tests"] = test_results

    # === Section 2: Architecture Validation (18-point suite) ===
    print("\n─── Section 2: Architecture Validation ───")
    run_status, out, secs = _run_script("scripts/validate_architecture.py")
    # Extract pass count
    lines = out.strip().split("\n")
    summary = [
        line
        for line in lines
        if "passed" in line.lower() or "PASS" in line or "FAIL" in line
    ]
    print(f"  {_icon(run_status)} validate_architecture.py ({secs:.1f}s)")
    for line in summary[-3:]:
        print(f"    {line.strip()}")
    results["sections"]["architecture_validation"] = {
        "status": run_status,
        "seconds": round(secs, 2),
        "summary": summary,
    }

    # === Section 3: E3 Payload Survival ===
    print("\n─── Section 3: E3 Payload Survival ───")
    run_status, out, secs = _run_script("scripts/run_e3_payload_survival.py")
    print(f"  {_icon(run_status)} E3 payload survival ({secs:.1f}s)")
    results["sections"]["e3_payload_survival"] = {
        "status": run_status, "seconds": round(secs, 2),
    }

    # === Section 4: E3 Extended Encodings ===
    print("\n─── Section 4: E3 Extended Encodings ───")
    run_status, out, secs = _run_script("scripts/run_e3_extended.py")
    print(f"  {_icon(run_status)} E3 extended encodings ({secs:.1f}s)")
    results["sections"]["e3_extended"] = {
        "status": run_status, "seconds": round(secs, 2),
    }

    # === Section 5: Invariant Evaluation ===
    print("\n─── Section 5: Invariant Evaluation ───")
    run_status, out, secs = _run_script("scripts/run_invariant_evaluation.py")
    print(f"  {_icon(run_status)} Invariant evaluation ({secs:.1f}s)")
    results["sections"]["invariant_evaluation"] = {
        "status": run_status, "seconds": round(secs, 2),
    }

    # === Section 6: Defense Analysis ===
    print("\n─── Section 6: Defense Analysis ───")
    run_status, out, secs = _run_script("scripts/run_defense_analysis.py")
    print(f"  {_icon(run_status)} Defense analysis ({secs:.1f}s)")
    results["sections"]["defense_analysis"] = {
        "status": run_status, "seconds": round(secs, 2),
    }

    # === Section 7: Campaign Demo ===
    print("\n─── Section 7: Campaign Demo ───")
    run_status, out, secs = _run_script("scripts/run_campaign_demo.py")
    # Extract summary
    campaign_lines = [
        line
        for line in out.split("\n")
        if "ALL GREEN" in line or "Chain" in line or "Campaign" in line
    ]
    print(f"  {_icon(run_status)} Campaign demo ({secs:.1f}s)")
    for campaign_line in campaign_lines[:5]:
        print(f"    {campaign_line.strip()}")
    results["sections"]["campaign_demo"] = {
        "status": run_status, "seconds": round(secs, 2),
        "summary": campaign_lines,
    }

    # === Section 8: E2E Demo ===
    print("\n─── Section 8: E2E Demo ───")
    run_status, out, secs = _run_script("scripts/run_e2e_demo.py")
    print(f"  {_icon(run_status)} E2E demo ({secs:.1f}s)")
    results["sections"]["e2e_demo"] = {
        "status": run_status, "seconds": round(secs, 2),
    }

    # === Section 9: Adversarial E2E Pipeline ===
    print("\n─── Section 9: Adversarial E2E Pipeline ───")
    run_status, out, secs = _run_script("scripts/run_adversarial_e2e.py")
    adv_lines = [
        line
        for line in out.split("\n")
        if "%" in line or "GREEN" in line or "Fox" in line or "Delta" in line
    ]
    print(f"  {_icon(run_status)} Adversarial E2E ({secs:.1f}s)")
    for adv_line in adv_lines[:8]:
        print(f"    {adv_line.strip()}")
    results["sections"]["adversarial_e2e"] = {
        "status": run_status, "seconds": round(secs, 2),
        "summary": adv_lines,
    }

    # === Section 10: Statistical Tests ===
    print("\n─── Section 10: Statistical Tests ───")
    stat_status, out, secs = _run_test("tests/test_statistical_tests.py")
    print(f"  {_icon(stat_status)} Statistical tests ({secs:.1f}s)")
    results["sections"]["statistical_tests"] = {
        "status": stat_status, "seconds": round(secs, 2),
    }

    # === Section 11: BETH Parser Validation ===
    print("\n─── Section 11: BETH Parser Validation ───")
    beth_status, out, secs = _run_script("scripts/generate_beth_synthetic.py")
    print(f"  {_icon(beth_status)} BETH synthetic generation ({secs:.1f}s)")
    results["sections"]["beth_validation"] = {
        "status": beth_status, "seconds": round(secs, 2),
    }

    # === Section 12: Benchmark Build ===
    print("\n─── Section 12: Benchmark Pack ───")
    run_status, out, secs = _run_script("scripts/build_benchmark_pack.py")
    bench_lines = [
        line
        for line in out.split("\n")
        if "alert" in line.lower() or "technique" in line.lower() or "tactic" in line.lower()
    ]
    print(f"  {_icon(run_status)} Benchmark build ({secs:.1f}s)")
    for bench_line in bench_lines[:5]:
        print(f"    {bench_line.strip()}")
    results["sections"]["benchmark_build"] = {
        "status": run_status, "seconds": round(secs, 2),
        "summary": bench_lines,
    }

    # === Section 13: GPU Experiments (optional) ===
    if with_gpu:
        print("\n─── Section 13: GPU Experiments ───")
        for exp in ["E1", "E2"]:
            run_status, out, secs = _run_script("scripts/run_experiment.py", [f"--experiment={exp}"])
            print(f"  {_icon(run_status)} Experiment {exp} ({secs:.1f}s)")
            results["sections"][f"experiment_{exp}"] = {
                "status": run_status, "seconds": round(secs, 2),
            }
    else:
        print("\n─── Section 13: GPU Experiments ───")
        print("  ⏭️  Skipped (run with --with-gpu)")

    # === Summary ===
    print("\n" + "═" * 70)
    sections = results["sections"]
    total = 0
    passed = 0
    skipped = 0
    for _name, data in sections.items():
        if isinstance(data, list):
            for item in data:
                if item.get("status") != "skipped":
                    total += 1
                    if item.get("status") == "pass":
                        passed += 1
                else:
                    skipped += 1
        elif isinstance(data, dict) and "status" in data:
            if data["status"] != "skipped":
                total += 1
            else:
                skipped += 1
            if data["status"] == "pass":
                passed += 1

    total_sections = total + skipped
    print(f"  REPRODUCIBILITY SUMMARY: {passed}/{total_sections} sections passed ({skipped} skipped)")
    print("═" * 70)

    # Save reports
    report_dir = ROOT / "results"
    report_dir.mkdir(exist_ok=True)

    json_path = report_dir / f"reproducibility_{timestamp}.json"
    json_path.write_text(json.dumps(results, indent=2, default=str))
    print(f"\n  JSON:     {json_path}")

    # Generate markdown report
    md_lines = [
        "# HADES Reproducibility Report",
        "",
        f"**Generated:** {timestamp}",
        f"**GPU mode:** {'Enabled' if with_gpu else 'Disabled'}",
        f"**Result:** {passed}/{total_sections} sections passed ({skipped} skipped)",
        "",
    ]
    for name, data in sections.items():
        md_lines.append(f"## {name.replace('_', ' ').title()}")
        if isinstance(data, list):
            for item in data:
                s = "✅" if item.get("status") == "pass" else "⏭️" if item.get("status") == "skipped" else "❌"
                md_lines.append(f"- {s} {item['file']}")
        elif isinstance(data, dict):
            s = "✅" if data.get("status") == "pass" else "⏭️" if data.get("status") == "skipped" else "❌"
            md_lines.append(f"- {s} {data.get('seconds', 0):.1f}s")
            for line in data.get("summary", []):
                md_lines.append(f"  - {line.strip()}")
        md_lines.append("")

    md_path = report_dir / f"reproducibility_{timestamp}.md"
    md_path.write_text("\n".join(md_lines))
    print(f"  Markdown: {md_path}")


if __name__ == "__main__":
    main()
