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

import asyncio
import json
import subprocess
import sys
import time
from datetime import UTC, datetime
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))


def _run_script(name: str, args: list[str] | None = None) -> tuple[bool, str, float]:
    """Run a Python script and return (success, output, seconds)."""
    cmd = [sys.executable, str(ROOT / name)] + (args or [])
    start = time.monotonic()
    try:
        result = subprocess.run(
            cmd, capture_output=True, text=True, timeout=300, cwd=str(ROOT),
        )
        elapsed = time.monotonic() - start
        output = result.stdout + result.stderr
        return result.returncode == 0, output, elapsed
    except subprocess.TimeoutExpired:
        return False, "TIMEOUT after 300s", time.monotonic() - start
    except Exception as e:
        return False, str(e), time.monotonic() - start


def _run_test(name: str) -> tuple[bool, str, float]:
    """Run a test file."""
    return _run_script(name)


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
    ]
    test_results = []
    for tf in test_files:
        if not (ROOT / tf).exists():
            print(f"  ⏭️  {tf} (not found, skipping)")
            test_results.append({"file": tf, "status": "skipped"})
            continue
        ok, out, secs = _run_test(tf)
        status = "✅" if ok else "❌"
        print(f"  {status} {tf} ({secs:.1f}s)")
        test_results.append({
            "file": tf, "status": "pass" if ok else "fail",
            "seconds": round(secs, 2), "output_tail": out[-200:] if not ok else "",
        })
    results["sections"]["unit_tests"] = test_results

    # === Section 2: Architecture Validation (18-point suite) ===
    print("\n─── Section 2: Architecture Validation ───")
    ok, out, secs = _run_script("scripts/validate_architecture.py")
    status = "✅" if ok else "❌"
    # Extract pass count
    lines = out.strip().split("\n")
    summary = [l for l in lines if "passed" in l.lower() or "PASS" in l or "FAIL" in l]
    print(f"  {status} validate_architecture.py ({secs:.1f}s)")
    for s in summary[-3:]:
        print(f"    {s.strip()}")
    results["sections"]["architecture_validation"] = {
        "status": "pass" if ok else "fail",
        "seconds": round(secs, 2),
        "summary": summary,
    }

    # === Section 3: E3 Payload Survival ===
    print("\n─── Section 3: E3 Payload Survival ───")
    ok, out, secs = _run_script("scripts/run_e3_payload_survival.py")
    status = "✅" if ok else "❌"
    print(f"  {status} E3 payload survival ({secs:.1f}s)")
    results["sections"]["e3_payload_survival"] = {
        "status": "pass" if ok else "fail", "seconds": round(secs, 2),
    }

    # === Section 4: E3 Extended Encodings ===
    print("\n─── Section 4: E3 Extended Encodings ───")
    ok, out, secs = _run_script("scripts/run_e3_extended.py")
    status = "✅" if ok else "❌"
    print(f"  {status} E3 extended encodings ({secs:.1f}s)")
    results["sections"]["e3_extended"] = {
        "status": "pass" if ok else "fail", "seconds": round(secs, 2),
    }

    # === Section 5: Invariant Evaluation ===
    print("\n─── Section 5: Invariant Evaluation ───")
    ok, out, secs = _run_script("scripts/run_invariant_evaluation.py")
    status = "✅" if ok else "❌"
    print(f"  {status} Invariant evaluation ({secs:.1f}s)")
    results["sections"]["invariant_evaluation"] = {
        "status": "pass" if ok else "fail", "seconds": round(secs, 2),
    }

    # === Section 6: Defense Analysis ===
    print("\n─── Section 6: Defense Analysis ───")
    ok, out, secs = _run_script("scripts/run_defense_analysis.py")
    status = "✅" if ok else "❌"
    print(f"  {status} Defense analysis ({secs:.1f}s)")
    results["sections"]["defense_analysis"] = {
        "status": "pass" if ok else "fail", "seconds": round(secs, 2),
    }

    # === Section 7: Campaign Demo ===
    print("\n─── Section 7: Campaign Demo ───")
    ok, out, secs = _run_script("scripts/run_campaign_demo.py")
    status = "✅" if ok else "❌"
    # Extract summary
    campaign_lines = [l for l in out.split("\n") if "ALL GREEN" in l or "Chain" in l or "Campaign" in l]
    print(f"  {status} Campaign demo ({secs:.1f}s)")
    for cl in campaign_lines[:5]:
        print(f"    {cl.strip()}")
    results["sections"]["campaign_demo"] = {
        "status": "pass" if ok else "fail", "seconds": round(secs, 2),
        "summary": campaign_lines,
    }

    # === Section 8: E2E Demo ===
    print("\n─── Section 8: E2E Demo ───")
    ok, out, secs = _run_script("scripts/run_e2e_demo.py")
    status = "✅" if ok else "❌"
    print(f"  {status} E2E demo ({secs:.1f}s)")
    results["sections"]["e2e_demo"] = {
        "status": "pass" if ok else "fail", "seconds": round(secs, 2),
    }

    # === Section 9: Benchmark Build ===
    print("\n─── Section 9: Benchmark Pack ───")
    ok, out, secs = _run_script("scripts/build_benchmark_pack.py")
    status = "✅" if ok else "❌"
    bench_lines = [l for l in out.split("\n") if "alert" in l.lower() or "technique" in l.lower() or "tactic" in l.lower()]
    print(f"  {status} Benchmark build ({secs:.1f}s)")
    for bl in bench_lines[:5]:
        print(f"    {bl.strip()}")
    results["sections"]["benchmark_build"] = {
        "status": "pass" if ok else "fail", "seconds": round(secs, 2),
        "summary": bench_lines,
    }

    # === Section 10: GPU Experiments (optional) ===
    if with_gpu:
        print("\n─── Section 10: GPU Experiments ───")
        for exp in ["E1", "E2"]:
            ok, out, secs = _run_script("scripts/run_experiment.py", [f"--experiment={exp}"])
            status = "✅" if ok else "❌"
            print(f"  {status} Experiment {exp} ({secs:.1f}s)")
            results["sections"][f"experiment_{exp}"] = {
                "status": "pass" if ok else "fail", "seconds": round(secs, 2),
            }
    else:
        print("\n─── Section 10: GPU Experiments ───")
        print("  ⏭️  Skipped (run with --with-gpu)")

    # === Summary ===
    print("\n" + "═" * 70)
    sections = results["sections"]
    total = 0
    passed = 0
    for name, data in sections.items():
        if isinstance(data, list):
            for item in data:
                if item.get("status") != "skipped":
                    total += 1
                    if item.get("status") == "pass":
                        passed += 1
        elif isinstance(data, dict) and "status" in data:
            total += 1
            if data["status"] == "pass":
                passed += 1

    print(f"  REPRODUCIBILITY SUMMARY: {passed}/{total} sections passed")
    print("═" * 70)

    # Save reports
    report_dir = ROOT / "results"
    report_dir.mkdir(exist_ok=True)

    json_path = report_dir / f"reproducibility_{timestamp}.json"
    json_path.write_text(json.dumps(results, indent=2, default=str))
    print(f"\n  JSON:     {json_path}")

    # Generate markdown report
    md_lines = [
        f"# HADES Reproducibility Report",
        f"",
        f"**Generated:** {timestamp}",
        f"**GPU mode:** {'Enabled' if with_gpu else 'Disabled'}",
        f"**Result:** {passed}/{total} sections passed",
        f"",
    ]
    for name, data in sections.items():
        md_lines.append(f"## {name.replace('_', ' ').title()}")
        if isinstance(data, list):
            for item in data:
                s = "✅" if item.get("status") == "pass" else "⏭️" if item.get("status") == "skipped" else "❌"
                md_lines.append(f"- {s} {item['file']}")
        elif isinstance(data, dict):
            s = "✅" if data.get("status") == "pass" else "❌"
            md_lines.append(f"- {s} {data.get('seconds', 0):.1f}s")
            for line in data.get("summary", []):
                md_lines.append(f"  - {line.strip()}")
        md_lines.append("")

    md_path = report_dir / f"reproducibility_{timestamp}.md"
    md_path.write_text("\n".join(md_lines))
    print(f"  Markdown: {md_path}")


if __name__ == "__main__":
    main()
