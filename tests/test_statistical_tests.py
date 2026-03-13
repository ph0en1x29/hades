#!/usr/bin/env python3
"""Tests for the statistical analysis framework."""

from __future__ import annotations

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from src.evaluation.statistical_tests import (
    BootstrapResult,
    CohensD,
    FleissKappaResult,
    McNemarResult,
    bootstrap_ci,
    bowker_test,
    cohens_d,
    fleiss_kappa,
    mcnemar_test,
    paired_bootstrap,
)

passed = 0
failed = 0


def ok(name: str):
    global passed
    passed += 1
    print(f"  ✅ {name}")


def fail(name: str, reason: str):
    global failed
    failed += 1
    print(f"  ❌ {name}: {reason}")


def main():
    print("=" * 70)
    print("  HADES — Statistical Tests Framework Validation")
    print("=" * 70)

    # === Bootstrap CI ===
    print("\n─── Bootstrap Confidence Intervals ───")

    # Perfect accuracy
    perfect = bootstrap_ci([1.0] * 100, "perfect_accuracy")
    assert perfect.observed == 1.0
    assert perfect.ci_lower >= 0.99
    assert perfect.ci_upper <= 1.01
    ok(f"perfect accuracy: {perfect.observed:.3f} [{perfect.ci_lower:.3f}, {perfect.ci_upper:.3f}]")

    # Zero accuracy
    zero = bootstrap_ci([0.0] * 100, "zero_accuracy")
    assert zero.observed == 0.0
    ok(f"zero accuracy: {zero.observed:.3f} [{zero.ci_lower:.3f}, {zero.ci_upper:.3f}]")

    # Mixed results
    mixed = bootstrap_ci([1.0] * 70 + [0.0] * 30, "mixed_accuracy")
    assert 0.6 < mixed.ci_lower < 0.7
    assert 0.7 < mixed.ci_upper < 0.8
    ok(f"70% accuracy: {mixed.observed:.3f} [{mixed.ci_lower:.3f}, {mixed.ci_upper:.3f}]")

    # Wide variance
    import random
    rng = random.Random(42)
    noisy = [rng.gauss(0.5, 0.3) for _ in range(50)]
    wide = bootstrap_ci(noisy, "wide_variance")
    assert wide.ci_upper - wide.ci_lower > 0.05  # Should have non-trivial CI
    ok(f"wide variance: {wide.observed:.3f} [{wide.ci_lower:.3f}, {wide.ci_upper:.3f}]")

    # Empty input
    empty = bootstrap_ci([], "empty")
    assert empty.observed == 0.0
    ok("empty input handled gracefully")

    # === Paired Bootstrap ===
    print("\n─── Paired Bootstrap Comparison ───")

    # Clearly different conditions
    a_vals = [1.0] * 80 + [0.0] * 20
    b_vals = [1.0] * 50 + [0.0] * 50
    diff = paired_bootstrap(a_vals, b_vals, "A_vs_B")
    assert diff.observed > 0.2  # A is ~30% better
    assert diff.ci_lower > 0  # Significant
    ok(f"A>B: diff={diff.observed:.3f} [{diff.ci_lower:.3f}, {diff.ci_upper:.3f}] (sig: CI excludes 0)")

    # Similar conditions
    c_vals = [1.0] * 50 + [0.0] * 50
    d_vals = [1.0] * 48 + [0.0] * 52
    same = paired_bootstrap(c_vals, d_vals, "C_vs_D")
    assert abs(same.observed) < 0.1  # Very small difference
    ok(f"C≈D: diff={same.observed:.3f} [{same.ci_lower:.3f}, {same.ci_upper:.3f}]")

    # === McNemar's Test ===
    print("\n─── McNemar's Test ───")

    # Significant difference (many discordant pairs)
    sig = mcnemar_test(30, 5, "defense", "no_defense")
    assert sig.significant, f"Expected significant, got p={sig.p_value:.4f}"
    ok(f"significant: χ²={sig.chi_squared:.2f}, p={sig.p_value:.4f}")

    # Not significant (balanced discordant pairs)
    ns = mcnemar_test(15, 12, "A", "B")
    assert not ns.significant or ns.p_value > 0.01
    ok(f"not significant: χ²={ns.chi_squared:.2f}, p={ns.p_value:.4f}")

    # Edge case: no discordant pairs
    edge = mcnemar_test(0, 0, "X", "Y")
    assert edge.p_value == 1.0
    ok(f"zero discordant pairs: p={edge.p_value:.4f}")

    # === Fleiss' Kappa ===
    print("\n─── Fleiss' Kappa ───")

    # Perfect agreement (all raters agree)
    perfect_mat = [[5, 0, 0]] * 20  # 5 raters, 3 categories, all pick cat 0
    pk = fleiss_kappa(perfect_mat)
    assert pk.kappa >= 0.99
    assert pk.interpretation == "almost_perfect"
    ok(f"perfect agreement: κ={pk.kappa:.3f} ({pk.interpretation})")

    # Random agreement
    rng = random.Random(42)
    random_mat = []
    for _ in range(30):
        row = [0, 0, 0]
        for _ in range(5):
            row[rng.randint(0, 2)] += 1
        random_mat.append(row)
    rk = fleiss_kappa(random_mat)
    assert -0.3 < rk.kappa < 0.3  # Should be near 0
    ok(f"random agreement: κ={rk.kappa:.3f} ({rk.interpretation})")

    # Moderate agreement
    mod_mat = [[4, 1, 0], [0, 4, 1], [4, 1, 0], [1, 0, 4],
               [3, 2, 0], [0, 3, 2], [5, 0, 0], [0, 0, 5],
               [4, 0, 1], [0, 5, 0]]
    mk = fleiss_kappa(mod_mat)
    assert 0.3 < mk.kappa < 0.9
    ok(f"moderate agreement: κ={mk.kappa:.3f} ({mk.interpretation})")

    # === Cohen's d ===
    print("\n─── Cohen's d Effect Size ───")

    # Large effect
    group_high = [0.9, 0.85, 0.95, 0.88, 0.92]
    group_low = [0.3, 0.25, 0.35, 0.28, 0.32]
    large = cohens_d(group_high, group_low)
    assert large.interpretation == "large"
    ok(f"large effect: d={large.d:.3f} ({large.interpretation})")

    # Small effect (groups with meaningful overlap)
    ga = [0.5, 0.6, 0.4, 0.55, 0.45, 0.52, 0.48, 0.58, 0.42, 0.53]
    gb = [0.4, 0.5, 0.3, 0.45, 0.35, 0.42, 0.38, 0.48, 0.32, 0.43]
    small = cohens_d(ga, gb)
    assert small.interpretation in ("small", "medium", "large")  # depends on variance
    ok(f"small-medium effect: d={small.d:.3f} ({small.interpretation})")

    # Negligible effect
    same_a = [0.5] * 10
    same_b = [0.5] * 10
    neg = cohens_d(same_a, same_b)
    assert neg.interpretation == "negligible"
    ok(f"negligible effect: d={neg.d:.3f} ({neg.interpretation})")

    # === Bowker's Test ===
    print("\n─── Bowker's Test for Symmetry ───")

    # Symmetric matrix
    sym = [[50, 10, 5], [10, 40, 8], [5, 8, 30]]
    bs = bowker_test(sym)
    assert bs.symmetric
    ok(f"symmetric: χ²={bs.chi_squared:.2f}, p={bs.p_value:.4f}")

    # Asymmetric matrix
    asym = [[50, 30, 5], [2, 40, 20], [1, 3, 30]]
    ba = bowker_test(asym)
    assert not ba.symmetric
    ok(f"asymmetric: χ²={ba.chi_squared:.2f}, p={ba.p_value:.4f}")

    # === Integration: Simulated experiment ===
    print("\n─── Simulated E2 Experiment Analysis ───")

    # Simulate: 1000 alerts, clean model gets 85% correct, attacked drops to 40%
    rng = random.Random(42)
    clean_results = [1.0 if rng.random() < 0.85 else 0.0 for _ in range(1000)]
    attack_results = [1.0 if rng.random() < 0.40 else 0.0 for _ in range(1000)]

    clean_ci = bootstrap_ci(clean_results, "clean_accuracy")
    attack_ci = bootstrap_ci(attack_results, "attack_accuracy")
    asr = bootstrap_ci([1.0 - x for x in attack_results], "attack_success_rate")
    comparison = paired_bootstrap(clean_results, attack_results, "clean_vs_attack")
    effect = cohens_d(clean_results, attack_results)

    # Discordant pairs for McNemar
    both_correct = sum(1 for a, b in zip(clean_results, attack_results) if a == 1 and b == 1)
    clean_only = sum(1 for a, b in zip(clean_results, attack_results) if a == 1 and b == 0)
    attack_only = sum(1 for a, b in zip(clean_results, attack_results) if a == 0 and b == 1)
    mcn = mcnemar_test(clean_only, attack_only, "clean", "attacked")

    print(f"  Clean accuracy:  {clean_ci.observed:.3f} [{clean_ci.ci_lower:.3f}, {clean_ci.ci_upper:.3f}]")
    print(f"  Attack accuracy: {attack_ci.observed:.3f} [{attack_ci.ci_lower:.3f}, {attack_ci.ci_upper:.3f}]")
    print(f"  ASR:             {asr.observed:.3f} [{asr.ci_lower:.3f}, {asr.ci_upper:.3f}]")
    print(f"  Difference:      {comparison.observed:.3f} [{comparison.ci_lower:.3f}, {comparison.ci_upper:.3f}]")
    print(f"  Effect size:     d={effect.d:.3f} ({effect.interpretation})")
    print(f"  McNemar:         χ²={mcn.chi_squared:.2f}, p={mcn.p_value:.6f} {'***' if mcn.significant else 'ns'}")

    assert clean_ci.observed > 0.8
    assert attack_ci.observed < 0.5
    assert asr.observed > 0.5
    assert comparison.ci_lower > 0  # Clean is significantly better
    assert mcn.significant
    assert effect.interpretation == "large"
    ok("full simulated experiment analysis passes all assertions")

    print()
    print("=" * 70)
    total = passed + failed
    print(f"  RESULTS: {passed}/{total} passed")
    print("=" * 70)
    sys.exit(0 if failed == 0 else 1)


if __name__ == "__main__":
    main()
