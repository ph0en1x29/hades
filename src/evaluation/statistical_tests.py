"""Statistical analysis framework for Hades evaluation results.

Implements the statistical tests specified in TECHNICAL_SPEC.md §5:
  - Bootstrap confidence intervals (95%)
  - McNemar's test for binary subtask comparisons
  - Fleiss' kappa for inter-annotator agreement
  - Bowker's test for symmetry of classification changes
  - Effect size (Cohen's d) for continuous metrics
  - Paired bootstrap for model comparison

All tests work on pre-computed experiment results (no GPU needed).
"""

from __future__ import annotations

import math
import random
from collections import Counter
from dataclasses import dataclass, field


@dataclass
class BootstrapResult:
    """Result of a bootstrap confidence interval calculation."""
    metric_name: str
    observed: float
    ci_lower: float
    ci_upper: float
    ci_level: float = 0.95
    n_bootstrap: int = 10000
    n_samples: int = 0


@dataclass
class McNemarResult:
    """Result of McNemar's test."""
    condition_a: str
    condition_b: str
    b: int  # A correct, B wrong
    c: int  # A wrong, B correct
    chi_squared: float
    p_value: float
    significant: bool  # at alpha=0.05


@dataclass
class FleissKappaResult:
    """Result of Fleiss' kappa calculation."""
    kappa: float
    n_subjects: int
    n_raters: int
    n_categories: int
    interpretation: str  # poor/slight/fair/moderate/substantial/almost_perfect


@dataclass
class CohensD:
    """Effect size result."""
    d: float
    interpretation: str  # negligible/small/medium/large


@dataclass
class BowkerResult:
    """Result of Bowker's test for symmetry."""
    chi_squared: float
    df: int
    p_value: float
    symmetric: bool  # at alpha=0.05


def bootstrap_ci(
    values: list[float],
    metric_name: str = "metric",
    ci_level: float = 0.95,
    n_bootstrap: int = 10000,
    seed: int = 42,
) -> BootstrapResult:
    """Compute bootstrap confidence interval for a metric.

    Args:
        values: Observed metric values (one per sample/alert)
        metric_name: Label for the metric
        ci_level: Confidence level (default 0.95)
        n_bootstrap: Number of bootstrap resamples
        seed: Random seed for reproducibility
    """
    if not values:
        return BootstrapResult(
            metric_name=metric_name, observed=0.0,
            ci_lower=0.0, ci_upper=0.0, n_samples=0,
        )

    rng = random.Random(seed)
    n = len(values)
    observed = sum(values) / n

    # Bootstrap resampling
    means = []
    for _ in range(n_bootstrap):
        sample = [rng.choice(values) for _ in range(n)]
        means.append(sum(sample) / n)

    means.sort()
    alpha = 1 - ci_level
    lower_idx = int(math.floor(n_bootstrap * (alpha / 2)))
    upper_idx = int(math.ceil(n_bootstrap * (1 - alpha / 2))) - 1

    return BootstrapResult(
        metric_name=metric_name,
        observed=observed,
        ci_lower=means[lower_idx],
        ci_upper=means[upper_idx],
        ci_level=ci_level,
        n_bootstrap=n_bootstrap,
        n_samples=n,
    )


def paired_bootstrap(
    values_a: list[float],
    values_b: list[float],
    metric_name: str = "comparison",
    n_bootstrap: int = 10000,
    seed: int = 42,
) -> BootstrapResult:
    """Paired bootstrap test for comparing two conditions.

    Tests whether condition A is significantly different from condition B
    by bootstrapping the difference in means.
    """
    assert len(values_a) == len(values_b), "Paired bootstrap requires equal-length inputs"

    rng = random.Random(seed)
    n = len(values_a)
    diffs = [a - b for a, b in zip(values_a, values_b)]
    observed_diff = sum(diffs) / n

    boot_diffs = []
    for _ in range(n_bootstrap):
        sample = [rng.choice(diffs) for _ in range(n)]
        boot_diffs.append(sum(sample) / n)

    boot_diffs.sort()
    lower_idx = int(math.floor(n_bootstrap * 0.025))
    upper_idx = int(math.ceil(n_bootstrap * 0.975)) - 1

    return BootstrapResult(
        metric_name=metric_name,
        observed=observed_diff,
        ci_lower=boot_diffs[lower_idx],
        ci_upper=boot_diffs[upper_idx],
        ci_level=0.95,
        n_bootstrap=n_bootstrap,
        n_samples=n,
    )


def mcnemar_test(
    a_correct_b_wrong: int,
    a_wrong_b_correct: int,
    condition_a: str = "A",
    condition_b: str = "B",
) -> McNemarResult:
    """McNemar's test for comparing two classifiers on paired data.

    Args:
        a_correct_b_wrong: Cases where A is correct but B is wrong
        a_wrong_b_correct: Cases where A is wrong but B is correct
    """
    b, c = a_correct_b_wrong, a_wrong_b_correct
    total = b + c

    if total == 0:
        return McNemarResult(
            condition_a=condition_a, condition_b=condition_b,
            b=b, c=c, chi_squared=0.0, p_value=1.0, significant=False,
        )

    # McNemar's chi-squared with continuity correction
    chi_sq = (abs(b - c) - 1) ** 2 / total if total > 0 else 0.0

    # Approximate p-value using chi-squared with 1 df
    # Using Wilson-Hilferty approximation for chi-squared CDF
    p_value = _chi2_sf(chi_sq, df=1)

    return McNemarResult(
        condition_a=condition_a, condition_b=condition_b,
        b=b, c=c, chi_squared=chi_sq, p_value=p_value,
        significant=p_value < 0.05,
    )


def fleiss_kappa(
    ratings_matrix: list[list[int]],
) -> FleissKappaResult:
    """Fleiss' kappa for inter-rater reliability.

    Args:
        ratings_matrix: n_subjects × n_categories matrix where
            ratings_matrix[i][j] = number of raters who assigned
            category j to subject i.
    """
    if not ratings_matrix:
        return FleissKappaResult(kappa=0.0, n_subjects=0, n_raters=0,
                                 n_categories=0, interpretation="poor")

    N = len(ratings_matrix)  # subjects
    k = len(ratings_matrix[0])  # categories
    n = sum(ratings_matrix[0])  # raters per subject

    if n <= 1 or N == 0:
        return FleissKappaResult(kappa=0.0, n_subjects=N, n_raters=n,
                                 n_categories=k, interpretation="poor")

    # P_i for each subject
    P_i_values = []
    for row in ratings_matrix:
        sum_sq = sum(r * r for r in row)
        P_i = (sum_sq - n) / (n * (n - 1))
        P_i_values.append(P_i)

    P_bar = sum(P_i_values) / N

    # p_j: proportion of all assignments to category j
    p_j = []
    for j in range(k):
        total_j = sum(row[j] for row in ratings_matrix)
        p_j.append(total_j / (N * n))

    P_e_bar = sum(p * p for p in p_j)

    if abs(1 - P_e_bar) < 1e-10:
        kappa = 1.0 if abs(P_bar - 1) < 1e-10 else 0.0
    else:
        kappa = (P_bar - P_e_bar) / (1 - P_e_bar)

    interpretation = _interpret_kappa(kappa)

    return FleissKappaResult(
        kappa=kappa, n_subjects=N, n_raters=n,
        n_categories=k, interpretation=interpretation,
    )


def cohens_d(
    group_a: list[float],
    group_b: list[float],
) -> CohensD:
    """Cohen's d effect size for two groups."""
    if not group_a or not group_b:
        return CohensD(d=0.0, interpretation="negligible")

    mean_a = sum(group_a) / len(group_a)
    mean_b = sum(group_b) / len(group_b)

    var_a = sum((x - mean_a) ** 2 for x in group_a) / max(len(group_a) - 1, 1)
    var_b = sum((x - mean_b) ** 2 for x in group_b) / max(len(group_b) - 1, 1)

    pooled_std = math.sqrt((var_a + var_b) / 2)
    d = (mean_a - mean_b) / pooled_std if pooled_std > 0 else 0.0

    return CohensD(d=d, interpretation=_interpret_d(abs(d)))


def bowker_test(
    confusion_matrix: list[list[int]],
) -> BowkerResult:
    """Bowker's test for symmetry of a square confusion matrix.

    Tests whether the off-diagonal elements are symmetric:
    H0: n_ij = n_ji for all i ≠ j.
    """
    k = len(confusion_matrix)
    chi_sq = 0.0
    df = 0

    for i in range(k):
        for j in range(i + 1, k):
            n_ij = confusion_matrix[i][j]
            n_ji = confusion_matrix[j][i]
            total = n_ij + n_ji
            if total > 0:
                chi_sq += (n_ij - n_ji) ** 2 / total
                df += 1

    p_value = _chi2_sf(chi_sq, df) if df > 0 else 1.0

    return BowkerResult(
        chi_squared=chi_sq, df=df, p_value=p_value,
        symmetric=p_value >= 0.05,
    )


# ── Helpers ──────────────────────────────────────────────────────

def _chi2_sf(x: float, df: int) -> float:
    """Survival function for chi-squared distribution (stdlib only).

    Uses regularized incomplete gamma function approximation.
    Sufficient accuracy for df=1 to ~50.
    """
    if x <= 0 or df <= 0:
        return 1.0

    # For df=1 (McNemar), use normal approximation
    if df == 1:
        z = math.sqrt(x)
        return 2 * (1 - _normal_cdf(z))

    # General case: use Wilson-Hilferty approximation
    a = df / 2
    z = ((x / df) ** (1 / 3) - (1 - 2 / (9 * df))) / math.sqrt(2 / (9 * df))
    return 1 - _normal_cdf(z)


def _normal_cdf(z: float) -> float:
    """Standard normal CDF approximation (Abramowitz & Stegun)."""
    return 0.5 * (1 + math.erf(z / math.sqrt(2)))


def _interpret_kappa(kappa: float) -> str:
    """Landis & Koch (1977) kappa interpretation."""
    if kappa < 0:
        return "poor"
    if kappa < 0.21:
        return "slight"
    if kappa < 0.41:
        return "fair"
    if kappa < 0.61:
        return "moderate"
    if kappa < 0.81:
        return "substantial"
    return "almost_perfect"


def _interpret_d(d: float) -> str:
    """Cohen's d effect size interpretation."""
    if d < 0.2:
        return "negligible"
    if d < 0.5:
        return "small"
    if d < 0.8:
        return "medium"
    return "large"
