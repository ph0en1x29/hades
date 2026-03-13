# HADES — Experiments (E1–E8)

## Overview

HADES defines 8 experiments to systematically evaluate the adversarial robustness of LLM-based SOC triage. All experiments use statistical rigor: bootstrap confidence intervals, McNemar's test, Fleiss' kappa, Cohen's d effect size, and Bowker's symmetry test.

## Target Models

Four frontier open-weight Mixture-of-Experts (MoE) architectures:

| Model | Parameters | Architecture | Weight Size |
|-------|-----------|-------------|-------------|
| DeepSeek R1 | 671B | MoE | ~200GB |
| GLM-5 | 744B | MoE | ~400GB |
| Kimi K2.5 | 1T | MoE | ~630GB |
| Qwen 3.5 | 397B | MoE | ~200GB |

All models will be served locally via vLLM (OpenAI-compatible API). No cloud models in v1 scope.

**Estimated GPU requirement:** 40-60 hours on 4×A100 or 2×H100 cluster, concentrated in June-July 2026.

## Experiment Details

### E1 — Clean Baseline (GPU-blocked)
**Question:** How well do the 4 models triage unmodified alerts?

- Run all 12,147 benchmark alerts through each model
- Measure: accuracy, precision, recall, F1 per attack technique
- Establishes the baseline that adversarial experiments degrade from
- **Metrics:** Classification accuracy, confusion matrix, per-technique breakdown

### E2 — Injection Success Rate (GPU-blocked)
**Question:** How often do adversarial payloads successfully manipulate triage decisions?

- Inject payloads across all 12 vectors × 5 attack classes
- Measure success rate per vector, per class, per model
- This is the core attack measurement
- **Metrics:** Attack success rate (ASR), per-vector breakdown, statistical significance

### E3 — Payload Survival (✅ Complete)
**Question:** Do injection payloads survive SIEM normalization?

- Test all payload types against 11 SIEM normalization rules
- Measure which encodings bypass which rules
- **Results:**
  - 40% of attack classes survive ALL 11 normalization rules
  - Homoglyph and zero-width encodings bypass keyword-based defenses
  - Best layered defense achieves only 60% indicator removal on plaintext
  - **Conclusion:** Input sanitization alone is insufficient

### E4 — Defense Effectiveness (GPU-blocked)
**Question:** Which defense mechanisms reduce attack success, and by how much?

- Test each of 5 defenses individually and in combination
- Measure: attack success rate with/without each defense
- Compare across all 4 models
- **Metrics:** Relative ASR reduction, defense overhead (latency, cost), false positive impact

### E5 — Behavioral Invariant Evaluation (GPU-blocked)
**Question:** Do behavioral invariants catch attacks that input defenses miss?

- Run adversarial alerts through the full pipeline including invariant checks
- Measure: invariant violation detection rate per attack class
- Compare invariant-based defense vs. input-based defenses
- **Pre-GPU result:** 100% C1/C3 detection, 98% C4, 0% false positives (on mock data)

### E6 — Cross-Model Comparison (GPU-blocked)
**Question:** Which model architecture is most/least robust to adversarial manipulation?

- Statistical comparison across all 4 models
- Control for model size, architecture differences
- **Metrics:** McNemar's test for pairwise comparison, Cohen's d for effect size

### E7 — Encoding Evasion (GPU-blocked)
**Question:** Which encoding strategies bypass which defenses?

- Test all 9 encodings against all 5 defenses across all 4 models
- Map the evasion landscape: which combinations are most dangerous
- **Metrics:** Evasion success rate per encoding × defense × model

### E8 — Adaptive Attack (GPU-blocked)
**Question:** If the attacker knows the defense strategy, can they still bypass it?

- Simulate an adaptive attacker who adjusts payloads based on defense knowledge
- Test whether any defense remains robust under full attacker knowledge
- This is the strongest threat model and the hardest test
- **Metrics:** Adaptive ASR vs. non-adaptive ASR, defense degradation curve

## Statistical Framework

All experiments use:

- **Bootstrap confidence intervals** (95% CI) — robust estimation without distributional assumptions
- **McNemar's test** — pairwise model comparison on matched samples
- **Fleiss' kappa** — inter-model agreement on triage decisions
- **Cohen's d** — effect size of adversarial manipulation
- **Bowker's symmetry test** — whether classification changes are systematic or random

## Current Status

| Experiment | Status | Depends On |
|-----------|--------|-----------|
| E1 | ⏳ GPU-blocked | Lab GPU cluster (June-July) |
| E2 | ⏳ GPU-blocked | E1 baseline |
| E3 | ✅ Complete | — |
| E4 | ⏳ GPU-blocked | E1 + E2 |
| E5 | ⏳ GPU-blocked | E1 + E2 |
| E6 | ⏳ GPU-blocked | E1 + E2 |
| E7 | ⏳ GPU-blocked | E2 + E4 |
| E8 | ⏳ GPU-blocked | E2 + E4 + E7 |
