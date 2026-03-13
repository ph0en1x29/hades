# HADES — Timeline, Status, and Open Questions

## Project Timeline (March–August 2026)

### ✅ March 10 – April 6: Complete Phase 1
- Finalize triage pipeline and benchmark
- Baseline evaluation (pre-GPU, mock inference)
- First advisor meeting with Prof Liu
- **Deliverable:** Baseline results + dataset adequacy argument

### 🔜 April 7 – May 4: Adversarial Campaigns
- Finalize adversarial payload generation (scaffolding largely complete)
- Run injection campaigns against baseline
- Implement defense mechanisms
- **Deliverable:** Attack dataset + 5 defense modules

### May 5 – June 1: Integration Testing
- Integration testing and defense tuning
- Prepare experiment configurations for GPU phase
- **Deliverable:** E1-E8 experiment configs validated

### June 2 – June 29: GPU Experiments
- Run E1-E8 on lab GPU cluster (4×A100 or equivalent)
- Statistical analysis, cross-model comparison
- **Deliverable:** Experiment results (Tables A-D in paper)

### July 1 – July 27: Paper Writing
- Results, analysis, discussion, figures
- **Deliverable:** Paper draft v1

### July 28 – August 31: Review and Submission
- Advisor review cycles, revision, submission preparation
- **Deliverable:** Submission-ready paper

## Current Implementation Status

| Component | Status |
|-----------|--------|
| Ingestion Layer (5 parsers + unified schema) | ✅ Complete |
| RAG Pipeline (Qdrant + 691 MITRE docs) | ✅ Complete |
| Triage Agents (classifier, correlator, playbook) | ✅ Complete |
| Benchmark (12,147 alerts, 27 techniques, 9 tactics) | ✅ Complete |
| Adversarial Framework (12 vectors, 5 classes, 9 encodings) | ✅ Complete |
| SOC-Bench Adapter (Fox O1/O2/O3, ring scorer, 17 tests) | ✅ Complete |
| Dataset Gate (scaffold rejection) | ✅ Complete |
| Behavioral Invariants (INV-1–6, 0% FP) | ✅ Complete |
| Statistical Framework (Bootstrap CI, McNemar, etc.) | ✅ Complete |
| E3 Payload Survival Experiment | ✅ Complete |
| Fox Scorer Validation (mock inference) | ✅ Complete |
| Reproducibility Suite (29 sections, 25 pass) | ✅ Complete |
| Evaluation Engine (E1-E2, E4-E8) | ⏳ GPU-blocked |
| Paper Draft (10 sections, ~12K words) | 📝 In progress (26 TBDs in results) |

## Validation Results (March 13, 2026)

- pytest: 61 passed, 10 skipped
- Behavioral invariants: 10/10
- Fox scoring: 95.7/100
- Architecture validation: 18/18
- Comprehensive validation: 14/14 (7 skipped — dataset-dependent)
- Reproducibility: 25/29 sections (4 skipped — dataset-dependent)
- All skips are honest and reported (not hidden)

## Open Questions for Prof Liu

1. **Research direction:** Is the adversarial robustness framing correct? Is there a stronger angle?
2. **Experimental design:** Are E1-E8 the right experiments? Missing angles?
3. **SOC-Bench data:** Can HADES access Colonial Pipeline telemetry for full kill-chain evaluation?
4. **Real-world validation:** Is anonymized production SOC data (50-100 alerts) feasible?
5. **SOC-Bench fields:** Are scale_label and campaign-type needed for first evaluation, or Phase 2?
6. **GPU scheduling:** June-July, approximately 40-60 hours on 4×A100
7. **Lab meeting:** Opportunity to present and get feedback from the group?

## What's Done vs. What Needs GPU

### Done (no GPU needed):
- Full triage pipeline
- All parsers and schema validation
- Benchmark built and validated
- Adversarial framework (payload generation, injection, encoding)
- All defense implementations (except adversarial training fine-tuning)
- Behavioral invariants defined and tested
- SOC-Bench adapter and Fox scorer
- E3 payload survival experiment
- Statistical framework
- Reproducibility suite
- Paper draft (minus results tables)

### Needs GPU:
- E1: Clean baseline triage accuracy across 4 models
- E2: Injection success rates per vector × class × model
- E4-E7: Defense effectiveness, invariant evaluation, cross-model comparison, encoding evasion
- E8: Adaptive attack evaluation
- Adversarial training fine-tuning
- Paper results tables (Tables A-D, currently 26 TBDs)
