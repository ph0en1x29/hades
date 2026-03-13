# Figure 3: Experiment Matrix

```
                    HADES EXPERIMENT MATRIX
    ═══════════════════════════════════════════════════

    MODELS (4)                   BENCHMARK
    ──────────                   ─────────
    DeepSeek R1  (671B, 37B↑)   4,619 alerts
    GLM-5        (744B, 32B↑)   12 MITRE techniques
    Kimi K2.5    (1T,   32B↑)   7 ATT&CK tactics
    Qwen 3.5     (397B, 17B↑)   100% rule coverage
         All INT4 quantized      0 contract failures


    E1 ─── CLEAN BASELINE ──────────────────────────
    │      4 models × 4,619 alerts = 18,476 runs
    │      Metrics: F1, Precision, Recall, FP Rate
    │
    E2 ─── INJECTION VULNERABILITY ─────────────────
    │      4 models × 12 vectors × 5 classes × 9 enc
    │      = 554,280 adversarial variants
    │      Metrics: ASR per model/vector/class/enc
    │
    E3 ─── PAYLOAD SURVIVAL ✅ COMPLETE ────────────
    │      12 vectors × 11 SIEM rules × 5 classes
    │      = 13,200 survival tests
    │      Finding: 100% survival for C1, C2
    │      + 1,485 extended encoding tests
    │      Finding: dual vulnerability confirmed
    │
    E4 ─── DEFENSE: SANITIZATION ───────────────────
    │      3 levels × 4 models × adversarial set
    │      Metrics: ASR reduction, clean acc. loss
    │
    E5 ─── DEFENSE: STRUCTURED PROMPTS ─────────────
    │      D2 field tags × 4 models × adversarial set
    │      Metrics: ASR reduction, clean acc. loss
    │
    E6 ─── DEFENSE: DUAL-LLM VERIFICATION ─────────
    │      Verifier model × 4 primary × adversarial
    │      Metrics: detection rate, latency overhead
    │
    E7 ─── DEFENSE: CANARY TOKENS ──────────────────
    │      D3 canary × 4 models × adversarial set
    │      Metrics: canary survival, detection rate
    │
    E8 ─── ADAPTIVE ATTACKER ───────────────────────
           Attacker aware of each defense
           Per Nasr et al. (2025) methodology
           Metrics: ASR vs defense-aware attacks


    PRE-GPU RESULTS (VALIDATED)
    ═══════════════════════════

    ┌──────────────────────────┬──────────┬────────────┐
    │ Experiment               │  Status  │  Key #     │
    ├──────────────────────────┼──────────┼────────────┤
    │ E3 Payload Survival      │    ✅    │ 13,200     │
    │ E3 Extended Encodings    │    ✅    │  1,485     │
    │ Behavioral Invariants    │    ✅    │ C1:100%    │
    │ Defense Analysis         │    ✅    │    525     │
    │ Campaign Demo            │    ✅    │  4 chains  │
    │ Fox Scorer E2E           │    ✅    │ 69.7/100   │
    │ Full Pipeline            │    ✅    │  3 agents  │
    │ Reproducibility          │    ✅    │  18/18     │
    └──────────────────────────┴──────────┴────────────┘

    GPU-BLOCKED: E1, E2, E4-E8
    (Tables A-D in paper = TBD)
```
