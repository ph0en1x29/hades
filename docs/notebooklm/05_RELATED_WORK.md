# HADES — Related Work and Positioning

## Where HADES Fits

HADES sits at the intersection of three research areas that have not been combined before:

1. **Prompt injection / adversarial ML** — Well-studied, but not in SOC-specific contexts
2. **LLMs for security operations** — Growing field, but robustness not yet tested
3. **Security benchmarks** — SOC-Bench, CyBench, etc. evaluate capability, not adversarial robustness

No existing system combines all three: SOC-specific + adversarial + SIEM pipeline injection + adaptive evaluation.

## Key Related Systems

### SOC-Bench (Liu, 2026)
- **What it does:** Evaluates blue team AI agents across 5 tasks (Fox, Tiger, Panda, Goat, Mouse) in a ransomware incident lifecycle
- **Relationship to HADES:** HADES complements SOC-Bench by asking: once an agent performs well on clean data, does it remain robust when telemetry is adversarial?
- **HADES contributes:** Adversarial evaluation layer, Fox scoring adapter, behavioral invariants

### CyBench (ICLR 2025)
- **What it does:** Benchmarks LLM agents on cybersecurity tasks (CTF-style challenges)
- **Gap:** Not SOC-specific, no adversarial robustness evaluation, no SIEM integration

### AgentDojo (NeurIPS 2024)
- **What it does:** Evaluates LLM agent robustness against prompt injection in tool-use scenarios
- **Gap:** Not SOC-specific, no SIEM pipeline injection vector, general-purpose

### CORTEX (September 2025)
- **What it does:** Multi-agent LLM architecture for SOC alert triage
- **Gap:** Focuses on triage effectiveness, does not evaluate adversarial robustness

## Key Adversarial Research

### Carlini et al. — >90% bypass rates
Demonstrated that aligned LLMs can be reliably bypassed with adversarial prompts. Establishes that model-level alignment is insufficient as a sole defense.

### AgentSentry — 74.55% Universal Adversarial attack success
Shows that adversarial attacks generalize across different agent architectures. Motivates HADES's cross-model comparison (E6).

### L³ (MoE Expert Silencing) — 7% → 70% ASR
Showed that Mixture-of-Experts models have a unique vulnerability: adversarial inputs can silence specific experts, dramatically increasing attack success. Directly relevant to HADES since all 4 target models are MoE architectures.

### LevelBlue — 100% SOC injection success
Demonstrated 100% injection success rate in SOC assistant testing through log field manipulation. Validates HADES's threat model in a production-like setting.

### Neaves (2025) — Production SIEM injection
Successfully injected payloads through HTTP User-Agent headers, SSH usernames, and Windows Event Log fields in production SIEM environments. The most direct real-world validation of the SIEM pipeline injection threat.

### Unit 42 (2026) — 22 wild techniques
Palo Alto's threat intelligence team reported 22 distinct indirect prompt injection techniques observed in actual production telemetry. Confirms the threat is not academic — it's happening.

### Nasr et al. (2025)
Demonstrated that model-level defenses are consistently bypassed by adaptive attackers. This motivates HADES's behavioral invariant approach: defend at the workflow level (output validation) rather than relying solely on model-level robustness.

## HADES's Unique Contributions

| Dimension | Status in Literature | HADES Contribution |
|-----------|---------------------|-------------------|
| SIEM pipeline as injection vector | Demonstrated by Neaves, noted by Unit 42 | First systematic evaluation framework |
| SOC-specific adversarial benchmark | Does not exist | 12,147 alerts × 12 vectors × 5 classes × 9 encodings |
| Behavioral invariants for triage | Novel | 6 domain-specific output constraints, 0% FP |
| Cross-model adversarial comparison | Not done for SOC context | 4 MoE models under identical attack scenarios |
| Adaptive attack evaluation | Rare in SOC context | E8 tests defense robustness under full attacker knowledge |
| SOC-Bench adversarial extension | Does not exist | Fox scoring adapter + adversarial degradation measurement |
