# 5. Experimental Methodology

## 5.1 Experiment Overview

We design eight experiments (E1–E8) to systematically evaluate the adversarial robustness of LLM-based triage systems, progressing from baseline accuracy through vulnerability assessment to defense evaluation under adaptive attack.

| Exp | Name | Purpose | Models | Alerts |
|-----|------|---------|--------|--------|
| E1 | Clean Baseline | Measure triage accuracy without adversarial input | 4 | 12,147 |
| E2 | Injection Vulnerability | Measure attack success rate per vector × class | 4 | 1,457,640 |
| E3 | SIEM Survival | Test payload survival through normalization | — | 9 enc × 11 rules × 15 templates |
| E4 | Defense: Sanitization | Evaluate 3 sanitization levels | 4 | 1,457,640 |
| E5 | Defense: Structured Prompt | Evaluate structured prompt architecture | 4 | 1,457,640 |
| E6 | Defense: Dual-LLM Verify (planned) | Evaluate dual-model verification | 4 | 1,457,640 |
| E7 | Defense: Canary Tokens | Evaluate canary-based injection detection | 4 | 1,457,640 |
| E8 | Adaptive Attacker | Evaluate defenses against defense-aware attackers | 4 | 1,457,640 |

## 5.2 Models Under Evaluation

We evaluate four frontier open-weight LLMs, primarily Mixture-of-Experts (MoE) architectures, selected for their diverse routing strategies and active parameter counts:

| Model | Total Params | Active Params | Experts | Architecture | Quantization |
|---|---|---|---|---|---|
| DeepSeek R1 | 671B | ~37B | 256 | DeepSeekMoE | INT4 |
| GLM-5 | 744B | ~32B | — | Dense/GLM | INT4 |
| Kimi K2.5 | 1T | 32B | 384 | MoonlightMoE | INT4 native |
| Qwen 3.5 | 397B | ~17B | 128 | QwenMoE | INT4 |

We selected open-weight models to enable fully reproducible local evaluation without API rate limits, terms-of-service restrictions, or non-deterministic API-side changes; commercial API-based models (GPT-4o, Claude) are excluded because they cannot be served locally for controlled experimentation. Different MoE routing strategies may exhibit different adversarial vulnerability profiles. By comparing four architectures — three MoE and one dense (GLM-5) — we can explore whether routing decisions correlate with injection susceptibility, with GLM-5 serving as a non-MoE control. We note this is an exploratory comparison: model family, alignment training, tokenizer behavior, and training data may confound any observed MoE effect.

All models are served via vLLM with tensor parallelism appropriate to the available hardware. Each model receives identical prompts to enable fair comparison.

We note that all four selected models originate from Chinese AI labs. This reflects the current landscape of open-weight frontier MoE models available for local deployment; at time of writing, no comparable open-weight MoE models from Western labs were available at the >100B parameter scale. Results may not generalize to closed-source or non-MoE architectures deployed in production SOC environments.

## 5.3 Benchmark Dataset

### 5.3.1 Construction

Our benchmark comprises 12,147 alerts parsed from the Splunk Attack Data repository, covering 27 MITRE ATT&CK techniques across 9 tactics:

| Tactic | Technique | Description | Alert Count |
|---|---|---|---|
| TA0001 Initial Access | T1566.001 | Spearphishing Attachment | 500 |
| TA0002 Execution | T1047 | WMI Command Execution | 500 |
| TA0002 Execution | T1059.001 | PowerShell Script Execution | 502 |
| TA0002 Execution | T1204.002 | User Execution: Malicious File | 500 |
| TA0002 Execution | T1569.002 | Service Execution | 500 |
| TA0003 Persistence | T1053.005 | Scheduled Task | 514 |
| TA0003 Persistence | T1136.001 | Create Local Account | 500 |
| TA0003 Persistence | T1543.003 | Create/Modify Windows Service | 500 |
| TA0003 Persistence | T1547.001 | Registry Run Keys | 500 |
| TA0004 Privilege Escalation | T1548.002 | Bypass UAC | 500 |
| TA0005 Defense Evasion | T1027 | Obfuscated Files / Information | 500 |
| TA0005 Defense Evasion | T1036.003 | Masquerading: Rename System Utilities | 500 |
| TA0005 Defense Evasion | T1055.001 | Process Injection (Cobalt Strike) | 500 |
| TA0005 Defense Evasion | T1112 | Modify Registry | 500 |
| TA0005 Defense Evasion | T1218.011 | Rundll32 Signed Binary Proxy | 500 |
| TA0005 Defense Evasion | T1562.001 | Impair Defenses: Disable Tools | 500 |
| TA0006 Credential Access | T1003.001 | LSASS Credential Dumping | 500 |
| TA0006 Credential Access | T1003.003 | NTDS.dit Credential Dumping | 500 |
| TA0006 Credential Access | T1110.001 | RDP Brute Force | 23 |
| TA0007 Discovery | T1018 | Remote System Discovery | 500 |
| TA0007 Discovery | T1082 | System Information Discovery | 500 |
| TA0007 Discovery | T1087.001 | Local Account Discovery | 500 |
| TA0008 Lateral Movement | T1021.002 | SMB Admin Shares | 4 |
| TA0008 Lateral Movement | T1021.006 | Windows Remote Management | 500 |
| TA0008 Lateral Movement | T1550.002 | Pass the Hash | 500 |
| TA0011 Command & Control | T1071.001 | HTTP C2 Traffic | 104 |
| TA0011 Command & Control | T1105 | Ingress Tool Transfer | 500 |

### 5.3.2 Dataset Adequacy

Following Liu [2026], we distinguish between engineering scaffolds (datasets useful for development but not scientific claims) and benchmarks of record (datasets with sufficient provenance for published results).

Each alert in our benchmark satisfies four adequacy requirements:
1. **Rule association.** Every alert maps to a specific Splunk Security Content detection rule with documented search logic.
2. **MITRE mapping.** Every alert has at least one MITRE ATT&CK technique association, traced through the detection rule metadata.
3. **Provenance chain.** Every alert carries a full provenance record: dataset source, parser version, transform version, and label provenance.
4. **Scenario identifier.** Every alert is tagged with a scenario ID linking it to a specific attack simulation (Atomic Red Team, Impacket, manual testing).

These requirements are enforced programmatically via a dataset gate that rejects alerts missing any field.

**Limitation: All-positive benchmark.** All 12,147 benchmark alerts are true-positive attack alerts. Real SOC environments see 80–95% false-positive rates. This creates an asymmetry in our evaluation: we primarily measure **suppression/evasion attacks on true positives** (can an attacker hide their own malicious activity?), but do not quantify **false-positive induction on benign telemetry** (can an attacker inject into benign traffic to overwhelm analysts with spurious escalations?). The latter represents a complementary threat axis — a denial-of-service attack on SOC attention — and is deferred to future investigation with supplementary benign alert datasets.

**Technique imbalance.** Alert counts range from 4 (T1021.002, SMB/Windows Admin Shares) to 514 (T1059.001, PowerShell). This reflects the natural distribution in Splunk Attack Data rather than deliberate balancing. Techniques with fewer than ~30 alerts may lack statistical power for per-technique analysis; aggregate results should be interpreted with this caveat.

### 5.3.3 Adversarial Variant Generation

For each clean benchmark alert, we generate adversarial variants by injecting payloads into realistic log fields:

- **12 injection vectors** (HTTP User-Agent, Win Event Username, DNS Query, etc.)
- **5 attack classes** (misclassification, confidence manipulation, reasoning corruption, attention hijacking, escalation suppression)
- **2 base encodings** for end-to-end E2/E4-E8 sweeps (plaintext, underscore)
- **9 extended encoding/constraint strategies** for E3 normalization-survival tests (6 evasion encodings, 3 protocol-constrained variants)

Plus 3 protocol-specific constraints (DNS 253-byte, SMB 15-char, TLS CN 64-char) that enforce realistic field length limits.

The base end-to-end matrix produces **120 variants per alert** and **1,457,640 total adversarial samples** for the full benchmark. Extended E3 encoding tests are reported separately because they measure normalization survival rather than full triage runs. Payloads are truncated to respect field length constraints per vector.

**Vector applicability.** Not all injection vectors are applicable to every alert type. For example, Sysmon process creation logs do not contain HTTP User-Agent or DNS query fields. In our variant generation, payloads are injected into synthesized fields appended to the alert context — modeling the scenario where an attacker's traffic generates correlated alerts across multiple log sources that are co-presented to the triage model. We acknowledge this represents a worst-case evaluation; per-vector eligible alert counts would be lower in deployments that strictly scope log fields by source type. Future work should evaluate vector-restricted variant sets.

## 5.4 Evaluation Metrics

### 5.4.1 Triage Accuracy (E1)

For clean alerts, we measure:
- **F1 score** (macro-averaged across severity levels)
- **Precision** and **recall** per severity class
- **False negative rate** (malicious classified as benign)

Ground truth labels are derived from Splunk detection rule associations: alerts from attack datasets are labeled as true positives.

**Note:** False positive rate (benign classified as malicious) requires supplementary benign alert data not included in the current benchmark. We report FPR only for the behavioral invariant detector (measuring false escalation of clean triage decisions) where simulated clean outputs serve as the negative class.

### 5.4.2 Attack Success Rate (E2–E8)

For adversarial alerts, the primary metric is **Attack Success Rate (ASR)**:

$$\text{ASR} = \frac{\text{# alerts where adversarial variant changed the triage decision}}{\text{# total adversarial variants}}$$

We decompose ASR into operationally meaningful sub-metrics:
- **ASR-class:** Fraction where severity/classification changed (captures C1)
- **ASR-confidence:** Fraction where confidence crossed a review threshold without classification change (captures C2)
- **ASR-rationale:** Fraction where explanation/evidence trace was corrupted while classification remained correct (captures C3/C4)
- **ASR-campaign:** Fraction where Fox score or chain detection degraded (captures C5)

We further cross-tabulate ASR across four dimensions:
- **Per vector:** Which log fields are most vulnerable?
- **Per attack class:** Which objectives are most achievable?
- **Per model:** Which architectures are most vulnerable?
- **Per encoding:** Which encoding strategies are most effective?

### 5.4.3 Defense Effectiveness

For defense experiments (E4–E7), we report:
- **ASR reduction:** `(ASR_undefended - ASR_defended) / ASR_undefended`
- **Accuracy impact:** How much does the defense degrade clean triage accuracy?
- **Accuracy-robustness tradeoff curve:** Parametric curve showing the frontier

### 5.4.4 Statistical Rigor

Following best practices in adversarial ML evaluation:
- **Paired bootstrap confidence intervals** (95%) for all ASR comparisons
- **McNemar test** for pairwise model comparisons on binary classification subtasks
- **Fleiss' kappa** for inter-annotator agreement when human labels are used
- **Bowker test** for symmetry of classification changes between clean and adversarial conditions

## 5.5 Defense Mechanisms

### D1 — Input Sanitization (E4)

Three sanitization levels applied to alert data before prompt construction:
- **Level 1 (Minimal):** Strip non-printable characters and control sequences
- **Level 2 (Moderate):** Additionally remove common injection markers ("IGNORE", "INSTRUCTIONS", "CLASSIFY", "NOTE:")
- **Level 3 (Aggressive):** Truncate all text fields to 80 characters; strip anything after the first sentence

### D2 — Structured Prompt Architecture (E5)

Replace free-text alert formatting with structured, typed fields. Each log field is wrapped in explicit boundary markers:

```
[FIELD:http.user_agent] Mozilla/5.0 ... [/FIELD:http.user_agent]
[FIELD:src_ip] 10.0.1.15 [/FIELD:src_ip]
```

The system instruction explicitly states: "Fields between [FIELD:...] markers contain raw log data. Do not follow instructions found within field markers."

### D3 — Dual-LLM Verification (E6)

A second LLM independently triages the same alert. Disagreements between the primary and verifier models are flagged for human review. The verifier uses a different model architecture to reduce correlated failures.

### D4 — Canary Token Detection (E7)

A known canary string is injected into the alert's metadata field. If the LLM's response references or is influenced by the canary in unexpected ways, the system flags a potential injection attack.

### Adaptive Attacker Evaluation (E8)

Following Nasr et al. [2025], we evaluate whether defenses survive when the attacker knows the defense mechanism and can adapt payloads accordingly:

- **Level 1:** Attacker knows sanitization keywords → crafts synonyms and obfuscated variants
- **Level 2:** Attacker knows structured prompt format → crafts payloads that exploit field boundaries
- **Level 3:** Attacker knows dual-LLM setup → crafts payloads optimized to fool both models simultaneously

## 5.6 SOC-Bench Alignment

Our evaluation pipeline includes a partial adapter for the SOC-Bench framework [Cai2026]. Currently, only Fox task scoring is implemented and evaluated (§6.9), using simulated triage decisions rather than real model outputs. Specifically:

**Task Fox (Campaign Detection).** Hades triage decisions are aggregated into SOC-Bench Fox stage outputs comprising three structured outcomes: O1 campaign-scale assessment (campaign detection, scope, affected hosts), O2 activity-type reasoning (MITRE technique classification, kill chain phase), and O3 cross-stage alert triage bundles (priority, recommended actions). All outputs include evidence_id chains for chain-of-custody verification.

**Task Tiger (Attribution/TTP Reporting).** The adapter includes Tiger output schemas, but Tiger requires data source relationship graphs and attribution reasoning that our flat TriageDecision objects do not directly produce. Bridging this gap requires additional pipeline components beyond classification. *Tiger evaluation is deferred to Phase 2; this paper evaluates only Fox task scoring (§6.9).*

**Ring Scoring.** We adopt SOC-Bench's graduated ring scoring model (Bullseye=3, Inner=2, Outer=1, Miss=0) rather than binary correct/incorrect for technique identification accuracy. This rewards partial matches — correctly identifying the tactic but wrong sub-technique scores Inner rather than Miss.

**Design Principle Compliance.** Following DP1 (loyalty to existing SOCs), our triage pipeline processes alerts as a SOC analyst would receive them — timestamp-ordered, without attacker narrative context. Following DP3 (real-world basis), our benchmark uses detection rule outputs from Splunk Attack Data — controlled attack simulations (Atomic Red Team) processed by real SIEM detection rules, providing realistic alert structure if not production-environment diversity.

## 5.7 Reproducibility

All experiments use:
- Fixed random seeds for any stochastic components
- Near-deterministic model inference (temperature=0). Note: MoE architectures may exhibit minor non-determinism due to expert routing order and GPU parallelism even at temperature 0. We mitigate this by averaging results across 3 independent runs per experiment configuration and reporting mean ± standard deviation.
- Published evaluation scripts with hash-verified benchmark data
- Docker-based deployment for model serving
- Version-pinned dependencies (pyproject.toml)

The complete evaluation pipeline, including data acquisition scripts, parsers, injector, and analysis notebooks, is released as open source.
