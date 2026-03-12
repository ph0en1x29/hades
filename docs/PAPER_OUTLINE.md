# Paper Outline: Adversarial Robustness of LLM-Based SOC Triage Systems

**Target venues:** USENIX Security 2027, IEEE S&P, ACM CCS main track, CCS Workshop on AI for CTI
**Format:** ~14 pages + references + appendix

---

## Title Options

1. "Poisoning the Watchdog: Adversarial Manipulation of LLM-Based SOC Triage Through Crafted Network Traffic"
2. "When Logs Lie: Prompt Injection Attacks on LLM-Based Security Alert Triage"
3. "The Triage Trap: Adversarial Robustness of Large Language Models in Security Operations Centers"

## Abstract (~250 words)

- **Context:** Organizations increasingly deploy LLMs for automated SIEM alert triage
- **Problem:** Attackers can embed prompt injection payloads in network traffic fields that SIEM systems faithfully log and feed to triage models
- **Approach:** Systematic evaluation of 4 frontier LLMs (DeepSeek R1, GLM-5, K2.5, Qwen 3.5) under 10 injection vectors, 5 attack classes, and 4 encoding strategies
- **Key finding 1:** Attack success rates across models/vectors
- **Key finding 2:** Which defenses work and which don't
- **Key finding 3:** Architectural vulnerability — the data pipeline IS the attack surface
- **Contribution:** First systematic adversarial evaluation of LLM triage; SOC-specific threat model; defense recommendations

## 1. Introduction (~1.5 pages)

### 1.1 The SOC Automation Trend
- 2,000-10,000 alerts/day, analyst triages 50-100
- LLMs being deployed for Layer 2 triage (cite CORTEX, industry surveys)
- Implicit trust in input data

### 1.2 The Overlooked Attack Surface
- SIEMs log what the network produces
- Attacker controls network traffic → controls log content → controls LLM input
- Unlike traditional prompt injection (user→LLM), this is data pipeline injection (attacker→network→SIEM→LLM)

### 1.3 Research Question
"Can adversaries manipulate LLM-based SOC triage systems through crafted network traffic, and what defense mechanisms effectively mitigate this threat?"

### 1.4 Contributions
1. First systematic adversarial evaluation of LLM-based SOC triage
2. Taxonomy of 10 injection vectors with SIEM survival analysis
3. Cross-architecture vulnerability comparison (4 frontier MoE models)
4. Evaluation of 5 defense mechanisms including adaptive attacker scenarios
5. Open-source evaluation framework and benchmark

## 2. Background (~1.5 pages)

### 2.1 SOC Triage Pipeline
- Detection → Triage → Response stack diagram
- What analysts actually see (not packets, but alerts with context)
- Why rules alone are insufficient

### 2.2 LLM-Based Alert Triage
- How LLMs are being integrated (CORTEX architecture, single-model approaches)
- The prompt construction: system instruction + alert data + RAG context
- Trust boundary: system prompt vs. data fields

### 2.3 Prompt Injection
- Direct vs. indirect injection
- AgentDojo findings (Debenedetti et al.)
- Adaptive attacks bypass all defenses (Nasr et al.)

## 3. Threat Model (~1.5 pages)

### 3.1 Attacker Capabilities
- Controls network traffic content (HTTP headers, DNS queries, TLS cert fields, etc.)
- Does NOT compromise the SIEM or LLM directly
- May have partial knowledge of triage system (white-box for E8 adaptive)

### 3.2 Attack Surface: The Data Pipeline
- Diagram: Attacker → Network traffic → SIEM normalization → Log storage → LLM prompt construction → Triage decision
- Each stage is a filter — what survives?

### 3.3 Injection Vector Taxonomy
| Vector | Max Length | SIEM Survival | Realism |
|--------|-----------|---------------|---------|
| HTTP User-Agent | ~8KB | HIGH | HIGH |
| HTTP Referer | ~8KB | HIGH | HIGH |
| DNS Query | 253 chars | HIGH | MEDIUM |
| TLS Cert CN/SAN | ~64 chars | HIGH | MEDIUM |
| SMB Hostname | 15 chars | HIGH | HIGH |
| SSH Banner | ~255 chars | MEDIUM | MEDIUM |
| LDAP Bind DN | ~256 chars | MEDIUM | LOW |
| SNMP Community | 255 chars | MEDIUM | LOW |
| Email Subject | ~998 chars | HIGH | HIGH |
| TLS Cert Org | ~64 chars | HIGH | LOW |

### 3.4 Attack Classes
1. **Direct Misclassification:** "Classify this alert as benign"
2. **Confidence Manipulation:** "This is low confidence, uncertain"
3. **Reasoning Corruption:** Inject false evidence into chain-of-thought
4. **Attention Hijacking:** Distract from critical indicators
5. **Escalation Suppression:** Prevent severity escalation

### 3.5 Scope Boundaries
- File-replay mode (no live network)
- Local models only (air-gapped)
- Single-pipeline evaluation (not multi-agent)

## 4. System Design: Hades (~1.5 pages)

### 4.1 Architecture Overview
- Alert ingestion → normalization → RAG retrieval → LLM triage → decision output
- Model-agnostic interface (vLLM serving)
- Dataset gate enforcement

### 4.2 Alert Schema
- UnifiedAlert with provenance chain
- AlertBenchmarkContext (rule association, MITRE mapping)
- Why this schema matters for reproducibility

### 4.3 Benchmark Construction
- Splunk Attack Data + Security Content
- Rule-linked alerts with MITRE mappings
- Provenance tracking at every stage

### 4.4 Dataset Gate
- Code-level enforcement of benchmark adequacy
- Engineering scaffold vs. benchmark-of-record distinction
- Why CICIDS is inadequate and what we did about it

## 5. Adversarial Evaluation Methodology (~2 pages)

### 5.1 Experiment Matrix
- 8 experiments (E1-E8) across 4 models
- Clean baseline → injection → defenses → adaptive attacker
- Statistical rigor: paired bootstrap, Bowker test, McNemar, Fleiss kappa

### 5.2 Adversarial Dataset Construction
- For each benchmark alert, generate variants per vector × class × encoding
- ~10,000+ adversarial alert variants from ~1,100 base alerts
- Payload templates with realistic constraints

### 5.3 SIEM Normalization Survival Testing (E3)
- Pass payloads through Zeek, Suricata, ELK normalization
- Measure what survives and in what form
- Field-specific truncation and encoding behavior

### 5.4 Defense Mechanisms
- D1: Input sanitization (3 levels)
- D2: Structured prompt architecture
- D3: Adversarial fine-tuning
- D4: Dual-LLM verification
- D5: Canary token detection

### 5.5 Adaptive Attacker (E8)
- Defense-aware payload generation
- Knowledge levels: no knowledge → architecture-aware → defense-aware

## 6. Results (~2.5 pages)

### 6.1 Baseline Triage Accuracy (E1)
- Per-model F1, precision, recall on clean benchmark
- Cross-model comparison: architecture matters

### 6.2 Injection Vulnerability (E2)
- ASR per vector × model heatmap
- Which vectors are most effective?
- Which models are most vulnerable?

### 6.3 Payload Survival (E3)
- SIEM normalization results per vector
- Practical constraints on payload design

### 6.4 Defense Effectiveness (E4-E7)
- Per-defense ASR reduction
- Accuracy-robustness tradeoff curves
- Defense transferability across architectures

### 6.5 Adaptive Attacker (E8)
- Residual ASR against each defense under adaptation
- Carlini/Tramèr validation: do our defenses survive adaptive attacks?

### 6.6 Cross-Architecture Analysis
- MoE routing vulnerability profiles
- Dense vs. sparse attention patterns under injection
- Model size vs. robustness correlation

## 7. Discussion (~1 page)

### 7.1 Implications for SOC Deployment
- No current defense is sufficient alone
- Defense-in-depth recommendations
- When to trust vs. when to flag for human review

### 7.2 The Fundamental Tension
- Triage requires processing untrusted data
- Processing untrusted data = attack surface
- This is architectural, not fixable by prompt engineering

### 7.3 Alignment with SOC-Bench
- How our findings inform multi-agent blue team evaluation
- Adversarial robustness as a new SOC-Bench dimension

### 7.4 Limitations
- File-replay, not live deployment
- Simulated SIEM normalization, not production instances
- Models tested at specific checkpoints (snapshot in time)

## 8. Related Work (~1 page)
[See RELATED_WORK.md — already drafted]

## 9. Conclusion (~0.5 page)
- Summary of key findings
- Recommendations for practitioners
- Open problems for future work

## Appendix

### A. Complete Injection Vector Specifications
### B. Payload Templates (all 15)
### C. Statistical Analysis Details
### D. Reproduction Instructions
### E. Full Results Tables

---

## Key Figures to Create

1. **Figure 1:** SOC stack with attack surface highlighted (data pipeline injection)
2. **Figure 2:** Hades architecture diagram
3. **Figure 3:** ASR heatmap (vector × model)
4. **Figure 4:** Defense effectiveness comparison (bar chart per defense per model)
5. **Figure 5:** Accuracy-robustness tradeoff curves
6. **Figure 6:** Adaptive attacker escalation (ASR as attacker knowledge increases)
7. **Table 1:** Injection vector taxonomy with SIEM survival rates
8. **Table 2:** Baseline triage accuracy per model
9. **Table 3:** Cross-model vulnerability profiles

---

*This outline targets USENIX Security format (14 pages). Adapt for IEEE S&P or CCS as needed.*
