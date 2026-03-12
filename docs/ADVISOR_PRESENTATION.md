# Hades: Adversarial Robustness of LLM-Based SOC Triage Systems
## Advisor Presentation — Dr. Peng Liu, Penn State Cyber Security Lab

---

### The Problem

LLM-based SOC tools are in production:
- Microsoft Security Copilot: 26% faster, 44% more accurate (RCT)
- CrowdStrike Charlotte AI: 98%+ accuracy, 40hr/week saved
- Simbian benchmark: frontier LLMs complete 61-67% of real SOC tasks
- Google Chronicle/Gemini: Leader in 2025 Gartner SIEM MQ

**But nobody has asked:** What happens when attackers craft network traffic to manipulate these systems?

---

### The Attack

Indirect Prompt Injection (IPI) through SIEM log fields:

1. **Attacker controls log content** — HTTP User-Agent, SSH username, Windows Event fields, DNS queries
2. **SIEM ingests these fields** into alert records
3. **LLM triage agent** reads the alert → follows injected instructions
4. **Result:** falsified IPs, suppressed alerts, misdirected investigations

**Already proven:**
- LevelBlue (Sept 2025): 100% success on 3 vectors, Microsoft declined to patch
- Unit42 (Dec 2025): 22 distinct techniques in production telemetry
- Carlini et al. (Oct 2025): ALL 12 published defenses broken by adaptive attackers

---

### The Gap

| System | SOC-specific | Adversarial | SIEM injection | Adaptive eval |
|--------|:-----------:|:-----------:|:--------------:|:------------:|
| CyBench (ICLR 2025) | ✗ | ✗ | ✗ | ✗ |
| AgentDojo (NeurIPS 2024) | ✗ | ✓ | ✗ | ✗ |
| AgentSentry (Feb 2026) | ✗ | ✓ | ✗ | ✗ |
| CORTEX (Sep 2025) | ✓ | ✗ | ✗ | ✗ |
| SOC-Bench (Liu 2026) | ✓ | ✗ | ✗ | ✗ |
| **Hades** | **✓** | **✓** | **✓** | **✓** |

---

### What Hades Does

**Research question:** How vulnerable are frontier MoE LLMs to indirect prompt injection through SIEM data pipelines, and can domain-specific behavioral invariants detect such attacks?

**Architecture:**
1. **Ingestion** — Parsers for Splunk Sysmon, Suricata, BETH, CIC-IDS2018
2. **Adversarial framework** — 12 vectors × 5 attack classes × 9 encodings
3. **Triage pipeline** — Classifier → RAG (MITRE ATT&CK) → Decision
4. **Defense evaluation** — Sanitization, structured prompts, canary tokens, layered
5. **SOC-Bench adapter** — Fox/Tiger/Panda-compatible output schemas

**Cross-model comparison (4 frontier MoE architectures):**
- DeepSeek R1 (671B/37B active) — #1 cybersecurity reasoning
- GLM-5 (744B/32B active) — #1 overall reasoning
- Kimi K2.5 (1T/32B active) — largest MoE, agent swarm
- Qwen 3.5 (397B/17B active) — best GPQA (88.4%), smallest

---

### What We've Built (Pre-GPU)

✅ **Benchmark:** 4,619 alerts, 12 MITRE techniques, 7 tactics, 554K adversarial variants
✅ **Parsers:** 4 format parsers (Sysmon, Suricata, BETH, CIC-IDS2018) — all tested
✅ **Adversarial framework:** 12 vectors, 5 attack classes, 9 encodings, injector + defense harnesses
✅ **E3 Results (no GPU needed):**
  - Payload survival: 40% of attack classes survive all 11 SIEM normalization rules
  - Evasion encodings: homoglyph/zero-width/leetspeak bypass keyword defenses but LLMs can still read them
  - Defense analysis: best layered defense achieves only 60% indicator removal on plaintext
✅ **Fox ring scorer:** Validated — perfect score 100/100, adversarial score 9/100 (91-point drop)
✅ **RAG pipeline:** 691 MITRE ATT&CK techniques ingested, Qdrant hybrid retrieval ready
✅ **Dataset gate:** Programmatic enforcement of benchmark provenance requirements
✅ **Paper:** 1,031 lines, ~10K words, 24 references, 10 sections
✅ **Validation:** 18/18 architecture tests passing
✅ **Lab setup script:** One-command GPU deployment (`bash scripts/lab_setup.sh --model deepseek`)

---

### Dataset Adequacy (Addressing Your Feedback)

Your core directive: *"Until datasets are scientifically defensible, the work is a project, NOT scientific."*

**Our approach:**
1. **Engineering scaffold** (CIC-IDS2018) — network flows, no SIEM rules. Used for parser development only.
2. **Benchmark of record** (Splunk Attack Data) — Sysmon/Suricata logs with MITRE technique mappings and detection rule associations. 4,619 alerts across 12 techniques.
3. **Strategic benchmark** (SOC-Bench) — your benchmark, grounded in Colonial Pipeline. Hades outputs are SOC-Bench-compatible (Fox/Tiger schemas).

**Programmatic enforcement:** `dataset_gate.py` rejects `engineering_scaffold` datasets from benchmark claims at code level.

---

### SOC-Bench Alignment

Hades can be the **first system evaluated on SOC-Bench:**
- Fox (campaign detection) → maps to Hades triage pipeline output
- Tiger (attribution/TTP) → maps to MITRE ATT&CK RAG annotations
- Output schemas match Fox O1/O2/O3 JSON format
- Ring scoring implemented and validated

**Adversarial angle:** What happens to SOC-Bench Fox scores when log data contains IPI? Our E2 experiments measure exactly this — Fox score drops from 100→9 on adversarial inputs (mock model, pending real model runs).

---

### MoE-Specific Angle

L³ attack [TeLintelo2026]: silencing <20% of experts increases ASR from 7.3%→70.4%
SAFEx [Lai2025]: safety behavior concentrated in just 12 experts in Qwen3-30B

**Hypothesis:** Different MoE architectures distribute safety-critical behavior differently across experts → different adversarial vulnerability profiles → architecture-dependent IPI susceptibility.

Our 4-model comparison can test this. If confirmed, this is a novel finding with broad implications.

---

### GPU-Blocked Items (Need Lab Access)

1. **Model weights:** DeepSeek R1 ~400GB, K2.5 ~630GB, GLM-5 ~400GB, Qwen 3.5 ~200GB
2. **E1:** Baseline triage accuracy per model (clean alerts)
3. **E2:** IPI attack success rate (adversarial alerts)
4. **E4-E7:** Defense effectiveness per model
5. **E8:** Adaptive attacker evaluation (Carlini methodology)

**Estimated GPU time:** ~40-60 hours on 4×A100 cluster

---

### Publication Strategy

**Primary target:** ACM CCS Workshop on AI for Cyber Threat Intelligence (Nov 2026)
**Stretch:** IEEE CNS 2026 (paper deadline May 11)
**Long-term:** USENIX Security 2027 / IEEE S&P 2027

**Strongest claims:**
1. First SOC-domain IPI evaluation framework
2. Cross-architecture MoE vulnerability profiling
3. Domain-behavioral invariant detection (orthogonal to model-level defenses)
4. SOC-Bench-compatible evaluation

---

### Next Steps (Requesting)

1. **GPU allocation** — 4×A100 or 2×H100, ~60 hours
2. **SOC-Bench access** — evaluate Hades on Fox/Tiger tasks
3. **Feedback on paper structure** — 10 sections ready for review
4. **Lab meeting slot** — present findings and get team feedback

---

*Repository: github.com/ph0en1x29/hades (private)*
*Validation: 18/18 tests passing | Paper: 24 references | Benchmark: 4,619 alerts*
