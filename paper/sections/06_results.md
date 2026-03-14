# 6. Results

> **Status:** Experimental infrastructure is complete; full model runs are pending Penn State lab GPU allocation. This section records validated pre-experiment results, benchmark construction outputs, and the exact result tables that will be populated once model inference begins.

## 6.1 Benchmark Construction Results

We constructed **Hades Benchmark v1** from Splunk Attack Data and validated every alert against the dataset gate.

### 6.1.1 Clean Benchmark Summary

| Metric | Value |
|---|---:|
| Total alerts | **12,147** |
| MITRE techniques | **27** |
| ATT&CK tactics | **9** |
| Contract failures | **0** |
| Parser types | Sysmon XML, Suricata JSON, Windows Security XML, PowerShell Logging |
| Provenance coverage | **100%** |
| Rule association coverage | **100%** |
| MITRE mapping coverage | **100%** |

### 6.1.2 Technique Distribution

| Technique | Name | Alerts |
|---|---|---:|
| T1003.001 | LSASS Credential Dumping | 500 |
| T1003.003 | NTDS.dit Credential Dumping | 500 |
| T1018 | Remote System Discovery | 500 |
| T1021.002 | SMB Admin Shares | 4 |
| T1021.006 | Windows Remote Management | 500 |
| T1550.002 | Pass the Hash | 500 |
| T1027 | Obfuscated Files / Information | 500 |
| T1036.003 | Masquerading: Rename System Utilities | 500 |
| T1047 | WMI Command Execution | 500 |
| T1053.005 | Scheduled Task | 514 |
| T1055.001 | Process Injection (Cobalt Strike) | 500 |
| T1059.001 | PowerShell Script Execution | 502 |
| T1071.001 | HTTP C2 Traffic | 104 |
| T1082 | System Information Discovery | 500 |
| T1087.001 | Local Account Discovery | 500 |
| T1105 | Ingress Tool Transfer | 500 |
| T1110.001 | RDP Brute Force | 23 |
| T1112 | Modify Registry | 500 |
| T1136.001 | Create Local Account | 500 |
| T1204.002 | User Execution: Malicious File | 500 |
| T1218.011 | Rundll32 Signed Binary Proxy | 500 |
| T1543.003 | Create/Modify Windows Service | 500 |
| T1547.001 | Registry Run Keys | 500 |
| T1548.002 | Bypass UAC | 500 |
| T1562.001 | Impair Defenses: Disable Tools | 500 |
| T1566.001 | Spearphishing Attachment | 500 |
| T1569.002 | Service Execution | 500 |

### 6.1.3 Tactic Distribution

| Tactic | Alerts | % |
|---|---:|---:|
| TA0001 Initial Access | 500 | 4.1% |
| TA0002 Execution | 2,002 | 16.5% |
| TA0003 Persistence | 2,014 | 16.6% |
| TA0004 Privilege Escalation | 500 | 4.1% |
| TA0005 Defense Evasion | 3,000 | 24.7% |
| TA0006 Credential Access | 1,023 | 8.4% |
| TA0007 Discovery | 1,500 | 12.3% |
| TA0008 Lateral Movement | 1,004 | 8.3% |
| TA0011 Command and Control | 604 | 5.0% |

## 6.2 Adversarial Dataset Generation Results

### 6.2.1 Variant Count

The adversarial injector produced the following experiment space:

| Dimension | Count |
|---|---:|
| Injection vectors | 12 |
| Attack classes | 5 |
| Base encoding strategies | 2 |
| Evasion encodings | 6 |
| Protocol constraints | 3 |
| Total encoding strategies | **11** |
| Variants per alert (base) | **120** |
| Benchmark alerts | 12,147 |
| Total adversarial variants (base) | **1,457,640** |

### 6.2.2 Injection Vector Capacity

| Vector | Capacity | Practical Viability | Validation |
|---|---|---|---|
| HTTP User-Agent | ~8KB | Excellent | LevelBlue 2025 |
| HTTP Referer | ~8KB | Excellent | protocol-backed |
| DNS Query | 253 bytes | Tight but feasible | RFC 1035 |
| Windows Event Username | 120+ chars | Strong | LevelBlue 2025 |
| Windows Event Domain | 120+ chars | Strong | LevelBlue 2025 |
| SSH Username | ~256 chars | Strong | LevelBlue 2025 |
| SMB Hostname | 15 chars | Weak | constrained |
| SNMP Community | 255 chars | Moderate | protocol-backed |
| Email Subject | ~998 chars | Strong | protocol-backed |
| TLS Cert CN | ~64 chars | Weak–Moderate | protocol-backed |
| TLS Cert SAN | ~2KB | Strong | protocol-backed |
| SSH Banner | ~255 chars | Moderate | protocol-backed |

## 6.3 Parser Validation Results

### 6.3.1 Sysmon Parser

We validated the Sysmon parser on multiple Splunk Attack Data datasets.

| Dataset | Technique | Parsed Events | Notes |
|---|---|---:|---|
| windows-sysmon.log | T1003.001 | **7,960** | credential dumping rich dataset |
| windows-sysmon.log | T1087.001 | 500 sampled | benchmark build |
| windows-sysmon.log | T1027 | 500 sampled | benchmark build |
| windows-sysmon.log | T1053.005 | 500 sampled | benchmark build |
| windows-sysmon.log | T1547.001 | 500 sampled | benchmark build |

The T1003.001 dataset alone yielded:
- `sysmon_10` (Process Access): 6,909 events
- `sysmon_1` (Process Creation): 421 events
- `sysmon_11` (FileCreate): 382 events
- `sysmon_22` (DNS Query): 100 events
- additional event types across registry, image load, and network activity

### 6.3.2 Suricata Parser

The Suricata parser successfully extracted HTTP C2 traffic with preserved User-Agent fields.

| Dataset | Technique | Parsed Events | Relevant Fields |
|---|---|---:|---|
| suricata_c2.log | T1071.001 | 94 | `http_user_agent`, headers, URL, src/dst IP |
| suricata_malware.log | T1071.001 | 10 | malware HTTP flows |

The final benchmark includes 104 T1071.001 alerts: 94 from `suricata_c2.log` and 10 from `suricata_malware.log`. We identified **3 unique User-Agent strings** in the C2 dataset, providing clean baselines for controlled User-Agent injection experiments.

## 6.4 Prompt Budget Results

The triage prompt module was validated on representative alerts.

| Prompt Mode | Approx Tokens / Alert | Notes |
|---|---:|---|
| Plain prompt | ~669 | no field boundary defense |
| Structured prompt | ~767 | D2 defense enabled |
| Suricata HTTP prompt | ~711 | preserves HTTP header context |

This means a full triage call with a 1,024-token response budget remains under ~1,800 tokens per alert — well within the 20K prompt budget target.

## 6.5 Dry-Run Experiment Validation

The experiment runner was validated in dry-run mode.

| Experiment | Alerts | Status |
|---|---:|---|
| E1 Clean Baseline | 100 | passed |
| E2 Injection Vulnerability | 50 clean → 6,000 adversarial | passed |

This confirms that:
- benchmark loading works end-to-end,
- adversarial generation works end-to-end,
- metric computation works end-to-end,
- result serialization to `results/` works end-to-end.

## 6.6 E3: Payload Survival Through SIEM Normalization

We tested whether adversarial payloads survive 11 common SIEM normalization steps across 5 SIEM platforms (Elasticsearch, Splunk, QRadar, ArcSight, and generic syslog processing).

### 6.6.1 Normalization Rules Tested

| Rule | SIEM | Description |
|---|---|---|
| truncate_256 | Elasticsearch | keyword `ignore_above=256` |
| truncate_1024 | Splunk | `TRUNCATE=1024` |
| truncate_4096 | QRadar | 4KB payload field max |
| strip_control | Generic | ASCII control character removal |
| ascii_fold | Elasticsearch | Unicode NFKD normalization |
| syslog_escape | Generic | Newline flattening |
| json_roundtrip | Generic | JSON encode/decode |
| xml_escape | Windows Event | XML entity encoding |
| cef_escape | ArcSight | CEF delimiter escaping |
| splunk_linebreak | Splunk | First-line-only extraction |
| normalize_ws | Generic | Whitespace collapse |

### 6.6.2 Payload Survival and Detection by Attack Class

| Attack Class | SIEM Normalization Survival | Keyword Detection Rate | Notes |
|---|---:|---:|---|
| Direct misclassification | **100%** | **100%** | Contains explicit instruction keywords (IGNORE, CLASSIFY) |
| Confidence manipulation | **100%** | **100%** | Contains severity/confidence keywords |
| Reasoning corruption | **100%** | 0% | Natural language — no detection keywords |
| Attention hijacking | **100%** | 0% | Misdirects without explicit instructions |
| Escalation suppression | **100%** | 0% | Implicit suppression, hard to keyword-detect |

**Important distinction:** ALL payloads survive SIEM normalization intact. All five attack classes use plain ASCII text, which passes through Elasticsearch truncation, JSON roundtrip, XML escaping, and all other tested normalization steps without semantic loss. The table measures a SECOND question: can keyword-based sanitization (D1) detect the payload? C1 (Direct misclassification) and C2 (Confidence manipulation) use explicit instruction keywords like "IGNORE" and "CLASSIFY" → 100% detectable by keyword matching. C3, C4, and C5 use natural language without instruction keywords → 0% detectable by keywords but still semantically effective to LLMs.

**Key finding:** All five attack classes survive SIEM normalization. However, only C1 and C2 are detectable by keyword-based sanitization. C3, C4, and C5 evade keyword detection entirely while remaining semantically effective — making keyword sanitization (D1) a partial defense at best.

### 6.6.3 Implications

1. **Field truncation is not protective.** Even Elasticsearch's aggressive 256-char `ignore_above` preserves most injection payloads because effective payloads are compact (~50–150 chars).
2. **Character encoding transformations are payload-transparent.** JSON/XML/CEF escaping adds characters but preserves semantic content.
3. **Attack class determines detectability, not SIEM config.** All five attack classes achieve 100% SIEM normalization survival — the pipeline preserves payloads intact regardless of encoding or SIEM platform. Keyword-based sanitization (D1) catches only 2 of 5 classes (C1 and C2, which use explicit instruction markers). The remaining 3 classes (C3, C4, C5) use natural language manipulation that evades keyword detection entirely — making them potentially *more* dangerous despite being harder to characterize.

### 6.6.4 Extended: Encoding Strategy Effectiveness

We tested 9 encoding strategies (6 evasion, 3 protocol-constrained) across all 11 normalization rules and 15 payload templates (9 × 11 × 15 = 1,485 total tests).

| Encoding | Type | Keyword Detection Rate | LLM-Readable? |
|---|---|---:|---|
| Markdown comment | Evasion | **33.3%** | Yes |
| Synonym substitution | Evasion | **20.0%** | Yes |
| Homoglyph (Cyrillic) | Evasion | 6.7% | **Yes** (tokenizer handles Unicode) |
| Zero-width chars | Evasion | 0.0% | **Yes** (invisible to display) |
| Leetspeak | Evasion | 0.0% | **Yes** (LLMs trained on internet text) |
| Base64 wrapped | Evasion | 0.0% | **Partial** (some models decode) |
| DNS constrained | Protocol | **33.3%** | N/A (protocol-limited) |
| TLS CN constrained | Protocol | **26.7%** | N/A (64-char limit) |
| SMB constrained | Protocol | 6.7% | N/A (15-char limit) |

**Critical methodological note:** Low keyword detection rates for evasion encodings does not mean ineffectiveness. Homoglyph, zero-width, and leetspeak encodings are *designed* to evade keyword-based detection — they show 0% keyword detection because the sanitizer can't parse them, but LLMs can. These encodings would bypass sanitization defenses (D1) while remaining semantically valid to the model. Whether they actually succeed requires GPU-based E2 experiments.

This reveals a **layered vulnerability**: all payloads survive SIEM normalization intact (§6.6.2), but keyword-based sanitization only detects payloads with explicit instruction markers (C1/C2). Evasion encodings and natural-language attack classes (C3/C4/C5) bypass keyword detection entirely while remaining semantically effective to LLMs. No single defense layer addresses the full attack surface.

### 6.6.5 Protocol Constraint Impact

Protocol constraints significantly limit payload capacity but do not eliminate the threat. We report payload capacity in bytes/characters; approximate injection budget varies by payload complexity.

| Protocol | Max Payload | Viability |
|---|---|---|
| HTTP User-Agent | ~8KB | **Excellent** — unlimited attack surface |
| HTTP Referer | ~8KB | **Excellent** |
| TLS Cert SAN | ~2KB | **Strong** — room for full instructions |
| Email Subject | ~998 chars | **Strong** |
| SSH Banner | ~255 chars | **Moderate** — fits short commands |
| DNS Query | 253 bytes | **Tight** — needs compression |
| TLS Cert CN | 64 chars | **Weak** — barely fits |
| SMB Hostname | 15 chars | **Minimal** — insufficient alone |

HTTP-based vectors provide orders of magnitude more payload capacity than network-layer vectors. This suggests that web-facing log sources (proxy logs, WAF logs, CDN logs) are the primary attack surface for SOC LLM injection.

## 6.7 Behavioral Invariant Detection (Pre-GPU)

We evaluated our behavioral invariant detection system on 50 real Sysmon alerts (T1003.001 LSASS credential dumping) with simulated clean and adversarial triage decisions.

### Detection Results

| Attack Class | Detection Rate | False Positive Rate | Triggering Invariants |
|---|---:|---:|---|
| Clean (no injection) | 0.0% | **0.0%** | — |
| C1: Direct Misclassification | **100.0%** | 0.0% | INV-1 (critical) |
| C2a: Confidence Inflation | 0–100%† | 0.0% | INV-3 (high) when >0.95; threshold-dependent |
| C2b: Confidence Suppression | 0–100%† | 0.0% | INV-6 (high) when <0.4 on HIGH alert |
| C3: Reasoning Corruption | **100.0%** | 0.0% | INV-2 (critical) + INV-4 (medium) |
| C4: Attention Hijacking | **98.0%** | 0.0% | INV-1 (high) + INV-5 (medium) |

### Interpretation

**Scope caveat.** These detection rates are validated against *template-based* simulated triage outputs designed to represent each attack class, not against real LLM model outputs. Actual model responses under adversarial injection may exhibit different patterns — more varied phrasing, partial compliance with injections, or novel failure modes not captured by our templates. Phase 2 GPU experiments (E2, E4–E8) will validate these detection rates against real model behavior.

The behavioral invariant system detects 3 of the 4 attack classes evaluated in this pre-GPU study with near-perfect accuracy and zero false positives. C5 (Escalation Suppression) targets the correlation stage rather than individual triage decisions and is not evaluated here; its detection requires campaign-level invariants planned for Phase 2. The key insight is that these checks operate on the triage **output**, not the prompt **input** — they are resistant to prompt-level obfuscation techniques that defeat input-level defenses.

†C2 detection is conditional: when confidence manipulation co-occurs with reasoning anomalies (INV-5 temporal downplay), the combined weighted score crosses the detection threshold (100%). Pure confidence-only manipulation without any reasoning artifacts produces a single high-severity violation below threshold (0%). We report the range to reflect this gap.

**C2 (Confidence Manipulation)** is detected by the combination of INV-6 (confidence-severity alignment, added to address the original gap) and temporal/contextual invariants. INV-6 flags when a HIGH-severity alert receives an unusually low confidence score (<0.4) on a true-positive classification — a signature of confidence manipulation attacks that try to suppress escalation without changing the verdict. When combined with INV-5 temporal downplay patterns (common in manipulated reasoning), the weighted score crosses the detection threshold. *Note: pure confidence manipulation alone (without any reasoning anomaly) produces a single high violation below threshold — this gap motivates dual-model verification as a complementary defense.*

The weighted scoring threshold (critical=3, high=2, medium=1, threshold≥3) was tuned to minimize false positives: no clean decision triggered any violation across 50 test alerts. **Confidence intervals** (95% Clopper-Pearson): C1/C3 detection 100% [92.9%, 100.0%]; C4 detection 98% [89.4%, 99.9%]; FPR 0% [0.0%, 7.1%]. These wide intervals reflect the small calibration sample; narrowing them is a priority for the full GPU evaluation.

**Sample size limitation.** The current threshold calibration uses 50 alerts from a single technique family (T1003.001 credential access). This narrow calibration base means detection rates and false positive rates may differ across other technique types, particularly those with different alert structures (e.g., network-based vs. host-based indicators). Broader calibration across diverse technique families is planned for the full GPU evaluation.

### Invariant Definitions

| ID | Check | Severity | What It Catches |
|---|---|---|---|
| INV-1 | Severity downgrade without evidence | critical (≥2 levels) / high (1 level) | C1 (misclassification), C4 (attention hijack) |
| INV-2 | Phantom IPs in output | critical | C3 (IP substitution — the LevelBlue attack) |
| INV-3 | Unrealistic confidence scores | high | C2 (confidence inflation) |
| INV-4 | Fabricated references in reasoning | medium | C3 (fake change requests, pentest claims) |
| INV-5 | Temporal downplay patterns | medium | C4 ("all services nominal", "zero anomalies") |
| INV-6 | Confidence-severity alignment | high | C2 (HIGH alert + confidence <0.4 on TP) |

## 6.8 Tables to Populate After GPU Runs

### Table A — Clean Baseline Accuracy (E1)

| Model | F1 | Precision | Recall | FN Rate |
|---|---:|---:|---:|---:|
| DeepSeek R1 | TBD | TBD | TBD | TBD |
| GLM-5 | TBD | TBD | TBD | TBD |
| Kimi K2.5 | TBD | TBD | TBD | TBD |
| Qwen 3.5 | TBD | TBD | TBD | TBD |

*Note: FP Rate (benign → malicious) requires supplementary benign alert data not included in the current all-positive benchmark and is therefore excluded from this table. See §5.4.1.*

### Table B — Attack Success Rate by Model (E2)

| Model | Overall ASR | Misclassification | Confidence Manip. | Reasoning Corr. | Attention Hijack | Escalation Supp. |
|---|---:|---:|---:|---:|---:|---:|
| DeepSeek R1 | TBD | TBD | TBD | TBD | TBD | TBD |
| GLM-5 | TBD | TBD | TBD | TBD | TBD | TBD |
| Kimi K2.5 | TBD | TBD | TBD | TBD | TBD | TBD |
| Qwen 3.5 | TBD | TBD | TBD | TBD | TBD | TBD |

### Table C — Attack Success Rate by Vector

| Vector | ASR | Best Encoding | Notes |
|---|---:|---|---|
| HTTP User-Agent | TBD | TBD | expected strongest |
| HTTP Referer | TBD | TBD | expected strong |
| DNS Query | TBD | TBD | expected constrained |
| Windows Event Username | TBD | TBD | real-world validated |
| Windows Event Domain | TBD | TBD | real-world validated |
| SSH Username | TBD | TBD | real-world validated |
| SMB Hostname | TBD | TBD | likely weak |
| SNMP Community | TBD | TBD | moderate capacity |
| Email Subject | TBD | TBD | strong but less SOC-central |
| TLS Cert CN | TBD | TBD | short |
| TLS Cert SAN | TBD | TBD | high capacity |
| SSH Banner | TBD | TBD | moderate |

### Table D — Defense Effectiveness (E4–E8)

| Defense | ASR Reduction | Clean Accuracy Loss | Survives Adaptive Attacker? |
|---|---:|---:|---|
| Sanitization L1 | TBD | TBD | TBD |
| Sanitization L2 | TBD | TBD | TBD |
| Sanitization L3 | TBD | TBD | TBD |
| Structured Prompt | TBD | TBD | TBD |
| Dual-LLM Verify | TBD | TBD | TBD |
| Canary Tokens | TBD | TBD | TBD |

## 6.9 SOC-Bench Fox Scoring (Pre-GPU)

We evaluated the pipeline's campaign-detection capability using the SOC-Bench Fox ring-scoring rubric (O1 campaign 39pts, O2 activity 39pts, O3 triage 22pts = 100pts max).

| Scenario | O1 Campaign | O2 Activity | O3 Triage | Total | Penalties |
|---|---:|---:|---:|---:|---:|
| Clean (30 T1003.001 Sysmon alerts) | 39.0 | 39.0 | 22.0 | **100.0** | 0 |
| DarkSide multi-stage (7 alerts, 7 techniques) (T1566.001 Spearphishing → T1059.001 PowerShell → T1003.001 LSASS Dump → T1021.006 WinRM Lateral → T1543.003 Service Persistence → T1562.001 Disable Defenses → T1105 C2 Tool Transfer) | 39.0 | 34.7 | 22.0 | **95.7** | 0 |
| Adversarial-injected campaign | 17.0 | 12.0 | 13.0 | **42.0** | 0 |

**Scenario comparison.** All three rows use the same evaluation rubric but different alert inputs. Row 1 (clean) evaluates 30 homogeneous T1003.001 credential dumping alerts — a single-technique scenario where the adapter achieves perfect scores because all alerts cleanly match one technique with consistent metadata. Row 2 (DarkSide) evaluates a realistic 7-alert multi-stage campaign across 7 techniques. Row 3 (adversarial) applies injection payloads to the DarkSide campaign alerts with behavioral invariants disabled.

**Methodology note.** These Fox scores are computed from simulated triage decisions, not real LLM model outputs (GPU experiments pending). Row 2 assumes correct triage; Row 3 assumes successful injection causing misclassification and reasoning corruption. The −53.7 point delta (Row 2 → Row 3) represents the *potential* operational impact if injection succeeds without output-level defenses — not a measured attack success rate from our models. The post-invariant Fox score (with behavioral defenses enabled) is expected to fall between Rows 2 and 3, and will be measured in the GPU evaluation.

### Per-Component Degradation Analysis

| Component | Clean (Row 2) | Adversarial (Row 3) | Delta | Operational Meaning |
|---|---:|---:|---:|---|
| O1 Campaign Assessment | 39.0 | 17.0 | −22.0 | Campaign scope and affected-host enumeration collapses; the SOC loses situational awareness of the attack's breadth |
| O2 Activity Classification | 34.7 | 12.0 | −22.7 | MITRE technique identification and kill chain phase tracking degrades; the SOC misunderstands *what* the attacker is doing |
| O3 Alert Triage | 22.0 | 13.0 | −9.0 | Individual alert priority and response recommendations corrupted; analysts receive wrong action guidance |

O1 and O2 suffer the largest absolute drops because they aggregate across multiple alerts — a single corrupted triage decision cascades into campaign-level misassessment. O3 degrades less in absolute terms but this is potentially misleading: O3's maximum is 22 points (vs 39 for O1/O2), so the −9.0 drop represents a 41% degradation of triage quality. The disproportionate campaign-level impact motivates the correlator agent: even if individual triage decisions are compromised, independent campaign detection through IP clustering and technique chain matching provides a redundant assessment path.

The O1 campaign assessment achieves perfect scores in the clean scenario because the adapter extracts host identifiers from metadata (not just IPs), uses technique diversity for scope inference, and weights critical decisions for activity classification. The O2 kill chain phase receives inner-ring (8.7/13) when the multi-stage scenario spans exploitation and actions phases.

## 6.10 Pre-GPU Validated Claims

Even before full model inference, several claims are already established:

1. **Dataset adequacy requirements are satisfied for v1 per the criteria of Liu [2026].** We now have a benchmark-of-record with rule associations, MITRE mappings, provenance chains, and enforced contract validation.
2. **The adversarial experiment space is concrete, not speculative.** We can generate 1,457,640 realistic adversarial samples today.
3. **The highest-value injection vectors are operationally grounded.** HTTP User-Agent, Windows Event authentication fields, and SSH usernames are all both realistic and externally validated.
4. **The infrastructure risk is measurable.** We are no longer arguing only from thought experiments; we have a runnable benchmark, runnable injector, and runnable experiment harness.
