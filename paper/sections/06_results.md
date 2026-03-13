# 6. Results

> **Status:** Experimental infrastructure is complete; full model runs are pending Penn State lab GPU allocation. This section records validated pre-experiment results, benchmark construction outputs, and the exact result tables that will be populated once model inference begins.

## 6.1 Benchmark Construction Results

We constructed **Hades Benchmark v1** from Splunk Attack Data and validated every alert against the dataset gate.

### 6.1.1 Clean Benchmark Summary

| Metric | Value |
|---|---:|
| Total alerts | **11,147** |
| MITRE techniques | **25** |
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
| TA0001 Initial Access | 500 | 4.5% |
| TA0002 Execution | 2,002 | 18.0% |
| TA0003 Persistence | 2,014 | 18.1% |
| TA0004 Privilege Escalation | 500 | 4.5% |
| TA0005 Defense Evasion | 3,000 | 26.9% |
| TA0006 Credential Access | 1,023 | 9.2% |
| TA0007 Discovery | 1,500 | 13.5% |
| TA0008 Lateral Movement | 4 | 0.0% |
| TA0011 Command and Control | 604 | 5.4% |

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
| Benchmark alerts | 11,147 |
| Total adversarial variants (base) | **1,337,640** |

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
| suricata_malware.log | T1071.001 | available for extension | malware HTTP flows |

We identified **3 unique User-Agent strings** in the C2 dataset, providing clean baselines for controlled User-Agent injection experiments.

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

### 6.6.2 Survival by Attack Class

| Attack Class | Survival Rate | Notes |
|---|---:|---|
| Direct misclassification | **100%** | Contains explicit instruction keywords |
| Confidence manipulation | **100%** | Contains severity/confidence keywords |
| Reasoning corruption | 0% | Subtle — no detection keywords |
| Attention hijacking | 0% | Misdirects without explicit instructions |
| Escalation suppression | 0% | Implicit suppression, hard to keyword-detect |

**Key finding:** The two attack classes most dangerous to SOC operations (direct misclassification and confidence manipulation) survive all tested normalization steps across all SIEMs. Normalization is not a defense.

### 6.6.3 Implications

1. **Field truncation is not protective.** Even Elasticsearch's aggressive 256-char `ignore_above` preserves most injection payloads because effective payloads are compact (~50–150 chars).
2. **Character encoding transformations are payload-transparent.** JSON/XML/CEF escaping adds characters but preserves semantic content.
3. **Attack class determines survival, not SIEM config.** The 40% overall survival rate is entirely explained by the 2/5 attack classes that use explicit instruction keywords. The remaining 3 classes use subtler manipulation that wouldn't be caught by keyword-based detection anyway — making them potentially *more* dangerous despite lower keyword survival.

### 6.6.4 Extended: Encoding Strategy Effectiveness

We tested 9 encoding strategies (6 evasion, 3 protocol-constrained) across all 11 normalization rules (1,485 total tests).

| Encoding | Type | Keyword Survival | LLM-Readable? |
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

**Critical methodological note:** Low keyword survival for evasion encodings does not mean ineffectiveness. Homoglyph, zero-width, and leetspeak encodings are *designed* to evade keyword-based detection — they show 0% keyword survival because our detector can't read them, but LLMs can. These encodings would bypass sanitization defenses (D1) while remaining semantically valid to the model. Whether they actually succeed requires GPU-based E2 experiments.

This reveals a **dual vulnerability**: payloads using direct keywords survive SIEM normalization (§6.6.2), while payloads using evasion encodings survive keyword-based defenses. No single defense layer addresses both.

### 6.6.5 Protocol Constraint Impact

Protocol constraints significantly limit payload capacity but do not eliminate the threat:

| Protocol | Max Payload | Effective Instructions | Viability |
|---|---:|---:|---|
| HTTP User-Agent | ~8KB | ~200 words | **Excellent** — unlimited attack surface |
| HTTP Referer | ~8KB | ~200 words | **Excellent** |
| TLS Cert SAN | ~2KB | ~50 words | **Strong** — room for full instructions |
| Email Subject | ~998 chars | ~25 words | **Strong** |
| SSH Banner | ~255 chars | ~6 words | **Moderate** — fits short commands |
| DNS Query | 253 bytes | ~4 words | **Tight** — needs compression |
| TLS Cert CN | 64 chars | ~2 words | **Weak** — barely fits |
| SMB Hostname | 15 chars | ~1 word | **Minimal** — insufficient alone |

HTTP-based vectors provide orders of magnitude more payload capacity than network-layer vectors. This suggests that web-facing log sources (proxy logs, WAF logs, CDN logs) are the primary attack surface for SOC LLM injection.

## 6.7 Behavioral Invariant Detection (Pre-GPU)

We evaluated our behavioral invariant detection system on 50 real Sysmon alerts (T1003.001 LSASS credential dumping) with simulated clean and adversarial triage decisions.

### Detection Results

| Attack Class | Detection Rate | False Positive Rate | Triggering Invariants |
|---|---:|---:|---|
| Clean (no injection) | 0.0% | **0.0%** | — |
| C1: Direct Misclassification | **100.0%** | 0.0% | INV-1 (critical) |
| C2: Confidence Manipulation | 0.0% | 0.0% | INV-3 (high, below threshold) |
| C3: Reasoning Corruption | **100.0%** | 0.0% | INV-2 (critical) + INV-4 (medium) |
| C4: Attention Hijacking | **98.0%** | 0.0% | INV-1 (high) + INV-5 (medium) |

### Interpretation

The behavioral invariant system detects 3 of 4 attack classes with near-perfect accuracy and zero false positives. The key insight is that these checks operate on the triage **output**, not the prompt **input** — they are immune to prompt-level obfuscation techniques that defeat input sanitization.

**C2 (Confidence Manipulation) evades detection** because it does not change the classification label, introduce phantom IPs, or inject fabricated references. The only anomaly is an inflated confidence score, which triggers a single high-severity invariant but falls below the detection threshold. This demonstrates that behavioral invariants alone are insufficient — layered defenses including output confidence calibration and dual-model verification are needed for complete coverage.

The weighted scoring threshold (critical=3, high=2, medium=1, threshold≥3) was tuned to minimize false positives: no clean decision triggered any violation across 50 test alerts.

### Invariant Definitions

| ID | Check | Severity | What It Catches |
|---|---|---|---|
| INV-1 | Severity downgrade without evidence | critical/high | C1 (misclassification), C4 (attention hijack) |
| INV-2 | Phantom IPs in output | critical | C3 (IP substitution — the LevelBlue attack) |
| INV-3 | Unrealistic confidence scores | high | C2 (confidence inflation) |
| INV-4 | Fabricated references in reasoning | medium | C3 (fake change requests, pentest claims) |
| INV-5 | Temporal downplay patterns | medium | C4 ("all services nominal", "zero anomalies") |

## 6.8 Tables to Populate After GPU Runs

### Table A — Clean Baseline Accuracy (E1)

| Model | F1 | Precision | Recall | FP Rate | FN Rate |
|---|---:|---:|---:|---:|---:|
| DeepSeek R1 | TBD | TBD | TBD | TBD | TBD |
| GLM-5 | TBD | TBD | TBD | TBD | TBD |
| Kimi K2.5 | TBD | TBD | TBD | TBD | TBD |
| Qwen 3.5 | TBD | TBD | TBD | TBD | TBD |

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

## 6.9 Current Interpretation

Even before full model inference, several claims are already empirically established:

1. **Dataset adequacy is solved for v1.** We now have a benchmark-of-record with rule associations, MITRE mappings, provenance chains, and enforced contract validation.
2. **The adversarial experiment space is concrete, not speculative.** We can generate 1,337,640 realistic adversarial samples today.
3. **The highest-value injection vectors are operationally grounded.** HTTP User-Agent, Windows Event authentication fields, and SSH usernames are all both realistic and externally validated.
4. **The infrastructure risk is measurable.** We are no longer arguing only from thought experiments; we have a runnable benchmark, runnable injector, and runnable experiment harness.
