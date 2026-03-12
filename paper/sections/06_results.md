# 6. Results

> **Status:** Experimental infrastructure is complete; full model runs are pending Penn State lab GPU allocation. This section records validated pre-experiment results, benchmark construction outputs, and the exact result tables that will be populated once model inference begins.

## 6.1 Benchmark Construction Results

We constructed **Hades Benchmark v1** from Splunk Attack Data and validated every alert against the dataset gate.

### 6.1.1 Clean Benchmark Summary

| Metric | Value |
|---|---:|
| Total alerts | **4,619** |
| MITRE techniques | **12** |
| ATT&CK tactics | **7** |
| Contract failures | **0** |
| Parser types | Sysmon XML, Suricata JSON |
| Provenance coverage | **100%** |
| Rule association coverage | **100%** |
| MITRE mapping coverage | **100%** |

### 6.1.2 Technique Distribution

| Technique | Name | Alerts |
|---|---|---:|
| T1003.001 | LSASS Credential Dumping | 500 |
| T1110.001 | RDP Brute Force | 23 |
| T1087.001 | Local Account Discovery | 500 |
| T1021.002 | SMB Admin Shares | 2 |
| T1027 | Obfuscated Files / Information | 500 |
| T1036.003 | Masquerading: Rename System Utilities | 500 |
| T1053.005 | Scheduled Task | 500 |
| T1071.001 | HTTP C2 Traffic | 94 |
| T1105 | Ingress Tool Transfer | 500 |
| T1218.011 | Rundll32 Signed Binary Proxy Execution | 500 |
| T1547.001 | Registry Run Keys | 500 |
| T1569.002 | Service Execution | 500 |

### 6.1.3 Tactic Distribution

| Tactic | Alerts | % |
|---|---:|---:|
| TA0002 Execution | 500 | 10.8% |
| TA0003 Persistence | 1,000 | 21.6% |
| TA0005 Defense Evasion | 1,500 | 32.5% |
| TA0006 Credential Access | 523 | 11.3% |
| TA0007 Discovery | 500 | 10.8% |
| TA0008 Lateral Movement | 2 | 0.0% |
| TA0011 Command and Control | 594 | 12.9% |

## 6.2 Adversarial Dataset Generation Results

### 6.2.1 Variant Count

The adversarial injector produced the following experiment space:

| Dimension | Count |
|---|---:|
| Injection vectors | 12 |
| Attack classes | 5 |
| Encoding strategies | 2 |
| Variants per alert | **120** |
| Benchmark alerts | 4,619 |
| Total adversarial variants | **554,280** |

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

## 6.6 Tables to Populate After GPU Runs

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

## 6.7 Current Interpretation

Even before full model inference, several claims are already empirically established:

1. **Dataset adequacy is solved for v1.** We now have a benchmark-of-record with rule associations, MITRE mappings, provenance chains, and enforced contract validation.
2. **The adversarial experiment space is concrete, not speculative.** We can generate 554,280 realistic adversarial samples today.
3. **The highest-value injection vectors are operationally grounded.** HTTP User-Agent, Windows Event authentication fields, and SSH usernames are all both realistic and externally validated.
4. **The infrastructure risk is measurable.** We are no longer arguing only from thought experiments; we have a runnable benchmark, runnable injector, and runnable experiment harness.
