# Technical Specification: Hades v0.4

**Adversarial Robustness of LLM-Based SOC Triage Systems**

| Field | Value |
|---|---|
| Version | 0.5 |
| Date | March 12, 2026 |
| Status | Research pivot — adversarial manipulation focus |
| Repository state | Planning scaffold, not validated implementation |
| Target venues | USENIX Security 2027, IEEE S&P, ACM CCS main track |

## 1. Executive Summary

Hades is a research platform for studying adversarial manipulation of LLM-based Security Operations Center (SOC) triage systems. The project addresses a critical emerging threat: as organizations adopt LLMs for automated alert triage, attackers can craft network traffic that embeds prompt injection payloads in log fields, causing the triage LLM to misclassify genuine attacks as benign.

The research has two phases:

1. **Build a functional offline LLM triage pipeline** (the test bed) — ingest replayed alert files, normalize into a stable schema, run deterministic triage with optional RAG retrieval, emit auditable decisions.

2. **Systematically attack and defend it** (the research contribution) — inject adversarial payloads through realistic SIEM log vectors, measure misclassification rates across models, propose and evaluate defenses.

**Research question:** Can adversaries manipulate LLM-based SOC triage systems through crafted network traffic, and what defense mechanisms effectively mitigate this threat?

**Key insight:** The attacker doesn't compromise the LLM directly. They compromise the *data pipeline* — embedding instructions in HTTP headers, DNS queries, hostnames, and certificate fields that SIEM systems faithfully log and feed to the triage model.

## 2. Problem Statement

### 2.1 The SOC Triage Gap

Modern enterprise SOCs rely on a layered detection and response stack:

```text
Layer 1 — Detection: SIEM (Splunk, QRadar, ELK), IDS/IPS (Suricata, Snort),
           EDR (CrowdStrike, Carbon Black), threat intel feeds (STIX/TAXII)
           → Generates alerts using rules, signatures, and IOC matching

Layer 2 — Triage: HUMAN ANALYST reads each alert, decides severity,
           correlates related events, determines response
           → This is the bottleneck

Layer 3 — Response: SOAR (Phantom, XSOAR), firewall scripts, playbooks
           → Executes predefined actions based on analyst decisions
```

Layer 1 and Layer 3 are well-automated. Layer 2 — the triage decision — remains manual, slow, and expensive. An average enterprise SOC generates 2,000-10,000 alerts per day. A trained analyst triages 50-100. The rest are either ignored or bulk-closed.

### 2.2 Why Rules Are Insufficient

Existing detection tools are rule-based: Sigma rules, YARA signatures, correlation searches. These detect what they are programmed to detect.

| Capability | Rules/Scripts | LLM-based Triage |
|---|---|---|
| Detect known attack pattern | ✅ Excellent | ✅ Also capable |
| Detect novel/unseen pattern | ❌ Requires new rule | ✅ Reasons from first principles |
| Correlate disparate alerts into one attack chain | ❌ Only with pre-written correlation rules | ✅ Holds full context, finds connections |
| Explain reasoning to analyst | ❌ "Rule 4625 triggered" | ✅ "This appears to be lateral movement because..." |
| Handle ambiguous signals | ❌ Binary match/no-match | ✅ Probabilistic assessment with confidence |
| Adapt without rule updates | ❌ New attack = new rule written by human | ✅ Generalizes from threat knowledge |

**Example — slow password spray:**
A Sigma rule alerts on ">10 failed logins in 5 minutes." An attacker performing 3 failed logins per hour across 8 service accounts over 4 hours (24 total events) evades the threshold. No rule fires. An LLM with 256K context sees all 24 events, recognizes the pattern as T1110.003 (Password Spraying) with deliberate rate-limiting, and escalates.

### 2.3 Why Offline Matters

Cloud-based AI triage (GPT-4, Claude) exists but is unusable for organizations with air-gap requirements: government/defense (CMMC, ITAR), healthcare (HIPAA), critical infrastructure (NERC CIP), and financial institutions with strict data residency. SIEM alert data contains internal network topology, hostnames, IP ranges, user identities, and active vulnerability information — sending this to a cloud API is a security incident, not a solution.

### 2.4 What Hades Does

Hades fills the triage gap with an offline LLM pipeline:

```text
Layer 1 — Detection (existing tools, unchanged)
    ↓ generates alerts
Layer 2 — Triage (HADES — replaces manual analyst decision-making)
    ↓ produces structured decisions with evidence
Layer 3 — Response (existing SOAR/scripts, now fed by AI decisions)
```

Hades does not replace Splunk or firewalls. It replaces the analyst's manual triage work on each alert — and then asks: **what happens when attackers know the SOC uses an LLM?**

> Rules tell you WHAT happened. Hades tells you WHY it matters — unless an attacker tells it not to.

## 3. Adversarial Threat Model

### 3.1 Attack Surface: The Data Pipeline

LLM-based triage systems consume alert data generated by SIEM platforms. SIEM platforms faithfully log network metadata including attacker-controlled fields. This creates a direct injection path:

```text
Attacker crafts malicious traffic
    ↓ embeds payload in controllable log fields
SIEM ingests traffic metadata
    ↓ stores raw field values in alert
Alert normalizer includes fields in context
    ↓ passes to LLM as part of triage prompt
LLM reads attacker payload as instructions
    ↓ misclassifies alert
Attack proceeds undetected
```

The attacker does not need to compromise the LLM, the SIEM, or any infrastructure. They only need to send network traffic containing crafted strings in fields that will be logged.

### 3.1a Real-World Validation

This threat model is not theoretical. [Neaves2025] at LevelBlue (AT&T Cybersecurity) demonstrated three successful indirect prompt injection attacks through SOC/SIEM log files: (1) HTTP User-Agent injection causing source IP address falsification, (2) SSH username field injection with IP masking, and (3) Windows Event 4625 authentication failure injection using username+domain fields (which accept 120+ characters each despite documented 20-char limits). In all three cases, the LLM-based triage agent followed the injected instructions, changing IPs, hostnames, and hiding attack indicators.

[PaloAlto2026] (Unit 42) reports the first large-scale in-the-wild observations of web-based indirect prompt injection from production telemetry, identifying 22 distinct payload engineering techniques actively used by attackers.

These demonstrations validate our attack surface analysis and injection vector taxonomy below.

### 3.2 Injection Vectors

| Vector | Log Field | Max Length | SIEM Survival | Validated | SIEM Source |
|---|---|---|---|---|---|
| HTTP User-Agent | `http.user_agent` | ~8KB (RFC 2616: no limit) | HIGH | ✅ [Neaves2025] | Suricata, Zeek, WAF |
| HTTP Referer | `http.referer` | ~8KB | HIGH | | Web proxy, WAF |
| DNS Query | `dns.query` | 253 chars | HIGH | | DNS logs, Zeek |
| Win Event Username | `winlog.event_data.TargetUserName` | 120+ chars (tested) | HIGH | ✅ [Neaves2025] | Windows Event Log |
| Win Event Domain | `winlog.event_data.TargetDomainName` | 120+ chars (tested) | HIGH | ✅ [Neaves2025] | Windows Event Log |
| SSH Username | `source.user` | ~256 chars | HIGH | ✅ [Neaves2025] | SSH auth logs |
| SMB Hostname | `source.hostname` | 15 chars (NetBIOS) | HIGH | | Windows Event Log |
| SNMP Community | `snmp.community` | 255 chars | MEDIUM | | Network monitoring |
| Email Subject | `email.subject` | ~998 chars (RFC 2822) | HIGH | | Mail gateway |
| TLS Cert CN | `tls.server.cn` | ~64 chars | HIGH | | Zeek, TLS inspection |
| TLS Cert SAN | `tls.server.san` | ~2KB (multiple entries) | HIGH | | Zeek, TLS inspection |
| SSH Banner | `ssh.banner` | ~255 chars | MEDIUM | | Zeek, auth logs |
| LDAP Bind DN | `ldap.bind_dn` | ~256 chars | MEDIUM | | AD logs |

### 3.3 Attack Classes

**Class 1 — Direct Misclassification:** Payload instructs LLM to classify the alert as benign, low severity, or false positive.

**Class 2 — Confidence Manipulation:** Payload doesn't change the label but inflates confidence score, causing the alert to bypass human review thresholds.

**Class 3 — Reasoning Corruption:** Payload injects false evidence into the LLM's reasoning chain (e.g., "this IP is on the authorized scanner whitelist"), producing a plausible-looking but incorrect rationale.

**Class 4 — Attention Hijacking:** Payload introduces irrelevant context that causes the LLM to focus on benign aspects of the alert while ignoring malicious indicators.

**Class 5 — Escalation Suppression:** Payload targets the correlation step, preventing the LLM from linking related alerts into an attack chain.

### 3.4 Attacker Knowledge Assumptions

| Level | Knowledge | Realism |
|---|---|---|
| Black-box | Knows SOC uses LLM triage, no model details | Most realistic |
| Gray-box | Knows model family and general prompt structure | Realistic (vendor docs leak this) |
| White-box | Full prompt template and model weights | Worst-case for defense evaluation |

### 3.5 Scope Boundaries

**In scope:**
- Injection through log fields that originate from network traffic
- Payloads that survive SIEM normalization (realistic encoding)
- Attacks that a real attacker could execute during an actual intrusion

**Out of scope:**
- Direct prompt injection via analyst input (different threat model)
- Model poisoning / training data attacks
- Side-channel attacks on the inference engine
- Social engineering of SOC analysts

## 4. System Boundaries

### 4.1 In Scope for v1

- Replay alerts from local JSON or JSONL fixtures
- Normalize inputs into `UnifiedAlert`
- Run one deterministic triage path
- Optionally retrieve threat-intel context from a local RAG store
- Produce `TriageDecision` with structured evidence trace
- Expose results through CLI output and/or a local FastAPI dashboard
- Evaluate on a locked test set derived from transformed benchmark fixtures

### 4.2 Explicitly Out of Scope for v1

- Telegram bots or any internet-dependent operator workflow
- Live Splunk, Elastic, QRadar, syslog, Kafka, or Redis ingestion
- Native swarm orchestration as a required feature
- Automated SOAR actions
- A large cloud-vs-local comparison matrix
- Claims of real-time production throughput

## 5. Repo Reality Check

The repository currently contains schemas, configs, documentation, runtime scaffolding, local retrieval abstractions, packaging metadata, and basic tests. It still does not contain the end-to-end ingestion loop, benchmark runner, transformed benchmark fixtures, or analyst workflow described in the proposal. The spec must therefore track planned artifacts, not present the system as already validated.

## 6. Architecture Decisions

| Area | v1 Decision | Deferred |
|---|---|---|
| Input | file replay only | live SIEM connectors |
| Orchestration | deterministic single path | swarm and multi-agent graphs |
| Interface | local CLI and/or local web UI | Telegram and external chat tools |
| Retrieval | local Qdrant hybrid retrieval | distributed retrieval stack |
| Audit | evidence trace + rationale summary | raw chain-of-thought retention |
| Evaluation | locked benchmark with transformation pipeline | broad cloud baseline study |

## 7. Component Specification

### 7.1 Alert Ingestion and Normalization

The v1 ingestion path consumes replay fixtures from disk. Each raw record is transformed into `UnifiedAlert` and retains provenance fields that identify:

- source dataset or replay source
- original file path
- original record index or event id
- parser version
- transformation version

Normalization is allowed to leave some network fields empty when the source dataset does not contain them. Missing values must remain explicit rather than fabricated.

### 7.2 Triage Runtime

The v1 runtime is a deterministic pipeline:

1. load normalized alert
2. build prompt from alert fields and policy text
3. retrieve optional threat-intel context
4. invoke one reasoning model
5. apply thresholds for `needs_investigation` or human review
6. emit structured decision output

`src/openclaw/` remains a possible adapter layer for later tool-based orchestration, but the v1 design does not require OpenClaw. If it is used at all in v1, it must be treated as an implementation detail behind the deterministic pipeline rather than the central research contribution.

### 7.3 Model Strategy

Hades uses a **multi-model cross-architecture comparison** to strengthen scientific rigor. With access to Penn State Cyber Security Lab GPU hardware (multi-A100/H100 cluster), all models run at full precision without quantization compromise.

#### Primary Evaluation Models (Local, Full Precision)

| Model | Architecture | Total Params | Active Params | VRAM (FP16) | Key Strength |
|---|---|---|---|---|---|
| DeepSeek R1 | Dense MoE | 671B | ~37B | 4×H100 (320GB) | #1 for cybersecurity reasoning |
| GLM-5 | Dense MoE | 744B | ~32B | 4×H100 (320GB) | #1 overall reasoning benchmark |
| Kimi K2.5 | Sparse MoE | 1T | 32B | 4×H100 (320GB) | Largest MoE, agent swarm mode |
| Qwen 3.5 | Dense MoE | 397B | 17B | 2×A100 (160GB) | Best GPQA Diamond (88.4%), smallest active params |

#### Why Multi-Model Matters for This Research

Different architectures have **different vulnerability profiles** to prompt injection:
- MoE routing decisions may be manipulable (K2.5, Qwen 3.5)
- Dense attention patterns vs sparse attention affect context sensitivity (DeepSeek R1 vs K2.5)
- Models trained with different safety RLHF exhibit different injection resistance
- Cross-model consistency of triage decisions is itself a publishable finding

#### Experiment Design Impact

Each experiment (E1-E8) runs across all 4 models, producing a model×defense×attack matrix. This enables:
- Per-architecture vulnerability profiling
- Defense transferability analysis (does D2 work on all architectures?)
- Publication-grade comparison tables

#### Deployment via vLLM/SGLang

All models served via vLLM with tensor parallelism across available GPUs. Model-agnostic interface preserved — only the vLLM endpoint config changes between runs.

### 7.4 Retrieval Strategy

The original proposal named ChromaDB with hybrid retrieval, but the current documented hybrid Search API in Chroma is Chroma Cloud-only, with local support described as future work. The revised v1 uses Qdrant because Qdrant documents:

- local deployment
- local client mode
- dense retrieval
- sparse retrieval
- hybrid retrieval with score fusion

v1 RAG choices:

- store: Qdrant
- dense embedding: pinned FastEmbed-compatible open embedding model such as `BAAI/bge-small-en-v1.5`; stronger models like `bge-m3` require a different embedding pipeline than the current Qdrant FastEmbed path
- sparse retrieval: BM25-compatible sparse model
- knowledge sources: MITRE ATT&CK plus a curated CVE subset
- retrieval goal: evidence augmentation, not autonomous action selection

### 7.5 Output and Audit Layer

The audit record must not require storing raw chain-of-thought. The stable artifact is `TriageDecision`, which includes:

- final label
- confidence
- evidence trace
- tool invocations, if any
- short analyst-visible rationale summary
- override record

This is the artifact used for review, debugging, and evaluation.

## 8. Public Interfaces

### 8.1 `UnifiedAlert`

Defined in `src/ingestion/schema.py`.

Required behavior:

- stable alert id
- normalized severity
- optional network and signature fields
- benchmark block for scenario id, rule linkage, and MITRE mapping
- metadata block for vendor-specific detail
- provenance block for dataset path, dataset role, parser version, raw-record linkage, and label provenance

### 8.2 `TriageDecision`

Defined in `src/evaluation/schemas.py`.

Required behavior:

- model-agnostic classification output
- structured evidence trace
- optional tool call log
- rationale summary safe for analyst review
- explicit override record

### 8.3 Evaluation Config

Defined by `configs/eval_config_A.yaml`.

Required sections:

- dataset transformation stage
- split policy
- contamination controls
- annotator protocol
- statistical analysis plan

## 9. Dataset Gate

Dataset adequacy is the controlling gate for Hades. No benchmark, adversarial evaluation, or scientific validation claim is considered complete until the benchmark-of-record satisfies the dataset gate.

### 9.1 Benchmark of Record

The first public benchmark-of-record is:

- Splunk Attack Data
- Splunk Security Content

Strategic second-phase benchmark path:

- SOC-Bench, only after advisor-controlled access is confirmed

Supplementary only:

- OTRF Security-Datasets
- EVTX-to-MITRE-Attack

Engineering scaffolding only:

- CICIDS and CIC-IDS2018-derived flow parsers

### 9.2 Exit Criteria

Every benchmark alert used for scientific validation must include:

- a detection-rule association
- dataset provenance
- label provenance
- enough analyst-facing context to support triage
- MITRE ATT&CK mapping
- scenario grouping or correlation metadata when available

Every benchmark slice must document whether it is:

- public
- simulated
- advisor-provided

### 9.3 Implications for Current Work

- CIC-IDS2018 parsing remains useful engineering infrastructure
- CIC-IDS2018 does not qualify as benchmark-of-record evidence on its own
- adversarial evaluation is downstream of benchmark adequacy, not parallel to it

## 10. Evaluation Design

### 10.1 Benchmark Inputs

Raw datasets such as CICIDS, CIC-IDS2018, and BETH are not directly usable as SOC alert fixtures. Hades therefore adds a transformation stage that produces normalized alert records and records the transformation version.

Each benchmark item must preserve:

- original dataset name
- scenario or attack family
- source record ids or row range
- label provenance
- rule association metadata

### 10.2 Split Policy

The benchmark uses a locked test set. Prompt or threshold tuning is allowed only on a development split. Scenario-aware grouping is required so that near-duplicate samples do not leak across splits.

### 10.3 Contamination Controls

- RAG corpora may contain public ATT&CK or CVE knowledge.
- RAG corpora must not contain benchmark labels, benchmark rationales, or transformed benchmark records.
- Development notes used during prompt tuning must be kept separate from the locked test set.

### 10.4 Metrics

Primary metric:

- macro F1 on the locked test set

Secondary metrics:

- per-class precision and recall
- benign false-positive rate on explicitly benign subsets
- missed-detection rate on explicitly malicious subsets
- abstain or escalate rate
- latency p50 and p95

### 10.5 Human Review

If human review is included, use three reviewers and measure agreement with a multi-rater metric such as Fleiss' kappa. Do not describe the procedure as Cohen's kappa when there are three raters.

### 10.6 Statistical Analysis

Use:

- paired bootstrap confidence intervals for macro metrics
- Bowker or Stuart-Maxwell style tests when comparing paired multiclass predictions
- McNemar only for clearly defined binary sub-analyses, such as false-positive vs not-false-positive

## 11. Adversarial Evaluation Design

### 11.1 Experiment Matrix

| Experiment | Independent Variable | Dependent Variable | Purpose |
|---|---|---|---|
| E1: Baseline triage | Model (DeepSeek R1, GLM-5, K2.5, Qwen 3.5) | F1, precision, recall | Establish triage accuracy per model after dataset gate exit |
| E2: Injection success rate | Injection vector × attack class × model (4 models) | Misclassification rate, confidence delta | Measure vulnerability per vector per architecture |
| E3: Payload survival | Encoding method × SIEM normalizer | Payload preservation rate | Which payloads survive real SIEM processing |
| E4: Defense — sanitization | Sanitization aggressiveness (none/moderate/strict) | Triage accuracy vs injection resistance | Input-level defense |
| E5: Defense — structured prompts | Raw text vs structured-only alert fields | Injection success vs information loss | Architectural defense |
| E6: Defense — adversarial training | Fine-tuned vs base model | Injection resistance + baseline accuracy | Model-level defense |
| E7: Defense — dual verification | Single vs dual-LLM pipeline | Detection rate of injected alerts | Pipeline defense |
| E8: Adaptive attacker | Defense-aware payloads vs each defense | Residual attack success rate | Defense robustness under adaptation |

### 11.2 Adversarial Dataset Construction

For each alert in the benchmark-of-record after dataset gate approval, generate adversarial variants:

- **Clean version:** Original alert, no injection
- **Per-vector injection:** Same alert with payload in each injectable field (8+ variants per alert)
- **Per-class injection:** Each of the 5 attack classes applied
- **Encoding variants:** Plain text, Base64 fragments, Unicode homoglyphs, comment-style wrapping

Total adversarial test set: ~10,000+ alert variants derived from 1,100 base alerts.

### 11.3 Metrics (Adversarial)

Primary:
- **Attack Success Rate (ASR):** Percentage of injected alerts that change from correct to incorrect classification
- **Severity Downgrade Rate:** Percentage of critical/high alerts downgraded to medium/low/benign

Secondary:
- **Confidence Manipulation Delta:** Average confidence change between clean and injected versions
- **Reasoning Corruption Rate:** Percentage of decisions where injected content appears in the evidence trace
- **Defense Overhead:** Latency increase and accuracy loss from each defense mechanism
- **Adaptive Resistance:** ASR when attacker has knowledge of deployed defenses

### 11.4 Defense Mechanisms Under Evaluation

**D1 — Input Sanitization:**
Strip or escape suspicious patterns in log fields before prompt construction. Three levels: regex-based (fast, brittle), ML-based anomaly detection on field values (moderate), aggressive field truncation (safe, lossy).

**D2 — Structured Prompt Architecture:**
Separate data fields from instruction context. Alert data stays in the same nested schema but each string leaf is wrapped with explicit field labels instead of being merged into raw free-form log text. The defense must not change the alert contract that downstream components evaluate.

**D3 — Adversarial Fine-Tuning:**
Fine-tune the triage model on a dataset that includes injected alerts with correct labels. The model learns to ignore injection attempts while maintaining triage accuracy.

**D4 — Dual-LLM Verification:**
A second model reviews the first model's decision specifically looking for signs of prompt injection influence. The verifier has access to the raw alert AND the first model's reasoning, checking for evidence of manipulation.

**D5 — Canary Token Detection:**
Insert known-benign canary strings into the alert data boundary, not the instruction scaffold. If the model's output references or acts on that canary, the system records cross-boundary influence.

## 12. Delivery Plan for August 2026

### Phase 1: March–April 2026

- Lock dataset adequacy criteria and benchmark manifest
- Acquire the first public benchmark slice from Splunk Attack Data + Splunk Security Content
- Implement normalization with rule linkage, label provenance, and scenario metadata
- Add config-level and test-level dataset-gate enforcement
- Ask Dr. Liu for SOC-Bench access without blocking the public benchmark path

### Phase 2: May–June 2026

- Stand up local retrieval service (Qdrant)
- Implement deterministic triage pipeline on the benchmark-of-record
- Add CLI and local dashboard output
- Lock development and test splits
- Run baseline triage benchmark (E1) only after dataset gate exit criteria are satisfied

### Phase 3: July–August 2026

- Generate adversarial dataset from benchmark-of-record alerts
- Run injection experiments E2–E3
- Implement and evaluate defenses D1–D2 (E4–E5)
- Validate high-capacity local model deployment if hardware permits
- Implement and evaluate defenses D3–D5 (E6–E7)
- Run adaptive attacker experiments (E8)
- Cross-model comparison of vulnerability and defense effectiveness only within the approved benchmark scope
- Write paper — focus on adversarial findings, not just triage accuracy
- Target: USENIX Security 2027 submission (deadline ~Feb 2027)

## 13. Risks and Mitigations

| Risk | Impact | Mitigation |
|---|---|---|
| Public benchmark path proves scientifically inadequate | High | keep Splunk Attack Data + Security Content as the first public gate and seek SOC-Bench access in parallel |
| Kimi local deployment is unstable or too expensive | High | keep runtime interface model-agnostic and maintain one smaller local baseline |
| Benchmark transformation introduces label ambiguity | High | version transformation rules and preserve raw provenance |
| Retrieval contaminates evaluation | High | isolate RAG corpora from benchmark labels and benchmark-derived text |
| Proposal expands back into an unbuildable scope | High | treat all non-v1 features as explicitly deferred |
| Optional OpenClaw integration becomes a time sink | Medium | do not make it part of the critical path |
| Adversarial payloads don't survive SIEM normalization | High | test with real SIEM normalizers (Zeek, Suricata); document which vectors are realistic |
| Defenses degrade baseline triage accuracy | Medium | measure accuracy delta for each defense; reject defenses with >5% F1 drop |
| Responsible disclosure concerns | Medium | payloads are conceptual, not weaponized; follow standard academic disclosure practices |
| SOC-Bench access is delayed or unavailable | Medium | treat SOC-Bench as a second-phase benchmark path, not a prerequisite |
| Insufficient model diversity for cross-model claims | Medium | narrow claims to approved local-model comparisons until wider benchmark scope is justified |

## 14. Authentication and Encryption Analysis

### 13.1 Authentication Attack Detection

Beyond standard SIEM alert triage, v1 normalization supports authentication event analysis from common log sources:

**Supported log types:**
- Windows Security Events (4624/4625/4768/4769/4771/4776)
- Linux auth logs (PAM, sshd)
- Application authentication logs (OAuth token events, SAML assertions)

**Detection capabilities:**

| Attack | MITRE Technique | Detection Method |
|---|---|---|
| Brute force | T1110 | Failed login rate + source correlation |
| Password spraying | T1110.003 | Low-rate failures across many accounts from few sources |
| Credential stuffing | T1110.004 | High-rate failures with varied username patterns |
| Kerberoasting | T1558.003 | Anomalous volume of TGS requests for service accounts |
| Golden Ticket | T1558.001 | Kerberos tickets with abnormal lifetimes or encryption types |
| Pass-the-Hash | T1550.002 | NTLM authentication without preceding interactive logon |
| DCSync | T1003.006 | Domain replication requests from non-DC hosts |
| Valid account abuse | T1078 | Behavioral anomaly — geolocation, time-of-day, device fingerprint deviation |
| OAuth token theft | T1528 | Suspicious token refresh patterns, consent phishing indicators |

**Behavioral baselining (v2):** The correlator agent can build per-user authentication profiles (typical login times, source IPs, devices) and flag deviations even when credentials are valid — addressing the hardest class of insider threat and compromised account attacks.

### 13.2 Encrypted Traffic Analysis

Hades can analyze encrypted communications without decryption by examining metadata, handshake characteristics, and traffic patterns:

**TLS Fingerprinting (JA3/JA4):**
- Extract client hello fingerprints from TLS handshakes (via Zeek or Suricata logs)
- Cross-reference against known malware fingerprint database in local RAG
- Detect tool-specific signatures: Cobalt Strike, Metasploit, custom implants
- No decryption required — fingerprint is derived from cipher suite negotiation

**Certificate Anomaly Detection:**
- Self-signed certificates on services that should have CA-signed certs
- Recently issued certificates on typosquat domains resembling the organization
- Expired or revoked certificates still in active use
- Unusual Subject Alternative Names or certificate chains

**Behavioral Traffic Analysis (encrypted payload, no decryption):**
- C2 beaconing detection — regular interval communications (e.g., 60s ± jitter)
- Data exfiltration indicators — large encrypted uploads to unusual destinations
- DNS-over-HTTPS tunneling — encrypted DNS bypassing network monitoring
- Packet size and timing patterns characteristic of reverse shells or tunnels

**Cryptographic Misconfiguration Detection:**
- Weak cipher suites (RC4, DES, export-grade, NULL ciphers)
- Deprecated protocol versions (SSLv3, TLS 1.0, TLS 1.1)
- Missing HSTS headers or certificate pinning
- Flagged as compliance findings (SOX, HIPAA, CMMC, PCI-DSS)

### 13.3 Multi-Surface Correlation

The key advantage of combining auth + encryption + SIEM analysis in a single system: cross-surface correlation that standalone tools miss.

Example attack chain detected across surfaces:
1. **Auth surface:** Failed VPN login from unusual IP (low severity alone)
2. **Encryption surface:** Same IP shows JA3 fingerprint matching known reconnaissance tool
3. **SIEM surface:** Same IP ran port scans against 3 subnets 10 minutes prior
4. **Correlator output:** Combined evidence → confirmed reconnaissance campaign → HIGH severity

No single detection surface catches this with confidence. The correlator agent with 256K context can hold all three event streams simultaneously and produce a unified assessment.

## 15. Autonomous Response Architecture (v2 Roadmap)

v1 produces triage decisions for human review. v2 extends the pipeline with autonomous response capabilities, gated by confidence thresholds and configurable human-in-the-loop policies.

### 14.1 Response Action Framework

```
TriageDecision (v1 output)
    ↓
[Decision Gate] — confidence threshold + policy check
    ↓ (confidence ≥ threshold AND policy allows auto-response)
    ├→ [Containment] — network isolation, firewall rules, account lockout
    ├→ [Deception] — honeypot redirection, decoy credential injection
    ├→ [Remediation] — process termination, malware quarantine, patch trigger
    └→ [Notification] — SOC escalation, incident ticket creation
```

### 14.2 Response Tools (OpenClaw tool registry)

| Tool | Action | Risk Level | Default Policy |
|---|---|---|---|
| `firewall_block` | Block IP/CIDR at perimeter | Medium | Auto if confidence ≥ 0.95 |
| `host_isolate` | Quarantine host from network | High | Human approval required |
| `account_lockout` | Disable compromised account | Medium | Auto if credential abuse confirmed |
| `honeypot_redirect` | Redirect attacker traffic to decoy | Low | Auto for reconnaissance-phase attacks |
| `process_kill` | Terminate malicious process | High | Human approval required |
| `ioc_distribute` | Push IOCs to all network sensors | Low | Auto on confirmed threats |
| `ticket_create` | Open incident in ticketing system | Low | Always auto |

### 14.3 Confidence-Gated Automation

All autonomous actions require:
- Triage confidence above a configurable threshold (default: 0.95 for destructive actions, 0.80 for observational)
- Policy file approval for the action class
- Full audit trail logging the decision chain
- Rollback capability (temporary firewall rules auto-expire, account lockouts are time-bounded)

Actions below the confidence threshold produce recommendations instead of executions, preserving the human-in-the-loop for ambiguous cases.

### 14.4 Adaptive Deception (Honeypot Integration)

When Hades identifies early-stage attacks (reconnaissance, scanning), it can redirect rather than block:
- Route attacker traffic to a honeypot environment via firewall rules or DNS manipulation
- Monitor attacker behavior in the decoy environment in real-time
- Extract TTPs, tools, and objectives from honeypot logs
- Feed honeypot observations back into the triage pipeline for enhanced classification
- Attacker wastes time on decoys while real systems remain untouched

This produces intelligence value beyond simple blocking — understanding attacker methodology improves future detection.

### 14.5 Throughput Estimates

| Hardware | Tokens/sec | Triage Time (avg) | Alerts/day |
|---|---|---|---|
| 1x RTX 4090 (INT4) | ~1-2 | ~250-500s | ~170-350 |
| 2x A100 80GB | ~15-20 | ~25-33s | ~2,600-3,500 |
| 4x H100 80GB | ~40+ | ~12s | ~7,000+ |
| Human analyst | N/A | ~5-10 min | ~50-100 |

Even on modest hardware, Hades processes 3-10x more alerts per day than a human analyst, with consistent quality and full audit trails.

## 15. Source Notes

Feasibility-sensitive claims in this spec are grounded in primary documentation:

- Moonshot model card: [https://huggingface.co/moonshotai/Kimi-K2.5](https://huggingface.co/moonshotai/Kimi-K2.5)
- Moonshot deployment guide: [https://huggingface.co/moonshotai/Kimi-K2.5/blob/main/docs/deploy_guidance.md](https://huggingface.co/moonshotai/Kimi-K2.5/blob/main/docs/deploy_guidance.md)
- vLLM OpenAI-compatible server docs: [https://docs.vllm.ai/en/latest/serving/openai_compatible_server/](https://docs.vllm.ai/en/latest/serving/openai_compatible_server/)
- Qdrant quickstart: [https://qdrant.tech/documentation/quick-start/](https://qdrant.tech/documentation/quick-start/)
- Qdrant local and hybrid retrieval docs: [https://qdrant.tech/documentation/frameworks/langchain/](https://qdrant.tech/documentation/frameworks/langchain/)
- Chroma Search API availability: [https://docs.trychroma.com/cloud/search-api/overview](https://docs.trychroma.com/cloud/search-api/overview)
