# Technical Specification: Hades v0.3

**Scoped research prototype for offline SOC alert triage**

| Field | Value |
|---|---|
| Version | 0.3 |
| Date | March 12, 2026 |
| Status | Revised after strict design review |
| Repository state | Planning scaffold, not validated implementation |

## 1. Executive Summary

Hades is a scoped research prototype for offline SOC alert triage. The revised objective is narrower than the original proposal: build a defensible v1 that can ingest replayed alert files, normalize them into a stable schema, run a deterministic triage path with optional retrieval, and emit an auditable decision record for analyst review.

This revision deliberately removes or defers features that would weaken either research rigor or engineering feasibility:

- no internet-dependent analyst interface
- no required agent swarm
- no claim of full end-to-end validation before the code exists
- no requirement to store raw model chain-of-thought
- no broad eight-configuration benchmark in v1

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

Hades does not replace Splunk or firewalls. It replaces the analyst's manual triage work on each alert. The research question is: **can an offline LLM make triage decisions at human-level accuracy, with sufficient auditability for SOC deployment?**

> Rules tell you WHAT happened. Hades tells you WHY it matters and WHAT to do about it.

## 3. System Boundaries

### 3.1 In Scope for v1

- Replay alerts from local JSON or JSONL fixtures
- Normalize inputs into `UnifiedAlert`
- Run one deterministic triage path
- Optionally retrieve threat-intel context from a local RAG store
- Produce `TriageDecision` with structured evidence trace
- Expose results through CLI output and/or a local FastAPI dashboard
- Evaluate on a locked test set derived from transformed benchmark fixtures

### 3.2 Explicitly Out of Scope for v1

- Telegram bots or any internet-dependent operator workflow
- Live Splunk, Elastic, QRadar, syslog, Kafka, or Redis ingestion
- Native swarm orchestration as a required feature
- Automated SOAR actions
- A large cloud-vs-local comparison matrix
- Claims of real-time production throughput

## 4. Repo Reality Check

The repository currently contains schemas, configs, documentation, runtime scaffolding, local retrieval abstractions, packaging metadata, and basic tests. It still does not contain the end-to-end ingestion loop, benchmark runner, transformed benchmark fixtures, or analyst workflow described in the proposal. The spec must therefore track planned artifacts, not present the system as already validated.

## 5. Architecture Decisions

| Area | v1 Decision | Deferred |
|---|---|---|
| Input | file replay only | live SIEM connectors |
| Orchestration | deterministic single path | swarm and multi-agent graphs |
| Interface | local CLI and/or local web UI | Telegram and external chat tools |
| Retrieval | local Qdrant hybrid retrieval | distributed retrieval stack |
| Audit | evidence trace + rationale summary | raw chain-of-thought retention |
| Evaluation | locked benchmark with transformation pipeline | broad cloud baseline study |

## 6. Component Specification

### 6.1 Alert Ingestion and Normalization

The v1 ingestion path consumes replay fixtures from disk. Each raw record is transformed into `UnifiedAlert` and retains provenance fields that identify:

- source dataset or replay source
- original file path
- original record index or event id
- parser version
- transformation version

Normalization is allowed to leave some network fields empty when the source dataset does not contain them. Missing values must remain explicit rather than fabricated.

### 6.2 Triage Runtime

The v1 runtime is a deterministic pipeline:

1. load normalized alert
2. build prompt from alert fields and policy text
3. retrieve optional threat-intel context
4. invoke one reasoning model
5. apply thresholds for `needs_investigation` or human review
6. emit structured decision output

`src/openclaw/` remains a possible adapter layer for later tool-based orchestration, but the v1 design does not require OpenClaw. If it is used at all in v1, it must be treated as an implementation detail behind the deterministic pipeline rather than the central research contribution.

### 6.3 Model Strategy

Hades keeps `Kimi K2.5` as a candidate high-capacity local model, but it is no longer assumed to be frictionless for development or evaluation.

Source-backed constraints:

- Moonshot's official model card recommends `vLLM`, `SGLang`, or `KTransformers` for deployment and documents a 256k context window plus different parameter settings for thinking and instant modes.
- Moonshot's deployment guide explicitly says its commands are examples only, says inference engines are still changing, and currently points users to nightly builds for some Kimi-specific parsing features.

Implication for v1:

- Hades must remain model-agnostic at the interface level.
- The initial benchmark path must be able to run on one practical local baseline model.
- Kimi K2.5 local deployment is a gated evaluation target that becomes mandatory only after deployment is validated on available hardware.

### 6.4 Retrieval Strategy

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

### 6.5 Output and Audit Layer

The audit record must not require storing raw chain-of-thought. The stable artifact is `TriageDecision`, which includes:

- final label
- confidence
- evidence trace
- tool invocations, if any
- short analyst-visible rationale summary
- override record

This is the artifact used for review, debugging, and evaluation.

## 7. Public Interfaces

### 7.1 `UnifiedAlert`

Defined in `src/ingestion/schema.py`.

Required behavior:

- stable alert id
- normalized severity
- optional network and signature fields
- metadata block for vendor-specific detail
- provenance block for dataset path, parser version, and raw-record linkage

### 7.2 `TriageDecision`

Defined in `src/evaluation/schemas.py`.

Required behavior:

- model-agnostic classification output
- structured evidence trace
- optional tool call log
- rationale summary safe for analyst review
- explicit override record

### 7.3 Evaluation Config

Defined by `configs/eval_config_A.yaml`.

Required sections:

- dataset transformation stage
- split policy
- contamination controls
- annotator protocol
- statistical analysis plan

## 8. Evaluation Design

### 8.1 Benchmark Inputs

Raw datasets such as CICIDS, CIC-IDS2018, and BETH are not directly usable as SOC alert fixtures. Hades therefore adds a transformation stage that produces normalized alert records and records the transformation version.

Each benchmark item must preserve:

- original dataset name
- scenario or attack family
- source record ids or row range
- label provenance

### 8.2 Split Policy

The benchmark uses a locked test set. Prompt or threshold tuning is allowed only on a development split. Scenario-aware grouping is required so that near-duplicate samples do not leak across splits.

### 8.3 Contamination Controls

- RAG corpora may contain public ATT&CK or CVE knowledge.
- RAG corpora must not contain benchmark labels, benchmark rationales, or transformed benchmark records.
- Development notes used during prompt tuning must be kept separate from the locked test set.

### 8.4 Metrics

Primary metric:

- macro F1 on the locked test set

Secondary metrics:

- per-class precision and recall
- benign false-positive rate on explicitly benign subsets
- missed-detection rate on explicitly malicious subsets
- abstain or escalate rate
- latency p50 and p95

### 8.5 Human Review

If human review is included, use three reviewers and measure agreement with a multi-rater metric such as Fleiss' kappa. Do not describe the procedure as Cohen's kappa when there are three raters.

### 8.6 Statistical Analysis

Use:

- paired bootstrap confidence intervals for macro metrics
- Bowker or Stuart-Maxwell style tests when comparing paired multiclass predictions
- McNemar only for clearly defined binary sub-analyses, such as false-positive vs not-false-positive

## 9. Delivery Plan for August 2026

### Phase 1: April 2026

- finalize schemas and configs
- build file replay normalization path
- stand up local retrieval service
- create initial transformed benchmark fixtures

### Phase 2: May to June 2026

- implement deterministic triage path
- add CLI and local dashboard output
- lock development and test splits
- run first benchmark on one practical local baseline

### Phase 3: July to August 2026

- validate high-capacity local model deployment if hardware permits
- rerun locked evaluation with final prompt and threshold settings
- write paper/report around the implemented system only

## 10. Risks and Mitigations

| Risk | Impact | Mitigation |
|---|---|---|
| Kimi local deployment is unstable or too expensive | High | keep runtime interface model-agnostic and maintain one smaller local baseline |
| Benchmark transformation introduces label ambiguity | High | version transformation rules and preserve raw provenance |
| Retrieval contaminates evaluation | High | isolate RAG corpora from benchmark labels and benchmark-derived text |
| Proposal expands back into an unbuildable scope | High | treat all non-v1 features as explicitly deferred |
| Optional OpenClaw integration becomes a time sink | Medium | do not make it part of the critical path |

## 11. Authentication and Encryption Analysis

### 12.1 Authentication Attack Detection

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

### 12.2 Encrypted Traffic Analysis

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

### 12.3 Multi-Surface Correlation

The key advantage of combining auth + encryption + SIEM analysis in a single system: cross-surface correlation that standalone tools miss.

Example attack chain detected across surfaces:
1. **Auth surface:** Failed VPN login from unusual IP (low severity alone)
2. **Encryption surface:** Same IP shows JA3 fingerprint matching known reconnaissance tool
3. **SIEM surface:** Same IP ran port scans against 3 subnets 10 minutes prior
4. **Correlator output:** Combined evidence → confirmed reconnaissance campaign → HIGH severity

No single detection surface catches this with confidence. The correlator agent with 256K context can hold all three event streams simultaneously and produce a unified assessment.

## 12. Autonomous Response Architecture (v2 Roadmap)

v1 produces triage decisions for human review. v2 extends the pipeline with autonomous response capabilities, gated by confidence thresholds and configurable human-in-the-loop policies.

### 12.1 Response Action Framework

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

### 12.2 Response Tools (OpenClaw tool registry)

| Tool | Action | Risk Level | Default Policy |
|---|---|---|---|
| `firewall_block` | Block IP/CIDR at perimeter | Medium | Auto if confidence ≥ 0.95 |
| `host_isolate` | Quarantine host from network | High | Human approval required |
| `account_lockout` | Disable compromised account | Medium | Auto if credential abuse confirmed |
| `honeypot_redirect` | Redirect attacker traffic to decoy | Low | Auto for reconnaissance-phase attacks |
| `process_kill` | Terminate malicious process | High | Human approval required |
| `ioc_distribute` | Push IOCs to all network sensors | Low | Auto on confirmed threats |
| `ticket_create` | Open incident in ticketing system | Low | Always auto |

### 12.3 Confidence-Gated Automation

All autonomous actions require:
- Triage confidence above a configurable threshold (default: 0.95 for destructive actions, 0.80 for observational)
- Policy file approval for the action class
- Full audit trail logging the decision chain
- Rollback capability (temporary firewall rules auto-expire, account lockouts are time-bounded)

Actions below the confidence threshold produce recommendations instead of executions, preserving the human-in-the-loop for ambiguous cases.

### 12.4 Adaptive Deception (Honeypot Integration)

When Hades identifies early-stage attacks (reconnaissance, scanning), it can redirect rather than block:
- Route attacker traffic to a honeypot environment via firewall rules or DNS manipulation
- Monitor attacker behavior in the decoy environment in real-time
- Extract TTPs, tools, and objectives from honeypot logs
- Feed honeypot observations back into the triage pipeline for enhanced classification
- Attacker wastes time on decoys while real systems remain untouched

This produces intelligence value beyond simple blocking — understanding attacker methodology improves future detection.

### 12.5 Throughput Estimates

| Hardware | Tokens/sec | Triage Time (avg) | Alerts/day |
|---|---|---|---|
| 1x RTX 4090 (INT4) | ~1-2 | ~250-500s | ~170-350 |
| 2x A100 80GB | ~15-20 | ~25-33s | ~2,600-3,500 |
| 4x H100 80GB | ~40+ | ~12s | ~7,000+ |
| Human analyst | N/A | ~5-10 min | ~50-100 |

Even on modest hardware, Hades processes 3-10x more alerts per day than a human analyst, with consistent quality and full audit trails.

## 13. Source Notes

Feasibility-sensitive claims in this spec are grounded in primary documentation:

- Moonshot model card: [https://huggingface.co/moonshotai/Kimi-K2.5](https://huggingface.co/moonshotai/Kimi-K2.5)
- Moonshot deployment guide: [https://huggingface.co/moonshotai/Kimi-K2.5/blob/main/docs/deploy_guidance.md](https://huggingface.co/moonshotai/Kimi-K2.5/blob/main/docs/deploy_guidance.md)
- vLLM OpenAI-compatible server docs: [https://docs.vllm.ai/en/latest/serving/openai_compatible_server/](https://docs.vllm.ai/en/latest/serving/openai_compatible_server/)
- Qdrant quickstart: [https://qdrant.tech/documentation/quick-start/](https://qdrant.tech/documentation/quick-start/)
- Qdrant local and hybrid retrieval docs: [https://qdrant.tech/documentation/frameworks/langchain/](https://qdrant.tech/documentation/frameworks/langchain/)
- Chroma Search API availability: [https://docs.trychroma.com/cloud/search-api/overview](https://docs.trychroma.com/cloud/search-api/overview)
