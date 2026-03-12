# Technical Specification: Hades — Offline Agentic SOC Assistant

**Architecture, Component Specs, Data Schemas, and Implementation Plan**

| Field | Value |
|-------|-------|
| Version | 0.2 (Validated) |
| Date | March 2026 |
| Author | Jay (Li Zhe Yow) |
| Advisor | Dr. Peng Liu |
| Status | Planning / Pre-implementation |

---

## 1. System Overview

This document defines the technical architecture for an offline, air-gapped SOC assistant built on three open-source components: **Kimi K2.5** (reasoning + orchestration), **OpenClaw** (integration + tool routing), and a **local RAG pipeline** (threat intelligence). The system processes SIEM alerts through a multi-agent pipeline to produce triage classifications, correlated timelines, and incident response playbooks without any external network dependencies.

### 1.1 Design Principles

1. **Zero external dependencies** after initial deployment. All inference, retrieval, and orchestration happen on-premises.
2. **Auditable decisions.** Every triage output includes a full reasoning chain, confidence score, and evidence trail for compliance review.
3. **Modular and swappable.** Each component (model, agent framework, RAG store, SIEM connector) can be replaced independently.
4. **Graceful degradation.** If swarm mode hits resource limits, the system falls back to OpenClaw-orchestrated sequential processing.
5. **Evaluation-first.** The benchmarking harness is built alongside the system, not after it.
6. **Reproducible.** All experiments use pinned model versions, fixed seeds, Docker containers, and versioned datasets.

### 1.2 Hardware Requirements

| Tier | Hardware | Storage | Performance | Use Case |
|------|----------|---------|-------------|----------|
| Development | Moonshot K2.5 API + local dev env | Minimal | API-dependent | Prompt engineering, pipeline development |
| Development (local) | Qwen 72B on 1× A100 80GB | ~40GB | ~20 tok/s | Offline pipeline testing without K2.5 |
| Evaluation | 2× A100 80GB + 256GB RAM | 630GB+ (INT4) | ~15-20 tok/s | Full benchmark suite, swarm testing |
| Production | 4× H100 80GB + 512GB RAM | 630GB+ (INT4) | ~40+ tok/s | Real-time SOC deployment |
| Minimum (POC) | 1× RTX 4090 24GB + 256GB RAM | 240GB (1.58-bit) | ~1-2 tok/s | Air-gapped demo only (MoE offloaded to RAM) |

> **Note:** K2.5 INT4 requires ~630GB storage and 2× 80GB GPUs minimum for usable inference speeds. The RTX 4090 tier offloads MoE layers to system RAM, resulting in severely degraded performance (~1-2 tok/s). Development uses the Moonshot API or a smaller model (Qwen 72B) to unblock prompt engineering while reserving the full K2.5 for evaluation.

All tiers use local NVMe SSD storage for the vector database and model weights. Network connectivity is only required for initial setup (model download, RAG data sync).

---

## 2. Component Specifications

### 2.1 Data Ingestion Layer

**Purpose:** Normalize raw SIEM alerts from multiple vendor formats into a unified schema for downstream processing.

#### Supported Input Formats

| SIEM Platform | Format | Connector Type | Priority |
|---------------|--------|----------------|----------|
| Splunk | JSON via HEC | HTTP webhook listener | P1 |
| Elastic/ELK | JSON via Logstash output | TCP socket listener | P1 |
| QRadar | LEEF over syslog | Syslog UDP/TCP receiver | P2 |
| Generic | CEF over syslog | Syslog parser | P2 |
| File-based | CSV/JSON log files | File watcher (inotify) | For evaluation |

#### Unified Alert Schema (v1)

```json
{
  "alert_id": "uuid-v4",
  "timestamp": "ISO-8601",
  "source": "splunk|elastic|qradar|file",
  "severity": "critical|high|medium|low|info",
  "signature": "string (rule/signature name)",
  "signature_id": "string (vendor rule ID)",
  "src_ip": "string",
  "src_port": "integer|null",
  "dst_ip": "string",
  "dst_port": "integer|null",
  "protocol": "TCP|UDP|ICMP|other",
  "raw_log": "string (original log entry)",
  "metadata": {
    "vendor": "string",
    "device": "string",
    "category": "string (vendor category)"
  },
  "ingested_at": "ISO-8601"
}
```

The ingestion daemon runs as a systemd service, writing normalized alerts to a local Kafka topic (or Redis stream for lighter deployments). Batch mode reads from labeled CSV/JSON files for evaluation replays.

### 2.2 OpenClaw Integration Layer

**Purpose:** Manages the interface between external systems and the Kimi K2.5 reasoning engine. Handles tool definitions, context window management, session state, and the human-in-the-loop interface.

#### Key Responsibilities

- **Tool registry:** Defines available tools (SIEM query, RAG search, log lookup, ticket creation) as YAML specs that K2.5 can invoke.
- **Context management:** Sliding window with summarization when conversation exceeds effective context. Priority ordering: current alert > recent correlations > RAG context > historical summaries.
- **Session state:** SQLite-backed session store tracking per-alert triage progress, agent call history, and analyst overrides.
- **Rate limiting:** Controls K2.5 inference requests to prevent GPU saturation during alert storms.
- **Interface layer:** Telegram bot for analyst interaction, CLI for scripted evaluation, REST API for SOAR integration.
- **Multi-agent orchestration:** OpenClaw manages the agent graph (classifier → correlator → playbook), providing a reliable alternative to K2.5's native swarm when self-hosted swarm mode is unstable.

#### Tool Definition Example

```yaml
# tools/siem_query.yaml
name: siem_query
description: >
  Query the local SIEM index for log entries matching
  specified criteria within a time window.
parameters:
  query_type:
    type: string
    enum: [ip_lookup, signature_search, time_range]
  value:
    type: string
    description: IP address, signature name, or time range
  time_window_minutes:
    type: integer
    default: 30
    description: How far back to search (minutes)
returns:
  type: array
  items:
    type: object
    description: Matching log entries in unified schema
```

#### Context Priority Stack

| Priority | Content | Max Tokens | Strategy |
|----------|---------|------------|----------|
| 1 (highest) | Current alert + classification request | 2,000 | Always included |
| 2 | Correlated events from Log Correlator | 8,000 | Most recent first |
| 3 | RAG retrieval results | 4,000 | Top-k by relevance |
| 4 | Active session history | 4,000 | Sliding window |
| 5 (lowest) | Historical summaries | 2,000 | Compressed summaries |

> **Design rationale:** Target ~20,000 tokens per inference call despite K2.5's 256K window. Research shows that focused prompts improve classification accuracy and reduce latency. The 256K capacity is reserved for complex swarm-mode incidents requiring full incident timelines. The accuracy-vs-context-length tradeoff will be empirically measured in the evaluation (see Section 4.3).

### 2.3 Kimi K2.5 Reasoning Engine

**Purpose:** Core reasoning, decision-making, and multi-agent orchestration for the entire triage pipeline.

#### Model Configuration

| Parameter | Value | Notes |
|-----------|-------|-------|
| Model | Kimi K2.5 (moonshotai/Kimi-K2.5) | MIT license, open weights |
| Architecture | MoE (1T total, 32B active, 384 experts, 8+1 shared per token) | 50% more experts than DeepSeek-V3 |
| Attention | MLA (Multi-head Latent Attention) | ~10× KV cache reduction vs MHA |
| Quantization | Native INT4 (group size 32, QAT) | No post-hoc accuracy loss |
| Context window | 256K tokens | Full incident timeline capacity |
| Serving framework | vLLM or SGLang | Official deployment guides available |
| Thinking mode | temp=1.0, top_p=0.95, min_p=0.01 | For complex multi-step triage |
| Instant mode | temp=0.6, top_p=0.95 | For simple alert classification |
| Deterministic eval | temp=0.0 | For reproducible benchmark runs |

#### Operating Modes

| Mode | Complexity | Method | Latency Target | Description |
|------|-----------|--------|----------------|-------------|
| Instant | Low | Single inference, no sub-agents | < 2 sec | Well-known signatures, high confidence |
| Thinking | Medium | K2.5 thinking mode + RAG | < 15 sec | Ambiguous alerts, multi-step reasoning |
| Swarm | High | Parallel sub-agents | < 60 sec | Complex multi-alert incidents |

#### Orchestration Strategy (Dual-Path)

Two orchestration approaches are implemented and compared:

1. **OpenClaw-orchestrated** (primary): OpenClaw manages the agent graph, routing tasks to classifier/correlator/playbook agents sequentially or in parallel. Provides deterministic, debuggable agent coordination. This is the reliable baseline.

2. **K2.5 native swarm** (experimental): K2.5 self-directs up to 100 sub-agents with no predefined workflow. Dynamically decomposes tasks. Requires significant GPU resources for parallel inference streams.

> **Research contribution:** Comparing OpenClaw-orchestrated (deterministic) vs K2.5 native swarm (self-directed) is a novel evaluation axis. No prior work has compared these orchestration paradigms for SOC triage.

### 2.4 Agent Specifications

#### Alert Classifier Agent
- **Purpose:** First-pass classification into triage categories
- **Output:** `{True Positive | False Positive | Needs Investigation | Escalate}`, confidence score (0-1), reasoning chain
- **Behavior:** Low-confidence (<0.7) auto-triggers Log Correlator for additional context
- **Tracking:** Per-alert-type accuracy for continuous prompt improvement

#### Log Correlator Agent
- **Purpose:** Pull related events to build context around ambiguous alerts
- **Method:** Time-window correlation (±15min default), source/dest IP grouping, session reconstruction
- **Queries:** Elasticsearch/OpenSearch, auth logs, firewall logs, endpoint logs
- **Output:** Correlated event timeline JSON, related alerts, network flow summary
- **Note:** Leverages K2.5's 256K context for full incident timelines when needed

#### Playbook Generator Agent
- **Purpose:** Generate incident response playbooks based on classified threat + evidence
- **Framework:** NIST SP 800-61 incident response lifecycle (Preparation, Detection, Containment, Eradication, Recovery, Lessons Learned)
- **Output:** Step-by-step playbook, containment recommendations, escalation path, IOC extraction
- **Augmentation:** RAG-sourced threat intelligence, customizable template library

### 2.5 Local RAG Pipeline

**Purpose:** Provide up-to-date threat intelligence and security knowledge without internet access.

| Component | Choice | Rationale |
|-----------|--------|-----------|
| Vector store | ChromaDB | Lightweight, Python-native, <1M vectors sufficient for security KB |
| Embedding model | BGE-M3 (BAAI) | Open weights, multi-functionality (dense + sparse + colbert), <30ms latency, on-prem deployable, ~2GB VRAM |
| Knowledge sources | MITRE ATT&CK v15, NVD/CVE feed, custom threat intel docs | Comprehensive coverage |
| Chunking | 512 tokens, 128 overlap | Balanced precision/recall |
| Search | Hybrid (semantic + keyword BM25) | Higher precision for technical queries |
| Update method | Offline sync (USB, air-gapped transfer) | Periodic manual updates |

> **Alternative:** Milvus if scaling beyond 1M vectors or requiring distributed deployment. ChromaDB preferred for single-node air-gapped simplicity.

### 2.6 Output & Decision Layer

- **Decision aggregator:** Combines classification, correlation, and playbook outputs
- **Confidence thresholds:** Configurable per alert severity (e.g., critical alerts require >0.9 confidence)
- **Audit log:** Append-only SQLite with full reasoning chain for every decision
- **Human override:** Analyst can override any decision via Telegram/CLI interface
- **SOAR integration:** Optional webhook for automated ticket creation
- **Dashboard API:** FastAPI serving real-time triage metrics, FP rates, and processing latency

---

## 3. Data Schemas

### 3.1 Triage Decision Schema

```json
{
  "decision_id": "uuid-v4",
  "alert_id": "uuid-v4 (ref to ingested alert)",
  "classification": "true_positive|false_positive|needs_investigation|escalate",
  "confidence": 0.92,
  "severity_override": "critical|high|medium|low|null",
  "reasoning_chain": [
    {"step": 1, "agent": "classifier", "action": "Initial classification", "result": "true_positive (0.85)"},
    {"step": 2, "agent": "correlator", "action": "Time-window correlation", "result": "3 related events found"},
    {"step": 3, "agent": "classifier", "action": "Reclassification with context", "result": "true_positive (0.92)"},
    {"step": 4, "agent": "playbook", "action": "Generate response", "result": "Lateral movement playbook v2"}
  ],
  "correlated_events": ["alert_id_1", "alert_id_2"],
  "mitre_techniques": ["T1021.001", "T1078"],
  "playbook_id": "uuid-v4",
  "processing_time_ms": 8432,
  "mode_used": "thinking",
  "model_version": "moonshotai/Kimi-K2.5-INT4",
  "analyst_override": null,
  "created_at": "ISO-8601"
}
```

### 3.2 Evaluation Result Schema

```json
{
  "eval_id": "uuid-v4",
  "config_id": "A|B|C|D|E|F|G",
  "dataset": "cicids2017|cicids2018|beth|synthetic|fp_set",
  "alert_id": "uuid-v4",
  "ground_truth": "true_positive|false_positive|needs_investigation|escalate",
  "prediction": "true_positive|false_positive|needs_investigation|escalate",
  "confidence": 0.87,
  "latency_ms": 3200,
  "tokens_used": {"input": 1500, "output": 800},
  "mode_used": "instant|thinking|swarm",
  "seed": 42,
  "model_version": "string",
  "timestamp": "ISO-8601"
}
```

---

## 4. Evaluation Plan

### 4.1 Benchmark Dataset

| Source | Alert Count | Type | Labels | Role |
|--------|-------------|------|--------|------|
| CICIDS2017 | ~400 | Network intrusion (DDoS, PortScan, Brute Force, Web Attack) | Ground truth | Comparability baseline (widely cited) |
| CIC-IDS2018 / CSE-CIC-IDS2018 | ~300 | Updated network attacks (botnet, DoS, infiltration) | Ground truth | Primary network dataset (addresses CICIDS2017 limitations) |
| BETH | ~200 | Host-based anomalies (process, syscall) | Ground truth | Supplementary (honeypot, 23 hosts) |
| Synthetic MITRE ATT&CK | ~300 | Generated from ATT&CK technique scenarios | Expert-labeled | Primary evaluation — tests real-world alert patterns |
| False Positive Set | ~200 | Known benign alerts from production SIEM patterns | All labeled FP | FP reduction measurement |

**Total: 1,400+ alerts** across 4 categories (True Positive, False Positive, Needs Investigation, Escalate).

> **Note on CICIDS2017:** Included for comparability with prior work despite known limitations (label imbalance, dated attack patterns, per Engelen et al. "Troubleshooting an Intrusion Detection Dataset"). CIC-IDS2018 addresses many of these issues and serves as the primary network dataset.

### 4.2 Comparison Matrix

| Config | Model | Mode | Orchestration | RAG | Purpose |
|--------|-------|------|---------------|-----|---------|
| A (baseline) | Kimi K2.5 INT4 local | Single-agent | None | Off | Baseline local performance |
| B | Kimi K2.5 INT4 local | Single-agent | None | On | RAG impact measurement |
| C | Kimi K2.5 INT4 local | Multi-agent | OpenClaw | On | Orchestrated pipeline performance |
| D | Kimi K2.5 INT4 local | Multi-agent | K2.5 Swarm | On | Native swarm vs orchestrated comparison |
| E | Qwen 72B local | Single-agent | None | On | Alternative open model comparison |
| F | Llama 3.1 70B local | Single-agent | None | On | Dense model comparison |
| G | GPT-4o via API | Single-agent | None | On | Cloud baseline (upper bound) |
| H | Claude Sonnet via API | Single-agent | None | On | Cloud baseline (upper bound) |

> **Key comparison axes:** (1) RAG impact: A vs B, (2) Orchestration: B vs C vs D, (3) Model choice: B vs E vs F vs G vs H, (4) Offline feasibility: C/D vs G/H

### 4.3 Metrics

| Metric | Target | Measurement |
|--------|--------|-------------|
| Precision (per category) | > 0.85 | TP / (TP + FP) per class |
| Recall (per category) | > 0.80 | TP / (TP + FN) per class |
| F1 (macro-averaged) | > 0.82 | Harmonic mean across classes |
| False Positive Rate | < 15% | FP / (FP + TN) |
| Latency (instant mode) | < 2 sec | End-to-end per alert |
| Latency (thinking mode) | < 15 sec | End-to-end per alert |
| Latency (swarm mode) | < 60 sec | End-to-end per incident |
| Throughput | > 100 alerts/hour | Sustained processing rate |
| Cost per alert (cloud) | Measured | API cost for G/H configs |
| Cost per alert (local) | Measured | Amortized hardware cost for A-F |
| Context length vs accuracy | Measured | Accuracy at 5K/10K/20K/50K/100K tokens |

#### Statistical Testing
- **McNemar's test** for pairwise classifier comparison (paired, non-parametric)
- **Bootstrap CI** (10,000 iterations) for confidence intervals on F1/precision/recall
- **Significance level:** α = 0.05

### 4.4 Additional Evaluations

#### Cost of Autonomy Analysis
Calculate the efficiency frontier: hardware cost × inference time × accuracy across all configurations. Present as a Pareto chart showing the tradeoff between cost, speed, and accuracy for cloud vs. local deployment.

#### Human-in-the-Loop Validation
- 3 cybersecurity students/analysts review 100 randomly sampled triage decisions
- **Cohen's kappa** for inter-rater agreement between system and humans
- Qualitative feedback on reasoning chain quality

#### Per-Component Latency Profiling
Break down end-to-end latency into: ingestion (ms) → classification (ms) → correlation (ms) → playbook (ms) → decision aggregation (ms). Identify bottlenecks.

#### System Threat Model
- **Prompt injection via crafted SIEM alerts:** adversary crafts alert content to manipulate triage decisions
- **Model hallucination:** false negatives (missed threats) or fabricated ATT&CK techniques
- **RAG poisoning:** malicious threat intel documents injected during offline sync
- **Mitigation:** Input sanitization, confidence thresholds, human review for critical alerts, signed RAG updates

---

## 5. Implementation Timeline

### Phase 1: Foundation (March 10 – April 30)

**Week 1–2: Infrastructure Setup**
- Set up project repository, Docker containers, CI pipeline
- Register Moonshot API access for development
- Download Qwen 72B for local pipeline testing (if GPU available)
- Set up OpenClaw local environment with basic tool definitions
- Validate K2.5 inference with basic security prompts via API

**Week 3–4: Data Pipeline**
- Build ingestion daemon with file-based connector (CSV/JSON for evaluation)
- Implement unified alert schema with validation
- Build RAG pipeline: install ChromaDB, download MITRE ATT&CK v15 + NVD/CVE, chunk with BGE-M3 embeddings
- Curate evaluation dataset: download CICIDS2017, CIC-IDS2018, BETH
- Generate synthetic MITRE ATT&CK alerts, label with ground truth

**Week 5–6: Agent Pipeline v1**
- Build Alert Classifier agent with few-shot prompt engineering
- Build Log Correlator agent with time-window + IP correlation
- Build Playbook Generator agent with NIST 800-61 templates
- Integrate agents through OpenClaw tool routing
- End-to-end smoke test: 50 alerts through full pipeline

**Phase 1 Milestone:** Working e2e pipeline (file input → classification → correlation → playbook). RAG operational. Dataset ready.

### Phase 2: Benchmarking (May 1 – June 30)

**Week 7–8: Evaluation Harness + Baseline**
- Build automated evaluation framework: batch replay, metric collection, confusion matrix
- Implement statistical testing (McNemar's, bootstrap CI)
- Run Config A (K2.5 single-agent, no RAG) — baseline
- Run Config B (K2.5 single-agent, with RAG) — measure RAG impact

**Week 9–10: Model Comparison**
- Run Configs E, F (Qwen 72B, Llama 3.1 70B) on identical dataset
- Run Configs G, H (GPT-4o, Claude Sonnet) — cloud baselines
- Context length experiment: measure accuracy at 5K/10K/20K/50K/100K tokens

**Week 11–12: Orchestration Comparison**
- Run Config C (OpenClaw-orchestrated multi-agent)
- Run Config D (K2.5 native swarm) — if hardware permits
- Latency profiling per component
- Cost of autonomy analysis
- Human-in-the-loop evaluation (100 samples, 3 reviewers)
- Compile results, run statistical significance tests

**Phase 2 Milestone:** Complete benchmark across all configs. Statistical analysis done. Clear picture of local vs cloud performance.

### Phase 3: Optimization & Paper (July 1 – August 31)

**Week 13–14: System Optimization**
- Analyze failure cases from Phase 2
- Tune prompts based on error analysis
- Optimize RAG: adjust chunk size, top-k, similarity threshold
- Test agent specialization improvements

**Week 15–16: Scenario Testing**
- Design 5 end-to-end SOC shift simulations (8 hours each, mixed alert types)
- Measure sustained throughput and accuracy degradation over time
- Estimate analyst time savings

**Week 17–20: Paper & Release**
- Write research paper (target: USENIX Security 2027 or ACM CCS 2026 Workshop)
- Sections: Introduction, Related Work, Architecture, Methodology, Results, Discussion, Future Work
- Package open-source release: Docker containers, documentation, evaluation scripts, dataset
- Internal presentation to Cyber Security Lab
- Submit draft to Dr. Liu for review

**Phase 3 Milestone:** Optimized system, complete paper draft, open-source release.

---

## 6. Reproducibility

All experiments follow these reproducibility requirements:

- **Docker containers** for all components (model serving, RAG, evaluation harness)
- **Pinned versions:** model weights (commit hash), vLLM/SGLang version, ChromaDB version, dataset version
- **Deterministic inference:** temp=0.0 for all benchmark runs, fixed random seed (42)
- **Hardware profiling:** GPU utilization, VRAM usage, and system RAM logged per experiment
- **Dataset versioning:** SHA-256 checksums for all evaluation datasets
- **Config-as-code:** Every experiment configuration is a versioned YAML file

```bash
# Reproduce any experiment
python src/evaluation/run_benchmark.py \
  --config configs/eval_config_C.yaml \
  --seed 42 \
  --deterministic
```

---

## 7. Risks and Mitigations

| Risk | Likelihood | Impact | Mitigation |
|------|-----------|--------|------------|
| K2.5 too slow on available hardware | Medium | High | Use API for development, Qwen 72B as local fallback. Benchmark on cloud, optimize locally. |
| Swarm mode unstable on self-hosted | High | Medium | OpenClaw orchestration as primary. Swarm comparison is a paper contribution regardless of outcome. |
| Evaluation dataset too small | Low | High | Supplement with synthetic ATT&CK scenarios. Seek anonymized production data from lab. |
| OpenClaw breaking changes | Medium | Medium | Pin specific version. Maintain fork if needed. |
| GPU access limited/delayed | Medium | High | Start with API + Qwen 72B. Request lab GPU allocation early. Cloud GPU as temporary fallback. |
| Prompt injection via SIEM alerts | Low | High | Input sanitization layer. Confidence thresholds. Human review for critical decisions. |

---

## 8. Publication Strategy

| Target | Deadline | Type | Feasibility |
|--------|----------|------|-------------|
| USENIX Security 2027 | ~Nov 2026 | Top venue (main track) | ✅ Best fit — full results available |
| ACM CCS 2026 Workshop (AISec) | ~Aug 2026 | Workshop paper | ✅ Feasible with Phase 2 results |
| IEEE CNS 2026 | May 11, 2026 | Conference | ⚠️ Tight — Phase 1 only |
| ACSAC 2026 | ~Jun 2026 | Conference | ⚠️ Tight but possible |

**Recommended strategy:** Submit workshop paper to AISec@CCS 2026 with Phase 2 results, then expand to USENIX Security 2027 full paper with Phase 3 optimization + scenario testing.

---

## 9. Deliverables Summary

| Deliverable | Format | Target Date |
|-------------|--------|-------------|
| Working pipeline (single-agent) | Docker + source | April 30 |
| Evaluation dataset (1,400+ alerts) | JSON + CSV + labels | April 30 |
| RAG knowledge base | ChromaDB export | April 30 |
| Benchmark results (all configs) | Report + raw data | June 30 |
| Optimized prototype (multi-agent) | Docker + source | July 31 |
| Research paper draft | LaTeX + PDF | August 15 |
| Open-source release package | GitHub repository | August 31 |
| Lab presentation | Slides + demo | August 31 |

---

## 10. Related Work

| Paper | Year | Relevance | Gap Hades Fills |
|-------|------|-----------|-------------------|
| CORTEX: Collaborative LLM Agents for High-Stakes Alert Triage (Wei et al.) | 2025 | Multi-agent LLM alert triage | Cloud-only; no offline/air-gapped; no MoE |
| AI-Augmented SOC: Survey of LLMs and Agents (MDPI) | 2025 | Comprehensive survey | Survey only; no implementation |
| TechniqueRAG: RAG for MITRE ATT&CK Annotation | 2025 | RAG + ATT&CK | Single-task (annotation); no triage pipeline |
| Automated Alert Classification and Triage (Turcotte et al.) | 2025 | Classic AACT system | Traditional ML; no LLM reasoning |
| RAG for Robust Cyber Threat Intelligence (PNNL) | 2025 | RAG + CTI | No agent architecture; no triage |

**Hades contribution:** First open-source system combining (1) offline/air-gapped deployment, (2) open-weight MoE model, (3) multi-agent pipeline with dual orchestration comparison, (4) comprehensive benchmark across local vs cloud configurations.
