# Hades Architecture

## System Diagram

```
┌─────────────────────────────────────────────────────────────────────────┐
│                        INGESTION + ROUTING                              │
│  ┌──────────────────┐         ┌─────────────────────────┐              │
│  │  Data Ingestion   │────────▶│  OpenClaw Integration   │              │
│  │  ⚡ SIEM Parsers   │ Normalized│  🔧 Tool Registry      │              │
│  │  Splunk/ELK/QRadar│ Alerts   │  Context Manager       │              │
│  │  File Watcher     │         │  Session State (SQLite) │              │
│  └──────────────────┘         │  Rate Limiter           │              │
│                                └───────────┬─────────────┘              │
└────────────────────────────────────────────┼────────────────────────────┘
                                             │ Prompts + Context
                                             ▼
┌─────────────────────────────────────────────────────────────────────────┐
│                         REASONING ENGINE                                │
│                  ┌─────────────────────────┐                           │
│                  │    Kimi K2.5 Engine      │                           │
│                  │    🧠 1T MoE · 32B active │                           │
│                  │    256K context · INT4    │                           │
│                  │    Thinking / Instant /   │                           │
│                  │    Swarm modes            │                           │
│                  └──────┬──────┬──────┬─────┘                           │
└─────────────────────────┼──────┼──────┼─────────────────────────────────┘
                          │      │      │
             ┌────────────┘      │      └────────────┐
             ▼                   ▼                   ▼
┌─────────────────────────────────────────────────────────────────────────┐
│                          AGENT SWARM                                    │
│  ┌────────────────┐ ┌──────────────────┐ ┌────────────────────┐       │
│  │ Alert Classifier│ │  Log Correlator  │ │ Playbook Generator │       │
│  │ 🏷️ TP/FP/Inv/Esc│ │  🔗 ±15min window │ │ 📋 NIST 800-61     │       │
│  │ Confidence 0-1  │ │  IP grouping     │ │ IOC extraction     │       │
│  │ Few-shot chains │ │  Session recon   │ │ Escalation paths   │       │
│  └───────┬────────┘ └────────┬─────────┘ └──────────┬─────────┘       │
└──────────┼──────────────────┼───────────────────────┼──────────────────┘
           │                  │                       │
           ▼                  ▼                       ▼
┌─────────────────────────────────────────────────────────────────────────┐
│                     KNOWLEDGE + OUTPUT                                   │
│  ┌─────────────────────┐    ┌───────────────────────────┐              │
│  │  Local RAG Pipeline │    │  Output & Decision Layer  │              │
│  │  📚 ChromaDB         │    │  📊 Decision Aggregator    │              │
│  │  BGE-M3 embeddings  │    │  Confidence Thresholds    │              │
│  │  ATT&CK v15 + CVE   │    │  Audit Log (SQLite)      │              │
│  │  Hybrid search      │    │  SOAR hooks + Dashboard   │              │
│  └─────────────────────┘    └───────────────────────────┘              │
└─────────────────────────────────────────────────────────────────────────┘
           │
           ▼
┌─────────────────────────────────────────────────────────────────────────┐
│                         EVALUATION                                      │
│  ┌──────────────────────────────────────────────────────────────┐      │
│  │  📈 Benchmark Harness: Automated replay, confusion matrix,   │      │
│  │  McNemar's test, bootstrap CI, latency profiler, cost model  │      │
│  └──────────────────────────────────────────────────────────────┘      │
└─────────────────────────────────────────────────────────────────────────┘
```

## Data Flow

1. **Ingest:** Raw SIEM alerts (JSON/CEF/LEEF/syslog) → normalized unified schema
2. **Route:** OpenClaw receives normalized alert, constructs context-aware prompt
3. **Reason:** K2.5 analyzes alert, determines mode (instant/thinking/swarm)
4. **Classify:** Alert Classifier produces initial TP/FP/Investigation/Escalate decision
5. **Correlate:** If confidence < 0.7, Log Correlator pulls related events (±15min)
6. **Reclassify:** Classifier re-evaluates with enriched context
7. **Playbook:** Playbook Generator creates response plan using RAG + NIST framework
8. **Decide:** Output layer aggregates, applies thresholds, logs full audit trail
9. **Evaluate:** Benchmark harness compares against ground truth labels

## Orchestration Modes

### Mode A: OpenClaw-Orchestrated (Primary)
```
OpenClaw → Classifier → [low confidence?] → Correlator → Classifier (retry) → Playbook → Output
```
Deterministic, debuggable, no GPU overhead for coordination.

### Mode B: K2.5 Native Swarm (Experimental)
```
K2.5 Orchestrator → spawns N sub-agents in parallel → merges results → Output
```
Self-directed, potentially faster for complex incidents, but requires significant GPU resources.

## Deployment Topology

### Air-Gapped Production
```
[SIEM] ──syslog──▶ [Hades Server] ──webhook──▶ [SOAR/Ticketing]
                        │
                   ┌────┴────┐
                   │ GPU Node │ (K2.5 serving)
                   │ CPU Node │ (OpenClaw + RAG + ingestion)
                   └─────────┘
                   Local network only
```

### Development
```
[File-based alerts] ──▶ [Local dev env] ──▶ [Moonshot API / Qwen 72B]
                             │
                        [ChromaDB local]
```
