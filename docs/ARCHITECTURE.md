# Hades Architecture

## Current Position

Hades is not yet a full SOC platform. As of March 12, 2026, the repo should be read as a design scaffold for a scoped offline triage prototype.

## v1 Architecture

```text
┌───────────────────────┐
│ File Replay / JSONL   │
│ Benchmark Fixtures    │
└───────────┬───────────┘
            │
            ▼
┌───────────────────────┐
│ Alert Normalization   │
│ UnifiedAlert v1       │
│ Provenance preserved  │
└───────────┬───────────┘
            │
            ▼
┌──────────────────────────────────────┐
│ Deterministic Triage Pipeline        │
│ - prompt builder                     │
│ - optional retrieval step            │
│ - single reasoning path              │
│ - threshold-based human review       │
└───────────┬──────────────────────────┘
            │
            ├──────────────► Local RAG
            │                - Qdrant
            │                - dense + sparse retrieval
            │                - ATT&CK + selected CVE content
            │
            ▼
┌───────────────────────┐
│ Decision Output       │
│ TriageDecision v1     │
│ Evidence trace        │
│ Audit store + JSONL   │
└───────────┬───────────┘
            │
            ▼
┌───────────────────────┐
│ Analyst Interface     │
│ CLI and/or local UI   │
└───────────────────────┘
```

## v1 Decisions

- Input is file replay only.
- The first implementation path is deterministic, not swarm-based.
- `src/openclaw/` is treated as an optional adapter namespace, not a hard architectural dependency.
- Analyst interaction is local only; internet-dependent bots are out of scope for the offline prototype.
- Auditability uses structured evidence records, not stored raw chain-of-thought.

## Deferred Beyond v1

- Live Splunk, Elastic, or QRadar connectors
- Native Kimi swarm orchestration
- Automatic SOAR or ticket creation
- Cloud model baselines
- Multi-tenant dashboards
