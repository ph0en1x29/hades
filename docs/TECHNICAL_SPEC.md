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

## 2. System Boundaries

### 2.1 In Scope for v1

- Replay alerts from local JSON or JSONL fixtures
- Normalize inputs into `UnifiedAlert`
- Run one deterministic triage path
- Optionally retrieve threat-intel context from a local RAG store
- Produce `TriageDecision` with structured evidence trace
- Expose results through CLI output and/or a local FastAPI dashboard
- Evaluate on a locked test set derived from transformed benchmark fixtures

### 2.2 Explicitly Out of Scope for v1

- Telegram bots or any internet-dependent operator workflow
- Live Splunk, Elastic, QRadar, syslog, Kafka, or Redis ingestion
- Native swarm orchestration as a required feature
- Automated SOAR actions
- A large cloud-vs-local comparison matrix
- Claims of real-time production throughput

## 3. Repo Reality Check

The repository currently contains schemas, configs, documentation, runtime scaffolding, local retrieval abstractions, packaging metadata, and basic tests. It still does not contain the end-to-end ingestion loop, benchmark runner, transformed benchmark fixtures, or analyst workflow described in the proposal. The spec must therefore track planned artifacts, not present the system as already validated.

## 4. Architecture Decisions

| Area | v1 Decision | Deferred |
|---|---|---|
| Input | file replay only | live SIEM connectors |
| Orchestration | deterministic single path | swarm and multi-agent graphs |
| Interface | local CLI and/or local web UI | Telegram and external chat tools |
| Retrieval | local Qdrant hybrid retrieval | distributed retrieval stack |
| Audit | evidence trace + rationale summary | raw chain-of-thought retention |
| Evaluation | locked benchmark with transformation pipeline | broad cloud baseline study |

## 5. Component Specification

### 5.1 Alert Ingestion and Normalization

The v1 ingestion path consumes replay fixtures from disk. Each raw record is transformed into `UnifiedAlert` and retains provenance fields that identify:

- source dataset or replay source
- original file path
- original record index or event id
- parser version
- transformation version

Normalization is allowed to leave some network fields empty when the source dataset does not contain them. Missing values must remain explicit rather than fabricated.

### 5.2 Triage Runtime

The v1 runtime is a deterministic pipeline:

1. load normalized alert
2. build prompt from alert fields and policy text
3. retrieve optional threat-intel context
4. invoke one reasoning model
5. apply thresholds for `needs_investigation` or human review
6. emit structured decision output

`src/openclaw/` remains a possible adapter layer for later tool-based orchestration, but the v1 design does not require OpenClaw. If it is used at all in v1, it must be treated as an implementation detail behind the deterministic pipeline rather than the central research contribution.

### 5.3 Model Strategy

Hades keeps `Kimi K2.5` as a candidate high-capacity local model, but it is no longer assumed to be frictionless for development or evaluation.

Source-backed constraints:

- Moonshot's official model card recommends `vLLM`, `SGLang`, or `KTransformers` for deployment and documents a 256k context window plus different parameter settings for thinking and instant modes.
- Moonshot's deployment guide explicitly says its commands are examples only, says inference engines are still changing, and currently points users to nightly builds for some Kimi-specific parsing features.

Implication for v1:

- Hades must remain model-agnostic at the interface level.
- The initial benchmark path must be able to run on one practical local baseline model.
- Kimi K2.5 local deployment is a gated evaluation target that becomes mandatory only after deployment is validated on available hardware.

### 5.4 Retrieval Strategy

The original proposal named ChromaDB with hybrid retrieval, but the current documented hybrid Search API in Chroma is Chroma Cloud-only, with local support described as future work. The revised v1 uses Qdrant because Qdrant documents:

- local deployment
- local client mode
- dense retrieval
- sparse retrieval
- hybrid retrieval with score fusion

v1 RAG choices:

- store: Qdrant
- dense embedding: pinned FastEmbed-compatible open embedding model such as `BAAI/bge-small-en-v1.5`
- sparse retrieval: BM25-compatible sparse model
- knowledge sources: MITRE ATT&CK plus a curated CVE subset
- retrieval goal: evidence augmentation, not autonomous action selection

### 5.5 Output and Audit Layer

The audit record must not require storing raw chain-of-thought. The stable artifact is `TriageDecision`, which includes:

- final label
- confidence
- evidence trace
- tool invocations, if any
- short analyst-visible rationale summary
- override record

This is the artifact used for review, debugging, and evaluation.

## 6. Public Interfaces

### 6.1 `UnifiedAlert`

Defined in `src/ingestion/schema.py`.

Required behavior:

- stable alert id
- normalized severity
- optional network and signature fields
- metadata block for vendor-specific detail
- provenance block for dataset path, parser version, and raw-record linkage

### 6.2 `TriageDecision`

Defined in `src/evaluation/schemas.py`.

Required behavior:

- model-agnostic classification output
- structured evidence trace
- optional tool call log
- rationale summary safe for analyst review
- explicit override record

### 6.3 Evaluation Config

Defined by `configs/eval_config_A.yaml`.

Required sections:

- dataset transformation stage
- split policy
- contamination controls
- annotator protocol
- statistical analysis plan

## 7. Evaluation Design

### 7.1 Benchmark Inputs

Raw datasets such as CICIDS, CIC-IDS2018, and BETH are not directly usable as SOC alert fixtures. Hades therefore adds a transformation stage that produces normalized alert records and records the transformation version.

Each benchmark item must preserve:

- original dataset name
- scenario or attack family
- source record ids or row range
- label provenance

### 7.2 Split Policy

The benchmark uses a locked test set. Prompt or threshold tuning is allowed only on a development split. Scenario-aware grouping is required so that near-duplicate samples do not leak across splits.

### 7.3 Contamination Controls

- RAG corpora may contain public ATT&CK or CVE knowledge.
- RAG corpora must not contain benchmark labels, benchmark rationales, or transformed benchmark records.
- Development notes used during prompt tuning must be kept separate from the locked test set.

### 7.4 Metrics

Primary metric:

- macro F1 on the locked test set

Secondary metrics:

- per-class precision and recall
- benign false-positive rate on explicitly benign subsets
- missed-detection rate on explicitly malicious subsets
- abstain or escalate rate
- latency p50 and p95

### 7.5 Human Review

If human review is included, use three reviewers and measure agreement with a multi-rater metric such as Fleiss' kappa. Do not describe the procedure as Cohen's kappa when there are three raters.

### 7.6 Statistical Analysis

Use:

- paired bootstrap confidence intervals for macro metrics
- Bowker or Stuart-Maxwell style tests when comparing paired multiclass predictions
- McNemar only for clearly defined binary sub-analyses, such as false-positive vs not-false-positive

## 8. Delivery Plan for August 2026

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

## 9. Risks and Mitigations

| Risk | Impact | Mitigation |
|---|---|---|
| Kimi local deployment is unstable or too expensive | High | keep runtime interface model-agnostic and maintain one smaller local baseline |
| Benchmark transformation introduces label ambiguity | High | version transformation rules and preserve raw provenance |
| Retrieval contaminates evaluation | High | isolate RAG corpora from benchmark labels and benchmark-derived text |
| Proposal expands back into an unbuildable scope | High | treat all non-v1 features as explicitly deferred |
| Optional OpenClaw integration becomes a time sink | Medium | do not make it part of the critical path |

## 10. Source Notes

Feasibility-sensitive claims in this spec are grounded in primary documentation:

- Moonshot model card: [https://huggingface.co/moonshotai/Kimi-K2.5](https://huggingface.co/moonshotai/Kimi-K2.5)
- Moonshot deployment guide: [https://huggingface.co/moonshotai/Kimi-K2.5/blob/main/docs/deploy_guidance.md](https://huggingface.co/moonshotai/Kimi-K2.5/blob/main/docs/deploy_guidance.md)
- vLLM OpenAI-compatible server docs: [https://docs.vllm.ai/en/latest/serving/openai_compatible_server/](https://docs.vllm.ai/en/latest/serving/openai_compatible_server/)
- Qdrant quickstart: [https://qdrant.tech/documentation/quick-start/](https://qdrant.tech/documentation/quick-start/)
- Qdrant local and hybrid retrieval docs: [https://qdrant.tech/documentation/frameworks/langchain/](https://qdrant.tech/documentation/frameworks/langchain/)
- Chroma Search API availability: [https://docs.trychroma.com/cloud/search-api/overview](https://docs.trychroma.com/cloud/search-api/overview)
