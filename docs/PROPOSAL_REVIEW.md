# Proposal Review: Hades v0.2

Reviewed on March 12, 2026 against two standards at once:

1. research rigor
2. implementation feasibility

## Findings

### P0: The proposal described an already-validated architecture when the repo is still a scaffold

`README.md`, `docs/TECHNICAL_SPEC.md`, and `docs/ARCHITECTURE.md` described a working pipeline, but the repository only contained schemas, configs, and a stub `src/main.py`. Referenced runtime artifacts such as data-prep scripts, benchmark runners, tests, and ingestion services were absent. This made the proposal overstate maturity and weakened both the research and engineering story.

### P0: The air-gapped claim conflicted with the operator interface and development flow

The original design mixed "zero external dependencies" with a Telegram bot and cloud baseline workflows in the core architecture. That is a direct contradiction for a first-version offline system. The revision removes internet-dependent operator interfaces from v1 and separates development convenience from the actual offline target.

### P1: The audit design relied on storing raw reasoning chains

The original spec treated a "full reasoning chain" as a compliance artifact. That is a poor interface because it is unstable across providers, easy to overfit to, and unsafe to make part of an audit contract. The revision replaces it with a structured evidence trace, tool-call log, rationale summary, and override record.

### P1: The evaluation design treated raw datasets as if they were ready-made SOC alerts

CICIDS, CIC-IDS2018, and BETH are not directly equivalent to analyst-facing alert objects. Without a transformation layer, the benchmark would be underspecified and hard to reproduce. The revised spec makes dataset transformation a first-class, versioned stage.

### P1: The statistical plan used the wrong agreement and comparison framing

The original plan proposed `Cohen's kappa` with three reviewers and a broad use of `McNemar's test` for a multiclass triage task. That is not the right default framing. The revision moves to a multi-rater agreement metric and limits McNemar to binary sub-analyses, using paired bootstrap and multiclass paired tests for the main comparisons.

### P1: The schedule was not credible for one engineer by August 2026

The original plan combined multi-agent orchestration, live SIEM connectors, local Kimi deployment, broad cloud baselines, human review, paper submission, and open-source release in one cycle. That scope would produce either weak evidence or incomplete software. The revision narrows v1 to a deterministic file-replay prototype with a smaller benchmark footprint.

### P2: The original storage choice was weakly aligned with the local hybrid-search requirement

Chroma's newer Search API and documented hybrid search flow are currently described as Chroma Cloud features, with local support noted as future work. Qdrant, by contrast, documents local deployment, local client mode, and dense, sparse, and hybrid retrieval. The revised v1 therefore switches the local retrieval plan to Qdrant.

Sources:

- Chroma Search API overview: [https://docs.trychroma.com/cloud/search-api/overview](https://docs.trychroma.com/cloud/search-api/overview)
- Qdrant quickstart: [https://qdrant.tech/documentation/quick-start/](https://qdrant.tech/documentation/quick-start/)
- Qdrant hybrid retrieval docs: [https://qdrant.tech/documentation/frameworks/langchain/](https://qdrant.tech/documentation/frameworks/langchain/)

### P2: Kimi deployment was treated as easier and more deterministic than the primary docs support

Moonshot's own documentation recommends specific engines, notes ongoing changes, and currently points to nightly builds for some Kimi-specific features. That does not make Kimi a bad choice, but it does make it a gated deployment target rather than a safe assumption for the whole project plan.

Sources:

- Moonshot model card: [https://huggingface.co/moonshotai/Kimi-K2.5](https://huggingface.co/moonshotai/Kimi-K2.5)
- Moonshot deployment guide: [https://huggingface.co/moonshotai/Kimi-K2.5/blob/main/docs/deploy_guidance.md](https://huggingface.co/moonshotai/Kimi-K2.5/blob/main/docs/deploy_guidance.md)

### P2: OpenClaw was positioned as a core architectural requirement without enough justification

The repo contained tool-definition placeholders, but there was not yet evidence that OpenClaw should be the central orchestration dependency for the first benchmarkable prototype. The revision keeps `src/openclaw/` as an optional adapter namespace and removes it from the critical path.

## Revision Outcome

The revised proposal now does five things the old one did not:

- matches the current repo maturity
- removes air-gap contradictions
- uses stable audit artifacts
- defines a benchmark transformation and contamination policy
- scopes v1 to something buildable by August 2026
