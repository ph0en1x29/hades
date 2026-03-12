# Hades — Offline SOC Triage Research Prototype

Hades is a scoped research prototype for offline SOC alert triage. The repository currently contains the proposal, public schemas, and baseline configuration needed to build the system, but it does not yet contain an end-to-end production implementation.

## Status

- Reviewed and reframed on March 12, 2026.
- Current repository state: initial scaffold, not a validated system.
- Primary proposal artifact: `docs/TECHNICAL_SPEC.md`
- Findings-first review artifact: `docs/PROPOSAL_REVIEW.md`

## v1 Scope

- File replay input using one normalized alert schema
- Deterministic triage pipeline instead of agent swarm
- Local CLI and/or FastAPI dashboard for analyst review
- Structured evidence trace for auditability
- Local hybrid retrieval using Qdrant
- One high-capacity local model candidate and one smaller local baseline

## Explicit Non-Goals for v1

- Telegram or other internet-dependent analyst interfaces
- Native swarm orchestration as a required path
- Multi-SIEM live connectors
- Automated SOAR/ticketing actions
- Large cloud-model comparison matrix

## Why The Scope Changed

The original proposal mixed an ambitious research agenda with claims the repo could not yet support. This revision narrows the project to something one engineer can plausibly build and evaluate by August 2026, while keeping a clean path to later research extensions.

Two stack decisions are intentionally conservative:

- `Kimi K2.5` remains a candidate core model, but Moonshot's own deployment guidance recommends specific inference engines and currently points users to nightly builds for some features. Hades therefore treats Kimi as a gated deployment target, not a guaranteed day-one runtime.
- `Qdrant` replaces `Chroma` for the local RAG plan because Qdrant documents local mode plus dense, sparse, and hybrid retrieval, while Chroma's newer hybrid Search API is currently documented as Chroma Cloud-only.

## Source-Backed Feasibility Notes

- Moonshot model card: [moonshotai/Kimi-K2.5](https://huggingface.co/moonshotai/Kimi-K2.5)
- Moonshot deployment guide: [Kimi-K2.5 deployment guide](https://huggingface.co/moonshotai/Kimi-K2.5/blob/main/docs/deploy_guidance.md)
- vLLM OpenAI-compatible serving: [vLLM docs](https://docs.vllm.ai/en/latest/serving/openai_compatible_server/)
- Qdrant local quickstart: [Qdrant quickstart](https://qdrant.tech/documentation/quick-start/)
- Qdrant hybrid retrieval and local mode: [Qdrant LangChain integration docs](https://qdrant.tech/documentation/frameworks/langchain/)
- Chroma hybrid search availability: [Chroma Search API overview](https://docs.trychroma.com/cloud/search-api/overview)

## Repository Layout

```text
hades/
├── configs/    # Prototype configs and optional tool contracts
├── docs/       # Revised technical spec and review
├── src/        # Public schemas and entrypoint scaffold
└── docker-compose.yml
```

## Quick Start

```bash
python -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
python src/main.py --config configs/default.yaml
```

`src/main.py` is still a scaffold entrypoint. The revised docs define what the implementation should build next.
