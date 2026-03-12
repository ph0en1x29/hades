# Hades — Offline Agentic SOC Assistant

> Rules tell you WHAT happened. Hades tells you WHY it matters and WHAT to do about it.

## The Problem

Enterprise SOCs generate 2,000-10,000 alerts daily. Detection (Splunk, Suricata, CrowdStrike) and response (SOAR playbooks, firewall scripts) are well-automated. **The triage decision in between is not.** A human analyst reads each alert, decides if it's real, how bad it is, and what to do. They handle 50-100 per day. The rest are ignored.

Cloud AI (GPT-4, Claude) can help — but organizations with air-gap requirements (government, defense, healthcare, critical infrastructure) **cannot send SIEM data to cloud APIs**. Alert data contains internal topology, hostnames, user identities, and active vulnerabilities.

**Hades fills the triage gap with a fully offline LLM pipeline.**

```text
Detection (existing SIEM/IDS/EDR) → alerts
    ↓
HADES (offline LLM triage) → structured decisions with evidence
    ↓
Response (existing SOAR/scripts) → actions
```

## What Makes This Different from Rules

| | Rules/Scripts | Hades |
|---|---|---|
| Known patterns | ✅ | ✅ |
| Novel/unseen attacks | ❌ needs new rule | ✅ reasons from threat knowledge |
| Correlate disparate alerts | ❌ only with pre-written rules | ✅ holds full context (256K tokens) |
| Explain reasoning | ❌ "Rule 4625 triggered" | ✅ natural language evidence trail |
| Handle ambiguity | ❌ binary match | ✅ probabilistic with confidence |

## Status

- Research prototype — initial scaffold, not a validated system
- Primary spec: `docs/TECHNICAL_SPEC.md`
- Design review: `docs/PROPOSAL_REVIEW.md`

## v1 Scope (Research Paper)

- File replay input → normalized alert schema
- Deterministic triage pipeline with optional RAG retrieval
- Local CLI and/or FastAPI dashboard for analyst review
- Structured evidence trace for auditability
- Local hybrid retrieval using Qdrant (MITRE ATT&CK + CVE)
- Authentication attack detection (brute force, Kerberoasting, Pass-the-Hash, credential abuse)
- Encrypted traffic analysis (JA3/JA4 fingerprinting, certificate anomalies, beaconing detection)
- Evaluation on 1,100+ alerts with statistical rigor (bootstrap CI, Fleiss kappa, McNemar)

## v2 Roadmap (Autonomous Response)

- Confidence-gated firewall rule creation
- Honeypot redirection for early-stage attacks
- Host isolation and account lockout
- SOAR integration for automated playbook execution
- Real-time SIEM connectors (Splunk, Elastic, QRadar)

## Explicit Non-Goals for v1

- Internet-dependent interfaces
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
├── src/        # Public schemas, runtime scaffolding, and retrieval layer
└── docker-compose.yml
```

## Quick Start

```bash
python -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
python src/main.py --config configs/default.yaml
```

`src/main.py` now initializes the scoped v1 scaffold, but ingestion, benchmark execution, and analyst-facing workflow are still incomplete.
