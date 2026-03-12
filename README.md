# Hades — Offline Agentic SOC Assistant

An air-gapped, multi-agent Security Operations Center (SOC) assistant built on **Kimi K2.5** (open-source 1T MoE), **OpenClaw** (tool orchestration), and a **local RAG pipeline** (MITRE ATT&CK + CVE threat intelligence).

Hades processes SIEM alerts through a specialized agent pipeline to produce triage classifications, correlated event timelines, and incident response playbooks — all without external network dependencies.

## Architecture

```
┌──────────────┐   ┌──────────────────┐   ┌──────────────────┐
│ Data Ingest  │──▶│ OpenClaw Routing  │──▶│ Kimi K2.5 Engine │
│ (SIEM/Logs)  │   │ (Tools + Context) │   │ (Reasoning/Orch) │
└──────────────┘   └──────────────────┘   └────────┬─────────┘
                                                    │
                                    ┌───────────────┼───────────────┐
                                    ▼               ▼               ▼
                            ┌──────────┐   ┌──────────────┐  ┌──────────┐
                            │Classifier│   │Log Correlator│  │ Playbook │
                            │  Agent   │   │    Agent     │  │Generator │
                            └────┬─────┘   └──────┬───────┘  └────┬─────┘
                                 │                 │               │
                            ┌────▼─────────────────▼───────────────▼────┐
                            │        Local RAG (ATT&CK + CVE)          │
                            └──────────────────────────────────────────┘
                                                │
                            ┌───────────────────▼──────────────────────┐
                            │      Output & Decision Layer (Audit)     │
                            └──────────────────────────────────────────┘
```

## Key Features

- **Zero network dependency** after initial setup — fully air-gapped operation
- **Multi-agent pipeline** — classifier, correlator, playbook generator with parallel execution
- **Auditable decisions** — full reasoning chain + confidence scores for compliance
- **Modular** — swap models, SIEM connectors, or RAG sources independently
- **Evaluation-first** — benchmark harness built alongside the system

## Quick Start

```bash
# 1. Set up environment
python -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt

# 2. Download model weights (requires internet)
python scripts/download_model.py --model moonshotai/Kimi-K2.5 --quantization int4

# 3. Build RAG knowledge base
python scripts/build_rag.py --sources mitre,cve,custom

# 4. Start the pipeline
python src/main.py --config configs/default.yaml

# 5. Run evaluation
python src/evaluation/run_benchmark.py --config configs/eval_config_A.yaml
```

## Project Structure

```
hades/
├── configs/                 # YAML configs (model, pipeline, eval)
├── data/
│   ├── datasets/            # Evaluation datasets (CICIDS, BETH, synthetic)
│   ├── embeddings/          # Pre-built vector store
│   └── models/              # Local model weights
├── docs/                    # Technical spec, architecture, paper drafts
├── scripts/                 # Setup, download, build scripts
├── src/
│   ├── ingestion/           # SIEM connectors + normalization
│   ├── openclaw/            # OpenClaw integration + tool definitions
│   ├── agents/              # Classifier, correlator, playbook agents
│   ├── rag/                 # Vector store + embedding + retrieval
│   ├── evaluation/          # Benchmark harness + metrics
│   └── output/              # Decision aggregation + audit logging
├── tests/                   # Unit + integration tests
└── docker-compose.yml       # Full deployment stack
```

## Hardware Requirements

| Tier | Hardware | Performance | Use Case |
|------|----------|-------------|----------|
| Development | Moonshot API or Qwen 72B local | Variable | Prompt engineering, pipeline testing |
| Evaluation | 2× A100 80GB + 256GB RAM | ~15-20 tok/s | Full benchmark suite |
| Production | 4× H100 80GB + 512GB RAM | ~40+ tok/s | Real-time SOC deployment |
| Minimum (POC) | 1× RTX 4090 + 256GB RAM | ~1-2 tok/s (1.58-bit) | Air-gapped demo only |

## Research Context

- **Institution**: Penn State University, College of IST
- **Advisor**: Dr. Peng Liu (Cyber Security Lab)
- **Program**: BS Cybersecurity Analytics & Operations
- **Timeline**: March – August 2026
- **Paper target**: USENIX Security 2027 / ACM CCS 2026 Workshop

## License

MIT

## Citation

```bibtex
@misc{hades2026,
  title={Hades: An Offline Agentic SOC Assistant Using Open-Source MoE Models},
  author={Li, Jay},
  year={2026},
  institution={Penn State University}
}
```
