# 4. Hades System Architecture

Hades is a modular evaluation framework for measuring the adversarial robustness of LLM-based SOC triage systems. It implements a deterministic, file-replay pipeline that processes benchmark alerts through configurable triage agents and defense mechanisms.

## 4.1 Design Principles

**P1: Reproducibility over realism.** We sacrifice the complexity of live SIEM integration for deterministic, reproducible experiments. All data enters through file replay; all model calls use temperature=0; all results are hash-verified.

**P2: Dataset gate enforcement.** Every alert that enters the evaluation pipeline must pass a programmatic benchmark contract check. Alerts missing rule associations, MITRE mappings, provenance chains, or scenario identifiers are rejected before reaching the model.

**P3: Separation of concerns.** The ingestion layer (parsers), adversarial layer (injector, payloads, defenses), evaluation layer (pipeline, metrics), and model layer (vLLM) are independently testable components with clean interfaces.

**P4: Defense-agnostic injection.** Adversarial variants are generated at the data layer, before defense mechanisms are applied. This ensures that the same adversarial dataset can be evaluated against multiple defense configurations without regeneration.

## 4.2 Pipeline Architecture

```
┌──────────────┐     ┌──────────────┐     ┌──────────────┐
│   Data       │     │  Adversarial │     │   Defense    │
│  Ingestion   │────▶│   Injector   │────▶│    Layer     │
└──────────────┘     └──────────────┘     └──────────────┘
       │                     │                    │
  ┌────┴────┐          ┌────┴────┐          ┌────┴────┐
  │ Sysmon  │          │ Vector  │          │ Sanitize│
  │ Parser  │          │ Selector│          │ Struct  │
  ├─────────┤          ├─────────┤          │ Canary  │
  │Suricata │          │ Payload │          │ Dual-LLM│
  │ Parser  │          │ Encoder │          └────┬────┘
  ├─────────┤          ├─────────┤               │
  │CIC-IDS  │          │ Field   │               ▼
  │ Parser  │          │Injector │     ┌──────────────┐
  └────┬────┘          └─────────┘     │   Triage     │
       │                               │   Agent      │
       ▼                               │  (vLLM)      │
  ┌──────────┐                         └──────┬───────┘
  │ Dataset  │                                │
  │  Gate    │                                ▼
  └──────────┘                         ┌──────────────┐
                                       │  Evaluation  │
                                       │   Metrics    │
                                       │  (ASR, F1)   │
                                       └──────────────┘
```

## 4.3 Data Ingestion Layer

### 4.3.1 Unified Alert Schema

All parsers emit `UnifiedAlert` objects with a fixed schema:

| Field Group | Fields | Purpose |
|---|---|---|
| Identity | `alert_id`, `timestamp` | Unique identification |
| Network | `src_ip`, `dst_ip`, `src_port`, `dst_port`, `protocol` | Network context |
| Classification | `severity`, `signature`, `event_type` | Alert metadata |
| Raw Data | `raw_log` | Full original event (JSON string) |
| Provenance | `dataset_name`, `dataset_role`, `parser_version`, `label_provenance` | Reproducibility |
| Benchmark | `scenario_id`, `rule_id`, `rule_source`, `mitre_techniques` | Scientific validity |

### 4.3.2 Implemented Parsers

**Sysmon XML Parser** (`splunk_sysmon.py`). Parses Windows Sysmon event logs from Splunk Attack Data. Handles concatenated `<Event>` XML elements with no root wrapper. Maps Sysmon EventIDs (1=Process Creation, 3=Network Connection, 10=Process Access, etc.) to alert severity levels and human-readable descriptions. Extracts source/destination IPs from network connection events.

**Suricata JSON Parser** (`splunk_suricata.py`). Parses Suricata eve.json-format logs. Handles HTTP, DNS, TLS, alert, and fileinfo event types. Extracts HTTP User-Agent strings (our primary injection vector), request/response headers, and full network context.

**CIC-IDS2018 CSV Parser** (`cicids2018.py`). Parses CICFlowMeter network flow features. Used as an engineering scaffold for pipeline development; not part of the benchmark of record due to missing rule associations.

### 4.3.3 Dataset Gate

The dataset gate (`dataset_gate.py`) enforces benchmark quality:

```python
def benchmark_contract_issues(alert: UnifiedAlert) -> list[str]:
    """Returns empty list if alert passes all benchmark requirements."""
    issues = []
    if not alert.provenance.label_provenance:
        issues.append("missing label provenance")
    if not alert.benchmark.scenario_id:
        issues.append("missing scenario identifier")
    if not alert.benchmark.mitre_techniques:
        issues.append("missing MITRE mapping")
    if not alert.benchmark.rule_id:
        issues.append("missing rule association")
    return issues
```

Alerts with any issues are rejected before entering the evaluation pipeline.

## 4.4 Adversarial Layer

### 4.4.1 Injection Vectors

The vector catalog (`vectors.py`) defines 12 SIEM log fields exploitable for injection, each with validated payload length constraints, SIEM normalization survival estimates, and realism ratings. Four vectors are validated against production SIEM systems [Neaves2025].

### 4.4.2 Payload Templates

The payload library (`payloads.py`) contains 15 templates across 5 attack classes, with 4 encoding strategies:

- **Plaintext:** Direct English instructions
- **Underscore:** Space-to-underscore substitution (demonstrated in [Neaves2025])
- **URL-encoded:** Percent-encoding for HTTP fields
- **Base64 fragment:** Partial base64 wrapping

### 4.4.3 Injector

The injector (`injector.py`) takes a clean alert and produces adversarial variants by:
1. Selecting a target vector (log field)
2. Choosing a payload template matching the desired attack class
3. Encoding the payload per the selected strategy
4. Truncating to respect field length constraints
5. Injecting into the appropriate field of the alert's raw_log

The injector is format-aware: it handles Sysmon XML EventData fields differently from Suricata JSON HTTP fields, ensuring payloads land in the correct location.

### 4.4.4 Defense Implementations

Three defense mechanisms are implemented:
- **SanitizationDefense:** Regex-based removal of instruction-like patterns
- **StructuredPromptDefense:** Recursive field wrapping with `[FIELD:path]` markers
- **CanaryDefense:** Injects known canary strings into alert metadata

## 4.5 Evaluation Layer

### 4.5.1 Triage Pipeline

The triage pipeline (`pipeline.py`) processes alerts through:
1. Optional defense preprocessing
2. Prompt construction from alert fields
3. LLM inference via vLLM
4. Response parsing into structured `TriageDecision` objects
5. Evidence trace construction for audit

### 4.5.2 Benchmark Builder

The benchmark builder (`build_benchmark_pack.py`) constructs validated alert sets:
- Loads raw data from multiple Splunk Attack Data technique directories
- Applies the appropriate parser per source format
- Validates all alerts against the dataset gate
- Produces JSONL output with manifest for reproducibility

Current benchmark: 2,619 alerts across 8 techniques, 6 tactics, 0 contract failures.

## 4.6 Model Serving

Models are served via vLLM with the following configuration:
- INT4 quantization for all models (native for Kimi K2.5, GPTQ for others)
- Tensor parallelism scaled to available GPUs
- Temperature=0 for deterministic inference
- Max output tokens=1024 per triage decision

## 4.7 Deployment

The system is containerized via Docker Compose:
- `vllm-server`: Model serving with configurable model path
- `qdrant`: Vector database for RAG retrieval
- `hades`: Pipeline orchestration and evaluation
- `evaluator`: Metrics computation and statistical analysis
