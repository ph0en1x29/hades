# 4. Hades System Architecture

Hades is a modular evaluation framework for measuring the adversarial robustness of LLM-based SOC triage systems. It implements a near-deterministic, file-replay pipeline that processes benchmark alerts through configurable triage agents and defense mechanisms.

## 4.1 Design Principles

**P1: Reproducibility over realism.** We sacrifice the complexity of live SIEM integration for near-deterministic, reproducible experiments. All data enters through file replay; all model calls use temperature=0; all results are hash-verified.

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

**Evaluation-only metadata.** The unified alert schema includes benchmark provenance fields (`scenario_id`, `source_dataset`, `mitre_techniques`, `rule_id`) used exclusively for evaluation scoring and ground-truth comparison. These fields are NOT included in the prompt sent to the triage model. The model receives only the alert content fields (timestamp, source/destination IPs, log message, severity, parsed fields). This separation prevents information leakage from benchmark metadata into model inference.

### 4.3.2 Implemented Parsers

**Sysmon XML Parser** (`splunk_sysmon.py`). Parses Windows Sysmon event logs from Splunk Attack Data. Handles concatenated `<Event>` XML elements with no root wrapper. Maps Sysmon EventIDs (1=Process Creation, 3=Network Connection, 10=Process Access, etc.) to alert severity levels and human-readable descriptions. Extracts source/destination IPs from network connection events.

**Suricata JSON Parser** (`splunk_suricata.py`). Parses Suricata eve.json-format logs. Handles HTTP, DNS, TLS, alert, and fileinfo event types. Extracts HTTP User-Agent strings (our primary injection vector), request/response headers, and full network context.

**Windows Security XML Parser** (`windows_security.py`). Parses Windows Security Event Logs in XML format. Handles authentication events (EventID 4624/4625), account management (4720/4726), and privilege escalation (4672). Extracts TargetUserName, TargetDomainName, and LogonType fields for authentication-based attack scenarios.

**PowerShell Logging Parser** (integrated in `splunk_sysmon.py`). Parses Windows PowerShell event logs (EventID 4103/4104) from Splunk Attack Data. Extracts ScriptBlock content, HostApplication, and command-line arguments for detection of malicious PowerShell execution (T1059.001).

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

The payload library (`payloads.py`) contains 15 templates across 5 attack classes, with 2 base encoding strategies (plaintext, underscore) used for end-to-end evaluation, plus 9 extended strategies for normalization survival testing:

- **Base encodings (end-to-end E2/E4-E8):**
  - **Plaintext:** Direct English instructions
  - **Underscore:** Space-to-underscore substitution (demonstrated in [Neaves2025])

- **Extended encodings (E3 normalization tests):**
  - **URL-encoded:** Percent-encoding for HTTP fields
  - **Base64 fragment:** Partial base64 wrapping
  - **Markdown comment:** Injection wrapped in HTML comment syntax
  - **Synonym substitution:** Rephrasing to evade keyword detection
  - **Homoglyph (Cyrillic):** Visually similar Unicode characters
  - **Zero-width characters:** Invisible Unicode insertion
  - **Leetspeak:** Character substitution (e.g., "3" for "E")
  - **DNS constrained:** 253-byte payload limit
  - **TLS CN constrained:** 64-character payload limit

### 4.4.3 Injector

The injector (`injector.py`) takes a clean alert and produces adversarial variants by:
1. Selecting a target vector (log field)
2. Choosing a payload template matching the desired attack class
3. Encoding the payload per the selected strategy
4. Truncating to respect field length constraints
5. Injecting into the appropriate field of the alert's raw_log

The injector is format-aware: it handles Sysmon XML EventData fields differently from Suricata JSON HTTP fields, ensuring payloads land in the correct location.

### 4.4.4 Defense Implementations

Three defense mechanisms are currently implemented:
- **SanitizationDefense:** Regex-based removal of instruction-like patterns
- **StructuredPromptDefense:** Recursive field wrapping with `[FIELD:path]` markers
- **CanaryDefense:** Injects known canary strings into alert content fields presented to the model (distinct from evaluation-only benchmark metadata)

A fourth defense (**Dual-LLM Verification**, D3) is designed but not yet implemented. E6 results are therefore deferred beyond the initial GPU campaign. The dual-model verification defense will use a second LLM to independently triage alerts, flagging disagreements for human review.

## 4.5 Multi-Agent Pipeline

### 4.5.1 Triage Pipeline

The triage pipeline (`pipeline.py`) processes alerts through:
1. Optional defense preprocessing
2. Prompt construction from alert fields
3. LLM inference via vLLM (ClassifierAgent)
4. Response parsing into structured `TriageDecision` objects
5. **Behavioral invariant checking** — auto-escalates if injection suspected
6. Evidence trace and override record construction for audit

### 4.5.2 Correlator Agent

The correlator (`correlator.py`) detects multi-stage attack campaigns by running four parallel strategies against an in-memory alert store:

1. **IP clustering** — groups alerts sharing source/destination IPs within a configurable time window (default ±15 min)
2. **Technique chain detection** — maps observed MITRE techniques to tactics, then matches against 5 known attack patterns (ransomware, data exfiltration, credential theft, lateral movement, persistence establishment). A pattern is flagged when ≥40% of its expected tactic sequence is observed.
3. **Session reconstruction** — groups alerts by `src_ip→dst_ip` pairs to identify persistent attacker sessions
4. **Temporal burst detection** — detects spikes of ≥5 alerts from a single source within the time window

**Technique source.** In the evaluation pipeline, the correlator receives MITRE technique labels from the triage model's structured output (the `TriageDecision.mitre_techniques` field), not from benchmark ground-truth metadata. This means correlator accuracy depends on triage model accuracy — if adversarial injection causes the triage model to misidentify techniques, campaign detection degrades accordingly. The benchmark metadata is used only for scoring the correlator's output against ground truth.

Campaign assessment combines all strategies: a campaign is declared when any attack chain is detected, any temporal burst occurs, or ≥10 correlated events are found. All benchmark alerts preserve their original timestamps from the Splunk Attack Data repository, enabling realistic temporal correlation during file-replay evaluation.

### 4.5.3 Playbook Agent

The playbook generator (`playbook.py`) produces NIST SP 800-61 incident response playbooks using a technique-specific knowledge base covering 7 MITRE techniques plus a generic fallback. Each KB entry defines:
- **Containment** actions with priority and automation flags
- **Eradication** steps with evidence collection guidance
- **Recovery** procedures including credential rotation and re-imaging
- **Post-incident** documentation and detection rule updates

Severity is dynamically escalated when attack chains are detected: a medium-severity discovery alert becomes critical when it's part of a credential theft chain.

### 4.5.4 Behavioral Invariant Defense

The invariant layer (`behavioral_invariants.py`) functions as a **runtime assurance monitor** — analogous to runtime verification in safety-critical systems — that checks model outputs against externally verifiable safety properties. Crucially, it operates on triage **outputs**, not **inputs**. Because input-level defenses like sanitization and structured prompts are consistently bypassed by adaptive attackers (Nasr et al., 2025), output-level checking is potentially more robust in principle — though this comparative advantage remains to be validated against real model outputs in E8.

Six invariants are checked against every triage decision:
- **INV-1:** Severity downgrade without supporting evidence (critical/high)
- **INV-2:** Phantom IPs referenced in output but absent from source alert (critical)
- **INV-3:** Unrealistically high confidence (>0.95) on benign classifications (high)
- **INV-4:** Fabricated references (pentest claims, change requests) not in source (medium)
- **INV-5:** Temporal downplay patterns ("all services nominal") (medium)
- **INV-6:** Confidence-severity alignment (HIGH alert + low confidence = manipulation) (high)

When injection is suspected (weighted score ≥3), the pipeline auto-escalates the classification from the model's output to `ESCALATE` and records an `OverrideRecord` in the audit trail with the previous classification, the intervening actor (`system:behavioral_invariants`), and the triggering violations.

**Completeness bound.** The six invariants are not exhaustive — they target observable symptoms of the five defined attack classes. An attacker who achieves their objective without violating any invariant (e.g., a C2 attack that adjusts confidence by exactly the amount that stays below INV-3/INV-6 thresholds) would evade detection. This honest limitation motivates the layered defense strategy: invariants catch the majority of attacks, while dual-LLM verification (D3) and human review provide backstops for subtle evasion.

**Planned campaign-level invariants.** C5 (Escalation Suppression) targets the correlation stage and is not addressed by per-alert invariants. Three campaign-level invariants are planned for Phase 2: (1) **chain incompleteness** — flagging temporal technique clusters that fail to produce expected campaign assessments; (2) **anomalous de-correlation** — detecting when alerts sharing infrastructure are suppressed from correlation; (3) **implausible tactic ordering** — identifying when the correlator's observed tactic sequence violates known attack progression patterns (e.g., exfiltration before initial access).

### 4.5.5 SOC-Bench Adapter

The SOC-Bench adapter (`socbench_adapter.py`) maps Hades `TriageDecision` outputs into the ring-scored Fox, Tiger, and Panda output formats defined by Cai et al. (2026). This enables direct evaluation against SOC-Bench ground truth when datasets become available.

### 4.5.6 Benchmark Builder

The benchmark builder (`build_benchmark_pack.py`) constructs validated alert sets:
- Loads raw data from multiple Splunk Attack Data technique directories
- Applies the appropriate parser per source format
- Validates all alerts against the dataset gate
- Produces JSONL output with manifest for reproducibility

Current benchmark: 12,147 alerts across 27 canonical ATT&CK techniques, 9 tactics, 0 contract failures.

## 4.6 Model Serving

Models are served via vLLM with the following configuration:
- INT4 quantization for all models (native for Kimi K2.5, GPTQ for others)
- Tensor parallelism scaled to available GPUs
- Temperature=0 for near-deterministic inference (see §5.7 for MoE caveats)
- Max output tokens=1024 per triage decision

## 4.7 Deployment

The system is containerized via Docker Compose:
- `vllm-server`: Model serving with configurable model path
- `qdrant`: Vector database for RAG retrieval
- `hades`: Pipeline orchestration and evaluation
- `evaluator`: Metrics computation and statistical analysis
