# Hades Data Guide

Everything about where data lives, how to feed new data in, and how results flow through the pipeline.

---

## 1. Directory Map

```
hades/
├── data/
│   ├── benchmark/                          # ✅ READY — Don't touch
│   │   ├── hades_benchmark_v1.jsonl        # 12,147 alerts (locked benchmark)
│   │   └── hades_benchmark_v1_manifest.json # 27 techniques, 9 tactics, 0 failures
│   │
│   ├── datasets/                           # Raw source data (pre-parsing)
│   │   ├── splunk_attack_data/             # Splunk ATT&CK data (already parsed → benchmark)
│   │   ├── beth/                           # BETH dataset (engineering scaffold)
│   │   ├── socbench/                       # ← PUT SOC-BENCH DATA HERE
│   │   │   ├── README.md                   # Format guide
│   │   │   ├── colonial_pipeline/          # DarkSide scenario alerts
│   │   │   ├── fox_ground_truth/           # Fox task expected outputs
│   │   │   └── raw/                        # Any raw exports from Liu
│   │   └── liu_provided/                   # ← ANY OTHER DATA FROM PROF LIU
│   │       ├── README.md                   # Format guide
│   │       └── (alerts go here)
│   │
│   ├── adversarial/                        # Generated during experiments
│   │   └── (auto-created by run_gpu_experiments.sh)
│   │
│   ├── embeddings/                         # RAG vector embeddings
│   ├── fixtures/                           # Test fixtures
│   ├── manifests/                          # Benchmark manifest YAML
│   ├── mitre_attack/                       # MITRE ATT&CK RAG documents (693 docs)
│   └── models/                             # Model weights (downloaded by vLLM)
│
├── results/
│   ├── gpu/                                # ← GPU EXPERIMENT RESULTS LAND HERE
│   │   ├── kimi/
│   │   │   ├── E1_baseline/run_{1,2,3}.json
│   │   │   ├── E2_stratified/run_{1,2,3}.json
│   │   │   ├── E4_sanitization/{moderate,strict}_run_{1,2,3}.json
│   │   │   ├── E5_structured_prompt/run_{1,2,3}.json
│   │   │   ├── E7_canary/run_{1,2,3}.json
│   │   │   ├── E8_adaptive/{black,gray,white}_box_run_{1,2,3}.json
│   │   │   └── analysis/statistical_report.json
│   │   ├── r1/           (same structure)
│   │   ├── qwen/         (same structure)
│   │   ├── glm/          (same structure)
│   │   └── tables/       # Cross-model comparison (Tables A-D for paper)
│   │
│   ├── decisions/                          # Per-alert triage decision logs
│   ├── (existing pre-GPU result files)     # E3 survival, invariant eval, etc.
│   └── ...
│
├── configs/
│   ├── eval_config_A.yaml                  # E1 baseline configuration
│   ├── eval_adversarial.yaml               # E2-E8 adversarial configuration
│   └── ...
│
├── scripts/
│   ├── setup.sh                            # One-command GPU machine setup
│   └── run_gpu_experiments.sh              # Automated experiment runner
│
└── src/
    ├── ingestion/
    │   ├── schema.py                       # UnifiedAlert schema
    │   └── parsers/                        # Data format parsers
    │       ├── splunk_attack_data.py       # Splunk JSONL → UnifiedAlert
    │       ├── splunk_sysmon.py            # Sysmon XML → UnifiedAlert
    │       ├── splunk_suricata.py          # Suricata JSON → UnifiedAlert
    │       ├── windows_security.py         # Windows Security XML → UnifiedAlert
    │       ├── cicids2018.py               # CIC-IDS CSV → UnifiedAlert (scaffold)
    │       └── beth.py                     # BETH CSV → UnifiedAlert (scaffold)
    ├── adversarial/                        # Injection engine
    │   ├── vectors.py                      # 12 injection vectors
    │   ├── payloads.py                     # 15 payload templates, 5 attack classes
    │   ├── encodings.py                    # 11 encoding strategies
    │   ├── injector.py                     # Combines vector + payload + encoding
    │   └── defenses.py                     # D1-D4 defense implementations
    ├── evaluation/
    │   ├── socbench_adapter.py             # Fox/Tiger/Panda output schemas
    │   ├── fox_scorer.py                   # Fox ring-based scoring (O1+O2+O3=100)
    │   ├── behavioral_invariants.py        # 6 invariants (INV-1 to INV-6)
    │   ├── statistical_tests.py            # Bootstrap CI, McNemar, Fleiss κ, Bowker
    │   ├── dataset_gate.py                 # Benchmark contract validation
    │   └── schemas.py                      # TriageDecision, EvidenceItem, etc.
    └── pipeline.py                         # Multi-agent triage pipeline
```

---

## 2. How to Feed Data from Prof Liu

### Scenario A: SOC-Bench Dataset (Colonial Pipeline)

SOC-Bench uses a Colonial Pipeline / DarkSide ransomware scenario. If Prof Liu provides SOC-Bench data:

**Put it here:**
```
data/datasets/socbench/colonial_pipeline/
```

**Expected format — SOC-Bench stage-based alerts:**
```json
{
    "stage_id": "stage_1",
    "stage_start": "2021-05-07T05:00:00Z",
    "stage_end": "2021-05-07T05:30:00Z",
    "alerts": [
        {
            "alert_id": "cp-001",
            "timestamp": "2021-05-07T05:12:33Z",
            "source": "sysmon",
            "severity": "high",
            "signature": "Suspicious PowerShell Execution",
            "event_type": "sysmon_1",
            "src_ip": "10.0.1.15",
            "dst_ip": "10.0.1.1",
            "raw_log": "<Event xmlns='...'>...</Event>",
            "mitre_techniques": ["T1059.001"],
            "kill_chain_phase": "execution"
        }
    ]
}
```

**Fox ground truth (for scoring):**
```
data/datasets/socbench/fox_ground_truth/
```
```json
{
    "stage_id": "stage_1",
    "expected_o1": {
        "campaign_detected": true,
        "campaign_scope": "targeted",
        "affected_hosts": ["WORKSTATION-1"]
    },
    "expected_o2": {
        "activity_type": "execution",
        "mitre_techniques": ["T1059.001"],
        "kill_chain_phase": "exploitation"
    },
    "expected_o3": {
        "priority": "critical",
        "bundle_alerts": ["cp-001", "cp-002"]
    }
}
```

**How it flows:**
```
SOC-Bench JSON → socbench_adapter.py → Fox/Tiger format
  → pipeline.py (triage) → fox_scorer.py (ring scoring)
    → results/gpu/<model>/socbench/fox_scores.json
```

### Scenario B: Additional SIEM Alerts (any format)

If Liu gives raw Sysmon/Suricata/Windows Security logs:

**Put it here:**
```
data/datasets/liu_provided/
```

**Supported formats:**
| Format | Parser | Example filename |
|--------|--------|-----------------|
| Sysmon XML | `splunk_sysmon.py` | `sysmon_events.xml` or `.evtx` |
| Suricata JSON | `splunk_suricata.py` | `eve.json` |
| Windows Security XML | `windows_security.py` | `security.evtx` or `.xml` |
| Splunk JSONL | `splunk_attack_data.py` | `alerts.jsonl` |
| CIC-IDS CSV | `cicids2018.py` | `flows.csv` (scaffold only) |

**How to convert to UnifiedAlert:**
```python
# Already built — just point to the file:
from src.ingestion.parsers import load_sysmon_log, load_suricata_log

# Sysmon
alerts = load_sysmon_log("data/datasets/liu_provided/sysmon_events.xml")

# Suricata
alerts = load_suricata_log("data/datasets/liu_provided/eve.json")

# Then validate through dataset gate:
from src.evaluation.dataset_gate import benchmark_contract_issues
for alert in alerts:
    issues = benchmark_contract_issues(alert)
    if issues:
        print(f"Alert {alert.alert_id}: {issues}")
```

### Scenario C: Liu's Own Format (unknown)

If it's a format we don't have a parser for:

**Put it here:**
```
data/datasets/liu_provided/raw/
```

Then tell me (Phoenix) or the Hades agent what the format looks like. We'll write a parser that converts it to `UnifiedAlert` JSONL.

**The UnifiedAlert schema (what every parser produces):**
```json
{
    "alert_id": "unique-id",
    "timestamp": "2021-05-07T05:12:33Z",
    "source": "file_replay",
    "severity": "high",
    "signature": "Suspicious PowerShell Execution",
    "signature_id": "rule-123",
    "event_type": "sysmon_1",
    "src_ip": "10.0.1.15",
    "src_port": 49152,
    "dst_ip": "10.0.1.1",
    "dst_port": 445,
    "protocol": "tcp",
    "raw_log": "<original log entry>",
    "metadata": {
        "vendor": "Microsoft",
        "device": "Sysmon",
        "category": "ProcessCreate",
        "message": "Process created: powershell.exe"
    },
    "benchmark": {
        "scenario_id": "colonial_pipeline_stage_1",
        "rule_id": "SSA-windows-powershell",
        "rule_source": "splunk_security_content",
        "rule_name": "Suspicious PowerShell Execution",
        "mitre_techniques": ["T1059.001"],
        "correlation_id": "campaign-darkside-001"
    },
    "provenance": {
        "dataset_name": "liu_socbench_2026",
        "dataset_role": "benchmark_of_record",
        "source_path": "data/datasets/liu_provided/alerts.jsonl",
        "label_provenance": "liu_manual_annotation_v1"
    }
}
```

---

## 3. Complete Data Flow (End to End)

```
┌─────────────────────────────────────────────────────────────┐
│ INPUT                                                       │
│                                                             │
│  Raw Data (any format)                                      │
│  └── data/datasets/{source}/                                │
│       ├── splunk_attack_data/  (existing, 12,147 alerts)    │
│       ├── socbench/            (from Prof Liu)              │
│       └── liu_provided/        (from Prof Liu)              │
│                                                             │
├─────────────────────────────────────────────────────────────┤
│ PARSE (src/ingestion/parsers/)                              │
│                                                             │
│  Raw → UnifiedAlert JSONL                                   │
│  Each parser normalizes to the same schema                  │
│                                                             │
├─────────────────────────────────────────────────────────────┤
│ VALIDATE (src/evaluation/dataset_gate.py)                   │
│                                                             │
│  4 contract checks per alert:                               │
│  ✓ Rule association    ✓ MITRE mapping                      │
│  ✓ Label provenance    ✓ Analyst-facing context             │
│  Failures rejected, logged                                  │
│                                                             │
├─────────────────────────────────────────────────────────────┤
│ BENCHMARK (data/benchmark/)                                 │
│                                                             │
│  Validated alerts → hades_benchmark_v1.jsonl (12,147)       │
│  + manifest with technique/tactic counts                    │
│  New Liu data would create hades_benchmark_v2.jsonl         │
│                                                             │
├─────────────────────────────────────────────────────────────┤
│ INJECT (src/adversarial/)                                   │
│                                                             │
│  Clean alerts → inject payloads into log fields             │
│  12 vectors × 5 attack classes × 11 encodings               │
│  Output: data/adversarial/<model>/                          │
│                                                             │
├─────────────────────────────────────────────────────────────┤
│ INFERENCE (Docker: vLLM + Qdrant)                           │
│                                                             │
│  Injected alerts → vLLM (one model at a time)               │
│  temp=0, INT4 quantization, 4× GPU tensor parallel          │
│  RAG retrieval from MITRE ATT&CK knowledge base             │
│  Output: TriageDecision per alert                           │
│                                                             │
├─────────────────────────────────────────────────────────────┤
│ EVALUATE (src/evaluation/)                                  │
│                                                             │
│  TriageDecision → multiple evaluation paths:                │
│                                                             │
│  ┌── behavioral_invariants.py ──→ INV-1 to INV-6 checks    │
│  ├── fox_scorer.py ─────────────→ O1+O2+O3 ring scoring    │
│  ├── socbench_adapter.py ───────→ Fox/Tiger/Panda format    │
│  └── statistical_tests.py ─────→ Bootstrap CI, McNemar,    │
│                                   Fleiss κ, Bowker          │
│                                                             │
├─────────────────────────────────────────────────────────────┤
│ OUTPUT                                                      │
│                                                             │
│  results/gpu/<model>/                                       │
│  ├── E1_baseline/       (clean triage F1, precision, recall)│
│  ├── E2_stratified/     (ASR per vector × class × model)    │
│  ├── E2_full/           (full sweep where variation found)  │
│  ├── E4_sanitization/   (ASR reduction + accuracy impact)   │
│  ├── E5_structured/     (prompt defense effectiveness)      │
│  ├── E7_canary/         (canary detection rate)             │
│  ├── E8_adaptive/       (defense robustness 3 levels)       │
│  └── analysis/          (statistical significance tests)    │
│                                                             │
│  results/gpu/tables/    (cross-model Tables A-D for paper)  │
│                                                             │
├─────────────────────────────────────────────────────────────┤
│ PAPER UPDATE (Phoenix)                                      │
│                                                             │
│  results/gpu/ → Phoenix reads JSONs                         │
│  → Fills Tables A-D in paper/sections/06_results.md         │
│  → Updates §7 Discussion with actual findings               │
│  → Checks MoE predictions against real data                 │
│  → Final review pass with real numbers                      │
│  → Commit + push updated paper                              │
└─────────────────────────────────────────────────────────────┘
```

---

## 4. Quick Reference: What to Do

| Situation | Action |
|-----------|--------|
| Prof Liu gives SOC-Bench data | Put in `data/datasets/socbench/` |
| Prof Liu gives raw SIEM logs | Put in `data/datasets/liu_provided/` |
| Prof Liu gives unknown format | Put in `data/datasets/liu_provided/raw/`, tell Phoenix |
| Ready to run experiments | `bash scripts/setup.sh && bash scripts/run_gpu_experiments.sh` |
| Experiments complete | `git add results/gpu/ && git commit && git push` |
| Want Phoenix to analyze | Push results, say "GPU results are in" |
| Need to add more alerts to benchmark | Parse → validate → create `hades_benchmark_v2.jsonl` |
| SOC-Bench Fox scoring needed | Adapter already built — just needs ground truth data |

---

## 5. Alert Count Summary

| Source | Alerts | Status | Location |
|--------|--------|--------|----------|
| Splunk Attack Data | 12,147 | ✅ Benchmark v1 | `data/benchmark/` |
| SOC-Bench (Liu) | TBD | ⏳ Waiting | `data/datasets/socbench/` |
| Liu additional | TBD | ⏳ Waiting | `data/datasets/liu_provided/` |
| BETH | ~2M | Engineering scaffold | `data/datasets/beth/` |
| CIC-IDS 2018 | ~440K | Engineering scaffold | `data/datasets/` |

---

## 6. For Prof Liu

If you need to share this with Prof Liu, the key points are:

1. **We accept any standard SIEM format** — Sysmon XML, Suricata JSON, Windows Security logs, Splunk exports, or raw JSONL
2. **SOC-Bench data goes in `data/datasets/socbench/`** — our adapter already produces Fox-compatible output
3. **Every alert needs**: timestamp, severity, signature/event description, MITRE technique mapping, and a detection rule association
4. **The dataset gate validates automatically** — any alert missing required fields gets flagged (not silently dropped)
5. **We have 12,147 alerts already** — additional data from Liu would extend the benchmark, not replace it
