# SOC-Bench Data (from Prof Liu)

Place SOC-Bench data here. Our adapter (`src/evaluation/socbench_adapter.py`) converts Hades triage outputs into SOC-Bench-compatible format.

## Directory Structure

```
socbench/
├── colonial_pipeline/     # DarkSide ransomware scenario alerts
│   └── stage_N.json       # One file per 30-minute stage (SOC-Bench DP3)
├── fox_ground_truth/      # Expected Fox task outputs for scoring
│   └── stage_N_truth.json # Ground truth per stage
└── raw/                   # Any raw exports before conversion
```

## Expected Alert Format

SOC-Bench stages alerts in 30-minute windows. Each stage file:

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
            "raw_log": "<original log entry>",
            "mitre_techniques": ["T1059.001"],
            "kill_chain_phase": "execution"
        }
    ]
}
```

## Fox Ground Truth Format

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

## What Happens to This Data

1. Alerts parsed into UnifiedAlert format
2. Run through dataset gate (validates MITRE mapping, provenance, rule association)
3. Triage pipeline processes alerts through vLLM
4. Fox scorer compares triage output against ground truth using ring scoring
5. Results saved to `results/gpu/<model>/socbench/`
