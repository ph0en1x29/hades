# Data from Prof Liu

Place any additional data from Prof Liu here.

## Supported Formats

| Format | Extension | Parser |
|--------|-----------|--------|
| Sysmon events | `.xml`, `.evtx` | `src/ingestion/parsers/splunk_sysmon.py` |
| Suricata alerts | `.json` (eve format) | `src/ingestion/parsers/splunk_suricata.py` |
| Windows Security logs | `.xml`, `.evtx` | `src/ingestion/parsers/windows_security.py` |
| Splunk export | `.jsonl` | `src/ingestion/parsers/splunk_attack_data.py` |
| Unknown format | any | Put in `raw/`, we'll write a parser |

## Requirements Per Alert

The dataset gate (`src/evaluation/dataset_gate.py`) requires:
- MITRE ATT&CK technique mapping (e.g., T1059.001)
- Detection rule association (rule ID + source)
- Label provenance (who labeled it and how)
- Analyst-facing context (signature, event type, or message)

Alerts missing these fields are flagged but not silently dropped.

## Quick Convert

```python
from src.ingestion.parsers import load_sysmon_log
alerts = load_sysmon_log("data/datasets/liu_provided/events.xml")
# Alerts are now UnifiedAlert objects ready for the pipeline
```
