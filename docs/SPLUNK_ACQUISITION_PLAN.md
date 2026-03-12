# Splunk Attack Data Acquisition Plan for Hades

**Author:** Phoenix AI  
**Date:** 2026-03-12  
**Status:** Research Complete - Ready for Implementation

---

## Executive Summary

This document outlines a comprehensive plan to acquire benchmark-quality SIEM alert data from the Splunk Attack Data repository for the Hades project. Splunk Attack Data provides curated datasets mapped to MITRE ATT&CK techniques with corresponding detection rules from the Splunk Security Content repository.

**Key Findings:**
- **Repository Structure:** Datasets organized by MITRE technique ID (T-codes)
- **Total Size:** ~9GB for full repository (selective download recommended)
- **Format:** Raw log files (JSON, CSV, XML) with YAML metadata
- **Detection Rules:** YAML-based with full MITRE ATT&CK mappings
- **Coverage:** 200+ MITRE techniques with multiple datasets per technique

---

## 1. Repository Structure & Organization

### 1.1 Splunk Attack Data Repository

**URL:** https://github.com/splunk/attack_data  
**Research URL:** https://research.splunk.com/attack_data/

#### Directory Structure:
```
attack_data/
├── datasets/
│   └── attack_techniques/
│       ├── T1003.001/          # MITRE Technique ID
│       │   ├── atomic_red_team/
│       │   │   ├── atomic_red_team.yml     # Metadata
│       │   │   ├── windows-sysmon.log      # Raw log data
│       │   │   ├── windows-security.log
│       │   │   └── crowdstrike_falcon.log
│       │   └── other_tool_name/
│       ├── T1110.001/
│       └── ...
└── environments/              # Environment descriptions
    ├── attack_range.md
    └── TEMPLATE.md
```

#### Dataset Organization:
- **By MITRE Technique:** Each technique (T-code) has its own folder
- **By Attack Tool:** Subfolders for data sources (atomic_red_team, metasploit, etc.)
- **Metadata File:** Each dataset folder contains a YAML file with:
  - Author, date, description
  - Environment (attack_range, custom, etc.)
  - MITRE technique mapping
  - Dataset list with paths, sourcetypes, and sources

#### Dataset Metadata Schema (YAML):
```yaml
author: <string>
id: <uuid>
date: <YYYY-MM-DD>
description: <test results and execution details>
environment: attack_range | custom | vm
directory: atomic_red_team | metasploit | etc
mitre_technique:
  - T1003.001
datasets:
  - name: <dataset_name>
    path: /datasets/attack_techniques/T1003.001/tool/filename.log
    sourcetype: <splunk_sourcetype>
    source: <splunk_source>
```

### 1.2 Splunk Security Content Repository

**URL:** https://github.com/splunk/security_content  
**Research URL:** https://research.splunk.com/

#### Directory Structure:
```
security_content/
├── detections/
│   ├── endpoint/
│   ├── network/
│   ├── cloud/
│   └── ...
├── stories/                   # Analytic Stories (grouped detections)
├── macros/                    # Splunk search macros
├── lookups/                   # Static lookup tables
└── docs/
    └── yaml-spec/
        ├── detection_spec.yml
        └── stories_spec.yml
```

#### Detection Rule Schema (YAML):
```yaml
name: <Detection Name>
id: <uuid>
version: <int>
date: <YYYY-MM-DD>
author: <string>
status: production | experimental | deprecated
type: TTP | Anomaly | Baseline | Hunting | Correlation
data_source:
  - Sysmon EventID 1
  - Windows Event Log Security 4688
description: <full description>
search: <SPL query>
how_to_implement: <implementation details>
known_false_positives: <false positive details>
references:
  - <url>
tags:
  analytic_story:
    - <Story Name>
  asset_type:
    - Endpoint
  mitre_attack_id:
    - T1003.001
  confidence: <1-100>
  impact: <1-100>
  risk_score: <1-100>
  message: <risk message>
  observable:
    - name: <field_name>
      type: Hostname | IP Address | User Name | etc
      role: [Victim, Attacker]
  product:
    - Splunk Enterprise Security
  required_fields:
    - field1
    - field2
  security_domain: endpoint | network | threat | identity | access | audit | cloud
tests:
  - name: True Positive Test
    attack_data:
      - data: https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/...
        source: <splunk_source>
        sourcetype: <splunk_sourcetype>
```

**Key Detection Fields for Hades Integration:**
- `mitre_attack_id`: List of MITRE technique IDs
- `tests.attack_data.data`: Direct link to dataset URL
- `tags.confidence`, `tags.impact`, `tags.risk_score`: Severity metrics
- `tags.observable`: Alert entity mappings
- `search`: SPL query for detection logic

---

## 2. Data Formats & Specifications

### 2.1 Log File Formats

Datasets are provided as **raw log files** in various formats:

| Format | Example Sourcetype | Description |
|--------|-------------------|-------------|
| XML | `XmlWinEventLog` | Windows Event Logs (Sysmon, Security) |
| JSON | `aws:cloudtrail`, `azure:monitor:aad` | Cloud platform logs |
| CSV | Various | Structured data exports |
| Custom | `crowdstrike:events:sensor` | Vendor-specific formats |

### 2.2 Common Log Sources

| Source | Sourcetype | Technique Coverage |
|--------|-----------|-------------------|
| Windows Sysmon | `XmlWinEventLog` | T1003.*, T1059.*, T1110.* |
| Windows Security | `XmlWinEventLog:Security` | T1078.*, T1098.* |
| CrowdStrike Falcon | `crowdstrike:events:sensor` | Multi-technique |
| AWS CloudTrail | `aws:cloudtrail` | T1078.004, T1098.* |
| Azure AD | `azure:monitor:aad` | T1078.004, T1098.003 |

### 2.3 Dataset Size Estimates

Based on repository analysis:

| Category | Size Estimate | Notes |
|----------|--------------|-------|
| Full Repository | ~9GB | All techniques, all sources |
| Single Technique (avg) | 10-50MB | 1-10 datasets per technique |
| Priority 5 Tactics (est) | 500MB-1GB | ~50-100 techniques total |
| Selective Download | 100-500MB | 10-20 key techniques |

**Storage Requirements for Hades:**
- Raw logs: 500MB-1GB (compressed)
- Parsed alerts: 50-100MB (structured JSON)
- Metadata: ~10MB

---

## 3. Priority MITRE Tactics & Available Datasets

### 3.1 TA0006: Credential Access

**Techniques with Datasets:**

| Technique ID | Name | Dataset Count | Key Sources |
|--------------|------|---------------|-------------|
| T1110 | Brute Force | 3+ | Windows Security, O365, Okta |
| T1110.001 | Password Guessing | 2+ | Azure AD, AWS |
| T1110.003 | Password Spraying | 2+ | Azure AD, O365 |
| T1003 | OS Credential Dumping | 15+ | Sysmon, Security, CrowdStrike |
| T1003.001 | LSASS Memory | 5+ | Sysmon, Security, CrowdStrike |
| T1003.002 | Security Account Manager | 4+ | Sysmon, PowerShell |
| T1003.003 | NTDS | 3+ | Sysmon, Security |
| T1003.006 | DCSync | 2+ | Sysmon, Security |
| T1003.008 | /etc/passwd and /etc/shadow | 3+ | Linux auditd, Sysmon |

**Example Dataset URL:**
```
https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1003.001/atomic_red_team/windows-sysmon.log
```

### 3.2 TA0007: Discovery

| Technique ID | Name | Dataset Count | Key Sources |
|--------------|------|---------------|-------------|
| T1087 | Account Discovery | 8+ | PowerShell, AD queries |
| T1087.001 | Local Account | 2+ | Sysmon, Security |
| T1087.002 | Domain Account | 6+ | PowerShell, AD logs |
| T1018 | Remote System Discovery | 4+ | Sysmon, Security |
| T1016 | System Network Configuration Discovery | 5+ | Sysmon, Linux auditd |
| T1033 | System Owner/User Discovery | 5+ | Sysmon, Security |
| T1082 | System Information Discovery | 4+ | Sysmon, Linux auditd |

### 3.3 TA0008: Lateral Movement

| Technique ID | Name | Dataset Count | Key Sources |
|--------------|------|---------------|-------------|
| T1021 | Remote Services | 10+ | Sysmon, Security |
| T1021.001 | Remote Desktop Protocol | 9+ | Sysmon, Security, Registry |
| T1021.002 | SMB/Windows Admin Shares | 4+ | Sysmon, Security |
| T1021.003 | Distributed Component Object Model | 5+ | Sysmon, Security |
| T1021.004 | SSH | 3+ | Linux auditd, Sysmon |
| T1021.006 | Windows Remote Management | 6+ | Sysmon, PowerShell |
| T1570 | Lateral Tool Transfer | 2+ | Sysmon, Network |

### 3.4 TA0002: Execution

| Technique ID | Name | Dataset Count | Key Sources |
|--------------|------|---------------|-------------|
| T1059 | Command and Scripting Interpreter | 20+ | Sysmon, Security |
| T1059.001 | PowerShell | 15+ | PowerShell ScriptBlock, Sysmon |
| T1059.003 | Windows Command Shell | 4+ | Sysmon, Security |
| T1059.004 | Unix Shell | 3+ | Linux auditd |
| T1059.005 | Visual Basic | 3+ | Sysmon, Security |
| T1569 | System Services | 5+ | Sysmon, Security |
| T1569.002 | Service Execution | 4+ | Sysmon, Security |

### 3.5 TA0003: Persistence

| Technique ID | Name | Dataset Count | Key Sources |
|--------------|------|---------------|-------------|
| T1053 | Scheduled Task/Job | 15+ | Sysmon, Security |
| T1053.002 | At | 5+ | Sysmon, Linux auditd |
| T1053.003 | Cron | 7+ | Linux auditd |
| T1053.005 | Scheduled Task | 13+ | Sysmon, Security, WinEvent |
| T1543 | Create or Modify System Process | 8+ | Sysmon, Security |
| T1543.003 | Windows Service | 6+ | Sysmon, Security |

---

## 4. Splunk → UnifiedAlert Parser Specification

### 4.1 Field Mapping Overview

**Source Data:**
1. **Raw Log Files:** Splunk-formatted logs (XML, JSON, CSV)
2. **Dataset Metadata:** YAML file with technique mapping
3. **Detection Rules:** YAML with SPL query and MITRE mapping

**Target Schema:** UnifiedAlert (from Hades benchmark contract)

### 4.2 Field Mapping Table

| UnifiedAlert Field | Splunk Source | Extraction Method | Example |
|-------------------|---------------|-------------------|---------|
| **alert_id** | Generated | UUID v4 | `uuid.uuid4()` |
| **timestamp** | `_time` or log timestamp | Parse from log | `2024-01-15T10:30:00Z` |
| **source_system** | Detection metadata | Static | `"splunk_attack_data"` |
| **rule_id** | Detection YAML `id` | Direct mapping | `b3b7ce35-fce5-4c73-85f4-700aeada81a9` |
| **rule_name** | Detection YAML `name` | Direct mapping | `"Windows Credential Dumping LSASS Memory"` |
| **severity** | Detection `tags.risk_score` | Map to enum | `risk_score > 70 → "high"` |
| **confidence** | Detection `tags.confidence` | Direct mapping | `0.85` (confidence/100) |
| **description** | Detection `description` | Direct mapping | Full description text |
| **raw_log** | Log file content | Full log entry | JSON/XML string |
| **entities** | Detection `tags.observable` | Extract observables | See Entity Mapping below |
| **mitre_tactics** | Detection `tags.mitre_attack_id` | Lookup technique → tactic | `["TA0006"]` |
| **mitre_techniques** | Detection `tags.mitre_attack_id` | Direct mapping | `["T1003.001"]` |
| **data_sources** | Detection `data_source` | Direct mapping | `["Sysmon EventID 1"]` |
| **false_positive_rate** | Detection `known_false_positives` | Parse to estimate | `"low"`, `"medium"`, `"high"` |
| **references** | Detection `references` | Direct mapping | List of URLs |

### 4.3 Entity Mapping (Observable → Entities)

Detection `tags.observable` structure:
```yaml
observable:
  - name: user
    type: User Name
    role: [Victim]
  - name: dest
    type: Hostname
    role: [Victim]
  - name: process_name
    type: Process Name
    role: [Attacker]
```

Map to UnifiedAlert `entities`:
```json
{
  "entities": [
    {
      "type": "user",
      "value": "<extracted_from_log>",
      "role": "target"
    },
    {
      "type": "host",
      "value": "<extracted_from_log>",
      "role": "target"
    },
    {
      "type": "process",
      "value": "<extracted_from_log>",
      "role": "threat"
    }
  ]
}
```

**Observable Type Mapping:**
| Splunk Observable Type | UnifiedAlert Entity Type |
|------------------------|-------------------------|
| User Name | `user` |
| Hostname | `host` |
| IP Address | `ip` |
| Process Name | `process` |
| File Name | `file` |
| File Hash | `file_hash` |
| URL String | `url` |
| Email Address | `email` |

**Role Mapping:**
| Splunk Role | UnifiedAlert Role |
|-------------|------------------|
| Victim | `target` |
| Attacker | `threat` |

### 4.4 AlertBenchmarkContext Mapping

```json
{
  "benchmark_context": {
    "dataset_id": "<dataset_metadata_id>",
    "technique_coverage": ["T1003.001"],
    "tactic_coverage": ["TA0006"],
    "detection_rule_id": "<detection_yaml_id>",
    "confidence_score": 0.85,
    "impact_score": 0.80,
    "test_scenario": "<dataset_description>",
    "attack_tool": "atomic_red_team",
    "environment": "attack_range"
  }
}
```

### 4.5 AlertProvenance Mapping

```json
{
  "provenance": {
    "source": "splunk_attack_data",
    "dataset_url": "https://github.com/splunk/attack_data",
    "detection_url": "https://github.com/splunk/security_content",
    "dataset_path": "/datasets/attack_techniques/T1003.001/atomic_red_team/windows-sysmon.log",
    "dataset_author": "Patrick Bareiss, Michael Haag",
    "dataset_date": "2022-01-12",
    "detection_author": "Michael Haag, Splunk",
    "detection_version": 12,
    "license": "Apache-2.0",
    "verified": true
  }
}
```

### 4.6 Severity Mapping Logic

Detection `tags.risk_score` (1-100) to UnifiedAlert `severity` enum:

```python
def map_severity(risk_score: int) -> str:
    if risk_score >= 90:
        return "critical"
    elif risk_score >= 70:
        return "high"
    elif risk_score >= 50:
        return "medium"
    elif risk_score >= 30:
        return "low"
    else:
        return "info"
```

### 4.7 False Positive Rate Estimation

Parse `known_false_positives` text for keywords:

```python
def estimate_fp_rate(fp_text: str) -> str:
    fp_lower = fp_text.lower()
    
    if any(word in fp_lower for word in ["rare", "unlikely", "minimal", "none"]):
        return "low"
    elif any(word in fp_lower for word in ["possible", "may occur", "some"]):
        return "medium"
    elif any(word in fp_lower for word in ["common", "frequent", "expected", "many"]):
        return "high"
    else:
        return "medium"  # default
```

---

## 5. Download Script Specification

### 5.1 GitHub API Approach

**Base URLs:**
- API: `https://api.github.com/repos/splunk/attack_data`
- Raw: `https://raw.githubusercontent.com/splunk/attack_data/master`
- Media: `https://media.githubusercontent.com/media/splunk/attack_data/master`

**Note:** Dataset files use Git LFS, so use `media.githubusercontent.com` for direct downloads.

### 5.2 Script Architecture

```
splunk_acquisition/
├── download_datasets.py        # Main download orchestrator
├── parse_detections.py         # Parse detection YAML to JSON
├── parse_datasets.py           # Parse raw logs to UnifiedAlert
├── validate_benchmark.py       # Validate against contract
├── config/
│   └── priority_techniques.json   # List of techniques to download
├── output/
│   ├── raw_logs/               # Downloaded log files
│   ├── metadata/               # Dataset metadata YAML
│   ├── detections/             # Detection rule YAML
│   └── unified_alerts/         # Parsed UnifiedAlert JSON
└── requirements.txt
```

### 5.3 Download Script Outline (`download_datasets.py`)

```python
#!/usr/bin/env python3
"""
Splunk Attack Data Downloader for Hades Benchmark

Downloads datasets for priority MITRE techniques from Splunk Attack Data repo.
"""

import os
import json
import requests
import yaml
from pathlib import Path
from typing import List, Dict
from tqdm import tqdm

# Configuration
GITHUB_API = "https://api.github.com/repos/splunk/attack_data"
RAW_BASE = "https://raw.githubusercontent.com/splunk/attack_data/master"
MEDIA_BASE = "https://media.githubusercontent.com/media/splunk/attack_data/master"
SECURITY_CONTENT_API = "https://api.github.com/repos/splunk/security_content"

OUTPUT_DIR = Path("output")
RAW_LOGS_DIR = OUTPUT_DIR / "raw_logs"
METADATA_DIR = OUTPUT_DIR / "metadata"
DETECTIONS_DIR = OUTPUT_DIR / "detections"

# Priority techniques from config
PRIORITY_TECHNIQUES = [
    # TA0006 Credential Access
    "T1110", "T1110.001", "T1110.003",
    "T1003", "T1003.001", "T1003.002", "T1003.003",
    # TA0007 Discovery
    "T1087", "T1087.001", "T1087.002",
    "T1018", "T1016", "T1033", "T1082",
    # TA0008 Lateral Movement
    "T1021", "T1021.001", "T1021.002", "T1021.006",
    "T1570",
    # TA0002 Execution
    "T1059", "T1059.001", "T1059.003",
    "T1569", "T1569.002",
    # TA0003 Persistence
    "T1053", "T1053.005",
    "T1543", "T1543.003",
]

def get_technique_datasets(technique_id: str) -> List[Dict]:
    """
    Get all datasets for a MITRE technique from GitHub API.
    
    Returns list of dataset metadata dicts.
    """
    api_url = f"{GITHUB_API}/contents/datasets/attack_techniques/{technique_id}"
    
    try:
        response = requests.get(api_url)
        response.raise_for_status()
        contents = response.json()
        
        datasets = []
        for item in contents:
            if item["type"] == "dir":
                # Get YAML metadata file
                yaml_url = f"{RAW_BASE}/datasets/attack_techniques/{technique_id}/{item['name']}/{item['name']}.yml"
                yaml_response = requests.get(yaml_url)
                
                if yaml_response.status_code == 200:
                    metadata = yaml.safe_load(yaml_response.text)
                    metadata["technique_id"] = technique_id
                    metadata["tool_dir"] = item["name"]
                    datasets.append(metadata)
        
        return datasets
    
    except requests.exceptions.HTTPError as e:
        if e.response.status_code == 404:
            print(f"  No datasets found for {technique_id}")
            return []
        raise

def download_dataset_files(metadata: Dict) -> List[str]:
    """
    Download all log files for a dataset.
    
    Returns list of downloaded file paths.
    """
    technique_id = metadata["technique_id"]
    tool_dir = metadata["tool_dir"]
    
    downloaded_files = []
    
    for dataset in metadata.get("datasets", []):
        # Dataset path: /datasets/attack_techniques/T1003.001/atomic_red_team/windows-sysmon.log
        path = dataset["path"]
        filename = path.split("/")[-1]
        
        # Download URL (use media.githubusercontent.com for LFS files)
        download_url = f"{MEDIA_BASE}{path}"
        
        # Local output path
        output_path = RAW_LOGS_DIR / technique_id / tool_dir / filename
        output_path.parent.mkdir(parents=True, exist_ok=True)
        
        print(f"    Downloading {filename}...")
        response = requests.get(download_url, stream=True)
        response.raise_for_status()
        
        # Write file
        with open(output_path, 'wb') as f:
            for chunk in response.iter_content(chunk_size=8192):
                f.write(chunk)
        
        downloaded_files.append(str(output_path))
        
        # Save dataset metadata
        dataset["local_path"] = str(output_path)
    
    return downloaded_files

def download_detection_rules(technique_id: str) -> List[Dict]:
    """
    Download detection rules for a MITRE technique from security_content repo.
    
    Returns list of detection rule dicts.
    """
    # Search detections directory for rules with this technique
    api_url = f"{SECURITY_CONTENT_API}/contents/detections"
    
    detections = []
    
    # Recursively search detection directories
    def search_directory(path: str):
        response = requests.get(f"{SECURITY_CONTENT_API}/contents/{path}")
        if response.status_code != 200:
            return
        
        for item in response.json():
            if item["type"] == "dir":
                search_directory(f"{path}/{item['name']}")
            elif item["name"].endswith(".yml"):
                # Download and parse YAML
                yaml_url = item["download_url"]
                yaml_response = requests.get(yaml_url)
                
                if yaml_response.status_code == 200:
                    detection = yaml.safe_load(yaml_response.text)
                    
                    # Check if this detection covers our technique
                    mitre_ids = detection.get("tags", {}).get("mitre_attack_id", [])
                    if technique_id in mitre_ids:
                        detection["detection_file"] = item["name"]
                        detections.append(detection)
    
    search_directory("detections")
    return detections

def main():
    """Main download orchestrator."""
    print("Splunk Attack Data Downloader for Hades")
    print("=" * 60)
    
    # Create output directories
    RAW_LOGS_DIR.mkdir(parents=True, exist_ok=True)
    METADATA_DIR.mkdir(parents=True, exist_ok=True)
    DETECTIONS_DIR.mkdir(parents=True, exist_ok=True)
    
    stats = {
        "techniques_processed": 0,
        "datasets_downloaded": 0,
        "detections_downloaded": 0,
        "total_size_mb": 0,
    }
    
    for technique_id in tqdm(PRIORITY_TECHNIQUES, desc="Processing techniques"):
        print(f"\n[{technique_id}] Fetching datasets...")
        
        # Get datasets for this technique
        datasets = get_technique_datasets(technique_id)
        
        if not datasets:
            continue
        
        stats["techniques_processed"] += 1
        
        # Download each dataset
        for metadata in datasets:
            print(f"  Dataset: {metadata.get('id', 'unknown')}")
            
            # Download log files
            files = download_dataset_files(metadata)
            stats["datasets_downloaded"] += len(files)
            
            # Save metadata
            metadata_path = METADATA_DIR / f"{technique_id}_{metadata['tool_dir']}.json"
            with open(metadata_path, 'w') as f:
                json.dump(metadata, f, indent=2)
        
        # Download detection rules
        print(f"  Fetching detection rules...")
        detections = download_detection_rules(technique_id)
        
        for detection in detections:
            detection_path = DETECTIONS_DIR / f"{detection['id']}.json"
            with open(detection_path, 'w') as f:
                json.dump(detection, f, indent=2)
            
            stats["detections_downloaded"] += 1
    
    # Calculate total size
    total_size = sum(f.stat().st_size for f in RAW_LOGS_DIR.rglob("*") if f.is_file())
    stats["total_size_mb"] = round(total_size / (1024 * 1024), 2)
    
    # Save stats
    with open(OUTPUT_DIR / "download_stats.json", 'w') as f:
        json.dump(stats, f, indent=2)
    
    print("\n" + "=" * 60)
    print("Download Complete!")
    print(f"  Techniques: {stats['techniques_processed']}")
    print(f"  Datasets: {stats['datasets_downloaded']}")
    print(f"  Detection Rules: {stats['detections_downloaded']}")
    print(f"  Total Size: {stats['total_size_mb']} MB")

if __name__ == "__main__":
    main()
```

### 5.4 Validation Script Outline (`validate_benchmark.py`)

```python
#!/usr/bin/env python3
"""
Validate parsed UnifiedAlerts against Hades benchmark contract.
"""

import json
from pathlib import Path
from typing import Dict, List

UNIFIED_ALERTS_DIR = Path("output/unified_alerts")

def validate_alert(alert: Dict) -> List[str]:
    """
    Validate a single UnifiedAlert against schema.
    
    Returns list of validation errors (empty if valid).
    """
    errors = []
    
    # Required fields
    required_fields = [
        "alert_id", "timestamp", "source_system", "rule_id",
        "rule_name", "severity", "description", "raw_log"
    ]
    
    for field in required_fields:
        if field not in alert or alert[field] is None:
            errors.append(f"Missing required field: {field}")
    
    # Severity enum
    valid_severities = ["critical", "high", "medium", "low", "info"]
    if alert.get("severity") not in valid_severities:
        errors.append(f"Invalid severity: {alert.get('severity')}")
    
    # MITRE fields
    if "mitre_techniques" in alert:
        for tech in alert["mitre_techniques"]:
            if not tech.startswith("T"):
                errors.append(f"Invalid technique ID: {tech}")
    
    if "mitre_tactics" in alert:
        for tactic in alert["mitre_tactics"]:
            if not tactic.startswith("TA"):
                errors.append(f"Invalid tactic ID: {tactic}")
    
    # Entities structure
    if "entities" in alert:
        for entity in alert["entities"]:
            if "type" not in entity or "value" not in entity:
                errors.append("Entity missing type or value")
    
    return errors

def main():
    """Validate all parsed alerts."""
    print("Validating UnifiedAlerts against benchmark contract...")
    
    total_alerts = 0
    valid_alerts = 0
    errors_by_type = {}
    
    for alert_file in UNIFIED_ALERTS_DIR.glob("*.json"):
        with open(alert_file) as f:
            alert = json.load(f)
        
        total_alerts += 1
        errors = validate_alert(alert)
        
        if not errors:
            valid_alerts += 1
        else:
            for error in errors:
                errors_by_type[error] = errors_by_type.get(error, 0) + 1
    
    print(f"\nValidation Results:")
    print(f"  Total Alerts: {total_alerts}")
    print(f"  Valid: {valid_alerts}")
    print(f"  Invalid: {total_alerts - valid_alerts}")
    
    if errors_by_type:
        print("\nError Summary:")
        for error, count in sorted(errors_by_type.items(), key=lambda x: -x[1]):
            print(f"  {error}: {count}")
    
    return valid_alerts == total_alerts

if __name__ == "__main__":
    success = main()
    exit(0 if success else 1)
```

### 5.5 Dependencies (`requirements.txt`)

```
requests>=2.31.0
pyyaml>=6.0
tqdm>=4.66.0
jsonschema>=4.20.0
```

---

## 6. Implementation Steps

### Phase 1: Setup & Download (Week 1)

1. **Environment Setup**
   ```bash
   cd /home/jay/hades
   mkdir -p splunk_acquisition/{config,output/{raw_logs,metadata,detections,unified_alerts}}
   cd splunk_acquisition
   python3 -m venv venv
   source venv/bin/activate
   pip install -r requirements.txt
   ```

2. **Configure Priority Techniques**
   - Create `config/priority_techniques.json` with technique list
   - Optionally filter by tactic, data source, or environment

3. **Run Download Script**
   ```bash
   python download_datasets.py
   ```
   - Expected output: 500MB-1GB of raw logs
   - ~50-100 datasets across 30-40 techniques
   - ~100-200 detection rules

4. **Verify Downloads**
   ```bash
   python validate_downloads.py
   ```
   - Check file integrity
   - Verify metadata completeness
   - Log missing/failed downloads

### Phase 2: Parsing & Transformation (Week 2)

1. **Implement Log Parsers**
   - Create parsers for each sourcetype:
     - `XmlWinEventLog` (Windows Sysmon/Security)
     - `aws:cloudtrail` (AWS logs)
     - `azure:monitor:aad` (Azure logs)
     - `crowdstrike:events:sensor` (CrowdStrike)

2. **Implement UnifiedAlert Mapper**
   - Use field mapping tables from Section 4
   - Extract entities from observables
   - Map severity, confidence, FP rate

3. **Run Parser Pipeline**
   ```bash
   python parse_datasets.py --input output/raw_logs --output output/unified_alerts
   ```

4. **Validate Parsed Alerts**
   ```bash
   python validate_benchmark.py
   ```
   - Ensure schema compliance
   - Check required fields
   - Verify MITRE mappings

### Phase 3: Integration & Testing (Week 3)

1. **Load into Hades**
   - Import UnifiedAlerts into Hades benchmark database
   - Index by technique, tactic, severity
   - Link detection rules to datasets

2. **Run Benchmark Tests**
   - Test alert retrieval by technique
   - Verify MITRE coverage
   - Check provenance tracking

3. **Quality Assurance**
   - Sample 10% of alerts for manual review
   - Verify entity extraction accuracy
   - Check false positive rate estimates

4. **Documentation**
   - Document parsing edge cases
   - Create dataset catalog
   - Generate coverage report

---

## 7. Coverage Analysis

### 7.1 Expected Technique Coverage

Based on research.splunk.com analysis:

| Tactic | Techniques Available | Target Techniques | Coverage % |
|--------|---------------------|------------------|------------|
| TA0006 Credential Access | 15+ | 7 | 100% |
| TA0007 Discovery | 10+ | 6 | 100% |
| TA0008 Lateral Movement | 12+ | 5 | 100% |
| TA0002 Execution | 20+ | 4 | 100% |
| TA0003 Persistence | 15+ | 4 | 100% |

**Total Unique Techniques:** 30-40 across 5 tactics

### 7.2 Alert Volume Estimates

| Category | Estimate | Notes |
|----------|----------|-------|
| Total Raw Logs | 50-100 files | ~10-50MB each |
| Alerts per Dataset | 100-1000 | Depends on log size |
| Total Alerts | 5,000-50,000 | After parsing |
| Unique Detection Rules | 100-200 | Covers all techniques |
| High-Confidence Alerts | 2,000-10,000 | Confidence > 70% |

### 7.3 Data Source Distribution

| Data Source | Technique Count | % Coverage |
|-------------|----------------|------------|
| Windows Sysmon | 25+ | 60% |
| Windows Security Logs | 20+ | 50% |
| PowerShell Logs | 15+ | 35% |
| Cloud Platform Logs | 10+ | 25% |
| Linux auditd | 8+ | 20% |
| CrowdStrike Falcon | 12+ | 30% |

---

## 8. Quality Assurance & Limitations

### 8.1 Data Quality Metrics

For each dataset/detection pair, track:

| Metric | Calculation | Target |
|--------|-------------|--------|
| Detection Coverage | # techniques with detections / # total techniques | > 90% |
| Dataset Completeness | # required fields populated / # total fields | > 95% |
| MITRE Mapping Accuracy | # correct mappings / # total mappings | 100% |
| Entity Extraction Rate | # alerts with entities / # total alerts | > 80% |
| Provenance Completeness | # alerts with full provenance / # total alerts | 100% |

### 8.2 Known Limitations

1. **Synthetic Data:** Attack data generated in lab environments, not production
2. **Limited Context:** Some alerts may lack full attack chain context
3. **Sourcetype Variation:** Not all log formats supported (custom parsers needed)
4. **Temporal Gaps:** Dataset timestamps may not reflect real-world alert timing
5. **False Positive Estimates:** Based on text parsing, not empirical measurement

### 8.3 Mitigation Strategies

- **Synthetic Data:** Supplement with public datasets (CICIDS, UNSW-NB15)
- **Limited Context:** Use Analytic Stories to group related detections
- **Sourcetype Variation:** Prioritize common sources (Sysmon, Security)
- **Temporal Gaps:** Normalize timestamps or treat as relative
- **FP Estimates:** Validate against real SIEM deployments if possible

---

## 9. Next Steps & Recommendations

### Immediate Actions (Week 1)

1. ✅ **Review this plan** with Hades team
2. ⬜ **Set up acquisition environment** (`splunk_acquisition/`)
3. ⬜ **Run initial download** for 5-10 test techniques
4. ⬜ **Validate downloaded files** and metadata

### Short-Term (Weeks 2-3)

1. ⬜ **Implement parsers** for top 3 sourcetypes
2. ⬜ **Test UnifiedAlert mapping** on sample dataset
3. ⬜ **Integrate with Hades** benchmark database
4. ⬜ **Generate coverage report**

### Long-Term (Month 2+)

1. ⬜ **Expand to all 5 tactics** (full technique coverage)
2. ⬜ **Add supplementary datasets** (public sources)
3. ⬜ **Implement ML feature extraction** for alert triage
4. ⬜ **Create detection effectiveness metrics** (precision/recall)

### Alternative/Supplementary Sources

If Splunk Attack Data is insufficient:

1. **MITRE ATT&CK Evaluations:** Real APT emulation data
   - URL: https://attackevals.mitre-engenuity.org/
   - Format: Detection analytics + SIEM logs
   - Coverage: Full attack chains

2. **Atomic Red Team:** Open-source test framework
   - URL: https://github.com/redcanaryco/atomic-red-team
   - Format: Test definitions + execution logs
   - Coverage: 200+ techniques

3. **CICIDS2017/2018:** Network intrusion datasets
   - URL: https://www.unb.ca/cic/datasets/
   - Format: PCAP + labeled flows
   - Coverage: Network-based attacks

4. **UNSW-NB15:** Comprehensive network dataset
   - URL: https://research.unsw.edu.au/projects/unsw-nb15-dataset
   - Format: Labeled network traffic
   - Coverage: 9 attack families

---

## 10. Appendix

### A. Key URLs

| Resource | URL |
|----------|-----|
| Splunk Attack Data Repo | https://github.com/splunk/attack_data |
| Splunk Security Content Repo | https://github.com/splunk/security_content |
| Attack Data Research Portal | https://research.splunk.com/attack_data/ |
| Security Content Research Portal | https://research.splunk.com/ |
| Detection Spec YAML | https://github.com/splunk/security_content/blob/develop/docs/yaml-spec/detection_spec.yml |
| MITRE ATT&CK Matrix | https://attack.mitre.org/ |

### B. File Format Examples

**Dataset Metadata YAML:**
```yaml
author: Patrick Bareiss, Michael Haag
id: cc9b25d6-efc9-11eb-926b-550bf0943fbb
date: '2022-01-12'
description: 'Atomic Test Results: Successful Execution...'
environment: attack_range
directory: atomic_red_team
mitre_technique:
  - T1003.001
datasets:
  - name: windows-sysmon_creddump
    path: /datasets/attack_techniques/T1003.001/atomic_red_team/windows-sysmon_creddump.log
    sourcetype: XmlWinEventLog
    source: XmlWinEventLog:Microsoft-Windows-Sysmon/Operational
```

**Detection Rule YAML (excerpt):**
```yaml
name: Windows Credential Dumping LSASS Memory Createdump
id: b3b7ce35-fce5-4c73-85f4-700aeada81a9
version: 12
date: '2026-03-10'
type: TTP
tags:
  mitre_attack_id:
    - T1003.001
  confidence: 85
  impact: 80
  risk_score: 68
  observable:
    - name: user
      type: User Name
      role: [Victim]
tests:
  - name: True Positive Test
    attack_data:
      - data: https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/...
        sourcetype: XmlWinEventLog
```

**UnifiedAlert Example:**
```json
{
  "alert_id": "550e8400-e29b-41d4-a716-446655440000",
  "timestamp": "2022-01-12T14:30:00Z",
  "source_system": "splunk_attack_data",
  "rule_id": "b3b7ce35-fce5-4c73-85f4-700aeada81a9",
  "rule_name": "Windows Credential Dumping LSASS Memory Createdump",
  "severity": "high",
  "confidence": 0.85,
  "description": "The following analytic detects the use of CreateDump.exe...",
  "raw_log": "<Event xmlns='http://schemas.microsoft.com/...'",
  "entities": [
    {"type": "user", "value": "admin", "role": "target"},
    {"type": "host", "value": "WIN-SERVER01", "role": "target"},
    {"type": "process", "value": "createdump.exe", "role": "threat"}
  ],
  "mitre_tactics": ["TA0006"],
  "mitre_techniques": ["T1003.001"],
  "data_sources": ["Sysmon EventID 1"],
  "benchmark_context": {
    "dataset_id": "cc9b25d6-efc9-11eb-926b-550bf0943fbb",
    "technique_coverage": ["T1003.001"],
    "confidence_score": 0.85,
    "test_scenario": "Atomic Test T1003.001 - Dump LSASS Memory"
  },
  "provenance": {
    "source": "splunk_attack_data",
    "dataset_author": "Patrick Bareiss, Michael Haag",
    "dataset_date": "2022-01-12",
    "license": "Apache-2.0"
  }
}
```

### C. Contact & Support

**Splunk Resources:**
- GitHub Issues: https://github.com/splunk/attack_data/issues
- Community Slack: https://splunkcommunity.slack.com/ (#security-research)
- Documentation: https://docs.splunk.com/

**MITRE ATT&CK:**
- Contact: https://attack.mitre.org/resources/
- Technique Updates: https://attack.mitre.org/resources/updates/

---

## Document Metadata

**Version:** 1.0  
**Last Updated:** 2026-03-12  
**Status:** Research Complete - Ready for Implementation  
**Next Review:** After Phase 1 completion (Week 2)

**Approval Required From:**
- [ ] Hades Project Lead
- [ ] Data Engineering Team
- [ ] Security Research Team

**Implementation Owner:** TBD

---

*End of Splunk Attack Data Acquisition Plan*
