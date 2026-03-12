# Dataset Decision — Addressing Dr. Liu's Adequacy Concern

The dataset question now controls Hades. CICIDS-derived flows remain useful engineering input, but they do not satisfy the scientific bar on their own because they lack SIEM rule associations and analyst-facing alert context.

## Decision

**Benchmark of record for the first public validation pass:**
- Splunk Attack Data
- Splunk Security Content

**Strategic second-phase path:**
- SOC-Bench if Dr. Liu grants access

**Supplementary only:**
- OTRF Security-Datasets
- EVTX-to-MITRE-Attack

**Engineering scaffold only:**
- CIC-IDS2018 parser path

## Adequacy Criteria

For Hades to claim scientific benchmark adequacy, each benchmark alert must have:

1. a detection-rule association
2. dataset provenance
3. label provenance
4. analyst-facing alert context
5. MITRE ATT&CK mapping
6. scenario grouping or correlation metadata when available

The benchmark slice must also document whether the underlying data is:
- public
- simulated
- advisor-provided

## Primary Validation Path

### Splunk Attack Data + Splunk Security Content

- **Why this is the default:** public, reproducible, and already tied to detection content
- **What it gives us:** telemetry, rule associations, ATT&CK mappings, and a defensible public benchmark path
- **What Hades must build on top:** normalization into `UnifiedAlert`, explicit provenance preservation, and a documented benchmark manifest

This is the benchmark-of-record until SOC-Bench access is confirmed.

## Fallback and Escalation

### If SOC-Bench access is granted

- treat SOC-Bench as a second benchmark path
- compare it against the public baseline instead of replacing the public baseline
- use SOC-Bench to strengthen external validity and advisor alignment

### If SOC-Bench access is not granted

- proceed with Splunk Attack Data + Splunk Security Content as the official validation benchmark
- keep OTRF and EVTX-to-MITRE-Attack as supplementary enrichment sources only

## Evidence Package for the Advisor

To demonstrate adequacy to Dr. Liu and other reviewers, Hades must produce:

1. a benchmark manifest naming the public benchmark-of-record
2. a normalized alert contract that encodes rule linkage, provenance, MITRE mapping, and scenario identifiers
3. a config-level guard that rejects engineering scaffolds as benchmark-of-record inputs
4. benchmark-contract tests proving required fields are present
5. a written distinction between scientific benchmark data and engineering scaffolds

## Explicit Position on CIC-IDS2018

CIC-IDS2018 remains in the repo for:
- parser development
- fixture generation
- engineering smoke tests

It does **not** count as scientific validation evidence for Hades unless it is later transformed into rule-linked SIEM alerts through a separate documented methodology.

## Immediate Next Questions for Dr. Liu

1. Can SOC-Bench data be shared for Hades evaluation?
2. Is Splunk Attack Data + Security Content sufficient as the first scientific public benchmark?
3. If SOC-Bench is available, which tasks should Hades target first?

## Public Sources

- Splunk Attack Data: https://github.com/splunk/attack_data
- Splunk Security Content: https://github.com/splunk/security_content
- OTRF Security-Datasets: https://github.com/OTRF/Security-Datasets
- EVTX-to-MITRE-Attack: https://github.com/mdecrevoisier/EVTX-to-MITRE-Attack

---

*Decision updated: 2026-03-12*
