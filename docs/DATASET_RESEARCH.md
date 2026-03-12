# Dataset Research — Addressing Dr. Liu's Adequacy Concern

*The core problem: CICIDS datasets have network flow labels but NO SIEM rule associations. A real SOC analyst sees alerts from detection rules (Sigma/Suricata/Splunk), not raw packet features.*

## What "Adequate" Means for SIEM Research

A scientifically adequate dataset needs:
1. **Detection rule associations** — which Sigma/Suricata/Splunk rules fired
2. **Alert context** — severity, source/dest, timestamps, rule metadata
3. **Multi-source correlation** — network + endpoint + auth logs correlated
4. **Ground truth** — labeled true/false positive with analyst reasoning
5. **MITRE ATT&CK mapping** — techniques associated with each alert

## Candidate Datasets (Ranked by Relevance)

### Tier 1: SIEM-Native (Best Fit)

#### 1. Splunk Attack Data + Security Content
- **What:** Curated attack datasets with matching Splunk detection rules
- **Source:** https://github.com/splunk/attack_data + https://github.com/splunk/security_content
- **Format:** Raw logs (Sysmon EVTX, Windows Security, network) + corresponding Splunk SPL detection rules
- **MITRE:** Full ATT&CK mapping per detection
- **Strengths:** Every dataset has a matching detection rule. Real telemetry from Atomic Red Team / Attack Range simulations.
- **Weakness:** Splunk-specific format; need conversion. Individual technique datasets, not full attack campaigns.
- **Adequacy:** ⭐⭐⭐⭐ — Has rule associations Dr. Liu requires

#### 2. OTRF Security Datasets (Mordor)
- **What:** Pre-recorded security events from simulated attack scenarios
- **Source:** https://github.com/OTRF/Security-Datasets
- **Format:** JSON (Sysmon, Windows Security, etc.), mapped to MITRE ATT&CK
- **MITRE:** Full technique mapping
- **Strengths:** Rich endpoint telemetry, APT simulations, community-maintained
- **Weakness:** No SIEM rules included (but can be paired with Sigma rules)
- **Adequacy:** ⭐⭐⭐ — Needs Sigma rule overlay

#### 3. EVTX-to-MITRE-Attack
- **What:** 270+ Windows EVTX samples mapped to MITRE ATT&CK
- **Source:** https://github.com/mdecrevoisier/EVTX-to-MITRE-Attack
- **Format:** EVTX files organized by tactic
- **Strengths:** Direct tactic/technique mapping, real event format
- **Weakness:** Individual samples, not campaigns

### Tier 2: Enrichable (Need Processing)

#### 4. Sigma Rules + CICIDS2018 (Hybrid Approach)
- **What:** Run Sigma detection rules against CICIDS2018 PCAPs via Suricata/Zeek
- **Process:** PCAP → Suricata (with ET rules) → alerts with SIDs → map SIDs to MITRE
- **Strengths:** Bridges the gap Dr. Liu identified. Creates SIEM-like alerts from existing data.
- **Weakness:** Requires infrastructure setup. Rules may not fire on all attack types.
- **Adequacy:** ⭐⭐⭐ — Scientifically defensible if methodology is documented

#### 5. SIEVE Dataset (2025)
- **What:** Synthetic dataset for SIEM log classification
- **Source:** ScienceDirect (Computer Networks, Vol 266)
- **Format:** 6 synthetic log collections
- **Weakness:** Dr. Liu specifically warned synthetic may not be adequate

### Tier 3: SOC-Bench Alignment (Best Strategic Fit)

#### 6. SOC-Bench Data (Colonial Pipeline Reconstruction)
- **What:** Dr. Liu's own benchmark uses reconstructed Colonial Pipeline telemetry
- **Data sources in SOC-Bench spec:** File-system metadata, EDR/XDR process telemetry, VSS logs, SIEM alerts, network flows, OS logs, host metrics, CTI reports
- **Strengths:** Perfect alignment with advisor. Already has ground truth. Multi-source.
- **Action:** Ask Dr. Liu if SOC-Bench data can be shared/used for Hades evaluation

## Recommended Strategy

### Option A: SOC-Bench Data (Preferred — ask Dr. Liu)
Use SOC-Bench's Colonial Pipeline reconstruction data. Hades becomes a system evaluated on SOC-Bench tasks. Dataset adequacy is guaranteed by the benchmark design itself.

### Option B: Splunk Attack Data + Sigma Rules (Independent)
Build a pipeline: Splunk Attack Data → normalize to UnifiedAlert → pair with Sigma/Splunk detection rules → create SIEM-context-enriched dataset. This addresses Dr. Liu's concern directly — every alert has a rule association.

### Option C: Hybrid (CICIDS2018 + Suricata Rules)
Run CICIDS2018 PCAPs through Suricata with Emerging Threats ruleset. Generate real SIEM alerts with rule IDs, then map to MITRE. Bridges flow data → SIEM alerts gap.

## Key Papers for Related Work

- **RuleGenie** (arxiv:2505.06701) — SIEM rule optimization, evaluated on 2,347 Sigma + 1,640 Splunk rules
- **Rule-ATT&CK Mapper (RAM)** (arxiv:2502.02337) — LLM-based mapping of SIEM rules to MITRE techniques
- **SIEVE** (Computer Networks 2025) — Synthetic SIEM log generation methodology
- **Labeling NIDS Rules with MITRE ATT&CK** (arxiv:2412.10978) — Snort/Suricata rule labeling
- **CORTEX** (arxiv:2510.00311) — Collaborative LLM agents for alert triage (closest competitor)
- **SecBench** (arxiv:2412.20787) — Multi-dimensional LLM cybersecurity benchmark

## Questions for First Meeting with Dr. Liu

1. Can we access SOC-Bench data for Hades evaluation?
2. Would building a SIEM-rule-enriched dataset from Splunk Attack Data be considered adequate?
3. Does "adequate" mean real enterprise telemetry, or is well-documented simulation (Atomic Red Team + detection rules) acceptable?
4. Should Hades target specific SOC-Bench tasks (e.g., Fox/Tiger) or remain a general triage system?
5. What is the SOC-Bench publication timeline — can Hades contribute as an evaluated system?

---

*Researched: 2026-03-12*
