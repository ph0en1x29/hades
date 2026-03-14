# 1. Introduction

Security Operations Centers (SOCs) process thousands of alerts daily, yet human analysts can effectively triage only 50–100 alerts per shift [MDPI2025]. This capacity gap has driven rapid adoption of Large Language Models (LLMs) for automated alert triage, where models classify incoming Security Information and Event Management (SIEM) alerts by severity, identify potential attack patterns, and recommend response actions [Wei2025]. Commercial platforms now embed LLM-based assistants directly into SIEM workflows, and research systems like CORTEX demonstrate that multi-agent LLM architectures can substantially reduce false positive rates across enterprise scenarios.

However, this integration introduces a fundamental vulnerability that collapses a trust boundary traditional security tools maintain: **the data that LLM triage systems process originates from the same adversaries they are designed to detect.** In LLM triage, the evidence stream and the adversary-controlled instruction stream are the same object. SIEM platforms log network traffic, authentication events, and system telemetry — all of which contain fields whose content is directly controlled by external actors. When an LLM processes these logs, attacker-controlled data enters the model's context window alongside system instructions, creating a classic indirect prompt injection attack surface [OWASP2025].

## 1.1 The Overlooked Attack Surface

Unlike conventional prompt injection, where a malicious user interacts directly with an LLM interface, the threat we characterize operates through the organization's own data pipeline:

> **Attacker → Network traffic → SIEM normalization → Log storage → LLM prompt construction → Triage decision**

At each stage, attacker-controlled content is preserved and eventually presented to the LLM as "data" to analyze. From an information-flow perspective, the system prompt represents a high-trust control channel and the log data represents a low-trust data channel — but LLMs do not enforce noninterference between the two. The model cannot reliably distinguish between legitimate log fields and injected instructions, because the boundary between data and instruction is defined only by prompt formatting — a boundary that LLMs are known to violate [Nasr2025].

This attack surface is no longer hypothetical. Neaves [2025] demonstrated successful prompt injection through HTTP User-Agent headers, SSH username fields, and Windows Event Log authentication records, causing LLM-based SIEM assistants to falsify source IP addresses, hide attack indicators, and fabricate decoy events. Unit 42 [2026] documented multiple indirect prompt injection patterns observed in production settings.

## 1.2 Research Question

We pose the following question:

> *Can adversaries manipulate LLM-based SOC triage systems through crafted network traffic, and what defense mechanisms appear promising for mitigating this threat?*

This question has three components: (1) characterizing the attack surface specific to SOC triage, (2) measuring vulnerability across different model architectures, and (3) evaluating whether proposed defenses survive adaptive attackers.

## 1.3 Contributions

This paper makes the following contributions:

1. **SOC-specific threat model.** We enumerate 12 candidate injection vectors through SIEM log fields, with payload length constraints, SIEM normalization survival rates, and realism assessments. Of these, 4 are empirically validated against production SIEM systems [Neaves2025]; the remaining 8 are characterized from protocol specifications and SIEM documentation.

2. **Adversarial evaluation framework and benchmark.** We construct a benchmark of 12,147 rule-linked SIEM alerts across 27 MITRE ATT&CK techniques in 9 tactics, and define an evaluation protocol for 4 frontier open-weight MoE models with diverse routing architectures under 5 attack classes and a 12-vector injection taxonomy, producing over 1.4 million base adversarial alert variants. Cross-model attack success results await GPU allocation; this paper validates benchmark construction, SIEM normalization survival, and preliminary defense mechanisms.

3. **Behavioral invariant defense.** We introduce an output-level defense that checks triage decisions against 6 behavioral invariants — detecting phantom IPs, severity downgrades, confidence anomalies, fabricated references, temporal downplay patterns, and confidence-severity alignment violations. By operating on the model's *output* rather than input, invariants shift detection to the problem's constraint space rather than the attacker's action space — a hypothesis we formalize but have not yet validated against adaptive attackers. Preliminary evaluation on 50 simulated triage outputs shows 100% detection on direct misclassification (C1) and reasoning corruption (C3), 98% on attention hijacking (C4), with 0% false positives. Whether this advantage holds against real model outputs and adaptive attackers (E8) remains open.

4. **Multi-agent correlation pipeline.** Our pipeline demonstrates that single-alert triage is insufficient — a correlator agent using IP clustering, technique chain matching, and temporal burst detection identifies multi-stage campaigns that individual alert classification misses, demonstrated on a simulated DarkSide ransomware scenario using hand-crafted triage decisions. A playbook agent generates NIST SP 800-61 response guidance with chain-aware severity escalation. Full model-driven evaluation pending GPU experiments.

5. **Defense evaluation protocol.** We implement 3 defense mechanisms — input sanitization, structured prompt architecture, and canary token detection — and design a fourth (dual-LLM verification). Our adaptive attacker evaluation follows Nasr et al. [2025] methodology; defense effectiveness results await GPU experiments.

6. **Benchmark-quality dataset with provenance.** We construct a benchmark from Splunk Attack Data with full MITRE ATT&CK technique mappings, detection rule associations, and provenance chains, aligning with the dataset adequacy recommendations for LLM-based security research [Liu2026] across four dimensions (rule association, MITRE mapping, provenance chain, scenario identifier).

7. **Open-source evaluation framework.** We release Hades, a modular multi-agent pipeline for adversarial evaluation of LLM triage systems, with a reproducibility harness (see scripts/reproduce_all.py) and a partial SOC-Bench [Cai2026] Fox-task scoring adapter.

## 1.4 Paper Organization

Section 2 provides background on SOC triage and LLM security. Section 3 defines our threat model, including the injection vector taxonomy and attacker knowledge assumptions. Section 4 describes the Hades system architecture. Section 5 details our experimental methodology. Section 6 presents results. Section 7 discusses implications, and Section 8 surveys related work.
