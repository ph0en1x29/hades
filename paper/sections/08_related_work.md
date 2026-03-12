# 8. Related Work

## 8.1 LLM-Based Security Operations

CORTEX [Wei2025] is the closest prior work: a multi-agent LLM system for collaborative alert triage that demonstrates significant false positive reduction across enterprise scenarios. However, CORTEX does not evaluate adversarial robustness — all alerts are assumed benign or malicious without considering that the alert data itself may contain adversarial content. Our work complements CORTEX by asking: what happens when the data CORTEX processes is deliberately crafted to manipulate its decisions?

Commercial LLM-based SOC tools are rapidly being adopted: Microsoft Security Copilot achieves 26% faster and 44% more accurate SOC tasks in randomized controlled trials [Microsoft2024]; CrowdStrike Charlotte AI reports 98%+ accuracy in threat assessment. Simbian's SOC benchmark [Simbian2025] shows frontier LLMs complete 61–67% of 100 real-world investigation tasks — establishing that LLM SOC agents are capable enough to be deployed but imperfect enough that adversarial manipulation could have outsized impact. None of these systems have published adversarial robustness evaluations. The vulnerability we characterize applies to any system that feeds SIEM log data into an LLM prompt.

## 8.2 Prompt Injection Attacks

**AgentDojo** [Debenedetti2024] provides a dynamic benchmark for prompt injection on LLM agents with 97 tasks and 629 security test cases. It evaluates generic tool-use agents under indirect injection; we apply the same principle to SOC-specific pipelines with domain-specific constraints (field lengths, SIEM normalization, protocol semantics).

**"The Attacker Moves Second"** [Nasr2025] is the definitive work on adaptive prompt injection. A 14-author team from OpenAI, Anthropic, DeepMind, and ETH demonstrates that adaptive attackers bypass ALL existing prompt injection defenses. We adopt their adaptive attacker methodology (E8) and extend it to the SOC domain.

**Real-world validation.** Neaves [2025] at LevelBlue (AT&T Cybersecurity) demonstrates three successful indirect prompt injections through SOC/SIEM log files: HTTP User-Agent, SSH username, and Windows Event 4625 authentication records. In all cases, the LLM triage agent followed injected instructions, falsifying source IPs and hiding attack indicators. Unit 42 [2026] reports 22 distinct IDPI techniques observed in production telemetry, including the first documented case of AI-based ad review evasion. These demonstrations validate our threat model with independent evidence.

**Indirect Prompt Injection in the Wild** [Chang2026] decomposes IPI into trigger and attack fragments, achieving near-100% retrieval across 11 benchmarks at $0.21/query. A single poisoned email coerced GPT-4o into exfiltrating SSH keys with >80% success. This establishes that IPI retrieval is a "critical open vulnerability" — Hades operates as a post-retrieval detection layer.

**AgentSentry** [Zhang2026] introduces temporal causal diagnostics — counterfactual re-executions at tool-return boundaries to detect multi-turn IPI. It achieves 74.55% Utility Under Attack, +20.8–33.6pp over prior baselines. However, AgentSentry's counterfactual re-execution requires replaying tool calls — infeasible in live SOC environments where SIEM queries are non-deterministic. Hades uses behavioral invariant checking as a lightweight alternative.

**Adaptive IPI attacks** [Zhan2025, NAACL Findings] systematically bypass all 8 evaluated IPI defenses with >50% ASR using adaptive attacks, confirming that static defenses are insufficient in agent contexts.

**DataFilter** [Meng2025] proposes a model-agnostic defense that strips injections from external data before LLM processing, reporting near-zero ASR. However, DataFilter was not evaluated against the SOC-specific injection vectors we characterize (SIEM field injection, protocol-constrained payloads). Whether DataFilter's training generalizes to domain-specific attack patterns (e.g., homoglyph substitution in hostnames, zero-width characters in User-Agent strings) remains an open question our E8 adaptive experiments can address.

OWASP LLM Top 10 [2025] ranks prompt injection as LLM01, the #1 vulnerability for LLM applications.

## 8.3 Security Benchmarks

**CyBench** [Zhang2025] evaluates LLM offensive cybersecurity capabilities across 40 CTF-style tasks (ICLR 2025 Oral). Funded by a $2.9M Open Philanthropy grant, it benchmarks whether LLMs can *attack* systems. We benchmark whether LLMs deployed *defensively* can be attacked through their data pipelines — the complementary question.

**SOC-Bench** [Liu2026] defines design principles for evaluating multi-agent AI in SOC contexts, grounded in the Colonial Pipeline/DarkSide ransomware incident. Its five tasks (Fox: campaign detection, Tiger: attribution, Panda: containment, Goat: forensics, Mouse: exfiltration detection) provide a structured evaluation framework. Our work could serve as the first system evaluated against SOC-Bench, with our adversarial angle measurable through the framework's formal rubric.

**SecBench** [Jing2024] benchmarks LLM cybersecurity knowledge through MCQ-style assessments. Unlike SecBench, we evaluate operational performance under adversarial conditions, not knowledge recall.

## 8.4 SIEM Data and Normalization

**SIEVE** [2025] generates synthetic SIEM logs using text augmentation techniques. While synthetic data addresses volume concerns, it lacks the provenance and rule associations required for benchmark-quality evaluation [Liu2026].

**CIC-IDS2017/2018** [Sharafaldin2018] provide labeled network flow data widely used in intrusion detection research. However, as Liu [2026] notes, these datasets lack SIEM rule associations, making them inadequate for research claiming to evaluate SOC triage systems. We use CIC-IDS2018 only as an engineering scaffold.

**Splunk Attack Data** provides curated attack datasets mapped to MITRE ATT&CK techniques with corresponding detection rules from the Splunk Security Content repository. This is our primary benchmark source, satisfying rule association, MITRE mapping, and provenance requirements.

## 8.5 RAG for Threat Intelligence

**TechniqueRAG** [Lekssays2025] (ACL Findings 2025) applies retrieval-augmented generation to MITRE ATT&CK technique identification, using BGE embeddings on ATT&CK descriptions. Our RAG component follows a similar architecture but focuses on retrieving context for triage decisions rather than technique classification.

**RAM** [Shabtai2025] maps SIEM rules to MITRE ATT&CK TTPs using LLMs, providing the intellectual foundation for our rule-linked benchmark construction.

## 8.6 Gap Analysis

Table 1 summarizes how our work fills gaps in the existing literature.

| Capability | CyBench | AgentDojo | AgentSentry | CORTEX | SOC-Bench | Hades |
|---|---|---|---|---|---|---|
| SOC-specific evaluation | ✗ | ✗ | ✗ | ✓ | ✓ | ✓ |
| Adversarial robustness | ✗ | ✓ | ✓ | ✗ | ✗ | ✓ |
| SIEM log field injection | ✗ | ✗ | ✗ | ✗ | ✗ | ✓ |
| Adaptive attacker eval | ✗ | ✗ | ✗ | ✗ | ✗ | ✓ |
| Rule-linked benchmark | ✗ | ✗ | ✗ | ✗ | ✓ | ✓ |
| Cross-model MoE comparison | ✗ | ✗ | ✗ | ✗ | ✗ | ✓ |
| Defense evaluation | ✗ | ✓ | ✓ | ✗ | ✗ | ✓ |
| Behavioral invariant detection | ✗ | ✗ | partial | ✗ | ✗ | ✓ |
| Open-source framework | ✓ | ✓ | ✓ | ✗ | ✗ | ✓ |

**Our unique contributions:** (1) the first systematic adversarial evaluation of LLM triage systems through SIEM log field injection, (2) cross-architecture vulnerability comparison of 4 frontier MoE models, (3) defense evaluation following the adaptive attacker methodology of [Nasr2025] and addressing the NAACL findings of [Zhan2025], (4) a benchmark-quality dataset with full provenance chain satisfying [Liu2026]'s dataset adequacy requirements, and (5) SOC-Bench-compatible output schemas enabling direct comparison with future SOC AI systems.

No prior work occupies the intersection of SOC-specific evaluation, SIEM-channel adversarial attack, and adaptive defense evaluation. AgentSentry [Zhang2026a] addresses adversarial robustness but not SOC workflows; CORTEX [Wei2025] addresses SOC triage but not adversarial robustness; SOC-Bench [Liu2026] defines evaluation structure but assumes benign inputs. Hades fills the gap where all three concerns converge.
