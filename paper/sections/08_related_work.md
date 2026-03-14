# 8. Related Work

## 8.1 LLM-Based Security Operations

CORTEX [Wei2025] is the closest prior work: a multi-agent LLM system for collaborative alert triage that demonstrates significant false positive reduction across enterprise scenarios. However, CORTEX does not evaluate adversarial robustness — all alerts are assumed benign or malicious without considering that the alert data itself may contain adversarial content. Our work complements CORTEX by asking: what happens when the data CORTEX processes is deliberately crafted to manipulate its decisions?

Commercial LLM-based SOC tools are rapidly being adopted: Microsoft Security Copilot achieves 26% faster and 44% more accurate SOC tasks in randomized controlled trials [Microsoft2024]; CrowdStrike Charlotte AI reports 98%+ accuracy in threat assessment. Simbian's SOC benchmark [Simbian2025] shows frontier LLMs complete 61–67% of 100 real-world investigation tasks — establishing that LLM SOC agents are capable enough to be deployed but imperfect enough that adversarial manipulation could have outsized impact. None of these systems have published adversarial robustness evaluations. The vulnerability we characterize applies to any system that feeds SIEM log data into an LLM prompt.

## 8.2 Prompt Injection Attacks

**AgentDojo** [Debenedetti2024] provides a dynamic benchmark for prompt injection on LLM agents with 97 tasks and 629 security test cases. It evaluates generic tool-use agents under indirect injection; we apply the same principle to SOC-specific pipelines with domain-specific constraints (field lengths, SIEM normalization, protocol semantics).

**"The Attacker Moves Second"** [Nasr2025] is the definitive work on adaptive prompt injection. A 14-author team from OpenAI, Anthropic, DeepMind, and ETH demonstrates that adaptive attackers bypass ALL existing prompt injection defenses. We adopt their adaptive attacker methodology (E8) and extend it to the SOC domain.

**Real-world validation.** Neaves [2025] at LevelBlue (AT&T Cybersecurity) demonstrates three successful indirect prompt injections through SOC/SIEM log files: HTTP User-Agent, SSH username, and Windows Event 4625 authentication records. In all cases, the LLM triage agent followed injected instructions, falsifying source IPs and hiding attack indicators. Unit 42 [2026] reports 22 distinct IDPI techniques observed in production telemetry, including the first documented case of AI-based ad review evasion.

**The hackerbot-claw campaign** [Datadog2026] provides compelling real-world validation of IPI in automated triage. In February–March 2026, an AI agent systematically targeted GitHub repositories with prompt injection payloads embedded in issue bodies and PR descriptions. When Datadog's Claude-powered issue triage workflow processed issue #47021, it encountered injection attempts but successfully blocked them — the Claude action logged: "The issue body contains an attempted prompt injection attack (which I ignored per instructions)." This demonstrates both the threat (attackers actively deploying IPI against LLM triage) and the potential for workflow-level defenses, validating our behavioral invariant approach.

**AgentLAB** [Jiang2026] introduces the first benchmark for long-horizon attacks on LLM agents, defining five attack types: intent hijacking, tool chaining, task injection, objective drifting, and memory poisoning across 644 security test cases. Their finding that "defenses designed for single-turn interactions fail to reliably mitigate long-horizon threats" reinforces our argument for workflow-level behavioral invariants that operate on triage outputs rather than individual prompt inputs.

**Indirect Prompt Injection in the Wild** [Chang2026] decomposes IPI into trigger and attack fragments, achieving near-100% retrieval across 11 benchmarks at $0.21/query. A single poisoned email coerced GPT-4o into exfiltrating SSH keys with >80% success. This establishes that IPI retrieval is a "critical open vulnerability" — Hades operates as a post-retrieval detection layer.

**AgentSentry** [Zhang2026a] introduces temporal causal diagnostics — counterfactual re-executions at tool-return boundaries to detect multi-turn IPI. It achieves 74.55% Utility Under Attack, +20.8–33.6pp over prior baselines. However, AgentSentry's counterfactual re-execution requires replaying tool calls — infeasible in live SOC environments where SIEM queries are non-deterministic. Hades uses behavioral invariant checking as a lightweight alternative.

**Adaptive IPI attacks** [Zhan2025, NAACL Findings] systematically bypass all 8 evaluated IPI defenses with >50% ASR using adaptive attacks, confirming that static defenses are insufficient in agent contexts.

**DataFilter** [Meng2025] proposes a model-agnostic defense that strips injections from external data before LLM processing, reporting near-zero ASR. However, DataFilter was not evaluated against the SOC-specific injection vectors we characterize (SIEM field injection, protocol-constrained payloads). Whether DataFilter's training generalizes to domain-specific attack patterns (e.g., homoglyph substitution in hostnames, zero-width characters in User-Agent strings) remains an open question our E8 adaptive experiments can address.

OWASP LLM Top 10 [2025] ranks prompt injection as LLM01, the #1 vulnerability for LLM applications.

## 8.3 MoE Architecture Vulnerabilities

Our cross-model comparison includes three MoE architectures (DeepSeek R1, Kimi K2.5, Qwen 3.5) plus GLM-5 as a dense control, making MoE-specific adversarial research directly relevant.

**L³ (Large Language Lobotomy)** [TeLintelo2026] demonstrates a training-free attack that silences safety-critical experts in MoE models, increasing ASR from 7.3% to 70.4% (peak 86.3%) by disabling <20% of layer-wise experts while preserving utility. **SAFEx** [Lai2025] identifies that safety behavior concentrates in specific expert groups (HCDG/HRCG) — disabling just 12 experts in Qwen3-30B reduces refusal rate by 22%.

These findings suggest that different MoE architectures may exhibit different adversarial vulnerability profiles depending on how safety-critical behavior is distributed across experts — a hypothesis our E1-E8 cross-model experiments can test. If injection payloads differentially exploit expert routing patterns, this would provide early evidence of architecture-dependent IPI vulnerability in SOC contexts.

## 8.4 Security Benchmarks

**CyBench** [Zhang2025] evaluates LLM offensive cybersecurity capabilities across 40 CTF-style tasks (ICLR 2025 Oral). Funded by a $2.9M Open Philanthropy grant, it benchmarks whether LLMs can *attack* systems. We benchmark whether LLMs deployed *defensively* can be attacked through their data pipelines — the complementary question.

**SOC-Bench** [Cai2026] defines design principles for evaluating multi-agent AI in SOC contexts, grounded in the Colonial Pipeline/DarkSide ransomware incident. Its five tasks (Fox: campaign detection, Tiger: attribution, Panda: containment, Goat: forensics, Mouse: exfiltration detection) provide a structured evaluation framework. Our adapter currently produces Fox-format outputs with simulated scoring (§6.9); Tiger schema support exists but is not evaluated; Panda, Goat, and Mouse are not addressed.

**SecBench** [Jing2024] benchmarks LLM cybersecurity knowledge through MCQ-style assessments. Unlike SecBench, we evaluate operational performance under adversarial conditions, not knowledge recall.

**SEC-bench** [Lee2025] introduces automated benchmarking for LLM agents on authentic security engineering tasks including PoC generation and vulnerability patching. Using a multi-agent scaffold that reproduces vulnerabilities in isolated environments, they find agents achieve at most 18.0% success on PoC generation and 34.0% on patching — highlighting significant performance gaps. While SEC-bench evaluates offensive security capabilities, Hades evaluates defensive robustness of security-deployed LLMs.

## 8.5 SIEM Data and Normalization

**SIEVE** [2025] generates synthetic SIEM logs using text augmentation techniques. While synthetic data addresses volume concerns, it lacks the provenance and rule associations required for benchmark-quality evaluation [Liu2026].

**CIC-IDS2017/2018** [Sharafaldin2018] provide labeled network flow data widely used in intrusion detection research. However, as Liu [2026] notes, these datasets lack SIEM rule associations, making them inadequate for research claiming to evaluate SOC triage systems. We use CIC-IDS2018 only as an engineering scaffold.

**Splunk Attack Data** provides curated attack datasets mapped to MITRE ATT&CK techniques with corresponding detection rules from the Splunk Security Content repository. This is our primary benchmark source, satisfying rule association, MITRE mapping, and provenance requirements.

## 8.6 RAG for Threat Intelligence

**TechniqueRAG** [Lekssays2025] (ACL Findings 2025) applies retrieval-augmented generation to MITRE ATT&CK technique identification, using BGE embeddings on ATT&CK descriptions. Our RAG component follows a similar architecture but focuses on retrieving context for triage decisions rather than technique classification.

**RAM** [Shabtai2025] maps SIEM rules to MITRE ATT&CK TTPs using LLMs, providing the intellectual foundation for our rule-linked benchmark construction.

## 8.7 Gap Analysis

Table 2 summarizes how our work fills gaps in the existing literature.

| Capability | CyBench | AgentDojo | AgentSentry | CORTEX | SOC-Bench | Hades |
|---|---|---|---|---|---|---|
| SOC-specific evaluation | ✗ | ✗ | ✗ | ✓ | ✓ | ✓ |
| Adversarial robustness | ✗ | ✓ | ✓ | ✗ | ✗ | ✓ |
| SIEM log field injection | ✗ | ✗ | ✗ | ✗ | ✗ | ✓ |
| Adaptive attacker eval | ✗ | ✗ | ✗ | ✗ | ✗ | ✓ (designed) |
| Rule-linked benchmark | ✗ | ✗ | ✗ | ✗ | ✓ | ✓ |
| Cross-model MoE comparison | ✗ | ✗ | ✗ | ✗ | ✗ | ✓ |
| Defense evaluation | ✗ | ✓ | ✓ | ✗ | ✗ | ✓ (designed) |
| Behavioral invariant detection | ✗ | ✗ | partial | ✗ | ✗ | ✓ (preliminary) |
| Open-source framework | ✓ | ✓ | ✓ | ✗ | ✗ | ✓ |
| Human study | ✗ | ✗ | ✗ | ✗ | ✗ | ✗ (L6) |
| Live deployment | ✗ | ✗ | ✗ | ✓ | ✗ | ✗ (L1) |

**Our contributions:** (1) a systematic framework for adversarial evaluation of LLM triage systems through SIEM log field injection, (2) cross-architecture vulnerability comparison of 4 frontier models (3 MoE + 1 dense control), (3) defense evaluation following the adaptive attacker methodology of [Nasr2025] and addressing the NAACL findings of [Zhan2025], (4) a benchmark-quality dataset with full provenance chain satisfying [Liu2026]'s dataset adequacy requirements, and (5) a Fox-task adapter for SOC-Bench [Cai2026] with preliminary simulated scoring; Tiger and Panda schema support exists but is not evaluated in this paper.

No prior work occupies the intersection of SOC-specific evaluation, SIEM-channel adversarial attack, and adaptive defense evaluation. AgentSentry [Zhang2026a] addresses adversarial robustness but not SOC workflows; CORTEX [Wei2025] addresses SOC triage but not adversarial robustness; SOC-Bench [Cai2026] defines evaluation structure but assumes benign inputs. Hades fills the gap where all three concerns converge.
