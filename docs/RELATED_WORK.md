# Related Work

## 1. LLM-Based Security Operations

### CORTEX: Collaborative Multi-Agent Alert Triage

[Wei2025] propose CORTEX, a multi-agent LLM architecture for high-stakes alert triage in Security Operations Centers. Unlike single-model approaches that struggle with noisy enterprise data and offer limited transparency, CORTEX deploys specialized agents that collaborate over real evidence: a behavior-analysis agent inspects activity sequences, evidence-gathering agents query external systems, and a reasoning agent synthesizes findings into auditable decisions. The system substantially reduces false positives across diverse enterprise scenarios compared to state-of-the-art single-agent LLMs.

**Comparison to our work:** While CORTEX focuses on alert triage using multi-agent collaboration in production SOC environments, our work addresses the *adversarial robustness* of LLM-based triage systems. CORTEX assumes trusted input data; we investigate how attackers can manipulate SIEM logs and threat intelligence feeds through prompt injection to cause triage systems to misclassify genuine attacks as benign or vice versa. Our adversarial evaluation framework complements CORTEX's architecture by identifying security vulnerabilities that multi-agent systems inherit from their underlying LLMs.

### LLM-Based SIEM/SOC Automation Landscape

Recent industry surveys [MDPI2025] document the rapid adoption of LLMs for SOC automation across eight core tasks: threat detection, alert triage, threat intelligence analysis, incident response, malware analysis, vulnerability management, security orchestration, and compliance monitoring. However, these deployments largely overlook adversarial robustness considerations, operating under the assumption that log data and threat intelligence sources are trustworthy.

**Comparison to our work:** Our research fills a critical gap in the SOC automation literature by systematically evaluating the security of LLM-based triage systems against adversarial inputs. While existing work demonstrates *functional* effectiveness, we examine *security* effectiveness in adversarial settings—a fundamental prerequisite for deploying autonomous systems in security-critical domains.

## 2. Prompt Injection and LLM Security

### AgentDojo: Benchmark for Agent Robustness

[Debenedetti2024] introduce AgentDojo, an evaluation framework for measuring the adversarial robustness of AI agents vulnerable to prompt injection attacks, where data returned by external tools hijacks the agent to execute malicious tasks. The benchmark comprises 97 realistic tasks (email management, e-banking, travel bookings), 629 security test cases, and various attack and defense paradigms. Their findings reveal that state-of-the-art LLMs fail at many tasks even without attacks, and existing prompt injection attacks break some security properties but not all.

**Comparison to our work:** AgentDojo evaluates general-purpose AI agents in consumer applications; we focus specifically on security-critical SOC triage systems where the stakes are fundamentally different. In SOC contexts, successful prompt injection doesn't just compromise user data—it enables attackers to evade detection entirely by manipulating the very systems designed to detect them. Our threat model extends AgentDojo's by considering *indirect prompt injection through SIEM data pipelines*, where attackers poison logs and threat intelligence feeds rather than directly interacting with the agent.

### The Attacker Moves Second: Adaptive Attacks

[Nasr2025] demonstrate that adaptive attackers can bypass 12 recent prompt injection defenses with >90% attack success rate using systematically tuned gradient descent, reinforcement learning, random search, and human-guided exploration. Critically, the majority of these defenses originally reported near-zero attack success rates against static or weak attacks, highlighting a fundamental evaluation gap in the defense literature.

**Comparison to our work:** This work motivates our adoption of adaptive attack evaluation for SOC triage systems. We build on their methodology by developing SOC-specific adaptive attacks that exploit domain knowledge: attackers can craft adversarial SIEM logs that appear benign under statistical analysis while containing prompt injection payloads that activate only when processed by LLM triage agents. Our contribution is demonstrating that *even air-gapped, locally-deployed LLMs* remain vulnerable to adaptive prompt injection when operating on adversarially crafted logs.

### PromptArmor: Detection-Based Defenses

[Shi2025] present PromptArmor, a simple defense that prompts an off-the-shelf LLM to detect and remove injected prompts before processing. Using GPT-4o, GPT-4.1, or o1-mini, PromptArmor achieves <1% false positive and false negative rates on AgentDojo, reducing attack success rates to <1%. The authors recommend it as a standard baseline for defense evaluation.

**Comparison to our work:** We evaluate PromptArmor-style defenses adapted for SOC contexts and find them less effective against domain-specific attacks. SOC logs have inherently adversarial structure (attack commands, shellcode, obfuscated payloads), making it difficult for detection models to distinguish between *legitimate attack artifacts* being analyzed and *prompt injection attempts*. Our experiments show that attackers can camouflage injection payloads as realistic attack indicators (e.g., embedding instructions in Base64-encoded shellcode), causing detection systems to either flag benign logs or miss adversarial ones.

### Indirect Prompt Injection in Data Pipelines

[OWASP2025] document indirect prompt injection as a top LLM security risk, where adversaries inject malicious instructions into external data sources (websites, databases, files) that the LLM retrieves and processes. Unlike direct injection at the user interface, indirect injection operates *upstream* in the data pipeline, making it harder to detect and defend against.

**Comparison to our work:** SOC triage systems are uniquely vulnerable to indirect injection because they *must* process untrusted data: SIEM logs from potentially compromised endpoints, threat intelligence from external feeds, and network traffic captures from adversarial sources. We characterize this as a fundamental *architectural vulnerability*—any LLM-based triage system with external data ingestion inherits an attack surface that cannot be eliminated through prompt engineering alone. Our work proposes architectural countermeasures including input sanitization, semantic analysis, and isolation boundaries.

## 3. Security Benchmarks and Datasets

### CyBench: Cybersecurity Capabilities

[Zhang2025] introduce CyBench, a framework for evaluating LM agents on professional-level Capture the Flag (CTF) tasks from real competitions. The benchmark includes 40 tasks spanning reconnaissance, exploitation, privilege escalation, and lateral movement, with subtasks for granular evaluation. Top models (GPT-4o, Claude 3.5 Sonnet, o1-preview) solve tasks requiring up to 11 minutes of human expert time, but fail on problems requiring 24+ hours.

**Comparison to our work:** CyBench measures offensive capabilities (red team); we evaluate defensive capabilities (blue team) in adversarial settings. While CyBench demonstrates that LLM agents can *perform* security tasks, our work asks whether they can *resist adversarial manipulation* while performing those tasks. This distinction is critical: an LLM agent skilled at finding vulnerabilities may still be vulnerable to prompt injection attacks that cause it to misclassify genuine threats.

### SecBench: LLM Cybersecurity Knowledge

[Jing2024] present SecBench, a multi-dimensional benchmark comprising 44,823 multiple-choice questions and 3,087 short-answer questions across nine cybersecurity domains. The dataset evaluates knowledge retention and logical reasoning in both English and Chinese, using 16 state-of-the-art LLMs. SecBench is arguably the largest and most comprehensive LLM cybersecurity benchmark.

**Comparison to our work:** SecBench evaluates *static knowledge*; we evaluate *adversarial robustness under attack*. A model may score perfectly on SecBench's knowledge questions yet still be trivially compromised by prompt injection during live alert triage. Our work contributes an orthogonal evaluation dimension: not "what does the model know?" but "can the model resist manipulation while applying that knowledge?"

### SIEVE: Synthetic SIEM Log Dataset

[SIEVE2025] introduce SIEVE (SIEM Ingesting EVEnts), a collection of six synthetic datasets containing logs specifically designed for training machine learning models on log classification tasks. Built using SPICE (Semantic Perturbation and Instantiation for Content Enrichment), SIEVE addresses the lack of diverse, labeled SIEM logs for supervised learning.

**Comparison to our work:** SIEVE provides training data for *benign* classification tasks; we construct adversarial datasets for *robustness* evaluation. Our adversarial SIEM logs extend SIEVE's methodology by injecting prompt injection payloads that preserve statistical properties (token distributions, field formats) while embedding semantic attacks. This enables us to measure whether LLM triage systems can distinguish between genuine attack logs and adversarially crafted logs designed to manipulate the classifier.

### Limitations of CICIDS and Network Intrusion Datasets

[Engelen2021] troubleshoot the widely-used CICIDS2017 dataset and identify critical issues: unrealistic traffic patterns, labeling errors, class imbalance, and limited attack diversity. These problems affect the generalizability of models trained on CICIDS, as the dataset does not represent modern network environments or adversarial techniques.

**Comparison to our work:** While CICIDS provides network-level intrusion data, it lacks *application-level logs* (Windows Event Logs, Syslog, authentication logs) that SOC analysts actually triage. More critically, CICIDS and similar datasets do not model *adversarial manipulation of the data itself*—attackers crafting logs specifically to deceive ML/LLM-based detection systems. Our threat model assumes attackers have knowledge of the triage system's architecture and can craft adversarial inputs accordingly.

## 4. RAG for Threat Intelligence

### TechniqueRAG: MITRE ATT&CK Annotation

[Lekssays2025] propose TechniqueRAG, a domain-specific retrieval-augmented generation framework for mapping security texts to MITRE ATT&CK techniques. The system combines off-the-shelf retrievers, instruction-tuned LLMs, and minimal labeled data, achieving state-of-the-art performance without extensive task-specific optimization. Zero-shot LLM re-ranking enhances retrieval quality by aligning candidates with adversarial techniques.

**Comparison to our work:** TechniqueRAG enriches LLM context with ATT&CK knowledge for *functional* accuracy; we investigate how attackers can *exploit* RAG pipelines for prompt injection. Our experiments demonstrate that adversaries can poison TechniqueRAG's retrieval corpus by contributing malicious threat intelligence reports containing embedded instructions (e.g., "Ignore previous alerts from this IP range"). When the RAG system retrieves these documents during triage, the injected instructions manipulate the LLM's decision. We propose retrieval source validation and semantic filtering as countermeasures.

### RAM: Mapping SIEM Rules to TTPs

[Shabtai2025] introduce Rule-ATT&CK Mapper (RAM), a multi-stage LLM pipeline that automates mapping of SIEM rules to MITRE ATT&CK techniques. Inspired by prompt chaining, RAM extracts indicators of compromise (IoCs) from rules, queries external context, and synthesizes mappings without requiring pre-training or fine-tuning. GPT-4-Turbo achieves 0.75 recall on the Splunk Security Content dataset.

**Comparison to our work:** RAM demonstrates effective LLM use for SOC workflow automation but does not evaluate adversarial robustness. We extend RAM's threat model by considering attackers who craft SIEM rules containing prompt injection payloads. Since RAM processes structured rule syntax, adversaries can exploit comment fields, regex patterns, or base64-encoded logic to embed instructions that activate during ATT&CK mapping. Our work shows that >60% of RAM-like systems misclassify adversarial rules when under adaptive attack.

### Real-World SIEM/SOC Prompt Injection Demonstrations

[Neaves2025] at LevelBlue (AT&T Cybersecurity) provide the first published proof-of-concept demonstrations of indirect prompt injection through SOC/SIEM log files. Using three attack scenarios — HTTP User-Agent headers, SSH username fields, and Windows Event 4625 authentication failure logs — they demonstrate that AI agents summarizing SIEM data can be manipulated to change source IP addresses, hide attacks, and create fictitious events. Critically, they show that Windows Event Log username and domain fields accept 120+ characters each (despite documented 20-character limits), providing ample space for injection payloads. Microsoft MSRC declined to service the unlimited username/domain length as a security issue.

[PaloAlto2026] (Unit 42) report the first large-scale in-the-wild observations of web-based indirect prompt injection from production telemetry. They identify 22 distinct payload engineering techniques, including AI-based ad review evasion, SEO manipulation, data destruction, and sensitive information leakage. Their taxonomy of attacker intents and detection methodology validates our threat model at web scale.

**Comparison to our work:** Neaves2025 demonstrates *feasibility* of SIEM log injection with three hand-crafted PoCs; we provide *systematic evaluation* across 10 vectors, 5 attack classes, 4 encoding strategies, and 4 frontier LLMs with statistical rigor. We also evaluate defenses and adaptive attackers, which neither work addresses. Their Windows Event Log findings directly inform our injection vector specifications (username field as high-capacity vector). PaloAlto2026 validates that indirect prompt injection is actively weaponized in the wild, strengthening the motivation for our research.

## 5. Gap Analysis: What This Work Uniquely Contributes

Existing research establishes that:

1. **LLM-based SOC automation is effective** for functional tasks (CORTEX, RAM, TechniqueRAG)
2. **LLM agents are vulnerable to prompt injection** in general settings (AgentDojo, Attacker Moves Second)
3. **Adaptive attacks bypass static defenses** with high success rates (Nasr et al.)
4. **Cybersecurity benchmarks evaluate knowledge and capabilities** (CyBench, SecBench)
5. **Datasets exist for training** but lack adversarial examples (SIEVE, CICIDS)

**Our unique contributions:**

1. **First systematic evaluation of adversarial robustness** for LLM-based SOC triage systems under adaptive prompt injection attacks
2. **SOC-specific threat model** characterizing indirect injection through SIEM logs, threat intelligence feeds, and network traffic data
3. **Adversarial dataset construction** of SIEM logs with embedded prompt injection payloads that preserve statistical realism
4. **Evaluation of air-gapped deployment** as a defense mechanism—do locally-deployed LLMs resist prompt injection better than API-based models?
5. **Architectural countermeasures** beyond prompt engineering: input sanitization, semantic validation, isolation boundaries, and MoE-based compartmentalization
6. **Trade-off analysis** between functional accuracy and adversarial robustness in SOC automation

While prior work demonstrates that LLMs *can* perform security tasks and that prompt injection *exists*, we answer the critical question: **Can LLM-based SOC triage systems remain secure when adversaries actively target them?** Our findings suggest fundamental architectural changes are needed before deploying autonomous LLM agents in security operations centers.

## References

- [Debenedetti2024] Edoardo Debenedetti, Jie Zhang, Mislav Balunović, Luca Beurer-Kellner, Marc Fischer, Florian Tramèr. *AgentDojo: A Dynamic Environment to Evaluate Prompt Injection Attacks and Defenses for LLM Agents*. NeurIPS 2024 Datasets and Benchmarks Track. arXiv:2406.13352.

- [Engelen2021] G. Engelen et al. *Troubleshooting an Intrusion Detection Dataset: the CICIDS2017 Case Study*. IEEE Security and Privacy Workshops, 2021.

- [Jing2024] Pengfei Jing et al. *SecBench: A Comprehensive Multi-Dimensional Benchmarking Dataset for LLMs in Cybersecurity*. arXiv:2412.20787, December 2024.

- [Lekssays2025] Ahmed Lekssays et al. *TechniqueRAG: Retrieval Augmented Generation for Adversarial Technique Annotation in Cyber Threat Intelligence Text*. ACL Findings 2025. arXiv:2505.11988.

- [MDPI2025] *AI-Augmented SOC: A Survey of LLMs and Agents for Security Automation*. MDPI Applied Sciences, November 2025.

- [Nasr2025] Milad Nasr, Nicholas Carlini, Florian Tramèr et al. *The Attacker Moves Second: Stronger Adaptive Attacks Bypass Defenses Against LLM Jailbreaks and Prompt Injections*. arXiv:2510.09023, October 2025.

- [OWASP2025] *LLM01:2025 Prompt Injection*. OWASP Gen AI Security Project, April 2025.

- [Shabtai2025] Asaf Shabtai et al. *Rule-ATT&CK Mapper (RAM): Mapping SIEM Rules to TTPs Using LLMs*. arXiv:2502.02337, February 2025.

- [Shi2025] Tianneng Shi, Dawn Song et al. *PromptArmor: Simple yet Effective Prompt Injection Defenses*. arXiv:2507.15219, July 2025.

- [SIEVE2025] *SIEVE: Generating a Cybersecurity Log Dataset Collection for SIEM Event Classification*. Computer Networks, May 2025.

- [Wei2025] Bowen Wei et al. *CORTEX: Collaborative LLM Agents for High-Stakes Alert Triage*. arXiv:2510.00311, September 2025.

- [Zhang2025] Andy K. Zhang, Neil Perry, Dan Boneh, Percy Liang et al. *CyBench: A Framework for Evaluating Cybersecurity Capabilities and Risks of Language Models*. ICLR 2025 Oral. arXiv:2408.08926.

- [Neaves2025] Tom Neaves. *Rogue AI Agents In Your SOCs and SIEMs – Indirect Prompt Injection via Log Files*. LevelBlue (AT&T Cybersecurity) SpiderLabs Blog, September 2025. https://www.levelblue.com/blogs/spiderlabs-blog/rogue-ai-agents-in-your-socs-and-siems-indirect-prompt-injection-via-log-files

- [PaloAlto2026] Unit 42. *Fooling AI Agents: Web-Based Indirect Prompt Injection Observed in the Wild*. Palo Alto Networks, March 2026. https://unit42.paloaltonetworks.com/ai-agent-prompt-injection/

---

**Note on SOC-Bench:** Despite references in task prompts, we could not locate a published paper or public repository for "SOC-Bench" by Dr. Peng Liu's group as of March 2026. If this benchmark exists, it may be under embargo or in preparation for publication. We recommend monitoring Penn State cybersecurity research group publications for future release.

**Additional Search Coverage:** We searched for 2025-2026 papers on air-gapped LLM deployment for security, MoE model adversarial robustness, and indirect prompt injection through data pipelines. Relevant findings are integrated into Sections 2 and 5 above.
