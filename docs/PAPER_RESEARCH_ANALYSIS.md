# Hades: Related Paper Research & Analysis
*Generated: 2026-03-12 | Sources: arXiv, LevelBlue SpiderLabs, Palo Alto Unit42*

---

## Table of Contents
1. [Indirect Prompt Injection in the Wild (arXiv:2601.07072)](#1-indirect-prompt-injection-in-the-wild)
2. [AgentSentry (arXiv:2602.22724)](#2-agentsentry)
3. [The Attacker Moves Second (arXiv:2510.09023)](#3-the-attacker-moves-second)
4. [CORTEX (arXiv:2510.00311)](#4-cortex-collaborative-llm-agents-for-alert-triage)
5. [LLMs for SOCs Survey (arXiv:2509.10858)](#5-llms-for-socs-a-comprehensive-survey)
6. [CyBench ICLR 2025 (arXiv:2408.08926)](#6-cybench-iclr-2025)
7. [AgentDojo NeurIPS 2024 (arXiv:2406.13352)](#7-agentdojo-neurips-2024)
8. [LevelBlue/SpiderLabs – Rogue AI Agents in Your SOCs (Sept 2025)](#8-levelblue-spiderlabs--rogue-ai-agents-in-your-socs)
9. [Palo Alto Unit42 – IDPI in the Wild (Dec 2025)](#9-palo-alto-unit42--idpi-in-the-wild)
10. [TechniqueRAG ACL Findings 2025 (arXiv:2505.11988)](#10-techniquerag-acl-findings-2025)

---

## 1. Indirect Prompt Injection in the Wild

**Citation:** Chang, H. et al. "Overcoming the Retrieval Barrier: Indirect Prompt Injection in the Wild for LLM Systems." arXiv:2601.07072 [cs.CR], Jan 11, 2026.

### Methodology
- **Core insight:** Decomposes malicious content into two fragments:
  - **Trigger fragment** — crafted to guarantee retrieval under natural user queries (optimized via embedding model API)
  - **Attack fragment** — encodes the actual malicious objective (arbitrary)
- **Attack algorithm:** Black-box; requires only API access to target embedding models. Constructs the trigger fragment by solving a retrieval optimization problem: find compact text such that cosine similarity to a target query exceeds a threshold.
- **Cost:** As low as **$0.21 per target user query** against OpenAI's embedding models.
- **Scope:** Evaluated on both RAG systems and multi-agent agentic pipelines. End-to-end IPI exploits demonstrated under realistic natural queries and real external corpora.

### Key Results / Numbers
- **Near-100% retrieval rate** across **11 benchmarks** and **8 embedding models** (open-source + proprietary)
- **>80% success rate** coercing GPT-4o to exfiltrate SSH keys in a multi-agent workflow from a single poisoned email
- Existing defenses evaluated — none sufficiently prevent retrieval of malicious text
- Retrieval labeled "a critical open vulnerability" that prior work side-stepped

### Methodology Gaps / What Hades Fills
- The paper focuses on **guaranteeing retrieval** but not on **detecting or attributing** the attack once it succeeds. Hades operates as a downstream detection/response system — it observes the agent's behavior after malicious content has been retrieved and identifies the deviation.
- The paper's threat model assumes a **passive external attacker** planting content. Hades addresses the **active in-flight scenario**: detecting the attack as the agent acts, not preventing poisoning upstream.
- **SOC-specific**: The email exfiltration demo is closest to Hades' domain; we can cite the 80% SSH key exfiltration result as evidence of practical severity.

### Claims to Cite / Address
- ✅ **Cite:** Near-100% retrieval across 11 benchmarks; $0.21/query cost; >80% data exfiltration success — establishes baseline severity.
- ✅ **Cite:** "Retrieval is a critical open vulnerability" — motivates Hades as post-retrieval defense layer.
- ⚠️ **Must address:** Defenses evaluated in this paper focus on preventing retrieval. Hades does not prevent retrieval — it detects the consequences. Frame Hades as complementary, not competing.

---

## 2. AgentSentry

**Citation:** Zhang, T., Xu, Y., Wang, J., et al. "Mitigating Indirect Prompt Injection in LLM Agents via Temporal Causal Diagnostics and Context Purification." arXiv:2602.22724 [cs.CR], Feb 26, 2026.

### Methodology
- **Core claim:** First inference-time defense to model multi-turn IPI as a **temporal causal takeover**.
- **Mechanism:**
  1. **Takeover localization:** Controlled counterfactual re-executions at tool-return boundaries — replays the trajectory with the suspicious tool output masked/replaced and observes behavioral divergence.
  2. **Context purification:** Once a takeover point is identified, causally guided purification removes attack-induced deviations from agent context while preserving task-relevant evidence.
  3. **Safe continuation:** Agent resumes execution from purified context rather than aborting the task.
- **Benchmark:** AgentDojo (4 task suites, 3 IPI attack families, multiple black-box LLMs including GPT-4o, Claude, Llama variants).
- Key limitation of prior work cited: MELON (masked re-execution detection) achieves only 32.91% utility under attack on GPT-4o — too aggressive in blocking.

### Key Results / Numbers
- **Average Utility Under Attack (UA): 74.55%** across all suites
- **Improvement over strongest baselines: +20.8 to +33.6 percentage points in UA**
- **Eliminates successful attacks** in tested scenarios
- **No degradation in benign performance**
- MELON comparison: 32.91% UA → AgentSentry: 74.55% (>2× improvement)
- Under review (not yet published at a venue as of Feb 2026)

### Methodology Gaps / What Hades Fills
- AgentSentry operates on **general-purpose agent tasks** (email, banking, travel). It has **no SOC/SIEM domain model** — it doesn't understand that log line mutations, IP address changes, or alert severity rewrites are adversarial.
- **Counterfactual re-execution** requires the ability to **re-run tool calls** — in a live SOC environment, re-querying SIEM with a redacted query may not be feasible or deterministic. Hades uses behavioral signatures and output analysis, not re-execution.
- AgentSentry treats all tool-return boundaries equally. Hades can prioritize **high-stakes tool outputs** (e.g., SIEM alert ingest, threat intel feeds) for deeper scrutiny based on SOC-specific risk weighting.
- No coverage of **multi-hop log injection** scenarios (e.g., attacker controls log entries across multiple sources that together form an injection).

### Claims to Cite / Address
- ✅ **Cite:** 74.55% UA — the current SOTA for defense utility under IPI attack; Hades should target comparable or superior UA in SOC-specific benchmarks.
- ✅ **Cite:** Counterfactual re-execution as a detection approach — cite as prior art, describe Hades' complementary behavioral approach.
- ⚠️ **Must address:** AgentSentry's method is the strongest current defense baseline. Hades must either benchmark against it on AgentDojo or clearly scope to the SOC domain where AgentSentry's assumptions break.
- ⚠️ **Must address:** "First inference-time defense modeling temporal causal takeover" — Hades does not make this same claim; our framing is domain-specialized behavioral detection, not causal re-execution.

---

## 3. The Attacker Moves Second

**Citation:** Nasr, M., Carlini, N., Sitawarin, C., Schulhoff, S.V., Hayes, J., et al. (OpenAI/Anthropic/Google DeepMind/ETH Zürich). "The Attacker Moves Second: Stronger Adaptive Attacks Bypass Defenses Against LLM Jailbreaks and Prompt Injections." arXiv:2510.09023 [cs.LG], Oct 10, 2025 (revised June 2025 internally).

### Methodology
- **Core argument:** Defense evaluations are flawed because they test against static or computationally weak attacks. In adversarial ML, defenses must be evaluated against **adaptive attackers** who design their attack specifically to circumvent the defense.
- **Approach:** Systematically applied 4 optimization techniques adapted to each defense:
  1. Gradient descent (white-box)
  2. Reinforcement learning
  3. Random search
  4. Human-guided exploration (red-teaming)
- **Scope:** Attacked **12 recent defenses** spanning 4 technique categories (prompt engineering, fine-tuning, inference-time detection, architectural).
- **Targets:** Both jailbreak defenses (preventing harmful content) and prompt injection defenses.

### Key Results / Numbers
- **>90% attack success rate (ASR) bypassing most of the 12 defenses**
- **Original reported ASR by defense papers: near-zero** for the majority
- Human red-teaming succeeded on **100% of tested scenarios** where static attacks succeeded on **0%**
- All 4 optimization techniques, when adapted to a specific defense, broke it
- Conclusion: "No current defense is robust to strong adaptive attacks"

### Methodology Gaps / What Hades Fills
- The paper addresses **single-turn or short-horizon** jailbreaks and prompt injections. Hades operates on **multi-turn SOC agent workflows** — the attack surface is the persistent agent context over an investigation session.
- Carlini et al.'s defenses are **model-level or prompt-level**. Hades operates at the **workflow/orchestration level** — the attack still needs to cause observable downstream behavioral anomalies even if the injection bypasses model-level guardrails.
- The paper doesn't model **domain-specific behavioral invariants**. In a SOC, Hades can flag anomalies that are domain-recognizable even if the LLM complied (e.g., an alert being upgraded when no new evidence arrived, or an IP address changing in a summary).
- This paper is the **most important threat to Hades' defense claims**. Any defense paper must respond to Carlini et al.

### Claims to Cite / Address
- ✅ **Cite:** ">90% bypass of 12 defenses with adaptive attacks" — motivates why Hades cannot rely solely on prompt-level defenses; must incorporate behavioral/environmental invariant checks.
- ✅ **Cite:** "Near-zero ASR claimed vs. >90% actual" — demonstrates evaluation gap; Hades should benchmark with adaptive attack baselines, not static injections.
- 🚨 **Critical to address:** This paper will be cited by reviewers against any defense claim Hades makes. Response: (1) Hades adds a **domain-behavioral detection layer** orthogonal to model-level defenses that Carlini et al. attacked; (2) Hades uses **environment-state invariants** (e.g., SIEM audit logs, alert state machine) that are harder for attackers to manipulate post-injection without triggering external system alerts; (3) frame Hades as **raising attacker cost**, not claiming perfect robustness.
- ⚠️ **Must address:** Do not claim "Hades prevents IPI" — claim "Hades detects and attributes IPI with high precision in SOC contexts, complementing model-level defenses."

---

## 4. CORTEX: Collaborative LLM Agents for Alert Triage

**Citation:** Wei, B. et al. "Collaborative LLM Agents for High-Stakes Alert Triage." arXiv:2510.00311 [cs.CL], Sep 30, 2025.

### Methodology
- **Architecture:** Multi-agent LLM pipeline for SOC alert triage. Three specialized agent roles:
  1. **Behavior-analysis agent** — inspects activity sequences (process chains, network flows)
  2. **Evidence-gathering agents** — query external systems (EDR, SIEM, threat intel)
  3. **Reasoning agent** — synthesizes findings into an auditable decision (True Positive / False Positive)
- **Key property:** Agents collaborate over **real evidence**, not simulated data. Decision is **auditable** — the reasoning trace is preserved.
- **Dataset:** Released a dataset of "fine-grained SOC investigations from production environments, capturing step-by-step analyst actions and linked tool outputs." (Exact size not in abstract; paper not yet at a venue.)
- **Comparison baseline:** Single-agent LLMs applied end-to-end to alert triage.

### Key Results / Numbers
- **Substantially reduces false positives** over single-agent LLMs (exact % not in abstract — paper needed)
- **Improves investigation quality** across diverse enterprise scenarios
- No specific accuracy numbers extractable from abstract alone; paper is a preprint
- Dataset: described as "production environments" — implies real SOC data, not synthetic

### Methodology Gaps / What Hades Fills
- CORTEX addresses **alert triage** (TP/FP classification) but **does not model adversarial manipulation of the inputs**. If an attacker embeds IPI in the logs or threat intel feeds CORTEX agents query, the pipeline would be compromised — CORTEX has no adversarial robustness layer.
- CORTEX's agents are **role-specialized but not adversarially hardened**. Hades specifically models the threat that the evidence-gathering step itself is poisoned.
- **Complementarity:** Hades could serve as the adversarial safety layer on top of a CORTEX-like architecture — detecting when a CORTEX agent's tool outputs have been tampered with.
- CORTEX focuses on **TP/FP decision quality**, not on **attacker-injected false context**. These are different problems.

### Claims to Cite / Address
- ✅ **Cite:** CORTEX as the closest existing SOC multi-agent architecture — establishes that the multi-agent SOC paradigm is real and deployed.
- ✅ **Cite:** "Classical detection pipelines are brittle and context-poor" — supports Hades' motivation.
- ⚠️ **Must address:** Distinguish Hades from CORTEX. CORTEX = better triage. Hades = adversarially robust triage. Frame as orthogonal or composable.

---

## 5. LLMs for SOCs: A Comprehensive Survey

**Citation:** Habibzadeh, A. et al. "Large Language Models for Security Operations Centers: A Comprehensive Survey." arXiv:2509.10858 [cs.CR], Sep 13, 2025 (v2: Sep 19, 2025).

### Methodology
- **Type:** Systematic literature survey — structured review of generative AI / LLM integration in SOC workflows.
- **Scope:** Covers capabilities, challenges, and future directions for LLMs in:
  - Log analysis automation
  - Alert triage and prioritization
  - Detection accuracy improvement
  - Threat intelligence provision
- **Claim:** "First comprehensive study to examine LLM applications in SOCs in detail."
- Authors: Ali Habibzadeh et al. (Wuhan University area based on prior work pattern).

### Key Results / Numbers
- Survey findings (from abstract + structure, not detailed tables):
  - SOCs face: **high alert volumes**, limited resources, **analyst burnout**, delayed response times
  - LLMs offer: automated log analysis, streamlined triage, improved detection accuracy, faster knowledge retrieval
  - **Gaps identified:** No specific adversarial robustness coverage in reviewed literature (implied by absence — this is where Hades fits)
- Paper covers academic state-of-the-art as of September 2025 — predates AgentSentry, CORTEX, and LevelBlue/Unit42 findings

### Methodology Gaps / What Hades Fills
- Survey explicitly identifies the research gap of **LLM integration challenges** in SOCs but does not address **LLM adversarial attacks specifically targeting SOC agents**.
- Identifies "high alert volumes" as challenge — this is also the attack surface: high volume reduces human scrutiny, enabling IPI to slip through.
- No surveyed work addresses **log-file-based IPI** (the LevelBlue attack class), which Hades specifically targets.

### Claims to Cite / Address
- ✅ **Cite:** "High alert volumes, analyst burnout" — Hades' motivation. SOC analysts process 10,000s of alerts daily; AI agents are being deployed; this creates the attack surface.
- ✅ **Cite:** As the foundational survey positioning the research landscape — Hades' "Related Work" section should cite this as the state of LLM-SOC integration literature.
- ✅ **Cite:** "First comprehensive study" claim confirms no prior comprehensive adversarial treatment of this space.
- ⚠️ **Must address:** Paper was published Sep 2025 — confirm it doesn't cover log injection attacks (it likely doesn't based on date; LevelBlue was Sep 5, 2025 but may have been concurrent or just after cutoff).

---

## 6. CyBench ICLR 2025

**Citation:** Zhang, A.K., Perry, N., Dulepet, R., Ji, J., et al. (Dan Boneh, Daniel E. Ho, Percy Liang). "Cybench: A Framework for Evaluating Cybersecurity Capabilities and Risks of Language Models." arXiv:2408.08926 [cs.CR]. **ICLR 2025 Oral.**

### Methodology
- **Task type:** Capture the Flag (CTF) — autonomous LM agent must solve real cybersecurity challenges
- **Dataset:**
  - **40 professional-level CTF tasks** from **4 distinct competitions**
  - Tasks chosen to be recent, meaningful, spanning wide difficulty range
  - Each task: own description, starter files, initialized environment with command execution
  - **Subtasks** introduced to break tasks into intermediate steps for granular evaluation
- **Models evaluated:** 8 total:
  - GPT-4o, OpenAI o1-preview, Claude 3 Opus, Claude 3.5 Sonnet, Mixtral 8×22B Instruct, Gemini 1.5 Pro, Llama 3 70B Chat, Llama 3.1 405B Instruct
- **Scaffolds tested** (for top models): Structured bash, action-only, pseudoterminal, web search
- Code/data: publicly available at cybench.github.io

### Key Results / Numbers
- **Top performers:** Claude 3.5 Sonnet and GPT-4o solved tasks that took human teams **up to 11 minutes**
- **Hardest task:** Required human teams **24 hours 54 minutes** — not solved by any agent
- Human comparison framing — no single task completion % given in abstract (full paper needed for exact solve rates)
- **ICLR 2025 Oral** — highly prestigious venue; strong signal of community acceptance
- Evaluated 8 models across 40 tasks × subtasks = substantial evaluation matrix

### Methodology Gaps / What Hades Fills
- CyBench measures **offensive capability** (CTF solving) — can LLMs hack? Hades measures **adversarial manipulation of defensive agents** — can attackers weaponize the LLMs doing defense?
- CyBench has no **adversarial prompt injection** component; the agent controls its own context. Hades adds the dimension of externally injected malicious content into the agent's workflow.
- CyBench tasks are **static and isolated**. Hades targets **live, streaming SOC data** where the attack surface is dynamic.

### Claims to Cite / Address
- ✅ **Cite:** CyBench as the established cybersecurity capability benchmark — Hades can reference it to frame the capability of LLMs that SOC defenders deploy (and thus the capability of agents that must be hardened).
- ✅ **Cite:** "Claude 3.5 Sonnet / GPT-4o solve 11-minute tasks" — establishes that frontier LLMs have meaningful offensive and defensive capability in security contexts.
- ⚠️ **Positioning note:** Hades is not a CTF benchmark. Do not conflate. CyBench = "can LLMs do offense?" Hades = "can attackers fool LLMs doing defense?"

---

## 7. AgentDojo NeurIPS 2024

**Citation:** Debenedetti, E., Zhang, J., Balunovic, M., Beurer-Kellner, L., Fischer, M., Tramèr, F. (ETH Zurich / Invariant Labs). "AgentDojo: A Dynamic Environment to Evaluate Prompt Injection Attacks and Defenses for LLM Agents." arXiv:2406.13352 [cs.CR]. **NeurIPS 2024 Datasets and Benchmarks Track.**

### Methodology
- **Framework design:** Extensible, dynamic benchmark — not a static test suite. Allows adding new tasks, attacks, and defenses.
- **Initial population:**
  - **97 realistic tasks** (email client, e-banking website, travel bookings)
  - **629 security test cases**
  - Various attack and defense paradigms from literature
- **Evaluation approach:** Formal utility checks computed over environment state (not LLM-judged), capturing utility-security tradeoff accurately.
- **Attack types included:** Direct and indirect prompt injection variants
- **Defense types included:** Secondary attack detectors (Lakera, ProtectAI DeBERTa), instruction hierarchy, others

### Key Results / Numbers
- **Without attacks:** Current LLMs solve **<66% of AgentDojo tasks** (ceiling on agent capability)
- **With attacks (no defense):** Attack success rate **<25%** against best-performing agents
- **With defenses (secondary detector):** Attack success rate drops to **~8%**
- **Key finding:** Current attacks "break some security properties but not all" — no universal injection succeeds
- **MELON baseline (cited by AgentSentry):** 32.91% utility under attack on GPT-4o
- Released code: github.com/ethz-spylab/agentdojo

### Methodology Gaps / What Hades Fills
- AgentDojo's tasks are **consumer/enterprise productivity** (email, banking, travel) — **not SOC/security operations**. Hades fills the gap of a specialized SOC environment with realistic log ingestion, alert triage, and threat intel workflows.
- AgentDojo tests injection via **external tool data** in generic pipelines. Hades specifically models **log-file injection**, **SIEM alert manipulation**, and **threat intel feed poisoning** — the actual vectors in real SOC AI deployments.
- AgentDojo's 629 test cases use **synthetic injection content**. Hades can use real IPI samples from Unit42 telemetry and LevelBlue PoCs.
- AgentDojo doesn't model **SOC-specific behavioral invariants** (e.g., an alert severity can't increase without new evidence; an IP address in a summary must match the raw log).

### Claims to Cite / Address
- ✅ **Cite:** AgentDojo as the foundational prompt injection benchmark — Hades must benchmark against it or explain why SOC-specific evaluation is necessary.
- ✅ **Cite:** "<66% task completion even without attacks" — establishes that LLM agents are still imperfect, increasing IPI risk (partial task completion + injection = unpredictable behavior).
- ✅ **Cite:** 629 security test cases — Hades' SOC-specific benchmark can be positioned as complementing AgentDojo's general framework with domain depth.
- ⚠️ **Must address:** If Hades is evaluated on AgentDojo, it must use AgentSentry as the comparative baseline (74.55% UA) and justify SOC-specific claims.

---

## 8. LevelBlue (SpiderLabs) – Rogue AI Agents in Your SOCs

**Citation:** Neaves, T. (SpiderLabs, LevelBlue/AT&T). "Rogue AI Agents In Your SOCs and SIEMs – Indirect Prompt Injection via Log Files." LevelBlue SpiderLabs Blog, **September 5, 2025**.

### Methodology
- **Type:** Security research blog post with **proof-of-concept (PoC) demonstrations**
- **Author expertise:** Tom Neaves, 2+ decades in security
- **Framework:** Sources-and-sinks analysis applied to SOC/SIEM AI architectures
  - Sources: user-controlled events → log entries
  - Sinks: LLM+RAG chatbot consuming log files
  - Attack vector: Attacker embeds IPI payload in the untrusted source data that flows into the LLM sink
- **Three scenarios demonstrated:**
  1. **Web server log injection:** Payload hidden in HTTP User-Agent header → LLM changes source IP from 127.0.0.1 to 1.3.3.7 in summary
  2. **SSHd log injection:** Payload in SSH username field → LLM changes source IP in auth failure summary
  3. **Windows Event ID 4625 (SMB auth failure):** Payload split across USERNAME + DOMAIN fields → LLM changes workstation name from "LEET" to "PAYROLL" and source IP

### Key Results / Numbers
- **100% success rate** across all 3 scenarios on multiple (unnamed/redacted) LLM models
- **Web server injection:** HTTP User-Agent has no maximum length per RFC 2616 — unlimited payload space
- **Windows SMB fields:** Documented 20-char limit is unenforced — tested 120 chars per field (240 total); all characters returned in event. Microsoft MSRC did **not deem it serviceable**.
- Attack objectives demonstrated:
  - IP address spoofing in SIEM summaries
  - Workstation name spoofing
  - Analyst misdirection (fabricating events at decoy host while real attack continues)
- All three LLM models tested showed compliance with injected instructions

### Methodology Gaps / What Hades Fills
- LevelBlue demonstrates the **attack** but proposes no detection or mitigation solution — just awareness.
- No systematic evaluation of how many LLMs are vulnerable, at what injection payload complexity.
- No coverage of **multi-injection scenarios** (multiple log entries across different sources forming a coordinated injection).
- Hades would detect: (1) IP address in LLM output doesn't match source IP in raw log; (2) Alert triage decision not supported by raw evidence; (3) Anomalous behavioral sequence in agent actions following tool call.

### Claims to Cite / Address
- ✅ **Cite:** This is the **primary real-world motivation paper** for Hades. The exact PoCs (User-Agent, SSHd, Windows Event 4625) are Hades' attack scenarios.
- ✅ **Cite:** "100% injection success across 3 platforms and multiple LLMs" — establishes attack prevalence and severity.
- ✅ **Cite:** "Feels like the 90s again, with buffer overflows and SQL injection" — quotable for impact framing.
- ✅ **Cite:** Microsoft MSRC did not patch the Windows SMB field overflow — the attack surface is unlikely to be closed at the OS level.
- ⚠️ **Must acknowledge:** Attack uses direct plaintext injection (no encoding/obfuscation). Unit42 (paper 9) shows attackers use far more sophisticated techniques in the wild — Hades must handle both.

---

## 9. Palo Alto Unit42 – IDPI in the Wild

**Citation:** Palo Alto Networks Unit 42 Research Team. "Fooling AI Agents: Web-Based Indirect Prompt Injection Observed in the Wild." Unit42 Blog, **published March 2026** (reporting Dec 2025 first observation). URL: unit42.paloaltonetworks.com/ai-agent-prompt-injection/

### Methodology
- **Type:** Threat intelligence report based on **large-scale real-world telemetry** analysis
- **Approach:** Web crawler / network telemetry scanning for hidden prompt injection content across indexed webpages
- **First reported case:** December 2025 — first observed real-world IDPI designed to bypass AI-based ad review system (hosted at reviewerpress[.]com)
- **Taxonomy developed along two axes:**
  1. **Attacker Intent** (4 severity levels: Low → Critical)
  2. **Payload Engineering** (2 sub-categories):
     - *Prompt delivery methods* — how prompts are embedded
     - *Jailbreak methods* — how prompts evade safeguards
- **22 distinct payload engineering techniques** identified in the wild

### Key Results / Numbers
**Attacker Intent Distribution (from telemetry):**
- Irrelevant output: **28.6%**
- Data destruction: **14.2%**
- AI content moderation bypass: **9.5%**

**Prompt Delivery Method Distribution:**
- Visible plaintext: **37.8%**
- HTML attribute cloaking: **19.8%**
- CSS rendering suppression: **16.9%**

**Jailbreak Method Distribution:**
- Social engineering: **85.2%**
- JSON/syntax injection: **7.0%**
- Multi-lingual instructions: **2.1%**

**Other numbers:**
- 75.8% of pages contained a **single injected prompt**; 24.2% contained multiple
- Top eTLDs: .com (73.2%), .dev (4.3%), .org (4.0%)
- **22 distinct techniques** identified

**Specific attack cases documented:**
- Ad review evasion (Critical) — first ever reported
- Database destruction (Critical) — `rm -rf` + fork bomb
- Fork bomb DoS (Critical)
- SEO poisoning via phishing impersonation (High)
- Multiple unauthorized transaction attempts (High)
- Sensitive information leakage (Critical)
- System prompt leakage (Critical)

### Methodology Gaps / What Hades Fills
- Unit42 focuses on **web-based IDPI** (browser/crawler attack surface). Hades extends to **SOC-specific channels**: log files, SIEM alerts, threat intel feeds, and API tool outputs.
- Unit42 provides a **detection taxonomy** for web crawlers. Hades provides **behavioral detection** at the agent workflow level — after the payload has been delivered and the agent has started acting.
- Unit42's data is from **consumer/general web applications**. Hades targets the **enterprise SOC** where the stakes (security decisions, incident response) are much higher.
- The 22 payload engineering techniques Unit42 identified are directly applicable as Hades' adversarial test cases.

### Claims to Cite / Address
- ✅ **Cite:** First real-world IDPI case (Dec 2025) — establishes that IDPI is no longer theoretical.
- ✅ **Cite:** 22 distinct injection techniques — Hades' adversarial test suite should cover at minimum these categories.
- ✅ **Cite:** Distribution stats (28.6% irrelevant output, 85.2% social engineering jailbreaks) — baseline for what Hades will encounter.
- ✅ **Cite:** Critical severity attacks (data destruction, system prompt leakage) — motivates the need for detection in SOC-adjacent systems.
- ⚠️ **Must address:** Unit42's scope is web-browser agents. Hades must explicitly scope to SOC agents (log ingestion, SIEM, threat intel) and note that web-browser-based IDPI techniques are a subset of Hades' threat model.

---

## 10. TechniqueRAG ACL Findings 2025

**Citation:** Lekssays, A., Shukla, U., Sencar, H.T., Parvez, M.R. (Qatar Computing Research Institute). "TechniqueRAG: Retrieval Augmented Generation for Adversarial Technique Annotation in Cyber Threat Intelligence Text." arXiv:2505.11988 [cs.CR]. **Accepted at ACL Findings 2025.**

### Methodology
- **Task:** Automated MITRE ATT&CK (sub-)technique annotation in cyber threat intelligence text
- **Problem:** Two-way tradeoff in existing methods:
  - Generic models: limited domain precision
  - Task-specific models: require large labeled datasets + expensive optimization (hard-negative mining, denoising)
- **TechniqueRAG approach:**
  1. **Off-the-shelf retrievers** for candidate technique retrieval (no retrieval training)
  2. **Fine-tune only the generation component** on limited in-domain examples (mitigates data scarcity)
  3. **Zero-shot LLM re-ranking** — explicitly aligns retrieved candidates with adversarial techniques (improves precision, reduces noise from generic retriever)
- **Benchmarks:** Multiple security benchmarks for (sub-)technique annotation
- **Prior art compared against:** Ladder, AttackKG, Text2TTP (hierarchical re-ranking), NCE (dual-encoder), IntelEX

### Key Results / Numbers
- **State-of-the-art performance** on multiple security benchmarks (exact F1/accuracy numbers require full paper — abstract confirms SOTA)
- Achieved without: extensive task-specific optimizations, large labeled datasets
- Zero-shot LLM re-ranking specifically addresses the "noisy candidates" problem of generic retrievers
- ACL Findings 2025 — prestigious peer-reviewed venue

### Methodology Gaps / What Hades Fills
- TechniqueRAG annotates **static threat intelligence text** — it maps existing CTI reports to ATT&CK. Hades operates on **live agent output and decision traces** — it detects when an LLM agent's output has been manipulated by injection.
- TechniqueRAG is a **classification/annotation system**, not an adversarial detection system. It doesn't model that the threat intel text itself could be poisoned.
- Hades could **incorporate TechniqueRAG-style ATT&CK mapping** as a module: after detecting suspicious agent behavior, map the behavioral anomaly to an ATT&CK technique (e.g., T1565 – Data Manipulation) to generate structured incident reports.
- TechniqueRAG's zero-shot re-ranking approach is applicable to Hades: when Hades retrieves candidate injection patterns to match against observed agent behavior, zero-shot LLM re-ranking could improve pattern matching precision.

### Claims to Cite / Address
- ✅ **Cite:** As evidence that MITRE ATT&CK automation is achievable with RAG — supports Hades' ability to produce ATT&CK-mapped alerts.
- ✅ **Cite:** "Data scarcity in specialized domains" — same problem Hades faces; can cite TechniqueRAG's limited-data fine-tuning approach as applicable.
- ✅ **Cite:** ACL Findings 2025 — lends credibility to the RAG-for-security paradigm Hades may employ.
- ⚠️ **Positioning:** TechniqueRAG and Hades are complementary, not competing. TechniqueRAG = "what ATT&CK technique is described here?" Hades = "has this agent been injected, and what ATT&CK technique does the attack represent?"

---

## Cross-Paper Analysis: What Hades' Contribution Space Is

### The Research Gap Map

| Dimension | Existing Work | Hades' Gap |
|---|---|---|
| **Attack vector** | Web content (Unit42), Email (arXiv:2601.07072), Generic tools (AgentDojo) | **SOC-specific:** log files, SIEM alerts, threat intel API feeds |
| **Detection approach** | Retrieval prevention (arXiv:2601.07072), Causal re-execution (AgentSentry), Perimeter detection (Unit42) | **Behavioral invariant checking** in SOC-specific decision workflows |
| **Domain** | General agent tasks (AgentDojo), Web browsing (Unit42), CTF/offense (CyBench) | **Security operations** — triage, investigation, response |
| **Adversarial robustness** | Model-level / prompt-level defenses (broken by Carlini et al.) | **Workflow/orchestration-level** + environment state cross-validation |
| **Real-world grounding** | PoCs (LevelBlue), Telemetry taxonomies (Unit42) | **Live SOC integration** with audit trail |
| **ATT&CK integration** | Annotation of static CTI (TechniqueRAG) | **Real-time attack classification** of detected injections |

### The Claims Hades Can Uniquely Make
1. **First SOC-domain IPI detection framework** — no prior work evaluates prompt injection defense in live SOC/SIEM workflows
2. **Domain-behavioral invariants as detection signals** — IP address consistency, alert state machine compliance, evidence-to-conclusion coherence
3. **Real-world attack taxonomy coverage** — benchmarks against LevelBlue PoC vectors AND Unit42's 22 wild techniques
4. **ATT&CK-mapped output** — transforms detected injection into structured, actionable incident data (TechniqueRAG lineage)
5. **Evaluation under adaptive attacks** — must cite Carlini et al. and include adaptive attack baselines (not just static injection)

### Critical Vulnerabilities to Pre-empt
- **Reviewer will cite Carlini et al.:** "Your defense will be broken by adaptive attacks." → Response: Hades operates at workflow + environment state level, not model level; cross-validate against authoritative sources (raw SIEM logs, audit trails) that the attacker cannot manipulate without separate compromise.
- **Reviewer will cite AgentSentry:** "74.55% UA exists already, what does Hades add?" → Response: AgentSentry is domain-general with expensive re-execution; Hades is SOC-specialized with lightweight behavioral invariant checks — different operational constraints.
- **Reviewer will note absence of real SOC benchmark:** → Response: LevelBlue PoCs are reproducible; Unit42 telemetry taxonomy provides ground truth; propose SOC-agent benchmark as contribution.

---

*End of research document. 10 papers analyzed. Generated by Hades research sub-agent, 2026-03-12.*
