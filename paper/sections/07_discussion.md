# 7. Discussion

## 7.1 Implications for SOC Deployment

The vulnerability we study is structural, not incidental: any SOC pipeline that asks an LLM to reason over attacker-controlled telemetry invites the adversary to compete for control of the model's interpretation process. This is not an implementation flaw to be patched; it is the predictable consequence of placing a language model inside an adversarially supplied data path. The same capability that makes LLMs useful for triage — processing unstructured log data with contextual reasoning — makes them vulnerable to adversarial manipulation through that data.

**Practical recommendation.** Organizations deploying LLM triage should treat model outputs as *suggestions* requiring human verification for any alert the model recommends downgrading. The confidence threshold for automatic closure must account for the possibility that the confidence score itself has been manipulated (Attack Class C2).

## 7.2 Behavioral Invariants: Output-Level Defense

Our key insight is that effective SOC triage defenses must operate at the *workflow level*, not the *model level*. Nasr et al. [2025] assembled a 14-author red team spanning OpenAI, Anthropic, DeepMind, and ETH Zurich, and demonstrated that adaptive attackers could break ALL 12 proposed prompt injection defenses with >90% attack success rate. This result is devastating for any defense that operates on the model's input or internal processing — an adaptive attacker can always find a way to craft payloads that bypass sanitization, structured prompts, or canary tokens.

Behavioral invariants address this from a different angle by checking the model's output against ground-truth properties of the source alert. The key asymmetry is informational: input-level defenses operate in the **attacker's action space** — the payload content, encoding, and phrasing, all of which the attacker controls and can iteratively refine. Output-level invariants operate in the **problem's constraint space** — physical and logical properties of the alert that the attacker cannot modify without controlling the network infrastructure itself. An alert from 10.0.1.15 will always originate from 10.0.1.15; a SIEM rule matching T1003.001 will always carry that technique tag. No amount of prompt engineering can change these ground-truth properties.

Concretely: a triage decision that references IP addresses not present in the original alert (INV-2) is suspicious regardless of how the model arrived at it. A classification of BENIGN for an alert the SIEM flagged as HIGH severity, without documented rationale (INV-1), warrants escalation regardless of whether the decision was caused by prompt injection or model error.

In effect, behavioral invariants shift defense from trying to sanitize language to verifying consequences. Our pre-GPU evaluation shows 100% detection on C1 (direct misclassification) and C3 (reasoning corruption), 98% on C4 (attention hijacking), and 0% false positives. These results are preliminary, validated against simulated template outputs (§6.7). Real model outputs may exhibit more varied failure modes, and detection rates could differ. Full validation awaits GPU experiments. The notable exception is C2 (confidence manipulation), where detection ranges from 0% (pure confidence inflation) to 100% (when combined with reasoning anomalies) — the subtlest attack class. This motivates layered defenses: behavioral invariants catch the overt attacks, while output confidence calibration and dual-model verification target C2.

## 7.3 The Input Defense Paradox

Defenses face a fundamental asymmetry that we term the **sanitization-utility tradeoff**: any input defense must distinguish attacker instructions from legitimate data, but this distinction is semantic — a sentence that is a benign log entry in one context is a malicious instruction in another. There is no syntactic marker that reliably separates "data" from "instruction" in natural language, which is precisely why LLMs are useful for triage in the first place.

In practice: sanitization must be aggressive enough to neutralize payloads without destroying the log content that makes triage useful. Overly aggressive sanitization (Level 3) effectively truncates the data the model needs to make accurate decisions, while minimal sanitization (Level 1) fails to catch semantically-varied payloads.

Structured prompt architectures (D2) show promise because they add explicit data/instruction boundaries, but Nasr et al. [2025] demonstrate that adaptive attackers can learn to exploit boundary markers themselves. Our planned E8 experiments will quantify whether this theoretical concern manifests in practice.

## 7.4 MoE Architecture Vulnerability

Different Mixture-of-Experts architectures may exhibit different vulnerability profiles because the expert routing decision determines which subset of model parameters processes the adversarial payload. Recent MoE security research enables concrete predictions for our experiments:

**Prediction 1: Expert granularity correlates with attack surface.** K2.5 (384 experts) has more fine-grained routing than Qwen 3.5 (128) or DeepSeek R1 (256). Te Lintelo et al. [TeLintelo2026] showed that silencing <20% of layer-wise experts raises ASR from 7.3% to 70.4%. Models with more experts have more potential targets for selective activation — K2.5 may show either higher vulnerability (more pathways to exploit) or higher resilience (safety behavior distributed across more experts, harder to silence simultaneously).

**Prediction 2: Safety expert concentration varies by architecture.** Lai et al. [Lai2025] found safety behavior concentrated in just 12 experts in Qwen3-30B. If our Qwen 3.5 shows similarly concentrated safety experts, it may be more vulnerable to injection payloads that happen to route around those specific experts. GLM-5, as a dense architecture without expert routing, should not exhibit this vulnerability pattern — providing a control for separating MoE-specific from general LLM vulnerabilities.

**Prediction 3: Dense vs MoE baseline.** GLM-5 (dense) should show different vulnerability *patterns* than the three MoE models, even if overall ASR is similar. Specifically, we predict MoE models will show higher variance across vectors (some vectors may preferentially activate safety-critical experts), while GLM-5 should show more uniform vulnerability across vectors.

These predictions are falsifiable in E1-E8 and, if confirmed, would provide early empirical evidence connecting MoE architecture properties to indirect prompt injection vulnerability in a domain-specific deployment.

## 7.5 Cost of Autonomy and Attack Economics

As SOC systems move toward autonomous response (blocking IPs, isolating hosts, triggering playbooks), the cost of adversarial manipulation scales dramatically. An attacker who can suppress triage escalation for their C2 traffic gains persistent access; an attacker who can trigger false containment actions against legitimate infrastructure achieves denial of service without launching a traditional attack.

**Attack economics favor the attacker.** The cost of injection is marginal: crafting a malicious HTTP User-Agent string and sending a single request to the target network costs effectively zero beyond the attacker's existing infrastructure. In contrast, the defender must process every alert through a computationally expensive LLM pipeline, apply multiple defense layers, and maintain human oversight for escalated alerts. This asymmetry is distinct from traditional network attacks (where exploit development is expensive) — prompt injection repurposes natural protocol fields that the attacker already controls as part of their attack. The attacker adds a payload to traffic they would generate anyway, making injection a zero-marginal-cost enhancement to any existing campaign.

**Scaling concern.** If injection succeeds at even moderate rates (e.g., 20% ASR), an attacker can embed payloads in a high volume of traffic and rely on statistical success. Our 1.4 million variant evaluation is designed to measure whether this volumetric strategy is viable. Our framework is designed to quantify the misclassification risk that would underlie autonomous response decisions.

## 7.6 Limitations

**L1: File replay vs. live deployment.** We evaluate on file-replayed alerts, not live SIEM data. Real deployments may apply additional normalization, enrichment, or filtering that affects injection viability. Our E3 experiment partially addresses this by analyzing SIEM normalization behavior across five platforms.

**L2: Correlation scope.** While Hades includes a correlator agent for multi-stage campaign detection, our adversarial evaluation currently targets single-alert triage decisions. Multi-alert injection attacks (where the payload is split across several related alerts to evade single-alert invariant checks) represent a promising future research direction.

**L3: Prompt template sensitivity.** Injection success rates depend heavily on the specific prompt template used for triage. We use a single, representative template derived from published SOC automation patterns. Different prompt designs may be more or less vulnerable.

**L4: Quantization effects.** All models are evaluated at INT4 quantization due to hardware constraints. Full-precision models may exhibit different vulnerability profiles, though existing research suggests that quantization has minimal impact on instruction-following behavior.

**L5: Benchmark coverage.** Our benchmark covers 27 MITRE ATT&CK techniques across 9 tactics, providing meaningful coverage of adversary behavior but representing a subset of the full ATT&CK Enterprise matrix (over 200 techniques). The benchmark builder supports easy extension as additional Splunk Attack Data is acquired.

**L6: No human study.** We do not evaluate whether human analysts would catch LLM triage errors introduced by adversarial injection. A user study measuring analyst detection of manipulated triage outputs would strengthen the practical impact assessment.

## 7.7 Ethical Considerations

This research demonstrates attack techniques against security systems. We mitigate dual-use risk through:
- **Defensive focus.** All experiments aim to improve security system robustness, not enable attacks.
- **Existing knowledge.** The injection vectors we characterize are already documented in practitioner literature [Neaves2025, PaloAlto2026].
- **Responsible disclosure.** We do not target specific commercial products or disclose vendor-specific vulnerabilities.
- **Open-source tooling.** Releasing Hades enables the community to evaluate and improve their own systems.
