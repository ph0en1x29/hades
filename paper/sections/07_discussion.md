# 7. Discussion

## 7.1 Implications for SOC Deployment

Our results demonstrate that LLM-based triage systems face a fundamental tension: the same capability that makes them useful — processing unstructured log data with contextual reasoning — makes them vulnerable to adversarial manipulation through that data. This is not a bug to be patched but a structural property of deploying language models on adversary-generated content.

**Practical recommendation.** Organizations deploying LLM triage should treat model outputs as *suggestions* requiring human verification for any alert the model recommends downgrading. The confidence threshold for automatic closure must account for the possibility that the confidence score itself has been manipulated (Attack Class C2).

## 7.2 Behavioral Invariants: Output-Level Defense

Our key insight is that effective SOC triage defenses must operate at the *workflow level*, not the *model level*. Nasr et al. [2025] demonstrated that 14 research teams could break ALL 12 proposed prompt injection defenses with >90% attack success rate using adaptive attacks. This result is devastating for any defense that operates on the model's input or internal processing — an adaptive attacker can always find a way to craft payloads that bypass sanitization, structured prompts, or canary tokens.

Behavioral invariants sidestep this entirely by checking the model's output against ground-truth properties of the source alert. A triage decision that references IP addresses not present in the original alert (INV-2) is suspicious regardless of how the model arrived at it. A classification of BENIGN for an alert the SIEM flagged as HIGH severity, without documented rationale (INV-1), warrants escalation regardless of whether the decision was caused by prompt injection or model error.

Our pre-GPU evaluation shows 100% detection on C1 (direct misclassification) and C3 (reasoning corruption), 98% on C4 (attention hijacking), and 0% false positives. The notable exception is C2 (confidence manipulation at 0% detection), where the attacker only inflates the confidence score without changing the classification label — the subtlest attack class. This motivates layered defenses: behavioral invariants catch the overt attacks, while output confidence calibration and dual-model verification target C2.

## 7.3 The Input Defense Paradox

Defenses face a fundamental asymmetry: sanitization must be aggressive enough to neutralize payloads without destroying the log content that makes triage useful. Overly aggressive sanitization (Level 3) effectively truncates the data the model needs to make accurate decisions, while minimal sanitization (Level 1) fails to catch semantically-varied payloads.

Structured prompt architectures (D2) show promise because they add explicit data/instruction boundaries, but Nasr et al. [2025] demonstrate that adaptive attackers can learn to exploit boundary markers themselves. Our E8 results [to be filled] will quantify whether this theoretical concern manifests in practice.

## 7.4 MoE Architecture Vulnerability

Different Mixture-of-Experts architectures may exhibit different vulnerability profiles because the expert routing decision determines which subset of model parameters processes the adversarial payload. If injection payloads consistently activate different experts than legitimate log content, models with more granular routing (e.g., K2.5 with 384 experts vs. Qwen 3.5 with 128) may show different susceptibility patterns. This hypothesis motivates our cross-architecture comparison.

## 7.5 Cost of Autonomy

As SOC systems move toward autonomous response (blocking IPs, isolating hosts, triggering playbooks), the cost of adversarial manipulation scales dramatically. An attacker who can suppress triage escalation for their C2 traffic gains persistent access; an attacker who can trigger false containment actions against legitimate infrastructure achieves denial of service without launching a traditional attack. Our evaluation quantifies the misclassification risk that would underlie such autonomous decisions.

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
