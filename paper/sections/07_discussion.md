# 7. Discussion

## 7.1 Implications for SOC Deployment

Our results demonstrate that LLM-based triage systems face a fundamental tension: the same capability that makes them useful — processing unstructured log data with contextual reasoning — makes them vulnerable to adversarial manipulation through that data. This is not a bug to be patched but a structural property of deploying language models on adversary-generated content.

**Practical recommendation.** Organizations deploying LLM triage should treat model outputs as *suggestions* requiring human verification for any alert the model recommends downgrading. The confidence threshold for automatic closure must account for the possibility that the confidence score itself has been manipulated (Attack Class C2).

## 7.2 The Defense Paradox

Defenses face a fundamental asymmetry: sanitization must be aggressive enough to neutralize payloads without destroying the log content that makes triage useful. Overly aggressive sanitization (Level 3) effectively truncates the data the model needs to make accurate decisions, while minimal sanitization (Level 1) fails to catch semantically-varied payloads.

Structured prompt architectures (D2) show promise because they add explicit data/instruction boundaries, but Nasr et al. [2025] demonstrate that adaptive attackers can learn to exploit boundary markers themselves. Our E8 results [to be filled] will quantify whether this theoretical concern manifests in practice.

## 7.3 MoE Architecture Vulnerability

Different Mixture-of-Experts architectures may exhibit different vulnerability profiles because the expert routing decision determines which subset of model parameters processes the adversarial payload. If injection payloads consistently activate different experts than legitimate log content, models with more granular routing (e.g., K2.5 with 384 experts vs. Qwen 3.5 with 128) may show different susceptibility patterns. This hypothesis motivates our cross-architecture comparison.

## 7.4 Cost of Autonomy

As SOC systems move toward autonomous response (blocking IPs, isolating hosts, triggering playbooks), the cost of adversarial manipulation scales dramatically. An attacker who can suppress triage escalation for their C2 traffic gains persistent access; an attacker who can trigger false containment actions against legitimate infrastructure achieves denial of service without launching a traditional attack. Our evaluation quantifies the misclassification risk that would underlie such autonomous decisions.

## 7.5 Limitations

**L1: File replay vs. live deployment.** We evaluate on file-replayed alerts, not live SIEM data. Real deployments may apply additional normalization, enrichment, or filtering that affects injection viability. Our E3 experiment partially addresses this by analyzing SIEM normalization behavior across five platforms.

**L2: Single-alert triage.** Our evaluation processes alerts individually. Real SOC triage often involves correlation across multiple alerts, time windows, and data sources. Multi-alert injection attacks (where the payload is split across several related alerts) are out of scope.

**L3: Prompt template sensitivity.** Injection success rates depend heavily on the specific prompt template used for triage. We use a single, representative template derived from published SOC automation patterns. Different prompt designs may be more or less vulnerable.

**L4: Quantization effects.** All models are evaluated at INT4 quantization due to hardware constraints. Full-precision models may exhibit different vulnerability profiles, though existing research suggests that quantization has minimal impact on instruction-following behavior.

**L5: Benchmark coverage.** Our benchmark covers 8 MITRE ATT&CK techniques across 6 tactics. This is sufficient for methodology validation but does not cover the full ATT&CK matrix. The benchmark builder supports easy extension as additional Splunk Attack Data is acquired.

**L6: No human study.** We do not evaluate whether human analysts would catch LLM triage errors introduced by adversarial injection. A user study measuring analyst detection of manipulated triage outputs would strengthen the practical impact assessment.

## 7.6 Ethical Considerations

This research demonstrates attack techniques against security systems. We mitigate dual-use risk through:
- **Defensive focus.** All experiments aim to improve security system robustness, not enable attacks.
- **Existing knowledge.** The injection vectors we characterize are already documented in practitioner literature [Neaves2025, PaloAlto2026].
- **Responsible disclosure.** We do not target specific commercial products or disclose vendor-specific vulnerabilities.
- **Open-source tooling.** Releasing Hades enables the community to evaluate and improve their own systems.
