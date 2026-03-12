# SOC-Bench Alignment Analysis

*How Hades maps to Dr. Liu's SOC-Bench framework and where it extends it.*

## SOC-Bench Design Principles → Hades Compliance

| Principle | SOC-Bench Definition | Hades Status |
|-----------|---------------------|--------------|
| **DP1: Loyalty to SOCs** | Reflects what a SOC observes, not attacker internals | ✅ UnifiedAlert schema models analyst-visible data (alerts, rule matches, SIEM context) |
| **DP2: Be Exclusive** | Each task focuses on one SOC function | ✅ Hades focuses exclusively on Layer 2 triage (classification + severity assignment) |
| **DP3: Real-world basis** | Based on real incidents, not generalized | ⚠️ Splunk Attack Data from Attack Range (simulated but realistic). Could strengthen with SOC-Bench Colonial Pipeline data |

## SOC-Bench Tasks → Hades Mapping

SOC-Bench defines 5 tasks across the ransomware incident lifecycle. Hades operates primarily at the **Fox** stage (early detection/triage) with implications for **Tiger** (TTP identification):

| SOC-Bench Task | SOC Function | Hades Relevance |
|---------------|-------------|-----------------|
| **Fox** — Early Campaign Detection | Detect coordinated attack, classify type, produce alert bundle | **PRIMARY.** Hades triage = Fox O1 (campaign-scale assessment) + O2 (type reasoning). Our TriageDecision maps directly to Fox's structured JSON outputs. |
| **Tiger** — Threat Intelligence/Attribution | Analyze IOCs, map TTPs, identify entry point | **SECONDARY.** RAG retrieval of MITRE ATT&CK → TTP mapping. Our AlertBenchmarkContext.mitre_techniques aligns with Tiger's threat graph. |
| **Panda** — Containment | Propose containment actions with BLUF reports | **DOWNSTREAM.** Hades outputs feed containment decisions. Adversarial triage failures cascade to wrong containment. |
| **Goat** — File System Forensics | Label encryption, attribute processes, assess impact | **OUT OF SCOPE** for v1. Hades handles alert-level triage, not host forensics. |
| **Mouse** — Data Exfiltration Detection | Detect exfil from network/host telemetry | **OUT OF SCOPE** for v1. Could extend with exfil-specific triage classifiers. |

## Structural Alignment: Hades TriageDecision ↔ SOC-Bench Fox Outputs

### Fox O1 (Campaign-Scale Assessment) → Hades Triage

```
SOC-Bench Fox O1:                    Hades TriageDecision:
{                                    {
  "stage_id": "T+60",                 "alert_id": "...",
  "scale_label": "campaign_scale",     "classification": "true_positive",
  "impacted_hosts": [...],             "severity": "critical",
  "evidence_ids": [...],               "confidence": 0.92,
  "rationale": "..."                   "evidence_trace": [...],
}                                      "mitre_techniques": ["T1110"],
                                       "recommended_action": "escalate"
                                    }
```

**Gap:** Hades doesn't currently produce `scale_label` (isolated/localized/campaign_scale). This is a single-alert classification — Fox requires *cross-alert* campaign assessment. 

**Proposed extension:** Add a correlation layer after individual triage that groups related TriageDecisions into campaign assessments. This directly produces Fox O1-compatible output.

### Fox O2 (Type Reasoning) → Hades Evidence Trace

Fox O2 requires `key_signals` with evidence objects. Hades `evidence_trace` already captures this:

```python
@dataclass
class EvidenceItem:
    source: str           # ↔ Fox data_source_attribution
    content: str          # ↔ Fox signal description
    relevance: str        # ↔ Fox rationale
```

**Gap:** Fox requires distinguishing "ransomware_like" vs "non_ransom_coordinated" vs "uncertain". Hades classifies alerts as TP/FP/benign but doesn't type the campaign. Need a secondary classifier.

### Fox O3 (Alert Triage Bundle) → Hades Pipeline Output

Fox O3 asks for correlated signals across stages + one-paragraph summary. This maps to Hades pipeline `PipelineRunResult`:
- `decisions` list = correlated signal set
- Would need a summarization pass to generate the paragraph

## Scoring Compatibility

SOC-Bench uses a ring-based scoring model. Hades evaluation uses F1/precision/recall. These are complementary:

| SOC-Bench Scoring | Hades Equivalent | Gap |
|-------------------|-----------------|-----|
| Bullseye (3 pts) — correct + evidence-backed | True positive with high confidence + evidence trace | ✅ Compatible |
| Inner (2 pts) — correct, weak justification | True positive with low confidence or thin evidence | ✅ Compatible |
| Outer (1 pt) — directionally plausible | Uncertain classification with relevant signals noted | ⚠️ Hades doesn't have "uncertain" as a classification |
| Miss (0 pts) — incorrect | False positive or false negative | ✅ Compatible |
| Penalties (wrong assertion, no evidence, etc.) | — | ❌ Not implemented. Need penalty tracking. |

**Proposed extension:** Add SOC-Bench scoring adapter that converts TriageDecisions into ring scores for Fox-compatible evaluation.

## The Adversarial Extension: What SOC-Bench Doesn't Cover

SOC-Bench assumes **trusted telemetry**. All design principles (DP1-DP3) treat data sources as authentic reconstructions from real incidents. This is the gap Hades fills:

> **What happens when the telemetry itself is adversarial?**

Our adversarial evaluation extends SOC-Bench's framework by asking:
1. Can an agent that scores Bullseye on clean Fox data be tricked into Miss on adversarially crafted data?
2. Do the penalties (wrong assertions, contradictions) increase under adversarial input?
3. Does the ring-based scoring model remain valid when inputs are manipulated?

**This is Hades' unique contribution to the SOC-Bench ecosystem:**

SOC-Bench answers: "How well can AI agents perform SOC tasks?"
Hades answers: "How well can AI agents perform SOC tasks **when adversaries are actively trying to fool them?**"

## Concrete Integration Points

### If Hades becomes a SOC-Bench system:

1. **Fox evaluation:** Run Hades triage on Fox telemetry, convert outputs to O1/O2/O3 format, score on ring model
2. **Adversarial Fox extension:** Inject adversarial payloads into Fox telemetry, measure ring score degradation
3. **Tiger support:** Use Hades RAG (MITRE ATT&CK retrieval) to produce Tiger O2 threat graph
4. **Cross-task dependency:** Test whether adversarial manipulation in Fox stage cascades through Panda containment decisions

### Architecture changes needed:

1. Add `scale_label` field to TriageDecision (isolated/localized/campaign_scale)
2. Add campaign-type classifier (ransomware_like/non_ransom/uncertain)
3. Implement cross-alert correlation layer (Fox requires multi-alert reasoning)
4. Add SOC-Bench scoring adapter for ring-based evaluation
5. Support 30-minute stage-based processing (incremental evidence delivery)

### Timeline:

- **Phase 1 (current):** Single-alert triage with adversarial evaluation
- **Phase 2:** Multi-alert correlation → Fox O1/O3 compatible
- **Phase 3:** Full SOC-Bench integration with Fox + Tiger tasks

## Questions for Dr. Liu

1. Can Hades be evaluated as a SOC-Bench system in its current single-alert form, or is multi-alert correlation required?
2. Would adversarial robustness be a valuable **new dimension** for SOC-Bench scoring (beyond the existing ring model)?
3. Can we access SOC-Bench's Colonial Pipeline telemetry for Hades evaluation?
4. Would a joint paper on "adversarial evaluation of SOC-Bench systems" be of interest?
5. Are there specific Fox/Tiger data sources we should prioritize for Hades ingestion?

---

*This document should be reviewed before the first meeting with Dr. Liu.*
