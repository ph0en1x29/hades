# ❓ Decisions & Open Questions

> In Notion: Create as a **Database — Inline**
> Properties: Question (title), Status (select: Open/Decided/Deferred), Decision (text), Date Decided (date), Context (text)

---

## Decided ✅

### Dataset: CICIDS demoted to engineering scaffold
- **Decision:** CIC-IDS2018 excluded from all benchmark claims
- **Date:** March 12, 2026
- **Context:** Satisfies 0/5 adequacy criteria. Programmatic gate enforces this.

### Dataset: Splunk Attack Data as benchmark-of-record
- **Decision:** Primary benchmark built on Splunk Attack Data (4/5 criteria)
- **Date:** March 12, 2026
- **Context:** 12,147 alerts, 27 techniques, 9 tactics. Rule-linked provenance.

### Models: Local MoE only for v1
- **Decision:** No cloud models (GPT-4o, Claude) in v1 scope
- **Date:** March 12, 2026
- **Context:** v1 is offline/air-gap compatible. Cloud models deferred to v2.

### Publication: IEEE CNS dropped
- **Decision:** Removed IEEE CNS May 11 deadline as unrealistic
- **Date:** March 13, 2026
- **Context:** GPU experiments won't be done by May. CCS Workshop (Nov) is primary target.

### Behavioral invariants: 6 invariants (INV-1 to INV-6)
- **Decision:** Added INV-6 (confidence-severity alignment) to catch C2 attacks INV-3 misses
- **Date:** March 12, 2026
- **Context:** INV-6 catches high-severity alert + true positive + suspiciously low confidence.

### BETH: Engineering scaffold only
- **Decision:** BETH synthetic data for parser development only, excluded from benchmark
- **Date:** March 13, 2026
- **Context:** Intentionally excluded from benchmark pack. NOTE comment in build_benchmark_pack.py.

---

## Open ❓

### SOC-Bench Colonial Pipeline data access
- **Status:** Open — waiting for Prof Liu
- **Context:** Would give HADES 5/5 adequacy criteria (adds C5 multi-stage correlation)

### Real-world validation corpus
- **Status:** Open — raised in proposal
- **Context:** 50-100 anonymized production alerts would strengthen external validity

### SOC-Bench scale_label and campaign-type fields
- **Status:** Open — need Prof Liu guidance
- **Context:** HADES doesn't produce these yet. Needed for first eval or Phase 2?

### GPU scheduling
- **Status:** Open — need to coordinate with lab
- **Context:** ~40-60 hours on 4×A100, June-July 2026

### Research framing
- **Status:** Open — asking Prof Liu in proposal
- **Context:** Is adversarial robustness the strongest framing? Different angle possible?

---

## Deferred 📌

### Cross-alert correlation layer
- **Context:** Needed for SOC-Bench stage-based processing. Phase 2.

### Cloud model comparison
- **Context:** GPT-4o, Claude Sonnet. Deferred to v2.

### Real-time SIEM connectors
- **Context:** Splunk, Elastic, QRadar integration. Phase 3.
