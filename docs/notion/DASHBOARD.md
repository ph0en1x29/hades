# 📊 HADES Dashboard

## Project At a Glance

| | |
|---|---|
| **Research Question** | Can adversaries manipulate LLM-based SOC triage through crafted network traffic? |
| **Advisor** | Dr. Peng Liu, LIONS Center, Penn State |
| **Target Venue** | ACM CCS Workshop on AI for CTI (Nov 2026) |
| **Current Phase** | Phase 1 complete → preparing for advisor meeting |
| **GPU Status** | Pending — need 40-60 hrs on 4×A100 (June-July) |

---

## Key Metrics

> Copy these as "Callout" blocks in Notion for visual impact

- **12,147** benchmark alerts
- **27** MITRE ATT&CK techniques
- **~1.46M** adversarial variants
- **13,474** lines of code
- **64** commits
- **95.7 → 51.0** Fox score degradation under attack (-44.7 points)

---

## What's Complete ✅

- [x] Triage pipeline (5 parsers, unified schema, RAG, 3 triage agents)
- [x] Benchmark built from Splunk Attack Data (12,147 alerts)
- [x] Adversarial framework (12 vectors × 5 classes × 9 encodings)
- [x] 6 behavioral invariants (100% C1/C3, 98% C4, 0% FP)
- [x] SOC-Bench Fox adapter + ring scorer (17 tests)
- [x] Dataset gate (programmatic scaffold rejection)
- [x] E3 payload survival experiment
- [x] Statistical framework
- [x] Reproducibility suite (29 sections)
- [x] Paper draft (~12K words)
- [x] Proposal v2 sent to Prof Liu

## What's Blocked ⏳

- [ ] E1-E8 experiments (need GPU)
- [ ] Paper results tables (26 TBDs)
- [ ] SOC-Bench Colonial Pipeline data (need Prof Liu access)
- [ ] Real-world validation corpus (need Prof Liu guidance)

---

## Quick Links

- **Repository:** github.com/ph0en1x29/hades
- **Paper draft:** `paper/HADES_PAPER_DRAFT.md`
- **Proposal:** sent to Prof Liu March 2026
- **Reviewer changelog:** `docs/REVIEWER_CHANGELOG.md`
