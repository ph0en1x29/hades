# 🧪 Experiments Database

> In Notion: Create this as a **Database — Full page**
> Properties: Name (title), Status (select), Priority (select), Depends On (text), Key Question (text), Notes (text)
> Status options: ✅ Complete, ⏳ GPU-Blocked, 🔄 In Progress, 📋 Not Started

---

## E1 — Clean Baseline
- **Status:** ⏳ GPU-Blocked
- **Priority:** Critical (everything depends on this)
- **Depends On:** Lab GPU access
- **Key Question:** How well do the 4 models triage unmodified alerts?
- **Notes:** Run 12,147 alerts through DeepSeek R1, GLM-5, Kimi K2.5, Qwen 3.5. Establishes baseline.

## E2 — Injection Success Rate
- **Status:** ⏳ GPU-Blocked
- **Priority:** Critical (core attack measurement)
- **Depends On:** E1
- **Key Question:** How often do adversarial payloads successfully manipulate triage?
- **Notes:** 12 vectors × 5 attack classes × 4 models. The central result of the paper.

## E3 — Payload Survival
- **Status:** ✅ Complete
- **Priority:** High
- **Depends On:** —
- **Key Question:** Do payloads survive SIEM normalization?
- **Notes:** 40% survive all 11 rules. Homoglyph/zero-width bypass keyword defenses. Sanitization alone insufficient.

## E4 — Defense Effectiveness
- **Status:** ⏳ GPU-Blocked
- **Priority:** High
- **Depends On:** E1 + E2
- **Key Question:** Which defense mechanisms reduce attack success?
- **Notes:** 5 defenses × 4 models, individual and combined.

## E5 — Behavioral Invariant Evaluation
- **Status:** ⏳ GPU-Blocked
- **Priority:** High
- **Depends On:** E1 + E2
- **Key Question:** Do invariants catch what input defenses miss?
- **Notes:** Pre-GPU: 100% C1/C3, 98% C4, 0% FP on mock data.

## E6 — Cross-Model Comparison
- **Status:** ⏳ GPU-Blocked
- **Priority:** Medium
- **Depends On:** E1 + E2
- **Key Question:** Which MoE architecture is most/least robust?
- **Notes:** McNemar's pairwise, Cohen's d effect size.

## E7 — Encoding Evasion
- **Status:** ⏳ GPU-Blocked
- **Priority:** Medium
- **Depends On:** E2 + E4
- **Key Question:** Which encodings bypass which defenses?
- **Notes:** 9 encodings × 5 defenses × 4 models. Maps the evasion landscape.

## E8 — Adaptive Attack
- **Status:** ⏳ GPU-Blocked
- **Priority:** Medium
- **Depends On:** E2 + E4 + E7
- **Key Question:** Can an informed attacker still bypass defenses?
- **Notes:** Strongest threat model. If a defense fails here, it's not robust.
