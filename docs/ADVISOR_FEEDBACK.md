# Advisor Feedback — Dr. Peng Liu

## 2026-03-12: Initial Review Response

**Status:** ✅ Accepted as faculty advisor

### Key Points

1. **GPU Access** — Lab has hardware described in proposal. Jay can get allocated hours for experiments.

2. **SOC-Bench Integration** — Dr. Liu's lab has an ongoing project called "SOC-Bench" (draft attached as `docs/SOC-Bench-Draft.pdf`). Hades may later become part of SOC-Bench.

3. **⚠️ CRITICAL: Dataset Adequacy** — First priority task before any other work.

> "A widely recognized technical challenge for academic SIEM research projects is that the available datasets are in general NOT adequate."

Specific issues raised:
- **CICIDS2017/2018 is not directly associated with SIEM rules** — flow features ≠ SIEM alerts
- **Synthetic SIEM logs may not contain all information needed** for scientific research
- **Without adequate datasets, the work is "a project, but NOT scientific"**

### Action Required

Before prototyping or validation can proceed, we must:
1. Demonstrate that our datasets are adequate for SIEM-based research
2. Convince Dr. Liu and other experts of dataset scientific validity
3. Treat this as **Task #1** in the project

### Implications for Current Work

- CIC-IDS2018 parser (built 2026-03-12) remains useful as engineering infrastructure
- But CIC-IDS2018 alone is **not scientifically adequate** per advisor feedback
- Need datasets with: SIEM rule associations, detection context, alert correlation metadata
- Potential alignment with SOC-Bench data (Colonial Pipeline–based telemetry)

---

*Filed: 2026-03-12*
