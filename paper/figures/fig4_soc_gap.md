# Figure 4: The SOC Triage Gap

```
    EXISTING SOC STACK              THE GAP                  HADES

    ┌─────────────────┐
    │   DETECTION      │
    │   ─────────      │
    │   SIEM Rules     │
    │   IDS Signatures │         ┌─────────────────┐
    │   Correlation    │────────▶│  MANUAL ANALYST  │
    │   Rules          │         │  TRIAGE          │
    └─────────────────┘         │  ─────────────   │
                                 │  • 50-100/day    │    ┌──────────────────┐
                                 │  • 15-30 min ea  │    │  LLM-BASED       │
                                 │  • Context from  │───▶│  TRIAGE          │
                                 │    memory        │    │  ─────────────   │
    ┌─────────────────┐         │  • Fatigue ↑     │    │  • 170-7000/day  │
    │   RESPONSE       │         │  • Consistency ↓ │    │  • <15s each     │
    │   ─────────      │         │                  │    │  • 256K context  │
    │   SOAR Playbooks │◀────────│  ← This is what  │    │  • Consistent    │
    │   Firewall Rules │         │    Hades replaces│    │  • Evidence-based│
    │   Ticketing      │         └─────────────────┘    └──────────────────┘
    └─────────────────┘
                                                         ┌──────────────────┐
                                                         │  BUT: NEW RISK   │
    Rules detect KNOWN patterns                          │  ─────────────   │
    Rules can't reason about:                            │  Attackers can   │
    • Novel attack combinations                          │  inject prompts  │
    • Slow/distributed campaigns                         │  through the     │
    • Ambiguous indicators                               │  same SIEM data  │
    • Context across 256K tokens                         │  the LLM reads   │
                                                         └──────────────────┘

    ┌─────────────────────────────────────────────────────────────────┐
    │                                                                 │
    │   HADES CONTRIBUTION:                                          │
    │                                                                 │
    │   1. QUANTIFY the risk  — E1-E8 experiments, 554K variants     │
    │   2. DETECT the attack  — behavioral invariants (output-level) │
    │   3. CORRELATE context  — multi-alert campaign detection       │
    │   4. RESPOND safely     — chain-aware playbook generation      │
    │   5. EVALUATE formally  — SOC-Bench ring scoring alignment     │
    │                                                                 │
    └─────────────────────────────────────────────────────────────────┘
```
