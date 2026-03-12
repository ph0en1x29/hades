# Hades Architecture

## Where Hades Fits

```text
┌─────────────────────────────────────────────────────────┐
│ EXISTING SOC STACK (unchanged)                          │
│                                                         │
│  Detection Layer          Response Layer                │
│  ┌──────────────┐        ┌──────────────┐              │
│  │ SIEM         │        │ SOAR         │              │
│  │ IDS/IPS      │        │ Firewall API │              │
│  │ EDR          │        │ Playbooks    │              │
│  │ Threat Intel │        │ Ticketing    │              │
│  └──────┬───────┘        └──────▲───────┘              │
│         │                       │                       │
│         │    ┌──────────────┐   │                       │
│         └──>│   HADES      │───┘                       │
│             │  Offline LLM │                            │
│             │  Triage      │                            │
│             └──────────────┘                            │
│              Replaces manual                            │
│              analyst decisions                          │
└─────────────────────────────────────────────────────────┘
```

Hades does not replace detection or response tooling. It fills the triage gap where human analysts currently sit, reading each alert and making decisions.

## Research Architecture

```text
┌─────────────────────────────────────────────────────────┐
│ ADVERSARIAL EVALUATION FRAMEWORK                        │
│                                                         │
│ ┌──────────────┐     ┌──────────────┐                   │
│ │ Payload      │     │ Defense      │                   │
│ │ Generator    │     │ Mechanisms   │                   │
│ │              │     │              │                   │
│ │ 10 vectors   │     │ D1: Sanitize │                   │
│ │ 5 classes    │     │ D2: Struct   │                   │
│ │ 4 encodings  │     │ D3: AdvTrain │                   │
│ │              │     │ D4: DualLLM  │                   │
│ │              │     │ D5: Canary   │                   │
│ └──────┬───────┘     └──────┬───────┘                   │
│        │                    │                           │
│        ▼                    ▼                           │
│ ┌──────────────────────────────────┐                    │
│ │  TRIAGE PIPELINE (test bed)     │                    │
│ │  Ingest → Normalize → Triage    │                    │
│ └──────────────┬───────────────────┘                    │
│                │                                        │
│                ▼                                        │
│ ┌──────────────────────────────────┐                    │
│ │  EVALUATION ENGINE              │                    │
│ │  ASR, F1, confidence delta,     │                    │
│ │  reasoning corruption rate      │                    │
│ └──────────────────────────────────┘                    │
└─────────────────────────────────────────────────────────┘
```

## Current Position

Research scaffold as of March 12, 2026. Adversarial pivot drafted; runtime wiring, tests, and benchmark execution remain in progress.

## v1 Architecture (Research Prototype)

```text
┌───────────────────────────┐
│ File Replay / JSONL       │
│ Benchmark Fixtures        │
│ Auth logs, TLS metadata,  │
│ SIEM alerts               │
└───────────┬───────────────┘
            │
            ▼
┌───────────────────────────┐
│ Alert Normalization       │
│ UnifiedAlert v1           │
│ Provenance preserved      │
│ Auth event parsing        │
│ TLS fingerprint extraction│
└───────────┬───────────────┘
            │
            ▼
┌──────────────────────────────────────┐
│ Triage Pipeline                      │
│                                      │
│ ┌──────────────┐  ┌───────────────┐  │
│ │  Classifier  │  │  Correlator   │  │
│ │  Agent       │→ │  Agent        │  │
│ │              │  │               │  │
│ │ - severity   │  │ - cross-alert │  │
│ │ - MITRE map  │  │ - attack chain│  │
│ │ - confidence │  │ - multi-surface│ │
│ └──────────────┘  └───────┬───────┘  │
│                           │          │
│                    ┌──────▼───────┐  │
│                    │  Playbook    │  │
│                    │  Generator   │  │
│                    │              │  │
│                    │ - response   │  │
│                    │ - evidence   │  │
│                    │ - rationale  │  │
│                    └──────────────┘  │
└───────────┬──────────────────────────┘
            │
            ├──────────────► Local RAG (Qdrant)
            │                - MITRE ATT&CK techniques
            │                - CVE database subset
            │                - JA3/JA4 fingerprint DB
            │                - Dense + sparse hybrid retrieval
            │
            ▼
┌───────────────────────────┐
│ Decision Output           │
│ TriageDecision v1         │
│ Evidence trace            │
│ MITRE technique mapping   │
│ Confidence scores         │
│ Audit store + JSONL       │
└───────────┬───────────────┘
            │
            ▼
┌───────────────────────────┐
│ Analyst Interface         │
│ CLI and/or local FastAPI  │
└───────────────────────────┘
```

## Detection Surfaces

Hades analyzes three complementary detection surfaces:

```text
┌─────────────┐  ┌─────────────┐  ┌─────────────┐
│ SIEM Alerts │  │ Auth Events │  │ Encrypted   │
│             │  │             │  │ Traffic     │
│ IDS/firewall│  │ Login/logoff│  │ Metadata    │
│ Endpoint    │  │ Kerberos    │  │             │
│ App logs    │  │ OAuth/SAML  │  │ JA3/JA4     │
│             │  │ AD events   │  │ Cert chains │
│             │  │             │  │ Beaconing   │
└──────┬──────┘  └──────┬──────┘  └──────┬──────┘
       │                │                │
       └────────────────┼────────────────┘
                        │
                        ▼
              ┌─────────────────┐
              │ Correlator Agent│
              │ 256K context    │
              │ Multi-surface   │
              │ attack chain    │
              │ reconstruction  │
              └─────────────────┘
```

Cross-surface correlation catches what individual tools miss. Example: a low-severity auth failure + a matching JA3 fingerprint for a recon tool + port scans from the same IP = confirmed reconnaissance campaign.

## v2 Architecture (Autonomous Response)

```text
┌───────────────────────────┐
│ TriageDecision            │
│ (v1 output)               │
└───────────┬───────────────┘
            │
            ▼
┌───────────────────────────┐
│ Decision Gate             │
│ - confidence threshold    │
│ - policy file check       │
│ - audit trail logging     │
│ - rollback capability     │
└───────────┬───────────────┘
            │
    ┌───────┼───────┬───────────────┐
    │       │       │               │
    ▼       ▼       ▼               ▼
┌───────┐┌───────┐┌──────────┐┌──────────┐
│Contain││Deceive││Remediate ││ Notify   │
│       ││       ││          ││          │
│Block  ││Honey- ││Kill proc ││SOC alert │
│IP/CIDR││pot    ││Quarantine││Ticket    │
│Isolate││redir  ││Patch     ││Escalate  │
│host   ││Decoy  ││trigger   ││          │
│Lock   ││creds  ││          ││          │
│account││       ││          ││          │
└───────┘└───────┘└──────────┘└──────────┘
```

## v1 Decisions

- Input is file replay only
- Deterministic pipeline, not swarm-based
- `src/openclaw/` is an optional adapter, not a hard dependency
- Local-only analyst interaction
- Structured evidence records, not stored raw chain-of-thought
- Model-agnostic interface (K2.5 is a gated target, not guaranteed)

## Deferred Beyond v1

- Live SIEM connectors (Splunk, Elastic, QRadar)
- Native Kimi swarm orchestration
- Autonomous response actions (firewall, honeypot, isolation)
- Cloud model baselines
- Multi-tenant dashboards
