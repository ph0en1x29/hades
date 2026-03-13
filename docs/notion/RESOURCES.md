# 📚 Resources

## Project Links
- **Repository:** github.com/ph0en1x29/hades
- **Paper Draft:** `paper/HADES_PAPER_DRAFT.md`
- **Technical Spec:** `docs/TECHNICAL_SPEC.md`
- **Reviewer Changelog:** `docs/REVIEWER_CHANGELOG.md`
- **Advisor Presentation:** `docs/ADVISOR_PRESENTATION.md`

## Key References

### Adversarial ML
- Carlini et al. — >90% LLM bypass rates
- Nasr et al. (2025) — Model-level defenses bypassed by adaptive attackers
- AgentSentry — 74.55% universal adversarial attack success
- L³ — MoE expert silencing (7% → 70% ASR)

### SOC / SIEM Injection
- Neaves (2025) — Production SIEM injection via HTTP UA, SSH, WinEvent
- LevelBlue — 100% SOC injection success
- Unit 42 (2026) — 22 indirect prompt injection techniques in the wild

### Benchmarks
- SOC-Bench (Liu, 2026) — Blue team AI agent evaluation
- CyBench (ICLR 2025) — LLM cybersecurity benchmark
- AgentDojo (NeurIPS 2024) — LLM agent robustness

### Frameworks
- OWASP Top 10 for LLM Applications (2025)
- MITRE ATT&CK Framework

## Tools Used
- **vLLM** — Model serving (OpenAI-compatible API)
- **Qdrant** — Vector store for RAG
- **Splunk Attack Data** — Benchmark source
- **Splunk Security Content** — Detection rules
- **pytest** — Testing
- **ruff + mypy** — Linting and type checking
