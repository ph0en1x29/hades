[2026-03-12 03:58] [Codex] Built the CIC-IDS2018 parser, sample alert fixtures, async triage pipeline, CLI replay flow, and parser coverage.
[2026-03-12 11:45] [Codex] Added dataset-gate enforcement, benchmark metadata schema, public benchmark manifest, and explicit engineering-scaffold labeling for CIC-IDS2018.
[2026-03-13 00:20] [Phoenix] Fixed test_cross_technique.py to work without pytest (try/import fallback). All 26 tests passing.
[2026-03-13 00:30] [Phoenix] Updated paper benchmark numbers: 11,147 alerts (was 7,119), 29 techniques (was 17), 9 tactics (was 8), 1.3M adversarial variants.
[2026-03-13 00:35] [Phoenix] Added 2026 related work: Datadog hackerbot-claw incident, AgentLAB (Jiang et al.), SEC-bench (Lee et al.).
[2026-03-13 00:45] [Phoenix] Added comprehensive SOC-Bench adapter tests (17 tests) - Fox O1/O2/O3, JSON serialization, edge cases.
[2026-03-13 00:55] [Phoenix] Added correlator stress tests with benchmark data (13 tests) - large batches, chain detection, performance benchmarks.
[2026-03-13 00:55] [Phoenix] Added MITRE RAG smoke tests (skips gracefully when Qdrant unavailable).
