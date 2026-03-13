# Reviewer Changelog

This document records targeted fixes made in response to review findings so the next reviewer can see:

- what changed
- why it changed
- which files were affected
- which commands were run to validate the update

## March 12, 2026 — Dataset Gate Revision

### Summary

This update makes dataset adequacy the controlling project gate instead of a side note.

### Changes Made

#### 1. Added benchmark metadata to the normalized alert contract

Files:

- `src/ingestion/schema.py`
- `src/evaluation/dataset_gate.py`

What changed:

- Added explicit benchmark-context fields for scenario ids, rule associations, MITRE mappings, and correlation ids
- Added dataset-role labeling and label provenance to alert provenance
- Added a benchmark-contract validator for scientific readiness

Why:

- The advisor feedback requires rule-linked, provenance-preserving alerts before Hades can claim benchmark adequacy

#### 2. Reclassified CIC-IDS2018 as engineering scaffold only

Files:

- `src/ingestion/parsers/cicids2018.py`
- `src/main.py`
- `tests/test_parsers.py`

What changed:

- CIC-IDS2018 alerts now carry `engineering_scaffold` provenance
- CSV ingestion logs a warning that the path is not valid as benchmark-of-record evidence

Why:

- The parser remains useful infrastructure, but it cannot be mistaken for the scientific benchmark path

#### 3. Added config-level dataset-gate enforcement

Files:

- `configs/eval_config_A.yaml`
- `src/evaluation/dataset_gate.py`
- `tests/test_dataset_gate.py`

What changed:

- Config A now names Splunk Attack Data + Splunk Security Content as the public benchmark-of-record
- Added validation that rejects engineering scaffolds as benchmark-of-record inputs unless explicitly experimental

Why:

- The benchmark choice now needs to be enforceable, not just written down in docs

#### 4. Rewrote the dataset docs as a decision package

Files:

- `docs/DATASET_RESEARCH.md`
- `docs/BENCHMARK_MANIFEST.md`
- `data/manifests/public_benchmark_of_record.yaml`
- `docs/TECHNICAL_SPEC.md`
- `README.md`

What changed:

- Replaced the open-ended survey with a decision-oriented dataset document
- Added a benchmark manifest for the first public validation slice
- Reordered the main spec so dataset adequacy gates prototype validation and adversarial work

Why:

- The repo must show that dataset adequacy controls the roadmap from this point forward

### Validation Commands Run

```bash
.venv/bin/ruff check src tests
.venv/bin/python -m mypy src
.venv/bin/pytest -q
git diff --check
```

### Validation Result

- `ruff check src tests` passed
- `python -m mypy src` passed
- `pytest -q` passed with `15 passed`
- `git diff --check` passed

## March 12, 2026 — Benchmark Ingestion and Runtime Gate Follow-Up

### Summary

This update closed the two remaining dataset-gate gaps:

1. the benchmark-of-record is now ingestible by the repo
2. loaded runtime alerts are now checked against the dataset gate

### Changes Made

#### 1. Added a Splunk benchmark ingestion path

Files:

- `src/ingestion/parsers/splunk_attack_data.py`
- `src/ingestion/parsers/__init__.py`
- `data/benchmarks/public/splunk_attack_data_windows.jsonl`
- `tests/test_parsers.py`

What changed:

- Added a JSONL parser for a public Splunk Attack Data benchmark slice
- Added a runnable benchmark fixture with rule linkage, MITRE mappings, and label provenance

Why:

- The benchmark-of-record must exist in code, not only in docs and config

#### 2. Enforced dataset-gate checks on loaded alerts

Files:

- `src/evaluation/dataset_gate.py`
- `src/main.py`
- `tests/test_dataset_gate.py`
- `data/fixtures/sample_alerts.jsonl`

What changed:

- Runtime now validates loaded alerts against the dataset gate
- Benchmark-of-record and benchmark-candidate alerts fail fast if required fields are missing
- Engineering scaffolds are allowed only with explicit warnings
- The existing sample fixture is now explicitly marked `engineering_scaffold`

Why:

- Config validation alone was not enough; benchmark-invalid JSONL inputs could still pass through the pipeline

## March 12, 2026 — Editorial Cleanup Follow-Up

### Summary

This update addressed two remaining presentation-level review findings:

1. The README still implied an in-scope proprietary/cloud comparison matrix
2. The technical spec section numbering was internally inconsistent

### Changes Made

#### 1. Aligned README messaging with active v1 scope

Files:

- `README.md`

What changed:

- Updated the differentiation table to say `Local MoE + dense, cloud deferred`

Why:

- The active v1 scope now defers proprietary/cloud baselines
- The top-level pitch should match the actual repo plan and active configs

#### 2. Fixed technical spec section numbering

Files:

- `docs/TECHNICAL_SPEC.md`

What changed:

- Renumbered `Component Specification` subsections from `9.x` to `7.x`
- Renumbered `Public Interfaces` subsections from `9.x` to `8.x`

Why:

- The previous numbering made the spec look merged rather than intentionally edited
- Clean numbering improves reviewer confidence and makes internal references more trustworthy

### Validation Commands Run

```bash
git diff --check
```

### Validation Result

- `git diff --check` passed

## March 12, 2026 — Adversarial Review Follow-Up

### Summary

This update addressed four review findings in the adversarial-robustness pivot:

1. `StructuredPromptDefense` changed the alert contract instead of hardening it
2. `CanaryDefense` did not actually inject a canary
3. `eval_adversarial.yaml` reintroduced a cloud-model comparison matrix that v1 explicitly excludes
4. `docs/ARCHITECTURE.md` overstated implementation maturity

### Changes Made

#### 1. Preserved the alert contract in `StructuredPromptDefense`

Files:

- `src/adversarial/defenses.py`

What changed:

- Replaced the flattening logic with recursive structure-preserving wrapping
- String leaves are now wrapped with field markers like `[FIELD:metadata.vendor] ... [/FIELD]`
- Nested dictionaries and lists remain intact

Why:

- The defense must harden prompt construction without changing the evaluated alert schema
- Flattening the alert would confound defense performance with data-shape mutation

#### 2. Made `CanaryDefense` a real canary-boundary defense

Files:

- `src/adversarial/defenses.py`

What changed:

- The defense now injects a canary into `metadata.prompt_boundary_canary`
- `check_output()` still detects canary leakage in model output
- Defense processing now uses `deepcopy` so input alerts are not mutated in place

Why:

- A canary defense is only valid if the model can actually encounter the canary through the alert-data boundary
- Mutating caller-owned alert objects is unsafe and makes tests misleading

#### 3. Restored v1 scope discipline in adversarial evaluation config

Files:

- `configs/eval_adversarial.yaml`

What changed:

- Removed `gpt_4o` and `claude_sonnet` from the active v1 model list
- Moved those cloud baselines into `deferred_models`
- Changed active experiment matrices to use local models only

Why:

- The repo’s v1 story is offline, local, and air-gap compatible
- The previous config reintroduced a cloud comparison matrix that the docs explicitly mark as deferred

#### 4. Toned down maturity claims in docs

Files:

- `docs/ARCHITECTURE.md`
- `docs/TECHNICAL_SPEC.md`

What changed:

- Replaced “validated/approved” language with scaffold/in-progress language
- Aligned defense descriptions with the actual implementation
- Updated the baseline experiment description to emphasize local-model evaluation

Why:

- Reviewers should be able to distinguish implemented behavior from planned research work
- The repo should not claim a stronger maturity level than the code and tests support

#### 5. Added dedicated adversarial defense tests

Files:

- `tests/test_adversarial_defenses.py`

What changed:

- Added tests for sanitization behavior
- Added tests that the structured defense preserves nested shape
- Added tests that the canary is inserted into alert metadata and can be detected in output

Why:

- The adversarial module previously had no direct tests
- These checks are the minimum needed to keep future review changes honest

#### 6. Restored lint/type hygiene

Files:

- `src/adversarial/__init__.py`
- `src/adversarial/payloads.py`
- `src/adversarial/defenses.py`

What changed:

- Fixed import ordering
- Updated typing to modern `X | None` style
- Removed typing patterns that were failing `mypy`

Why:

- `main` should stay green on its own declared static-analysis bar

### Validation Commands Run

```bash
.venv/bin/ruff check src tests
.venv/bin/python -m mypy src
.venv/bin/pytest -q
git diff --check
```

### Validation Result

- `ruff check src tests` passed
- `python -m mypy src` passed
- `pytest -q` passed with `9 passed`
- `git diff --check` passed

### Reviewer Notes

- These fixes do not claim that the full adversarial evaluation pipeline is implemented end to end
- They do make the current scaffolding internally consistent with the v1 proposal and remove the specific review contradictions identified on March 12, 2026

## March 13, 2026 — Final Pre-Submission Validation Follow-Up

### Summary

This update resolved the last two submission blockers found during final review:

1. the main `pytest` suite was red after `INV-6` was added
2. the reproducibility package could report green for sections that were actually skipped or silently failing

### Changes Made

#### 1. Restored consistency between behavioral invariants and their tests

Files:

- `src/evaluation/behavioral_invariants.py`
- `tests/test_behavioral_invariants.py`

What changed:

- Kept the new sixth invariant (`INV-6`) in the runtime path
- Updated the invariant test to assert `6` checks instead of the old `5`
- Made the standalone test runner exit non-zero on failure
- Simplified the new invariant control flow to satisfy lint

Why:

- The repo cannot claim a clean validation state while `pytest` fails on the current `main`
- The standalone test path must agree with the actual `pytest` contract

#### 2. Made adversarial E2E validation honest about missing prerequisites

Files:

- `scripts/run_adversarial_e2e.py`
- `scripts/reproduce_all.py`

What changed:

- `run_adversarial_e2e.py` now emits `SKIPPED:` and exits cleanly when the required Splunk Sysmon dataset is absent
- The script description was narrowed from “true end-to-end” to a mock pre-GPU validation path
- `reproduce_all.py` now reports the adversarial E2E section as skipped instead of passed when the dataset is unavailable
- The reproducibility summary now reports `passed / total sections`, including skipped sections, instead of hiding skips from the denominator

Why:

- Final review should not depend on false-green results
- Dataset-dependent checks are acceptable, but only when they are reported honestly

#### 3. Realigned submission-facing stats with the current repo state

Files:

- `README.md`
- `docs/ADVISOR_PRESENTATION.md`
- `scripts/generate_beth_synthetic.py`
- `tests/test_adversarial_defenses.py`

What changed:

- Updated the README and advisor presentation to match the current benchmark and reproducibility counts
- Cleaned the new synthetic-data and defense-test scripts so the touched validation path is lint-clean

Why:

- The professor-facing documents should match the benchmark manifest and current validation harness, not older intermediate counts

### Validation Commands Run

```bash
.venv/bin/ruff check src tests scripts/build_benchmark_pack.py scripts/generate_beth_synthetic.py scripts/reproduce_all.py scripts/run_adversarial_e2e.py
.venv/bin/python -m mypy src
.venv/bin/pytest -q
.venv/bin/python tests/test_behavioral_invariants.py
.venv/bin/python tests/test_fox_e2e.py
.venv/bin/python scripts/validate_architecture.py
.venv/bin/python scripts/run_comprehensive_validation.py
.venv/bin/python scripts/reproduce_all.py
.venv/bin/python scripts/run_adversarial_e2e.py
git diff --check
```

### Validation Result

- `ruff check ...` passed
- `python -m mypy src` passed
- `pytest -q` passed with `61 passed, 10 skipped`
- `python tests/test_behavioral_invariants.py` passed with `10/10`
- `python tests/test_fox_e2e.py` passed with `95.7/100`
- `python scripts/validate_architecture.py` passed with `18/18`
- `python scripts/run_comprehensive_validation.py` passed with `14/14` and `7 skipped`
- `python scripts/reproduce_all.py` passed with `25/29 sections` and `4 skipped`
- `python scripts/run_adversarial_e2e.py` now skips cleanly when the dataset is absent
- `git diff --check` passed

### Reviewer Notes

- Remaining skips are dataset- or corpus-dependent and are now reported explicitly rather than counted as passes
- This update does not add GPU-backed experiment results; it only makes the current pre-submission validation state accurate and reviewable
