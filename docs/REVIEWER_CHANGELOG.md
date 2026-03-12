# Reviewer Changelog

This document records targeted fixes made in response to review findings so the next reviewer can see:

- what changed
- why it changed
- which files were affected
- which commands were run to validate the update

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
