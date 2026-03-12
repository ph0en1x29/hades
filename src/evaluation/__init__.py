"""Hades evaluation — benchmark harness and metrics."""

from src.evaluation.schemas import EvalResult, InferenceMode, TriageCategory, TriageDecision
from src.evaluation.socbench_adapter import (
    FoxStageOutput,
    PandaBLUFReport,
    TigerStageOutput,
    triage_decisions_to_fox_stage,
)

__all__ = [
    "EvalResult", "InferenceMode", "TriageCategory", "TriageDecision",
    "FoxStageOutput", "PandaBLUFReport", "TigerStageOutput",
    "triage_decisions_to_fox_stage",
]
