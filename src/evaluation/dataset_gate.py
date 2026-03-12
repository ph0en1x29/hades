"""Benchmark contract and dataset-gate validation helpers."""

from __future__ import annotations

from pathlib import Path
from typing import Any

from src.ingestion.schema import DatasetRole, UnifiedAlert


def benchmark_contract_issues(alert: UnifiedAlert) -> list[str]:
    """Return benchmark-readiness issues for one normalized alert."""
    issues: list[str] = []

    if alert.provenance.dataset_role == DatasetRole.ENGINEERING_SCAFFOLD:
        issues.append("engineering scaffold sources cannot serve as benchmark-of-record")

    if not alert.provenance.dataset_name:
        issues.append("missing dataset provenance")
    if not alert.provenance.label_provenance:
        issues.append("missing label provenance")

    if not alert.benchmark.scenario_id:
        issues.append("missing scenario identifier")
    if not alert.benchmark.rule_id:
        issues.append("missing detection rule association")
    if not alert.benchmark.rule_source:
        issues.append("missing detection rule source")
    if not alert.benchmark.rule_name:
        issues.append("missing detection rule name")
    if not alert.benchmark.mitre_techniques:
        issues.append("missing MITRE mapping")

    if not (alert.signature or alert.event_type or alert.metadata.message):
        issues.append("missing analyst-facing context")

    return issues


def validate_benchmark_config(
    config: dict[str, Any],
    *,
    base_dir: str | Path | None = None,
) -> None:
    """Validate that an evaluation config respects the dataset gate."""
    dataset_prep = config.get("dataset_preparation")
    if not isinstance(dataset_prep, dict):
        return

    benchmark = dataset_prep.get("benchmark_of_record")
    if not isinstance(benchmark, dict):
        return

    raw_sources = dataset_prep.get("raw_sources", [])
    source_index = {
        source.get("name"): source
        for source in raw_sources
        if isinstance(source, dict) and source.get("name")
    }

    source_name = benchmark.get("source")
    if not isinstance(source_name, str) or source_name not in source_index:
        raise ValueError("benchmark_of_record.source must reference a declared raw source")

    source = source_index[source_name]
    source_role = str(source.get("dataset_role", ""))
    experimental = bool(source.get("experimental", False))

    if source_role == DatasetRole.ENGINEERING_SCAFFOLD.value and not experimental:
        raise ValueError(
            "benchmark_of_record cannot use an engineering_scaffold source unless experimental=true"
        )
    if source.get("benchmark_eligible") is False and not experimental:
        raise ValueError("benchmark_of_record source is marked benchmark_eligible=false")

    if benchmark.get("require_rule_associations", True) and not benchmark.get("rule_pack_source"):
        raise ValueError("benchmark_of_record requires a rule_pack_source")
    if benchmark.get("require_label_provenance", True) and not benchmark.get(
        "label_provenance_policy",
    ):
        raise ValueError("benchmark_of_record requires a label_provenance_policy")

    manifest_path = benchmark.get("manifest")
    if isinstance(manifest_path, str) and manifest_path:
        root = Path(base_dir or Path.cwd())
        if not (root / manifest_path).exists():
            raise ValueError(f"benchmark manifest not found: {manifest_path}")


__all__ = ["benchmark_contract_issues", "validate_benchmark_config"]
