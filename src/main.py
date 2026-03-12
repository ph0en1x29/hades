"""Hades — Offline Agentic SOC Assistant

Entry point for the triage pipeline, dashboard, and evaluation harness.
"""

from __future__ import annotations

import argparse
import asyncio
import logging
import sys
from datetime import UTC, datetime
from pathlib import Path
from typing import TYPE_CHECKING, Any, cast

import yaml

from src import __version__

if TYPE_CHECKING:
    from src.ingestion.schema import UnifiedAlert

logger = logging.getLogger("hades")


def load_config(config_path: str) -> dict[str, Any]:
    """Load and validate YAML configuration."""
    path = Path(config_path)
    if not path.exists():
        logger.error("Config not found: %s", path)
        sys.exit(1)
    with path.open() as f:
        config = cast("dict[str, Any]", yaml.safe_load(f))
    if not config:
        logger.error("Empty config: %s", path)
        sys.exit(1)
    return config


def setup_logging(level: str = "INFO") -> None:
    """Configure structured logging."""
    logging.basicConfig(
        level=getattr(logging, level.upper(), logging.INFO),
        format="%(asctime)s [%(name)s] %(levelname)s: %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
    )


def load_alerts(input_path: str | Path) -> list[UnifiedAlert]:
    """Load unified alerts from a CSV or JSONL file."""
    from src.ingestion.parsers import load_cicids2018_csv
    from src.ingestion.schema import UnifiedAlert

    path = Path(input_path)
    if not path.exists():
        logger.error("Input not found: %s", path)
        sys.exit(1)

    suffix = path.suffix.lower()
    if suffix == ".csv":
        logger.warning(
            "CSV ingestion uses the CIC-IDS2018 engineering scaffold path only; "
            "it is not valid as a benchmark-of-record dataset."
        )
        return load_cicids2018_csv(path)
    if suffix == ".jsonl":
        with path.open("r", encoding="utf-8") as handle:
            return [
                UnifiedAlert.from_json(line)
                for line in handle
                if line.strip()
            ]

    logger.error("Unsupported input type: %s", path.suffix or "<none>")
    sys.exit(1)


def build_decisions_output_path() -> Path:
    """Create a timestamped destination for pipeline decisions."""
    timestamp = datetime.now(UTC).strftime("%Y%m%dT%H%M%SZ")
    return Path("results/decisions") / f"decisions_{timestamp}.jsonl"


def print_pipeline_summary(
    total_alerts: int,
    counts: dict[str, int],
    avg_latency_ms: float,
) -> None:
    """Print a concise pipeline summary to stdout."""
    print("Pipeline summary")
    print(f"total alerts: {total_alerts}")
    print("classification breakdown:")
    if counts:
        for classification, count in sorted(counts.items()):
            print(f"  {classification}: {count}")
    else:
        print("  none")
    print(f"avg latency (ms): {avg_latency_ms:.2f}")


def run_pipeline(config: dict[str, Any], input_path: str | None = None) -> None:
    """Start the alert triage pipeline."""
    from src.agents import ClassifierAgent
    from src.pipeline import TriagePipeline

    if not input_path:
        logger.error("Pipeline mode requires --input pointing to a CSV or JSONL file")
        sys.exit(1)

    orch_config = config.get("orchestration", {})
    classifier = ClassifierAgent(orch_config.get("classifier", {}))
    alerts = load_alerts(input_path)
    output_path = build_decisions_output_path()

    logger.info(
        "Running pipeline — alerts=%d, agent=%s, input=%s",
        len(alerts),
        classifier.name,
        input_path,
    )

    pipeline = TriagePipeline(classifier)
    result = asyncio.run(pipeline.run(alerts, output_path))

    logger.info(
        "Pipeline finished — decisions=%d, output=%s, wall_clock_ms=%d",
        len(result.decisions),
        result.output_path,
        result.wall_clock_ms,
    )
    print_pipeline_summary(
        result.total_alerts,
        result.classification_counts,
        result.avg_latency_ms,
    )


def run_dashboard(config: dict[str, Any]) -> None:
    """Start the FastAPI dashboard."""
    dashboard_config = config.get("interfaces", {}).get("dashboard", {})
    host = dashboard_config.get("host", "0.0.0.0")
    port = dashboard_config.get("port", 8000)
    logger.info("Dashboard mode — starting on %s:%d (not yet implemented)", host, port)


def run_eval(config: dict[str, Any]) -> None:
    """Run the evaluation harness."""
    logger.info("Evaluation mode — benchmark harness not yet implemented")


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Hades — Offline Agentic SOC Assistant",
    )
    parser.add_argument(
        "--config",
        default="configs/default.yaml",
        help="Path to configuration file",
    )
    parser.add_argument(
        "--mode",
        choices=["pipeline", "dashboard", "eval"],
        default="pipeline",
        help="Run mode",
    )
    parser.add_argument(
        "--input",
        default=None,
        help="Path to input alerts (.csv or .jsonl) for pipeline mode",
    )
    parser.add_argument(
        "--log-level",
        default=None,
        help="Override log level (DEBUG, INFO, WARNING, ERROR)",
    )
    parser.add_argument(
        "--version",
        action="version",
        version=f"hades {__version__}",
    )
    args = parser.parse_args()

    config = load_config(args.config)
    log_level = args.log_level or config.get("system", {}).get("log_level", "INFO")
    setup_logging(log_level)

    from src.evaluation.dataset_gate import validate_benchmark_config

    try:
        validate_benchmark_config(config)
    except ValueError as exc:
        logger.error("Dataset gate validation failed: %s", exc)
        sys.exit(1)

    logger.info("Hades v%s starting in %s mode", __version__, args.mode)

    if args.mode == "pipeline":
        run_pipeline(config, args.input)
        return

    dispatch = {
        "dashboard": run_dashboard,
        "eval": run_eval,
    }
    dispatch[args.mode](config)


if __name__ == "__main__":
    main()
