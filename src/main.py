"""Hades — Offline Agentic SOC Assistant

Entry point for the triage pipeline, dashboard, and evaluation harness.
"""

from __future__ import annotations

import argparse
import logging
import sys
from pathlib import Path

import yaml

from src import __version__

logger = logging.getLogger("hades")


def load_config(config_path: str) -> dict:
    """Load and validate YAML configuration."""
    path = Path(config_path)
    if not path.exists():
        logger.error("Config not found: %s", path)
        sys.exit(1)
    with path.open() as f:
        config = yaml.safe_load(f)
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


def run_pipeline(config: dict) -> None:
    """Start the alert triage pipeline."""
    from src.agents import ClassifierAgent, CorrelatorAgent, PlaybookAgent
    from src.rag import Retriever, VectorStore

    logger.info("Initializing pipeline...")

    # Initialize RAG (graceful if chromadb not installed)
    rag_config = config.get("rag", {})
    store = VectorStore(rag_config)
    try:
        store.initialize()
    except ImportError:
        logger.warning("ChromaDB not installed — RAG disabled. Install: pip install chromadb")
    retriever = Retriever(store, rag_config)

    # Initialize agents
    orch_config = config.get("orchestration", {})
    classifier = ClassifierAgent(orch_config.get("classifier", {}))
    correlator = CorrelatorAgent(orch_config)
    playbook = PlaybookAgent(orch_config)

    logger.info(
        "Pipeline ready — agents=[%s, %s, %s], RAG docs=%d",
        classifier.name,
        correlator.name,
        playbook.name,
        store.document_count,
    )

    # TODO: Start ingestion loop (file watcher / Kafka consumer)
    # For each alert:
    #   1. Classify
    #   2. If low confidence → correlate → reclassify
    #   3. Generate playbook
    #   4. Log to audit DB
    logger.info("Pipeline mode — ingestion loop not yet implemented")


def run_dashboard(config: dict) -> None:
    """Start the FastAPI dashboard."""
    output_config = config.get("output", {}).get("dashboard", {})
    host = output_config.get("host", "0.0.0.0")
    port = output_config.get("port", 8000)
    logger.info("Dashboard mode — starting on %s:%d (not yet implemented)", host, port)


def run_eval(config: dict) -> None:
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

    logger.info("Hades v%s starting in %s mode", __version__, args.mode)

    dispatch = {
        "pipeline": run_pipeline,
        "dashboard": run_dashboard,
        "eval": run_eval,
    }
    dispatch[args.mode](config)


if __name__ == "__main__":
    main()
