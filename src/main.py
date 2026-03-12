"""Hades — Offline Agentic SOC Assistant

Entry point for the triage pipeline.
"""

import argparse
import yaml
from pathlib import Path


def load_config(config_path: str) -> dict:
    """Load YAML configuration."""
    with open(config_path) as f:
        return yaml.safe_load(f)


def main():
    parser = argparse.ArgumentParser(description="Hades SOC Assistant")
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
    args = parser.parse_args()

    config = load_config(args.config)
    print(f"[Hades v{config['system']['version']}] Starting in {args.mode} mode...")

    if args.mode == "pipeline":
        # TODO: Initialize and run the triage pipeline
        print("Pipeline mode — not yet implemented")
    elif args.mode == "dashboard":
        # TODO: Start FastAPI dashboard
        print("Dashboard mode — not yet implemented")
    elif args.mode == "eval":
        # TODO: Run evaluation harness
        print("Evaluation mode — not yet implemented")


if __name__ == "__main__":
    main()
