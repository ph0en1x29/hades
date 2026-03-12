.PHONY: setup test lint typecheck format run eval dashboard docker clean help

PYTHON ?= python
CONFIG ?= configs/default.yaml
EVAL_CONFIG ?= configs/eval_config_A.yaml

help: ## Show this help
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | sort | \
		awk 'BEGIN {FS = ":.*?## "}; {printf "\033[36m%-16s\033[0m %s\n", $$1, $$2}'

setup: ## Set up development environment
	$(PYTHON) -m venv .venv
	.venv/bin/pip install -e ".[all]"
	@echo "\n✅ Run: source .venv/bin/activate"

test: ## Run tests
	$(PYTHON) -m pytest tests/ -v

lint: ## Lint with ruff
	$(PYTHON) -m ruff check src/ tests/

typecheck: ## Type check with mypy
	$(PYTHON) -m mypy src/

format: ## Auto-format with ruff
	$(PYTHON) -m ruff format src/ tests/
	$(PYTHON) -m ruff check --fix src/ tests/

run: ## Run the triage pipeline
	$(PYTHON) -m src.main --config $(CONFIG) --mode pipeline

eval: ## Run evaluation harness
	$(PYTHON) -m src.main --config $(EVAL_CONFIG) --mode eval

dashboard: ## Start the dashboard
	$(PYTHON) -m src.main --config $(CONFIG) --mode dashboard

docker: ## Build and start all containers
	docker compose up -d --build

docker-eval: ## Run evaluation in Docker
	docker compose --profile eval up evaluator --build

docker-down: ## Stop all containers
	docker compose down

clean: ## Remove build artifacts and caches
	find . -type d -name __pycache__ -exec rm -rf {} + 2>/dev/null || true
	find . -type d -name .pytest_cache -exec rm -rf {} + 2>/dev/null || true
	find . -type d -name .mypy_cache -exec rm -rf {} + 2>/dev/null || true
	find . -type d -name .ruff_cache -exec rm -rf {} + 2>/dev/null || true
	rm -rf dist/ build/ *.egg-info/
