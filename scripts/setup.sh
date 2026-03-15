#!/usr/bin/env bash
# Hades GPU Setup — One script to rule them all
# Usage: curl -sL <raw-github-url> | bash
#   or:  git clone https://github.com/ph0en1x29/hades.git && cd hades && bash scripts/setup.sh
#
# What it does:
#   1. Checks GPU availability
#   2. Installs Python deps
#   3. Starts Docker (vLLM + Qdrant)
#   4. Runs all experiments
#   5. Pushes results to GitHub

set -euo pipefail

log() { echo -e "\n🔥 $*"; }
err() { echo -e "\n❌ $*" >&2; exit 1; }

# --- Check we're in the right place ---
[[ -f "src/main.py" ]] || err "Run this from the hades repo root: cd hades && bash scripts/setup.sh"

# --- Check GPU ---
log "Checking GPU..."
command -v nvidia-smi >/dev/null || err "No nvidia-smi found. Need NVIDIA GPU with drivers installed."
nvidia-smi --query-gpu=name,memory.total --format=csv,noheader
GPU_COUNT=$(nvidia-smi -L | wc -l)
log "Found $GPU_COUNT GPU(s)"

# --- Python deps ---
log "Setting up Python environment..."
if [[ ! -d ".venv" ]]; then
    python3 -m venv .venv
fi
source .venv/bin/activate
pip install -q -r requirements.txt 2>/dev/null || pip install -q pyyaml aiohttp

# --- Docker ---
log "Starting Docker services..."
command -v docker >/dev/null || err "Docker not installed"
docker compose up -d qdrant

# --- Pick first model ---
# Start with smallest (Qwen) if only 2 GPUs, otherwise K2.5
if (( GPU_COUNT >= 4 )); then
    FIRST_MODEL="kimi"
else
    FIRST_MODEL="qwen"
    log "Only $GPU_COUNT GPUs — starting with Qwen 3.5 (smallest)"
fi

log "Ready to run experiments!"
echo ""
echo "=========================================="
echo "  Hades GPU Experiment Runner"
echo "=========================================="
echo ""
echo "  Run all experiments:"
echo "    bash scripts/run_gpu_experiments.sh"
echo ""
echo "  Run one model at a time:"
echo "    bash scripts/run_gpu_experiments.sh $FIRST_MODEL e1      # baseline"
echo "    bash scripts/run_gpu_experiments.sh $FIRST_MODEL e2-sample  # stratified"
echo "    bash scripts/run_gpu_experiments.sh $FIRST_MODEL           # all phases"
echo ""
echo "  Results go to: results/gpu/<model>/"
echo "  When done:     git add results/ && git commit -m 'data: GPU results' && git push"
echo "=========================================="
