#!/usr/bin/env bash
# Hades Lab Deployment Script
# Run this on the Penn State lab GPU machine to get everything ready.
#
# Usage:
#   git clone https://github.com/ph0en1x29/hades.git
#   cd hades
#   bash scripts/lab_setup.sh [--model MODEL_NAME] [--skip-download]
#
# Models (pick one to start):
#   qwen3.5    — Qwen/Qwen3.5        (~200GB, smallest, good first test)
#   deepseek   — deepseek-ai/DeepSeek-R1  (~400GB, best cybersecurity reasoning)
#   glm5       — THUDM/glm-5         (~400GB, best overall reasoning)
#   kimi       — moonshotai/Kimi-K2.5 (~630GB INT4, largest MoE)

set -euo pipefail

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

log()  { echo -e "${GREEN}[hades]${NC} $*"; }
warn() { echo -e "${YELLOW}[hades]${NC} $*"; }
err()  { echo -e "${RED}[hades]${NC} $*" >&2; }

# --- Parse arguments ---
MODEL_ALIAS="qwen3.5"
SKIP_DOWNLOAD=false

while [[ $# -gt 0 ]]; do
    case "$1" in
        --model)     MODEL_ALIAS="$2"; shift 2 ;;
        --skip-download) SKIP_DOWNLOAD=true; shift ;;
        -h|--help)
            echo "Usage: $0 [--model MODEL] [--skip-download]"
            echo "Models: qwen3.5, deepseek, glm5, kimi"
            exit 0 ;;
        *) err "Unknown option: $1"; exit 1 ;;
    esac
done

# --- Model lookup ---
declare -A MODEL_MAP=(
    ["qwen3.5"]="Qwen/Qwen3.5"
    ["deepseek"]="deepseek-ai/DeepSeek-R1"
    ["glm5"]="THUDM/glm-5"
    ["kimi"]="moonshotai/Kimi-K2.5"
)

MODEL_NAME="${MODEL_MAP[$MODEL_ALIAS]:-$MODEL_ALIAS}"
log "Target model: $MODEL_NAME"

# --- Step 0: System checks ---
log "Step 0: System checks"

if ! command -v python3 &>/dev/null; then
    err "Python 3 not found. Install Python 3.12+."
    exit 1
fi

PY_VERSION=$(python3 -c "import sys; print(f'{sys.version_info.major}.{sys.version_info.minor}')")
log "  Python: $PY_VERSION"

if command -v nvidia-smi &>/dev/null; then
    GPU_COUNT=$(nvidia-smi -L 2>/dev/null | wc -l)
    GPU_MEM=$(nvidia-smi --query-gpu=memory.total --format=csv,noheader,nounits 2>/dev/null | head -1)
    log "  GPUs: $GPU_COUNT × ${GPU_MEM}MB"
else
    warn "  nvidia-smi not found — GPU checks skipped"
    GPU_COUNT=0
fi

DISK_FREE=$(df -BG --output=avail . 2>/dev/null | tail -1 | tr -d ' G')
log "  Disk free: ${DISK_FREE}GB"

if [[ "$DISK_FREE" -lt 250 ]]; then
    warn "  ⚠️  Less than 250GB free. Large models need 200-630GB."
fi

# --- Step 1: Python environment ---
log "Step 1: Python environment"

if [[ ! -d ".venv" ]]; then
    python3 -m venv .venv
    log "  Created virtual environment"
fi

source .venv/bin/activate
log "  Activated .venv ($(python3 --version))"

pip install --upgrade pip -q
pip install -r requirements.txt -q
pip install 'qdrant-client[fastembed]' -q

# Install optional cloud SDKs only if needed
# pip install 'openai>=1.50' 'anthropic>=0.40' -q

log "  Dependencies installed"

# --- Step 2: Verify Hades pipeline ---
log "Step 2: Verify pipeline"

python3 -c "
from src import __version__
from src.agents import ClassifierAgent
from src.pipeline import TriagePipeline
from src.rag import VectorStore, Retriever
from src.runtime import OpenAICompatChatClient
from src.ingestion.parsers import load_cicids2018_csv, load_beth_csv
from src.evaluation.schemas import TriageDecision, EvalResult
print(f'  Hades v{__version__} — all imports OK')
"

# --- Step 3: Build MITRE ATT&CK RAG corpus ---
log "Step 3: MITRE ATT&CK corpus"

MITRE_JSONL="data/mitre_attack/rag_documents/techniques.jsonl"
if [[ -f "$MITRE_JSONL" ]]; then
    TECHNIQUE_COUNT=$(wc -l < "$MITRE_JSONL")
    log "  Already built: $TECHNIQUE_COUNT techniques"
else
    log "  Building from STIX data..."
    if [[ ! -f "data/mitre_attack/enterprise-attack.json" ]]; then
        warn "  Downloading ATT&CK STIX bundle..."
        mkdir -p data/mitre_attack
        curl -sL "https://raw.githubusercontent.com/mitre/cti/master/enterprise-attack/enterprise-attack.json" \
            -o data/mitre_attack/enterprise-attack.json
    fi
    python3 scripts/build_mitre_rag.py
    TECHNIQUE_COUNT=$(wc -l < "$MITRE_JSONL")
    log "  Built: $TECHNIQUE_COUNT techniques"
fi

# --- Step 4: Ingest into Qdrant ---
log "Step 4: Qdrant ingestion"

python3 scripts/ingest_threat_intel.py --source mitre_attack 2>&1 | while IFS= read -r line; do
    log "  $line"
done

# --- Step 5: Build benchmark pack ---
log "Step 5: Benchmark pack"

BENCHMARK="data/benchmark/hades_benchmark_v1.jsonl"
if [[ -f "$BENCHMARK" ]]; then
    ALERT_COUNT=$(wc -l < "$BENCHMARK")
    log "  Already built: $ALERT_COUNT alerts"
else
    log "  Building from Splunk Attack Data..."
    python3 scripts/build_benchmark_pack.py
    ALERT_COUNT=$(wc -l < "$BENCHMARK")
    log "  Built: $ALERT_COUNT alerts"
fi

# --- Step 6: Model download ---
if [[ "$SKIP_DOWNLOAD" == "true" ]]; then
    log "Step 6: Model download SKIPPED (--skip-download)"
else
    log "Step 6: Model download"

    MODEL_DIR="data/models"
    mkdir -p "$MODEL_DIR"

    if command -v huggingface-cli &>/dev/null; then
        log "  Downloading $MODEL_NAME (this will take a while)..."
        huggingface-cli download "$MODEL_NAME" --local-dir "$MODEL_DIR/$MODEL_ALIAS" --quiet
        log "  Download complete"
    else
        warn "  huggingface-cli not found. Install with: pip install huggingface_hub[cli]"
        warn "  Then run: huggingface-cli download $MODEL_NAME --local-dir $MODEL_DIR/$MODEL_ALIAS"
    fi
fi

# --- Step 7: Dry-run experiment ---
log "Step 7: Dry-run validation"

python3 scripts/run_experiment.py --experiment E1 --model mock --dry-run --max-alerts 50 2>&1 | \
    while IFS= read -r line; do log "  $line"; done

python3 scripts/run_experiment.py --experiment E2 --model mock --dry-run --max-alerts 10 2>&1 | \
    while IFS= read -r line; do log "  $line"; done

# --- Step 8: Ready check ---
log ""
log "============================================"
log "  HADES LAB SETUP COMPLETE"
log "============================================"
log ""
log "  Model:     $MODEL_NAME"
log "  Benchmark: $(wc -l < "$BENCHMARK" 2>/dev/null || echo 'not built') alerts"
log "  RAG:       $(wc -l < "$MITRE_JSONL" 2>/dev/null || echo 'not built') techniques"
log "  Dry-run:   passed"
log ""

if [[ "$SKIP_DOWNLOAD" == "true" || ! -d "data/models/$MODEL_ALIAS" ]]; then
    log "  Next: Download model weights, then start vLLM:"
    log "    huggingface-cli download $MODEL_NAME --local-dir data/models/$MODEL_ALIAS"
    log "    python3 -m vllm.entrypoints.openai.api_server \\"
    log "      --model data/models/$MODEL_ALIAS \\"
    log "      --tensor-parallel-size $GPU_COUNT \\"
    log "      --max-model-len 128000 \\"
    log "      --port 8001"
else
    log "  Start vLLM:"
    log "    python3 -m vllm.entrypoints.openai.api_server \\"
    log "      --model data/models/$MODEL_ALIAS \\"
    log "      --tensor-parallel-size $GPU_COUNT \\"
    log "      --max-model-len 128000 \\"
    log "      --port 8001"
fi

log ""
log "  Then run experiments:"
log "    python3 scripts/run_experiment.py --experiment E1 --model $MODEL_NAME"
log "    python3 scripts/run_experiment.py --experiment E2 --model $MODEL_NAME"
log ""
