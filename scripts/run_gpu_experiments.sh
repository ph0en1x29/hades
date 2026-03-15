#!/usr/bin/env bash
# Hades GPU Experiment Runner
# Usage: ./scripts/run_gpu_experiments.sh [model] [phase]
#
# Examples:
#   ./scripts/run_gpu_experiments.sh              # Run all models, all phases
#   ./scripts/run_gpu_experiments.sh kimi          # Run K2.5 only, all phases
#   ./scripts/run_gpu_experiments.sh kimi e1       # Run K2.5 E1 baseline only
#   ./scripts/run_gpu_experiments.sh all e2-sample  # Stratified E2 sample, all models
#
# Prerequisites:
#   - Docker with NVIDIA runtime (nvidia-smi must work)
#   - 4x A100 80GB or 2x H100 for K2.5/R1/GLM-5
#   - 2x A100 sufficient for Qwen 3.5 (17B active)
#   - Clone this repo, run from repo root
#
# Data flow:
#   Benchmark alerts (data/benchmark/hades_benchmark_v1.jsonl, 12,147 alerts)
#     → Adversarial injection (data/adversarial/<model>/)
#       → vLLM inference (Docker, temp=0, 3 runs each)
#         → Raw results (results/gpu/<model>/<experiment>/)
#           → Statistical analysis (results/gpu/<model>/analysis/)
#             → Paper tables (results/gpu/tables/)

set -euo pipefail

# --- Configuration ---
REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
RESULTS_BASE="${REPO_ROOT}/results/gpu"
BENCHMARK="${REPO_ROOT}/data/benchmark/hades_benchmark_v1.jsonl"
ADVERSARIAL_BASE="${REPO_ROOT}/data/adversarial"
VLLM_PORT=8001
N_RUNS=3  # Repeated runs for MoE non-determinism averaging
STRATIFIED_SAMPLE_SIZE=200  # Alerts per stratified E2 sample

# Model configs: name, HuggingFace ID, min GPUs needed
declare -A MODEL_IDS=(
    ["kimi"]="moonshotai/Kimi-K2.5"
    ["r1"]="deepseek-ai/DeepSeek-R1"
    ["qwen"]="Qwen/Qwen3.5"
    ["glm"]="THUDM/glm-5"
)

# Priority order: strongest first (strongest claim if vulnerable)
MODEL_ORDER=("kimi" "r1" "qwen" "glm")

REQUESTED_MODEL="${1:-all}"
REQUESTED_PHASE="${2:-all}"

# --- Helpers ---
log() { echo "[$(date '+%Y-%m-%d %H:%M:%S')] $*"; }
err() { log "ERROR: $*" >&2; exit 1; }

check_prereqs() {
    command -v docker >/dev/null || err "Docker not found"
    command -v nvidia-smi >/dev/null || err "nvidia-smi not found — need NVIDIA GPU runtime"
    nvidia-smi >/dev/null 2>&1 || err "nvidia-smi failed — GPU driver issue"
    [[ -f "$BENCHMARK" ]] || err "Benchmark not found: $BENCHMARK"
    
    GPU_COUNT=$(nvidia-smi -L | wc -l)
    GPU_MEM=$(nvidia-smi --query-gpu=memory.total --format=csv,noheader,nounits | head -1)
    log "Found $GPU_COUNT GPUs, ${GPU_MEM}MB each"
    
    if (( GPU_COUNT < 2 )); then
        err "Need at least 2 GPUs (4 recommended for K2.5/R1/GLM-5)"
    fi
}

wait_for_vllm() {
    local max_wait=600  # 10 minutes for large model loading
    local elapsed=0
    log "Waiting for vLLM to be ready on port $VLLM_PORT..."
    while ! curl -sf "http://localhost:$VLLM_PORT/health" >/dev/null 2>&1; do
        sleep 10
        elapsed=$((elapsed + 10))
        if (( elapsed >= max_wait )); then
            err "vLLM failed to start within ${max_wait}s"
        fi
        log "  Still loading... (${elapsed}s)"
    done
    log "vLLM ready (${elapsed}s)"
}

start_model() {
    local model_key="$1"
    local model_id="${MODEL_IDS[$model_key]}"
    
    log "Starting vLLM with model: $model_id"
    
    # Stop any running vLLM
    docker compose -f "$REPO_ROOT/docker-compose.yml" down model-server 2>/dev/null || true
    
    # Start with specified model
    MODEL_NAME="$model_id" docker compose -f "$REPO_ROOT/docker-compose.yml" up -d model-server
    
    wait_for_vllm
}

stop_model() {
    log "Stopping vLLM..."
    docker compose -f "$REPO_ROOT/docker-compose.yml" down model-server 2>/dev/null || true
}

# --- Experiment Functions ---

run_e1_baseline() {
    local model_key="$1"
    local model_id="${MODEL_IDS[$model_key]}"
    local out_dir="${RESULTS_BASE}/${model_key}/E1_baseline"
    mkdir -p "$out_dir"
    
    log "=== E1 Baseline: $model_key (${N_RUNS} runs) ==="
    
    for run in $(seq 1 $N_RUNS); do
        local out_file="${out_dir}/run_${run}.json"
        if [[ -f "$out_file" ]]; then
            log "  Run $run already exists, skipping"
            continue
        fi
        
        log "  Run $run/$N_RUNS..."
        python3 -u "$REPO_ROOT/src/main.py" eval \
            --config "$REPO_ROOT/configs/eval_config_A.yaml" \
            --model "$model_id" \
            --input "$BENCHMARK" \
            --output "$out_file" \
            --seed $((42 + run - 1)) \
            2>&1 | tee "${out_dir}/run_${run}.log"
        
        log "  Run $run complete → $out_file"
    done
    
    log "E1 complete for $model_key → $out_dir/"
}

run_e2_stratified() {
    local model_key="$1"
    local model_id="${MODEL_IDS[$model_key]}"
    local out_dir="${RESULTS_BASE}/${model_key}/E2_stratified"
    mkdir -p "$out_dir"
    
    log "=== E2 Stratified Sample: $model_key ==="
    log "  Sampling $STRATIFIED_SAMPLE_SIZE alerts across 12 vectors × 5 classes × 2 encodings"
    
    # Generate stratified adversarial dataset if not exists
    local adv_dir="${ADVERSARIAL_BASE}/${model_key}/stratified"
    if [[ ! -d "$adv_dir" ]]; then
        log "  Generating stratified adversarial samples..."
        python3 -u "$REPO_ROOT/src/adversarial/generate.py" \
            --input "$BENCHMARK" \
            --output-dir "$adv_dir" \
            --sample-size "$STRATIFIED_SAMPLE_SIZE" \
            --vectors all \
            --classes all \
            --encodings plain_text,base64_fragment \
            2>&1 | tee "${out_dir}/generate.log"
    fi
    
    for run in $(seq 1 $N_RUNS); do
        local out_file="${out_dir}/run_${run}.json"
        if [[ -f "$out_file" ]]; then
            log "  Run $run already exists, skipping"
            continue
        fi
        
        log "  Run $run/$N_RUNS..."
        python3 -u "$REPO_ROOT/src/main.py" eval \
            --config "$REPO_ROOT/configs/eval_adversarial.yaml" \
            --model "$model_id" \
            --input "$adv_dir" \
            --output "$out_file" \
            --seed $((42 + run - 1)) \
            2>&1 | tee "${out_dir}/run_${run}.log"
        
        log "  Run $run complete → $out_file"
    done
    
    log "E2 stratified complete for $model_key → $out_dir/"
}

run_e2_full() {
    local model_key="$1"
    local model_id="${MODEL_IDS[$model_key]}"
    local out_dir="${RESULTS_BASE}/${model_key}/E2_full"
    mkdir -p "$out_dir"
    
    log "=== E2 Full Sweep: $model_key ==="
    log "  WARNING: This may take 24-48h per model depending on GPU speed"
    
    local adv_dir="${ADVERSARIAL_BASE}/${model_key}/full"
    if [[ ! -d "$adv_dir" ]]; then
        log "  Generating full adversarial dataset..."
        python3 -u "$REPO_ROOT/src/main.py" generate-adversarial \
            --input "$BENCHMARK" \
            --output-dir "$adv_dir" \
            --vectors all \
            --classes all \
            --encodings all \
            2>&1 | tee "${out_dir}/generate.log"
    fi
    
    for run in $(seq 1 $N_RUNS); do
        local out_file="${out_dir}/run_${run}.json"
        if [[ -f "$out_file" ]]; then
            log "  Run $run already exists, skipping"
            continue
        fi
        
        log "  Run $run/$N_RUNS..."
        python3 -u "$REPO_ROOT/src/main.py" eval \
            --config "$REPO_ROOT/configs/eval_adversarial.yaml" \
            --model "$model_id" \
            --input "$adv_dir" \
            --output "$out_file" \
            --seed $((42 + run - 1)) \
            2>&1 | tee "${out_dir}/run_${run}.log"
    done
    
    log "E2 full complete for $model_key → $out_dir/"
}

run_e4_sanitization() {
    local model_key="$1"
    local out_dir="${RESULTS_BASE}/${model_key}/E4_sanitization"
    mkdir -p "$out_dir"
    
    log "=== E4 Sanitization Defense: $model_key ==="
    
    for level in moderate strict; do
        for run in $(seq 1 $N_RUNS); do
            local out_file="${out_dir}/${level}_run_${run}.json"
            [[ -f "$out_file" ]] && continue
            
            python3 -u "$REPO_ROOT/src/main.py" eval \
                --config "$REPO_ROOT/configs/eval_adversarial.yaml" \
                --model "${MODEL_IDS[$model_key]}" \
                --defense sanitization --defense-level "$level" \
                --output "$out_file" \
                --seed $((42 + run - 1)) \
                2>&1 | tee "${out_dir}/${level}_run_${run}.log"
        done
    done
}

run_e5_structured() {
    local model_key="$1"
    local out_dir="${RESULTS_BASE}/${model_key}/E5_structured_prompt"
    mkdir -p "$out_dir"
    
    log "=== E5 Structured Prompt Defense: $model_key ==="
    
    for run in $(seq 1 $N_RUNS); do
        local out_file="${out_dir}/run_${run}.json"
        [[ -f "$out_file" ]] && continue
        
        python3 -u "$REPO_ROOT/src/main.py" eval \
            --config "$REPO_ROOT/configs/eval_adversarial.yaml" \
            --model "${MODEL_IDS[$model_key]}" \
            --defense structured_prompt \
            --output "$out_file" \
            --seed $((42 + run - 1)) \
            2>&1 | tee "${out_dir}/run_${run}.log"
    done
}

run_e7_canary() {
    local model_key="$1"
    local out_dir="${RESULTS_BASE}/${model_key}/E7_canary"
    mkdir -p "$out_dir"
    
    log "=== E7 Canary Token Defense: $model_key ==="
    
    for run in $(seq 1 $N_RUNS); do
        local out_file="${out_dir}/run_${run}.json"
        [[ -f "$out_file" ]] && continue
        
        python3 -u "$REPO_ROOT/src/main.py" eval \
            --config "$REPO_ROOT/configs/eval_adversarial.yaml" \
            --model "${MODEL_IDS[$model_key]}" \
            --defense canary_token \
            --output "$out_file" \
            --seed $((42 + run - 1)) \
            2>&1 | tee "${out_dir}/run_${run}.log"
    done
}

run_e8_adaptive() {
    local model_key="$1"
    local out_dir="${RESULTS_BASE}/${model_key}/E8_adaptive"
    mkdir -p "$out_dir"
    
    log "=== E8 Adaptive Attacker: $model_key ==="
    
    for level in black_box gray_box white_box; do
        for run in $(seq 1 $N_RUNS); do
            local out_file="${out_dir}/${level}_run_${run}.json"
            [[ -f "$out_file" ]] && continue
            
            python3 -u "$REPO_ROOT/src/main.py" eval \
                --config "$REPO_ROOT/configs/eval_adversarial.yaml" \
                --model "${MODEL_IDS[$model_key]}" \
                --defense all --adaptive-level "$level" \
                --output "$out_file" \
                --seed $((42 + run - 1)) \
                2>&1 | tee "${out_dir}/${level}_run_${run}.log"
        done
    done
}

run_analysis() {
    local model_key="$1"
    local out_dir="${RESULTS_BASE}/${model_key}/analysis"
    mkdir -p "$out_dir"
    
    log "=== Statistical Analysis: $model_key ==="
    
    python3 -u "$REPO_ROOT/src/evaluation/statistical_tests.py" \
        --results-dir "${RESULTS_BASE}/${model_key}" \
        --output "$out_dir/statistical_report.json" \
        2>&1 | tee "${out_dir}/analysis.log"
    
    log "Analysis complete → $out_dir/"
}

generate_tables() {
    local out_dir="${RESULTS_BASE}/tables"
    mkdir -p "$out_dir"
    
    log "=== Generating Paper Tables ==="
    
    # Cross-model comparison
    python3 -u -c "
import json, glob, sys
from pathlib import Path

results_base = '${RESULTS_BASE}'
models = ['kimi', 'r1', 'qwen', 'glm']
tables = {}

for model in models:
    model_dir = Path(results_base) / model
    if not model_dir.exists():
        continue
    
    # E1 baseline
    e1_files = sorted(model_dir.glob('E1_baseline/run_*.json'))
    if e1_files:
        tables.setdefault('Table_A_baseline', {})[model] = [
            json.loads(f.read_text()) for f in e1_files
        ]
    
    # E2 ASR
    e2_files = sorted(model_dir.glob('E2_*/run_*.json'))
    if e2_files:
        tables.setdefault('Table_B_asr', {})[model] = [
            json.loads(f.read_text()) for f in e2_files
        ]

out_path = Path('${out_dir}/cross_model_summary.json')
out_path.write_text(json.dumps(tables, indent=2, default=str))
print(f'Tables written to {out_path}')
" 2>&1 | tee "${out_dir}/tables.log"
    
    log "Tables complete → $out_dir/"
}

# --- Main ---

main() {
    log "=========================================="
    log "Hades GPU Experiment Runner"
    log "=========================================="
    
    check_prereqs
    
    # Determine which models to run
    local models=()
    if [[ "$REQUESTED_MODEL" == "all" ]]; then
        models=("${MODEL_ORDER[@]}")
    elif [[ -v "MODEL_IDS[$REQUESTED_MODEL]" ]]; then
        models=("$REQUESTED_MODEL")
    else
        err "Unknown model: $REQUESTED_MODEL. Options: ${MODEL_ORDER[*]} all"
    fi
    
    log "Models: ${models[*]}"
    log "Phase: $REQUESTED_PHASE"
    log "Results: $RESULTS_BASE/"
    log ""
    
    for model in "${models[@]}"; do
        log "====== Model: $model (${MODEL_IDS[$model]}) ======"
        
        start_model "$model"
        
        case "$REQUESTED_PHASE" in
            all)
                run_e1_baseline "$model"
                run_e2_stratified "$model"
                # Check stratified results before full sweep
                log ">>> Review stratified E2 results before running full sweep <<<"
                log ">>> Run: $0 $model e2-full <<<"
                run_e4_sanitization "$model"
                run_e5_structured "$model"
                run_e7_canary "$model"
                run_e8_adaptive "$model"
                run_analysis "$model"
                ;;
            e1)         run_e1_baseline "$model" ;;
            e2-sample)  run_e2_stratified "$model" ;;
            e2-full)    run_e2_full "$model" ;;
            e4)         run_e4_sanitization "$model" ;;
            e5)         run_e5_structured "$model" ;;
            e7)         run_e7_canary "$model" ;;
            e8)         run_e8_adaptive "$model" ;;
            analysis)   run_analysis "$model" ;;
            *)          err "Unknown phase: $REQUESTED_PHASE. Options: all e1 e2-sample e2-full e4 e5 e7 e8 analysis" ;;
        esac
        
        stop_model
    done
    
    # Generate cross-model tables if all models complete
    if [[ "$REQUESTED_MODEL" == "all" ]]; then
        generate_tables
    fi
    
    log ""
    log "=========================================="
    log "ALL EXPERIMENTS COMPLETE"
    log "Results: $RESULTS_BASE/"
    log ""
    log "Directory structure:"
    log "  results/gpu/"
    log "    ├── kimi/           # K2.5 (run first — strongest model)"
    log "    │   ├── E1_baseline/    run_1.json, run_2.json, run_3.json"
    log "    │   ├── E2_stratified/  run_1.json ... (96K calls)"
    log "    │   ├── E2_full/        run_1.json ... (if needed)"
    log "    │   ├── E4_sanitization/ moderate_run_1.json, strict_run_1.json ..."
    log "    │   ├── E5_structured/  run_1.json ..."
    log "    │   ├── E7_canary/      run_1.json ..."
    log "    │   ├── E8_adaptive/    black_box_run_1.json ..."
    log "    │   └── analysis/       statistical_report.json"
    log "    ├── r1/"
    log "    ├── qwen/"
    log "    ├── glm/"
    log "    └── tables/         # Cross-model comparison"
    log ""
    log "Next steps:"
    log "  1. git add results/gpu/ && git commit -m 'data: GPU experiment results' && git push"
    log "  2. Phoenix will analyze results and fill Tables A-D in the paper"
    log "=========================================="
}

main
