"""Model management — download tracking, vLLM serve/stop, health checks."""

from __future__ import annotations

import asyncio
import json
import os
import shutil
import subprocess
from pathlib import Path
from typing import Any

# ---------------------------------------------------------------------------
# Default model config — editable via /api/models/config
# ---------------------------------------------------------------------------
CONFIG_PATH = Path(__file__).parent / "model_config.json"

DEFAULT_CONFIG: list[dict] = [
    {
        "key": "kimi",
        "name": "Kimi K2.5",
        "hf_id": "moonshotai/Kimi-K2.5-GPTQ-Int4",
        "size_label": "~250 GB",
        "gpus_needed": 4,
        "tensor_parallel": 4,
        "notes": "Strongest model — run first. Confirm exact HF ID before downloading.",
    },
    {
        "key": "r1",
        "name": "DeepSeek R1",
        "hf_id": "deepseek-ai/DeepSeek-R1-GPTQ-Int4",
        "size_label": "~168 GB",
        "gpus_needed": 4,
        "tensor_parallel": 4,
        "notes": "Verify GPTQ variant ID on HuggingFace before downloading.",
    },
    {
        "key": "qwen",
        "name": "Qwen 3.5",
        "hf_id": "Qwen/Qwen3.5-MoE-A3B-GPTQ-Int4",
        "size_label": "~100 GB",
        "gpus_needed": 2,
        "tensor_parallel": 2,
        "notes": "MoE model — only 3B active params. Verify model ID on HF.",
    },
    {
        "key": "glm",
        "name": "GLM-5",
        "hf_id": "THUDM/GLM-5-GPTQ-Int4",
        "size_label": "~186 GB",
        "gpus_needed": 4,
        "tensor_parallel": 4,
        "notes": "Check THUDM org on HF for latest GLM-5 GPTQ release.",
    },
]

HF_CACHE = Path(os.environ.get("HF_HOME", Path.home() / ".cache" / "huggingface")) / "hub"
VLLM_CONTAINER = "hades-vllm"
VLLM_PORT = 8000

# Track background download tasks: key -> asyncio.Task
_download_tasks: dict[str, asyncio.Task] = {}
# Download progress state: key -> {pct, status, error}
_download_state: dict[str, dict] = {}


# ---------------------------------------------------------------------------
# Config management
# ---------------------------------------------------------------------------

def load_config() -> list[dict]:
    if CONFIG_PATH.exists():
        try:
            return json.loads(CONFIG_PATH.read_text())
        except Exception:
            pass
    return DEFAULT_CONFIG


def save_config(cfg: list[dict]) -> None:
    CONFIG_PATH.write_text(json.dumps(cfg, indent=2))


def get_model(key: str) -> dict | None:
    return next((m for m in load_config() if m["key"] == key), None)


# ---------------------------------------------------------------------------
# Download status
# ---------------------------------------------------------------------------

def _hf_cache_dir_for(hf_id: str) -> Path:
    """Return expected HF hub cache dir for a model ID."""
    slug = "models--" + hf_id.replace("/", "--")
    return HF_CACHE / slug


def _cache_size_gb(hf_id: str) -> float:
    """Estimate GB downloaded from HF cache dir."""
    d = _hf_cache_dir_for(hf_id)
    if not d.exists():
        return 0.0
    total = sum(f.stat().st_size for f in d.rglob("*") if f.is_file())
    return round(total / (1024 ** 3), 1)


def download_status(key: str) -> dict:
    """Return current download status for a model key."""
    model = get_model(key)
    if not model:
        return {"status": "unknown"}

    hf_id = model["hf_id"]
    cache_dir = _hf_cache_dir_for(hf_id)

    # Check if fully downloaded (has a refs/main or similar marker)
    complete_marker = cache_dir / "refs" / "main"
    if complete_marker.exists():
        size_gb = _cache_size_gb(hf_id)
        return {"status": "ready", "size_gb": size_gb, "cache_dir": str(cache_dir)}

    # Check if actively downloading
    if key in _download_tasks and not _download_tasks[key].done():
        state = _download_state.get(key, {})
        size_gb = _cache_size_gb(hf_id)
        return {
            "status": "downloading",
            "pct": state.get("pct", 0),
            "size_gb": size_gb,
            "log_line": state.get("log_line", ""),
        }

    # Check if partially downloaded
    if cache_dir.exists():
        size_gb = _cache_size_gb(hf_id)
        if size_gb > 0.1:
            state = _download_state.get(key, {})
            if state.get("error"):
                return {"status": "error", "error": state["error"], "size_gb": size_gb}
            return {"status": "partial", "size_gb": size_gb}

    return {"status": "not_downloaded"}


async def start_download(key: str) -> dict:
    """Kick off huggingface-cli download in the background."""
    model = get_model(key)
    if not model:
        return {"error": f"Unknown model key: {key}"}

    if key in _download_tasks and not _download_tasks[key].done():
        return {"error": "Download already running"}

    _download_state[key] = {"pct": 0, "log_line": "Starting..."}
    task = asyncio.create_task(_download_worker(key, model["hf_id"]))
    _download_tasks[key] = task
    return {"status": "started", "hf_id": model["hf_id"]}


async def _download_worker(key: str, hf_id: str) -> None:
    """Run huggingface-cli download and track progress."""
    cmd = ["huggingface-cli", "download", hf_id, "--local-dir-use-symlinks", "True"]
    try:
        proc = await asyncio.create_subprocess_exec(
            *cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.STDOUT,
        )
        async for raw in proc.stdout:
            line = raw.decode(errors="ignore").strip()
            if not line:
                continue
            # Parse progress percentage if present (e.g. "45%|████")
            pct = _parse_pct(line)
            _download_state[key] = {
                "pct": pct if pct is not None else _download_state.get(key, {}).get("pct", 0),
                "log_line": line[:120],
            }
        await proc.wait()
        if proc.returncode == 0:
            _download_state[key] = {"pct": 100, "log_line": "Complete"}
        else:
            _download_state[key] = {"error": f"huggingface-cli exited {proc.returncode}", "pct": 0}
    except FileNotFoundError:
        _download_state[key] = {"error": "huggingface-cli not found — run: pip install huggingface_hub", "pct": 0}
    except Exception as exc:
        _download_state[key] = {"error": str(exc), "pct": 0}


def _parse_pct(line: str) -> int | None:
    """Extract percentage integer from tqdm-style output."""
    import re
    m = re.search(r"\b(\d{1,3})%", line)
    if m:
        v = int(m.group(1))
        return min(v, 100)
    return None


# ---------------------------------------------------------------------------
# vLLM serve / stop
# ---------------------------------------------------------------------------

def _docker_available() -> bool:
    try:
        r = subprocess.run(["docker", "info"], capture_output=True, timeout=5)
        return r.returncode == 0
    except Exception:
        return False


def serving_status() -> dict:
    """Return current vLLM container status."""
    if not _docker_available():
        return {"status": "no_docker", "error": "Docker not available"}

    try:
        r = subprocess.run(
            ["docker", "inspect", "--format",
             "{{.State.Status}}|{{.State.Health.Status}}|{{index .Config.Cmd 1}}",
             VLLM_CONTAINER],
            capture_output=True, text=True, timeout=5,
        )
        if r.returncode != 0:
            return {"status": "stopped"}

        parts = r.stdout.strip().split("|")
        state = parts[0] if parts else "unknown"
        health = parts[1] if len(parts) > 1 else "unknown"
        # Try to pull model name from container cmd
        model_hint = parts[2] if len(parts) > 2 else ""

        # Check actual /health endpoint
        health_ok = _check_vllm_health()

        return {
            "status": state,  # running / exited / etc
            "health": "healthy" if health_ok else ("starting" if state == "running" else "stopped"),
            "model_hint": model_hint,
            "container": VLLM_CONTAINER,
            "port": VLLM_PORT,
        }
    except Exception as exc:
        return {"status": "error", "error": str(exc)}


def _check_vllm_health() -> bool:
    try:
        import urllib.request
        req = urllib.request.urlopen(f"http://localhost:{VLLM_PORT}/health", timeout=2)
        return req.status == 200
    except Exception:
        return False


def start_serving(hf_id: str, tensor_parallel: int, gpu_count: int) -> dict:
    """Start vLLM Docker container for given model."""
    if not _docker_available():
        return {"error": "Docker not available"}

    # Stop existing container if running
    subprocess.run(["docker", "rm", "-f", VLLM_CONTAINER],
                   capture_output=True, timeout=10)

    hf_home = str(Path.home() / ".cache" / "huggingface")
    cmd = [
        "docker", "run",
        "--gpus", f"\"device=0,1,2,3\"" if gpu_count >= 4 else f"\"device=0,1\"",
        "-d",
        "--name", VLLM_CONTAINER,
        "-v", f"{hf_home}:/root/.cache/huggingface",
        "-p", f"{VLLM_PORT}:{VLLM_PORT}",
        "vllm/vllm-openai:latest",
        "--model", hf_id,
        "--tensor-parallel-size", str(tensor_parallel),
        "--quantization", "gptq",
        "--dtype", "float16",
        "--max-model-len", "4096",
    ]

    try:
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
        if r.returncode != 0:
            return {"error": r.stderr.strip() or "docker run failed"}
        return {"status": "starting", "container": VLLM_CONTAINER, "model": hf_id}
    except subprocess.TimeoutExpired:
        return {"error": "docker run timed out (container may still be starting)"}
    except Exception as exc:
        return {"error": str(exc)}


def stop_serving() -> dict:
    """Stop and remove vLLM container."""
    if not _docker_available():
        return {"error": "Docker not available"}
    try:
        r = subprocess.run(
            ["docker", "rm", "-f", VLLM_CONTAINER],
            capture_output=True, text=True, timeout=15,
        )
        if r.returncode != 0 and "No such container" not in r.stderr:
            return {"error": r.stderr.strip()}
        return {"status": "stopped"}
    except Exception as exc:
        return {"error": str(exc)}


# ---------------------------------------------------------------------------
# Disk space
# ---------------------------------------------------------------------------

def disk_info() -> dict:
    """Return HF cache disk usage info."""
    try:
        total, used, free = shutil.disk_usage(Path.home())
        cache_size = 0.0
        if HF_CACHE.exists():
            cache_size = sum(
                f.stat().st_size for f in HF_CACHE.rglob("*") if f.is_file()
            ) / (1024 ** 3)
        return {
            "total_gb": round(total / (1024 ** 3), 1),
            "used_gb": round(used / (1024 ** 3), 1),
            "free_gb": round(free / (1024 ** 3), 1),
            "hf_cache_gb": round(cache_size, 1),
            "hf_cache_path": str(HF_CACHE),
        }
    except Exception as exc:
        return {"error": str(exc)}
