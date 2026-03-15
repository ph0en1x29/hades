"""Hades Dashboard — FastAPI backend."""

from __future__ import annotations

import asyncio
import json
import os
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

# Allow imports from Hades src/
REPO_ROOT = Path(__file__).parent.parent
sys.path.insert(0, str(REPO_ROOT))

from fastapi import FastAPI, File, UploadFile, WebSocket, WebSocketDisconnect
from fastapi.responses import FileResponse, JSONResponse
from fastapi.staticfiles import StaticFiles

import jobs as job_store
import gpu as gpu_mod
import models as model_mgr

# ---------------------------------------------------------------------------
# Paths
# ---------------------------------------------------------------------------
UPLOADS_DIR = REPO_ROOT / "data" / "datasets" / "uploads"
RESULTS_DIR = REPO_ROOT / "results"
GPU_RESULTS_DIR = RESULTS_DIR / "gpu"
BENCHMARK_FILE = REPO_ROOT / "data" / "benchmark" / "hades_benchmark_v1.jsonl"
SCRIPTS_DIR = REPO_ROOT / "scripts"

UPLOADS_DIR.mkdir(parents=True, exist_ok=True)

# ---------------------------------------------------------------------------
# App
# ---------------------------------------------------------------------------
app = FastAPI(title="Hades Dashboard", version="1.0.0")

# Static files
app.mount("/static", StaticFiles(directory=Path(__file__).parent / "static"), name="static")

# Init DB on startup
job_store.init_db()

# Active WebSocket connections keyed by job_id
_ws_clients: dict[str, list[WebSocket]] = {}


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _detect_format(path: Path) -> str | None:
    """Guess file format from name/content."""
    name = path.name.lower()
    if name.endswith(".xml"):
        try:
            text = path.read_text(errors="ignore")[:500]
            if "EventID" in text or "Security" in text:
                return "Windows Security XML"
            if "Sysmon" in text or "sysmon" in text:
                return "Sysmon XML"
            return "XML"
        except Exception:
            return "XML"
    if name.endswith(".jsonl") or name.endswith(".ndjson"):
        try:
            first = path.read_text(errors="ignore").split("\n")[0]
            obj = json.loads(first)
            if "source" in obj or "sourcetype" in obj:
                return "Splunk JSONL"
            return "JSONL"
        except Exception:
            return "JSONL"
    if name.endswith(".json"):
        try:
            obj = json.loads(path.read_text(errors="ignore")[:1000])
            if "alert" in str(obj).lower() or "event_type" in str(obj).lower():
                return "Suricata JSON"
            return "JSON"
        except Exception:
            return "JSON"
    if name.endswith(".csv"):
        return "CSV"
    return None


def _count_alerts(path: Path, fmt: str | None) -> int | None:
    """Count alerts/records in a file."""
    try:
        if fmt in ("JSONL", "Splunk JSONL"):
            return sum(1 for line in path.read_text(errors="ignore").splitlines() if line.strip())
        if fmt in ("JSON", "Suricata JSON"):
            data = json.loads(path.read_text(errors="ignore"))
            if isinstance(data, list):
                return len(data)
            return 1
        if fmt and "XML" in fmt:
            text = path.read_text(errors="ignore")
            return text.count("<Event") or text.count("<Alert") or None
        return None
    except Exception:
        return None


def _validate_upload(path: Path) -> tuple[str, str | None]:
    """Run dataset gate validation. Returns (status, issues_json)."""
    try:
        from src.ingestion.parsers import (
            load_sysmon_log,
            load_suricata_log,
            load_windows_security_log,
            load_splunk_attack_data_jsonl,
        )
        from src.evaluation.dataset_gate import benchmark_contract_issues

        name = path.name.lower()
        alerts = []

        if name.endswith(".xml"):
            text = path.read_text(errors="ignore")
            if "Sysmon" in text or "sysmon" in text:
                alerts = list(load_sysmon_log(str(path)))
            else:
                alerts = list(load_windows_security_log(str(path)))
        elif name.endswith(".jsonl") or name.endswith(".ndjson"):
            alerts = list(load_splunk_attack_data_jsonl(str(path)))
        elif name.endswith(".json"):
            alerts = list(load_suricata_log(str(path)))
        else:
            return "skipped", json.dumps(["Unsupported format for validation"])

        if not alerts:
            return "warning", json.dumps(["No alerts parsed from file"])

        all_issues: list[dict] = []
        pass_count = 0
        for alert in alerts[:200]:  # Cap at 200 for speed
            issues = benchmark_contract_issues(alert)
            if issues:
                all_issues.append({"alert": str(getattr(alert, "event_id", "?"))[:50], "issues": issues})
            else:
                pass_count += 1

        if all_issues:
            status = "warning" if pass_count > 0 else "fail"
        else:
            status = "pass"

        return status, json.dumps(all_issues[:20]) if all_issues else None

    except Exception as exc:
        return "error", json.dumps([f"Validation error: {exc}"])


def _read_results() -> dict[str, Any]:
    """Read all result JSON files from results/gpu/."""
    out: dict[str, dict] = {}

    if not GPU_RESULTS_DIR.exists():
        # Fall back to flat results dir for mock/dev results
        for f in sorted(RESULTS_DIR.glob("*.json"))[:50]:
            try:
                data = json.loads(f.read_text())
                model = str(data.get("model", f.stem))
                exp = str(data.get("experiment_id", "?"))
                out.setdefault(model, {})[exp] = data
            except Exception:
                pass
        return out

    for model_dir in GPU_RESULTS_DIR.iterdir():
        if not model_dir.is_dir():
            continue
        model = model_dir.name
        for exp_dir in model_dir.iterdir():
            if not exp_dir.is_dir():
                continue
            exp = exp_dir.name
            run_files = sorted(exp_dir.glob("run_*.json"))
            if run_files:
                try:
                    data = json.loads(run_files[-1].read_text())
                    out.setdefault(model, {})[exp] = data
                except Exception:
                    pass

    return out


def _get_benchmark_stats() -> dict:
    """Return benchmark stats from the benchmark file."""
    base = {"alerts": 12147, "techniques": 27, "tactics": 9}
    if not BENCHMARK_FILE.exists():
        return {**base, "source": "default"}

    try:
        lines = BENCHMARK_FILE.read_text().splitlines()
        alerts = [json.loads(l) for l in lines if l.strip()]
        techniques: set = set()
        tactics: set = set()
        for a in alerts:
            for t in a.get("benchmark", {}).get("mitre_techniques", []):
                techniques.add(t)
            for t in a.get("benchmark", {}).get("mitre_tactics", []):
                tactics.add(t)
        return {
            "alerts": len(alerts),
            "techniques": len(techniques) or base["techniques"],
            "tactics": len(tactics) or base["tactics"],
            "source": "live",
        }
    except Exception:
        return {**base, "source": "default"}


# ---------------------------------------------------------------------------
# Routes
# ---------------------------------------------------------------------------

@app.get("/")
async def index():
    return FileResponse(Path(__file__).parent / "static" / "index.html")


@app.get("/experiments")
@app.get("/results")
@app.get("/models")
async def spa():
    return FileResponse(Path(__file__).parent / "static" / "index.html")


# --- Data Management ---

@app.post("/api/upload")
async def upload_file(file: UploadFile = File(...)):
    dest = UPLOADS_DIR / file.filename
    content = await file.read()
    dest.write_bytes(content)

    fmt = _detect_format(dest)
    alert_count = _count_alerts(dest, fmt)
    status, issues = _validate_upload(dest)

    uid = job_store.add_upload(
        filename=file.filename,
        fmt=fmt,
        alert_count=alert_count,
        status=status,
        issues=issues,
    )

    return {
        "id": uid,
        "filename": file.filename,
        "format": fmt,
        "alert_count": alert_count,
        "validation_status": status,
        "validation_issues": json.loads(issues) if issues else [],
    }


@app.get("/api/uploads")
async def get_uploads():
    rows = job_store.list_uploads()
    for r in rows:
        if r.get("validation_issues"):
            try:
                r["validation_issues"] = json.loads(r["validation_issues"])
            except Exception:
                r["validation_issues"] = []
    return rows


@app.get("/api/benchmark")
async def get_benchmark():
    return _get_benchmark_stats()


# --- GPU ---

@app.get("/api/gpu")
async def get_gpu():
    status = gpu_mod.get_gpu_status()
    return {
        "available": status.available,
        "count": status.count,
        "total_memory_gb": round(status.total_memory_gb, 1),
        "used_memory_gb": round(status.used_memory_gb, 1),
        "error": status.error,
        "gpus": [
            {
                "index": g.index,
                "name": g.name,
                "memory_total_mb": g.memory_total_mb,
                "memory_used_mb": g.memory_used_mb,
                "utilization_pct": g.utilization_pct,
                "temperature_c": g.temperature_c,
            }
            for g in status.gpus
        ],
    }


# --- Experiments ---

@app.post("/api/experiments/run")
async def run_experiments(body: dict):
    models: list[str] = body.get("models", [])
    experiments: list[str] = body.get("experiments", [])

    if not models or not experiments:
        return JSONResponse({"error": "models and experiments required"}, status_code=400)

    # Map friendly names to script keys
    model_map = {
        "Kimi K2.5": "kimi",
        "DeepSeek R1": "r1",
        "Qwen 3.5": "qwen",
        "GLM-5": "glm",
    }
    exp_map = {
        "E1": "e1", "E2": "e2-sample", "E4": "e4",
        "E5": "e5", "E7": "e7", "E8": "e8",
    }

    job_id = job_store.create_job(models, experiments)
    job_store.update_job(job_id, status="running", started_at=datetime.now(timezone.utc).isoformat())

    asyncio.create_task(_run_job(job_id, models, experiments, model_map, exp_map))

    return {"job_id": job_id, "status": "started"}


async def _run_job(
    job_id: str,
    models: list[str],
    experiments: list[str],
    model_map: dict,
    exp_map: dict,
) -> None:
    """Run experiments sequentially as a background task."""
    total = len(models) * len(experiments)
    done = 0

    try:
        for model_name in models:
            model_key = model_map.get(model_name, model_name.lower().split()[0])

            for exp_name in experiments:
                phase = exp_map.get(exp_name, exp_name.lower())

                job_store.update_job(
                    job_id,
                    current_model=model_name,
                    current_experiment=exp_name,
                    progress=done,
                    total=total,
                    status="running",
                )
                await _broadcast(job_id, {
                    "type": "progress",
                    "job_id": job_id,
                    "current_model": model_name,
                    "current_experiment": exp_name,
                    "progress": done,
                    "total": total,
                })

                script = str(SCRIPTS_DIR / "run_gpu_experiments.sh")
                if Path(script).exists():
                    proc = await asyncio.create_subprocess_exec(
                        "bash", script, model_key, phase,
                        cwd=str(REPO_ROOT),
                        stdout=asyncio.subprocess.PIPE,
                        stderr=asyncio.subprocess.STDOUT,
                    )
                    async for line in proc.stdout:
                        text = line.decode(errors="ignore").strip()
                        await _broadcast(job_id, {"type": "log", "job_id": job_id, "line": text})
                    await proc.wait()
                    if proc.returncode != 0:
                        raise RuntimeError(f"Script exited {proc.returncode} for {model_name}/{exp_name}")
                else:
                    # Dev mode: simulate progress
                    await asyncio.sleep(1)
                    await _broadcast(job_id, {
                        "type": "log",
                        "job_id": job_id,
                        "line": f"[DEV] Would run: {script} {model_key} {phase}",
                    })

                done += 1
                job_store.update_job(job_id, progress=done)

        job_store.update_job(
            job_id,
            status="completed",
            progress=total,
            finished_at=datetime.now(timezone.utc).isoformat(),
        )
        await _broadcast(job_id, {"type": "done", "job_id": job_id, "status": "completed"})

    except Exception as exc:
        job_store.update_job(
            job_id,
            status="error",
            error=str(exc),
            finished_at=datetime.now(timezone.utc).isoformat(),
        )
        await _broadcast(job_id, {"type": "error", "job_id": job_id, "error": str(exc)})


@app.get("/api/experiments/status")
async def experiment_status():
    return job_store.list_jobs()


# --- Results ---

@app.get("/api/results")
async def get_all_results():
    return _read_results()


@app.get("/api/results/{model}")
async def get_model_results(model: str):
    all_results = _read_results()
    return all_results.get(model, {})


# --- WebSocket ---

@app.websocket("/ws/progress")
async def ws_progress(websocket: WebSocket):
    await websocket.accept()
    job_id = None
    try:
        # First message should be {"job_id": "..."}
        msg = await asyncio.wait_for(websocket.receive_json(), timeout=5.0)
        job_id = msg.get("job_id", "__all__")
        _ws_clients.setdefault(job_id, []).append(websocket)

        # Send current job state immediately
        job = job_store.get_job(job_id) if job_id != "__all__" else None
        if job:
            await websocket.send_json({"type": "state", **job})

        # Keep alive
        while True:
            await asyncio.wait_for(websocket.receive_text(), timeout=30)
    except (WebSocketDisconnect, asyncio.TimeoutError):
        pass
    finally:
        if job_id and job_id in _ws_clients:
            try:
                _ws_clients[job_id].remove(websocket)
            except ValueError:
                pass


# ---------------------------------------------------------------------------
# Model Management Routes
# ---------------------------------------------------------------------------

@app.get("/api/models")
async def list_models():
    cfg = model_mgr.load_config()
    result = []
    for m in cfg:
        dl = model_mgr.download_status(m["key"])
        result.append({**m, "download": dl})
    disk = model_mgr.disk_info()
    return {"models": result, "disk": disk}


@app.get("/api/models/config")
async def get_model_config():
    return model_mgr.load_config()


@app.put("/api/models/config")
async def update_model_config(body: list):
    model_mgr.save_config(body)
    return {"status": "saved"}


@app.post("/api/models/{key}/download")
async def download_model(key: str):
    result = await model_mgr.start_download(key)
    if "error" in result:
        return JSONResponse(result, status_code=400)
    return result


@app.get("/api/models/{key}/download-status")
async def model_download_status(key: str):
    return model_mgr.download_status(key)


@app.post("/api/models/{key}/serve")
async def serve_model(key: str):
    m = model_mgr.get_model(key)
    if not m:
        return JSONResponse({"error": f"Unknown model: {key}"}, status_code=404)
    result = model_mgr.start_serving(
        hf_id=m["hf_id"],
        tensor_parallel=m.get("tensor_parallel", 4),
        gpu_count=m.get("gpus_needed", 4),
    )
    if "error" in result:
        return JSONResponse(result, status_code=500)
    return result


@app.post("/api/models/stop")
async def stop_serving():
    return model_mgr.stop_serving()


@app.get("/api/models/serving")
async def get_serving():
    status = model_mgr.serving_status()
    health_ok = model_mgr._check_vllm_health()
    return {**status, "health_ok": health_ok}


# ---------------------------------------------------------------------------

async def _broadcast(job_id: str, payload: dict) -> None:
    for ws_list in [_ws_clients.get(job_id, []), _ws_clients.get("__all__", [])]:
        dead = []
        for ws in ws_list:
            try:
                await ws.send_json(payload)
            except Exception:
                dead.append(ws)
        for ws in dead:
            try:
                ws_list.remove(ws)
            except ValueError:
                pass
