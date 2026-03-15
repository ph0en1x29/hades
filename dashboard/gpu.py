"""GPU detection and status via nvidia-smi."""

from __future__ import annotations

import subprocess
from dataclasses import dataclass, field


@dataclass
class GPUInfo:
    index: int
    name: str
    memory_total_mb: int
    memory_used_mb: int
    utilization_pct: int
    temperature_c: int


@dataclass
class GPUStatus:
    available: bool
    gpus: list[GPUInfo] = field(default_factory=list)
    error: str | None = None

    @property
    def count(self) -> int:
        return len(self.gpus)

    @property
    def total_memory_gb(self) -> float:
        return sum(g.memory_total_mb for g in self.gpus) / 1024

    @property
    def used_memory_gb(self) -> float:
        return sum(g.memory_used_mb for g in self.gpus) / 1024


def get_gpu_status() -> GPUStatus:
    """Query nvidia-smi and return structured GPU info."""
    try:
        result = subprocess.run(
            [
                "nvidia-smi",
                "--query-gpu=index,name,memory.total,memory.used,utilization.gpu,temperature.gpu",
                "--format=csv,noheader,nounits",
            ],
            capture_output=True,
            text=True,
            timeout=10,
        )
        if result.returncode != 0:
            return GPUStatus(available=False, error=result.stderr.strip() or "nvidia-smi failed")

        gpus = []
        for line in result.stdout.strip().splitlines():
            parts = [p.strip() for p in line.split(",")]
            if len(parts) < 6:
                continue
            try:
                gpus.append(
                    GPUInfo(
                        index=int(parts[0]),
                        name=parts[1],
                        memory_total_mb=int(parts[2]),
                        memory_used_mb=int(parts[3]),
                        utilization_pct=int(parts[4]),
                        temperature_c=int(parts[5]),
                    )
                )
            except (ValueError, IndexError):
                continue

        return GPUStatus(available=True, gpus=gpus)

    except FileNotFoundError:
        return GPUStatus(available=False, error="nvidia-smi not found — no GPU or driver not installed")
    except subprocess.TimeoutExpired:
        return GPUStatus(available=False, error="nvidia-smi timed out")
    except Exception as exc:
        return GPUStatus(available=False, error=str(exc))
