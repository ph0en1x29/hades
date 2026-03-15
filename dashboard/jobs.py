"""Job queue manager backed by SQLite."""

from __future__ import annotations

import sqlite3
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

DB_PATH = Path(__file__).parent / "jobs.db"


def _conn() -> sqlite3.Connection:
    con = sqlite3.connect(DB_PATH)
    con.row_factory = sqlite3.Row
    return con


def init_db() -> None:
    with _conn() as con:
        con.execute("""
            CREATE TABLE IF NOT EXISTS jobs (
                id TEXT PRIMARY KEY,
                models TEXT NOT NULL,
                experiments TEXT NOT NULL,
                status TEXT NOT NULL DEFAULT 'pending',
                progress INTEGER NOT NULL DEFAULT 0,
                total INTEGER NOT NULL DEFAULT 0,
                current_model TEXT,
                current_experiment TEXT,
                alerts_processed INTEGER NOT NULL DEFAULT 0,
                alerts_total INTEGER NOT NULL DEFAULT 0,
                started_at TEXT,
                finished_at TEXT,
                error TEXT,
                created_at TEXT NOT NULL
            )
        """)
        con.execute("""
            CREATE TABLE IF NOT EXISTS uploads (
                id TEXT PRIMARY KEY,
                filename TEXT NOT NULL,
                format TEXT,
                alert_count INTEGER,
                validation_status TEXT,
                validation_issues TEXT,
                created_at TEXT NOT NULL
            )
        """)


def create_job(models: list[str], experiments: list[str]) -> str:
    job_id = str(uuid.uuid4())[:8]
    now = datetime.now(timezone.utc).isoformat()
    total = len(models) * len(experiments)
    with _conn() as con:
        con.execute(
            """INSERT INTO jobs (id, models, experiments, status, total, created_at)
               VALUES (?, ?, ?, 'pending', ?, ?)""",
            (job_id, ",".join(models), ",".join(experiments), total, now),
        )
    return job_id


def update_job(job_id: str, **kwargs: Any) -> None:
    if not kwargs:
        return
    cols = ", ".join(f"{k} = ?" for k in kwargs)
    values = list(kwargs.values()) + [job_id]
    with _conn() as con:
        con.execute(f"UPDATE jobs SET {cols} WHERE id = ?", values)


def get_job(job_id: str) -> dict | None:
    with _conn() as con:
        row = con.execute("SELECT * FROM jobs WHERE id = ?", (job_id,)).fetchone()
    return dict(row) if row else None


def list_jobs(limit: int = 50) -> list[dict]:
    with _conn() as con:
        rows = con.execute(
            "SELECT * FROM jobs ORDER BY created_at DESC LIMIT ?", (limit,)
        ).fetchall()
    return [dict(r) for r in rows]


def add_upload(
    filename: str,
    fmt: str | None,
    alert_count: int | None,
    status: str,
    issues: str | None,
) -> str:
    uid = str(uuid.uuid4())[:8]
    now = datetime.now(timezone.utc).isoformat()
    with _conn() as con:
        con.execute(
            """INSERT INTO uploads (id, filename, format, alert_count, validation_status, validation_issues, created_at)
               VALUES (?, ?, ?, ?, ?, ?, ?)""",
            (uid, filename, fmt, alert_count, status, issues, now),
        )
    return uid


def list_uploads(limit: int = 100) -> list[dict]:
    with _conn() as con:
        rows = con.execute(
            "SELECT * FROM uploads ORDER BY created_at DESC LIMIT ?", (limit,)
        ).fetchall()
    return [dict(r) for r in rows]
