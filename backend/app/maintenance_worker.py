from __future__ import annotations

import asyncio
import hashlib
import os
import socket
import time
from contextlib import suppress
from typing import Any

from app.main import (
    APP_VERSION,
    SAFE_RUNBOOKS,
    connect_db,
    get_host,
    inspect_maintenance_sudo_policy,
    redact_diagnostic_text,
    run_ssh,
)

WORKER_ID = os.getenv("MAINTENANCE_WORKER_ID", f"{socket.gethostname()}-{os.getpid()}")
CONCURRENCY = max(1, min(int(os.getenv("MAINTENANCE_WORKER_CONCURRENCY", "2")), 8))
POLL_SECONDS = max(1.0, float(os.getenv("MAINTENANCE_WORKER_POLL_SECONDS", "2")))


def register_worker(active_tasks: int = 0) -> None:
    with connect_db() as connection:
        connection.execute(
            """INSERT INTO maintenance_workers(id,version,concurrency,active_tasks,last_heartbeat_at)
               VALUES(%s,%s,%s,%s,NOW())
               ON CONFLICT(id) DO UPDATE SET version=EXCLUDED.version,
                 concurrency=EXCLUDED.concurrency,active_tasks=EXCLUDED.active_tasks,
                 last_heartbeat_at=NOW()""",
            (WORKER_ID, APP_VERSION, CONCURRENCY, active_tasks),
        )


def claim_task() -> dict[str, Any] | None:
    with connect_db() as connection:
        row = connection.execute(
            """SELECT t.id,t.host_id,t.runbook_id,t.timeout_seconds
               FROM maintenance_tasks t
               WHERE t.status='queued'
                 AND NOT EXISTS (
                   SELECT 1 FROM maintenance_tasks active
                   WHERE active.host_id=t.host_id AND active.status='running'
                 )
               ORDER BY t.queued_at NULLS LAST,t.requested_at
               FOR UPDATE SKIP LOCKED LIMIT 1"""
        ).fetchone()
        if not row:
            return None
        claimed = connection.execute(
            """UPDATE maintenance_tasks SET status='running',worker_id=%s,
                 started_at=NOW(),heartbeat_at=NOW(),error=NULL
               WHERE id=%s AND status='queued' RETURNING id,host_id,runbook_id,timeout_seconds""",
            (WORKER_ID, row["id"]),
        ).fetchone()
        return dict(claimed) if claimed else None


def task_is_running(task_id: str) -> bool:
    with connect_db() as connection:
        row = connection.execute(
            """UPDATE maintenance_tasks SET heartbeat_at=NOW()
               WHERE id=%s AND status='running' AND worker_id=%s
                 AND cancel_requested_at IS NULL RETURNING id""",
            (task_id, WORKER_ID),
        ).fetchone()
    return bool(row)


async def cancellable_ssh(task_id: str, host: dict[str, Any], command: str, timeout: int) -> str:
    execution = asyncio.create_task(run_ssh(host, command, timeout=timeout + 5))
    deadline = time.monotonic() + timeout
    try:
        while not execution.done():
            if time.monotonic() >= deadline:
                execution.cancel()
                raise TimeoutError("維運任務超過允許執行時間")
            if not await asyncio.to_thread(task_is_running, task_id):
                execution.cancel()
                raise asyncio.CancelledError
            await asyncio.sleep(1)
        return await execution
    finally:
        if not execution.done():
            execution.cancel()
        with suppress(asyncio.CancelledError):
            await execution


def finish_task(task_id: str, *, status: str, output: str = "", error: str | None = None,
                verification_status: str = "failed", duration_ms: int | None = None) -> None:
    safe_output, _ = redact_diagnostic_text(output)
    safe_error, _ = redact_diagnostic_text(error or "")
    digest = hashlib.sha256(safe_output.encode()).hexdigest() if safe_output else None
    with connect_db() as connection:
        connection.execute(
            """UPDATE maintenance_tasks SET status=%s,output=%s,error=%s,
                 verification_status=%s,duration_ms=%s,output_sha256=%s,
                 heartbeat_at=NOW(),completed_at=NOW()
               WHERE id=%s AND worker_id=%s""",
            (status, safe_output[:100000], safe_error[:2000] or None,
             verification_status, duration_ms, digest, task_id, WORKER_ID),
        )


async def execute_task(task: dict[str, Any]) -> None:
    started = time.monotonic()
    task_id = task["id"]
    runbook = SAFE_RUNBOOKS.get(task["runbook_id"])
    if not runbook:
        finish_task(task_id, status="failed", error="Runbook 已不存在")
        return
    try:
        host = await asyncio.to_thread(get_host, task["host_id"])
        if runbook.get("mutating"):
            readiness = await inspect_maintenance_sudo_policy(host)
            if not readiness["ready"]:
                raise RuntimeError(f"維運權限檢查失敗：{readiness['detail']}")
        timeout = int(task.get("timeout_seconds") or 30)
        evidence: list[str] = []
        if runbook.get("precheck"):
            evidence.append("=== PRECHECK ===\n" + await cancellable_ssh(
                task_id, host, runbook["precheck"], timeout
            ))
        evidence.append("=== EXECUTION ===\n" + await cancellable_ssh(
            task_id, host, runbook["command"], timeout
        ))
        if runbook.get("verify_command"):
            evidence.append("=== VERIFICATION ===\n" + await cancellable_ssh(
                task_id, host, runbook["verify_command"], timeout
            ))
        output = "\n".join(evidence)
        duration = int((time.monotonic() - started) * 1000)
        finish_task(task_id, status="succeeded", output=output,
                    verification_status="passed", duration_ms=duration)
    except asyncio.CancelledError:
        finish_task(task_id, status="cancelled", error="由管理者取消",
                    duration_ms=int((time.monotonic() - started) * 1000))
    except TimeoutError as error:
        finish_task(task_id, status="timed_out", error=str(error),
                    duration_ms=int((time.monotonic() - started) * 1000))
    except Exception as error:  # Worker must persist failures instead of exiting.
        finish_task(task_id, status="failed", error=str(error),
                    duration_ms=int((time.monotonic() - started) * 1000))


async def worker_loop() -> None:
    running: set[asyncio.Task[None]] = set()
    while True:
        running = {task for task in running if not task.done()}
        await asyncio.to_thread(register_worker, len(running))
        while len(running) < CONCURRENCY:
            task = await asyncio.to_thread(claim_task)
            if not task:
                break
            running.add(asyncio.create_task(execute_task(task), name=f"maintenance-{task['id']}"))
        await asyncio.sleep(POLL_SECONDS)


if __name__ == "__main__":
    asyncio.run(worker_loop())
