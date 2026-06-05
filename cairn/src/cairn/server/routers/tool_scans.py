from __future__ import annotations

import json
import uuid

from fastapi import APIRouter, HTTPException

from cairn.server.db import get_conn
from cairn.server.services import (
    check_project_active,
    expire_tool_scan_tasks,
    get_project_or_404,
    utcnow,
)
from cairn.server.source_models import (
    ClaimToolScanTaskRequest,
    CompleteToolScanTaskRequest,
    CreateToolScanTaskRequest,
    FailToolScanTaskRequest,
    ToolScanTask,
)


router = APIRouter(tags=["tool-scans"])


@router.get("/api/projects/{project_id}/tool-scan-tasks", response_model=list[ToolScanTask])
def list_project_tool_scan_tasks(
    project_id: str,
    snapshot_id: str | None = None,
    status: str | None = None,
):
    with get_conn() as conn:
        get_project_or_404(conn, project_id)
        expire_tool_scan_tasks(conn, project_id)
        clauses = ["project_id = ?"]
        params: list[object] = [project_id]
        if snapshot_id:
            clauses.append("snapshot_id = ?")
            params.append(snapshot_id)
        if status:
            clauses.append("status = ?")
            params.append(status)
        rows = conn.execute(
            f"""
            SELECT *
            FROM tool_scan_tasks
            WHERE {' AND '.join(clauses)}
            ORDER BY created_at DESC, id DESC
            """,
            params,
        ).fetchall()
    return [_task_from_row(row) for row in rows]


@router.post(
    "/api/projects/{project_id}/sources/{snapshot_id}/tool-scan-tasks",
    response_model=ToolScanTask,
    status_code=201,
)
def create_tool_scan_task(project_id: str, snapshot_id: str, body: CreateToolScanTaskRequest):
    task_id = f"scan_{uuid.uuid4().hex[:16]}"
    now = utcnow()
    with get_conn() as conn:
        check_project_active(conn, project_id)
        expire_tool_scan_tasks(conn, project_id)
        _validate_ready_snapshot(conn, project_id, snapshot_id)
        existing = conn.execute(
            """
            SELECT *
            FROM tool_scan_tasks
            WHERE project_id = ?
              AND snapshot_id = ?
              AND status IN ('pending', 'running')
            ORDER BY created_at
            LIMIT 1
            """,
            (project_id, snapshot_id),
        ).fetchone()
        if existing is not None:
            return _task_from_row(existing)
        conn.execute(
            """
            INSERT INTO tool_scan_tasks (
                id, project_id, snapshot_id, status, created_by, created_at,
                tools_json, timeout_per_tool
            )
            VALUES (?, ?, ?, 'pending', ?, ?, ?, ?)
            """,
            (
                task_id,
                project_id,
                snapshot_id,
                body.created_by,
                now,
                json.dumps(body.tools, ensure_ascii=False),
                body.timeout_per_tool,
            ),
        )
        row = conn.execute("SELECT * FROM tool_scan_tasks WHERE id = ?", (task_id,)).fetchone()
    assert row is not None
    return _task_from_row(row)


@router.get("/api/tool-scans/pending", response_model=list[ToolScanTask])
def list_pending_tool_scan_tasks(project_id: str | None = None, limit: int = 10):
    if limit < 1 or limit > 100:
        raise HTTPException(400, "limit must be between 1 and 100")
    clauses = ["t.status = 'pending'", "p.status = 'active'", "s.status = 'ready'"]
    params: list[object] = []
    if project_id:
        clauses.append("t.project_id = ?")
        params.append(project_id)
    params.append(limit)
    with get_conn() as conn:
        expire_tool_scan_tasks(conn, project_id)
        rows = conn.execute(
            f"""
            SELECT t.*
            FROM tool_scan_tasks t
            JOIN projects p ON p.id = t.project_id
            JOIN source_snapshots s ON s.id = t.snapshot_id AND s.project_id = t.project_id
            WHERE {' AND '.join(clauses)}
            ORDER BY t.created_at, t.id
            LIMIT ?
            """,
            params,
        ).fetchall()
    return [_task_from_row(row) for row in rows]


@router.get("/api/tool-scan-tasks")
def list_tool_scan_task_queue(
    status: str | None = None,
    limit: int = 100,
):
    if limit < 1 or limit > 500:
        raise HTTPException(400, "limit must be between 1 and 500")
    if status and status not in ("pending", "running", "completed", "failed"):
        raise HTTPException(400, "Unsupported tool scan task status")
    clauses: list[str] = []
    params: list[object] = []
    if status:
        clauses.append("t.status = ?")
        params.append(status)
    params.append(limit)
    where_sql = f"WHERE {' AND '.join(clauses)}" if clauses else ""
    with get_conn() as conn:
        expire_tool_scan_tasks(conn)
        rows = conn.execute(
            f"""
            SELECT t.*, p.title AS project_title, s.source_type, s.resolved_commit,
                   s.snapshot_sha256, s.original_name
            FROM tool_scan_tasks t
            JOIN projects p ON p.id = t.project_id
            LEFT JOIN source_snapshots s
              ON s.id = t.snapshot_id
             AND s.project_id = t.project_id
            {where_sql}
            ORDER BY
                CASE t.status
                    WHEN 'running' THEN 0
                    WHEN 'pending' THEN 1
                    WHEN 'failed' THEN 2
                    ELSE 3
                END,
                datetime(t.created_at) DESC,
                t.id DESC
            LIMIT ?
            """,
            params,
        ).fetchall()
    return [_queue_task_from_row(row) for row in rows]


@router.post("/api/tool-scans/{task_id}/claim", response_model=ToolScanTask)
def claim_tool_scan_task(task_id: str, body: ClaimToolScanTaskRequest):
    now = utcnow()
    with get_conn() as conn:
        row = conn.execute("SELECT * FROM tool_scan_tasks WHERE id = ?", (task_id,)).fetchone()
        if row is None:
            raise HTTPException(404, "Tool scan task not found")
        check_project_active(conn, row["project_id"])
        expire_tool_scan_tasks(conn, row["project_id"])
        row = conn.execute("SELECT * FROM tool_scan_tasks WHERE id = ?", (task_id,)).fetchone()
        assert row is not None
        if row["status"] != "pending":
            raise HTTPException(409, f"Tool scan task is {row['status']}")
        conn.execute(
            """
            UPDATE tool_scan_tasks
            SET status = 'running',
                worker = ?,
                started_at = COALESCE(started_at, ?),
                last_heartbeat_at = ?,
                error_message = NULL
            WHERE id = ? AND status = 'pending' AND worker IS NULL
            """,
            (body.worker, now, now, task_id),
        )
        updated = conn.execute("SELECT * FROM tool_scan_tasks WHERE id = ?", (task_id,)).fetchone()
        if updated is None or updated["status"] != "running" or updated["worker"] != body.worker:
            raise HTTPException(409, "Tool scan task was claimed by another worker")
    return _task_from_row(updated)


@router.post("/api/tool-scans/{task_id}/heartbeat", response_model=ToolScanTask)
def heartbeat_tool_scan_task(task_id: str, body: ClaimToolScanTaskRequest):
    now = utcnow()
    with get_conn() as conn:
        row = _running_task_for_worker(conn, task_id, body.worker)
        check_project_active(conn, row["project_id"])
        conn.execute(
            "UPDATE tool_scan_tasks SET last_heartbeat_at = ? WHERE id = ?",
            (now, task_id),
        )
        updated = conn.execute("SELECT * FROM tool_scan_tasks WHERE id = ?", (task_id,)).fetchone()
    assert updated is not None
    return _task_from_row(updated)


@router.post("/api/tool-scans/{task_id}/release", response_model=ToolScanTask)
def release_tool_scan_task(task_id: str, body: ClaimToolScanTaskRequest):
    with get_conn() as conn:
        row = conn.execute("SELECT * FROM tool_scan_tasks WHERE id = ?", (task_id,)).fetchone()
        if row is None:
            raise HTTPException(404, "Tool scan task not found")
        if row["status"] != "running":
            return _task_from_row(row)
        if row["worker"] != body.worker:
            raise HTTPException(409, f"Tool scan task is claimed by {row['worker']}")
        conn.execute(
            """
            UPDATE tool_scan_tasks
            SET status = 'pending',
                worker = NULL,
                last_heartbeat_at = NULL
            WHERE id = ?
            """,
            (task_id,),
        )
        updated = conn.execute("SELECT * FROM tool_scan_tasks WHERE id = ?", (task_id,)).fetchone()
    assert updated is not None
    return _task_from_row(updated)


@router.post("/api/tool-scans/{task_id}/complete", response_model=ToolScanTask)
def complete_tool_scan_task(task_id: str, body: CompleteToolScanTaskRequest):
    now = utcnow()
    with get_conn() as conn:
        _running_task_for_worker(conn, task_id, body.worker)
        conn.execute(
            """
            UPDATE tool_scan_tasks
            SET status = 'completed',
                completed_at = ?,
                last_heartbeat_at = ?,
                error_message = NULL,
                summaries_json = ?
            WHERE id = ?
            """,
            (
                now,
                now,
                json.dumps(body.summaries, ensure_ascii=False),
                task_id,
            ),
        )
        updated = conn.execute("SELECT * FROM tool_scan_tasks WHERE id = ?", (task_id,)).fetchone()
    assert updated is not None
    return _task_from_row(updated)


@router.post("/api/tool-scans/{task_id}/fail", response_model=ToolScanTask)
def fail_tool_scan_task(task_id: str, body: FailToolScanTaskRequest):
    now = utcnow()
    with get_conn() as conn:
        row = _running_task_for_worker(conn, task_id, body.worker)
        conn.execute(
            """
            UPDATE tool_scan_tasks
            SET status = 'failed',
                completed_at = ?,
                last_heartbeat_at = ?,
                error_message = ?
            WHERE id = ?
            """,
            (now, now, body.error_message[:2000], task_id),
        )
        updated = conn.execute("SELECT * FROM tool_scan_tasks WHERE id = ?", (task_id,)).fetchone()
    assert updated is not None
    return _task_from_row(updated)


@router.post("/api/tool-scans/{task_id}/cancel", response_model=ToolScanTask)
def cancel_tool_scan_task(task_id: str, body: ClaimToolScanTaskRequest):
    now = utcnow()
    with get_conn() as conn:
        row = conn.execute("SELECT * FROM tool_scan_tasks WHERE id = ?", (task_id,)).fetchone()
        if row is None:
            raise HTTPException(404, "Tool scan task not found")
        if row["status"] not in ("pending", "running"):
            return _task_from_row(row)
        conn.execute(
            """
            UPDATE tool_scan_tasks
            SET status = 'failed',
                completed_at = ?,
                last_heartbeat_at = ?,
                error_message = ?
            WHERE id = ?
            """,
            (now, now, f"Cancelled by {body.worker}", task_id),
        )
        updated = conn.execute("SELECT * FROM tool_scan_tasks WHERE id = ?", (task_id,)).fetchone()
    assert updated is not None
    return _task_from_row(updated)


@router.post("/api/tool-scans/{task_id}/retry", response_model=ToolScanTask)
def retry_tool_scan_task(task_id: str, body: ClaimToolScanTaskRequest):
    now = utcnow()
    with get_conn() as conn:
        row = conn.execute("SELECT * FROM tool_scan_tasks WHERE id = ?", (task_id,)).fetchone()
        if row is None:
            raise HTTPException(404, "Tool scan task not found")
        check_project_active(conn, row["project_id"])
        _validate_ready_snapshot(conn, row["project_id"], row["snapshot_id"])
        if row["status"] != "failed":
            raise HTTPException(409, f"Only failed tool scan tasks can be retried; current status is {row['status']}")
        conn.execute(
            """
            UPDATE tool_scan_tasks
            SET status = 'pending',
                worker = NULL,
                started_at = NULL,
                last_heartbeat_at = NULL,
                completed_at = NULL,
                error_message = NULL,
                created_by = ?,
                created_at = ?,
                summaries_json = '[]'
            WHERE id = ?
            """,
            (body.worker, now, task_id),
        )
        updated = conn.execute("SELECT * FROM tool_scan_tasks WHERE id = ?", (task_id,)).fetchone()
    assert updated is not None
    return _task_from_row(updated)


def _validate_ready_snapshot(conn, project_id: str, snapshot_id: str) -> None:
    row = conn.execute(
        "SELECT status FROM source_snapshots WHERE id = ? AND project_id = ?",
        (snapshot_id, project_id),
    ).fetchone()
    if row is None:
        raise HTTPException(404, "Source snapshot not found")
    if row["status"] != "ready":
        raise HTTPException(409, "Source snapshot is not ready")


def _running_task_for_worker(conn, task_id: str, worker: str):
    row = conn.execute("SELECT * FROM tool_scan_tasks WHERE id = ?", (task_id,)).fetchone()
    if row is None:
        raise HTTPException(404, "Tool scan task not found")
    if row["status"] != "running":
        raise HTTPException(409, f"Tool scan task is {row['status']}")
    if row["worker"] != worker:
        raise HTTPException(409, f"Tool scan task is claimed by {row['worker']}")
    return row


def _task_from_row(row) -> ToolScanTask:
    data = dict(row)
    data["tools"] = _decode_json_list(data.pop("tools_json", None))
    data["summaries"] = _decode_json_list(data.pop("summaries_json", None))
    return ToolScanTask(**data)


def _queue_task_from_row(row) -> dict:
    data = _task_from_row(row).model_dump()
    data["project_title"] = row["project_title"]
    source_label = row["resolved_commit"] or row["snapshot_sha256"] or row["original_name"] or row["snapshot_id"]
    data["source_label"] = source_label
    data["source_type"] = row["source_type"]
    return data


def _decode_json_list(raw: str | None) -> list:
    if not raw:
        return []
    try:
        value = json.loads(raw)
    except json.JSONDecodeError:
        return []
    return value if isinstance(value, list) else []
