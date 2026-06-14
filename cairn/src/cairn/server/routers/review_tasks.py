from __future__ import annotations

from pathlib import PurePosixPath
import json
import uuid

from fastapi import APIRouter, HTTPException

from cairn.server.db import get_conn
from cairn.server.review_models import (
    CompleteReviewTaskRequest,
    CreateReviewTaskRequest,
    FailReviewTaskRequest,
    ReviewTask,
    ReviewTaskAvailabilityRequest,
    ReviewTaskWorkerRequest,
)
from cairn.server.routers.findings import (
    _apply_audit_finding_review,
    _ensure_review_task,
    _normalized_worker_list,
)
from cairn.server.routers.report_enrichments import _source_snippet
from cairn.server.services import (
    check_project_active,
    expire_review_tasks,
    get_project_or_404,
    utcnow,
)
from cairn.server.source_service import snapshot_container_path


router = APIRouter(tags=["review-tasks"])
REVIEW_TASK_RETRY_LIMIT = 3


@router.get("/api/projects/{project_id}/review-tasks", response_model=list[ReviewTask])
def list_project_review_tasks(
    project_id: str,
    finding_id: str | None = None,
    status: str | None = None,
):
    with get_conn() as conn:
        get_project_or_404(conn, project_id)
        expire_review_tasks(conn, project_id)
        _ensure_pending_review_tasks(conn, project_id)
        clauses = ["project_id = ?"]
        params: list[object] = [project_id]
        if finding_id:
            clauses.append("finding_id = ?")
            params.append(finding_id)
        if status:
            clauses.append("status = ?")
            params.append(status)
        rows = conn.execute(
            f"""
            SELECT *
            FROM review_tasks
            WHERE {' AND '.join(clauses)}
            ORDER BY created_at DESC, id DESC
            """,
            params,
        ).fetchall()
    return [_task_from_row(row) for row in rows]


@router.post("/api/projects/{project_id}/review-tasks", response_model=ReviewTask, status_code=201)
def create_review_task(project_id: str, body: CreateReviewTaskRequest):
    with get_conn() as conn:
        check_project_active(conn, project_id)
        expire_review_tasks(conn, project_id)
        finding = _reviewable_finding_or_409(conn, project_id, body.finding_id)
        _ensure_review_task(
            conn,
            project_id,
            body.finding_id,
            finding["discovered_by"],
            excluded_workers=[finding["discovered_by"]],
        )
        row = conn.execute(
            """
            SELECT *
            FROM review_tasks
            WHERE project_id = ?
              AND finding_id = ?
              AND status IN (
                  'pending', 'running', 'waiting_for_reviewer',
                  'blocked_no_independent_worker', 'completed'
              )
            ORDER BY created_at
            LIMIT 1
            """,
            (project_id, body.finding_id),
        ).fetchone()
    assert row is not None
    return _task_from_row(row)


@router.get("/api/review-tasks/pending", response_model=list[ReviewTask])
def list_pending_review_tasks(project_id: str | None = None, limit: int = 10):
    if limit < 1 or limit > 100:
        raise HTTPException(400, "limit must be between 1 and 100")
    clauses = [
        "t.status IN ('pending', 'waiting_for_reviewer', 'blocked_no_independent_worker')",
        "p.status = 'active'",
        "f.status = 'pending_review'",
    ]
    params: list[object] = []
    if project_id:
        clauses.append("t.project_id = ?")
        params.append(project_id)
    params.append(limit)
    with get_conn() as conn:
        expire_review_tasks(conn, project_id)
        _ensure_pending_review_tasks(conn, project_id)
        rows = conn.execute(
            f"""
            SELECT t.*, f.discovered_by
            FROM review_tasks t
            JOIN projects p ON p.id = t.project_id
            JOIN audit_findings f ON f.id = t.finding_id AND f.project_id = t.project_id
            WHERE {' AND '.join(clauses)}
            ORDER BY t.created_at, t.id
            LIMIT ?
            """,
            params,
        ).fetchall()
    return [_task_from_row(row) for row in rows]


@router.get("/api/review-tasks")
def list_review_task_queue(
    project_id: str | None = None,
    finding_id: str | None = None,
    status: str | None = None,
    limit: int = 100,
):
    allowed = {
        "pending",
        "running",
        "waiting_for_reviewer",
        "blocked_no_independent_worker",
        "completed",
        "failed",
    }
    if limit < 1 or limit > 500:
        raise HTTPException(400, "limit must be between 1 and 500")
    if status and status not in allowed:
        raise HTTPException(400, "Unsupported review task status")
    clauses: list[str] = []
    params: list[object] = []
    if project_id:
        clauses.append("t.project_id = ?")
        params.append(project_id)
    if finding_id:
        clauses.append("t.finding_id = ?")
        params.append(finding_id)
    if status:
        clauses.append("t.status = ?")
        params.append(status)
    params.append(limit)
    where_sql = f"WHERE {' AND '.join(clauses)}" if clauses else ""
    with get_conn() as conn:
        expire_review_tasks(conn, project_id)
        _ensure_pending_review_tasks(conn, project_id)
        rows = conn.execute(
            f"""
            SELECT t.*, p.title AS project_title, f.title AS finding_title,
                   f.severity AS finding_severity, f.discovered_by
            FROM review_tasks t
            JOIN projects p ON p.id = t.project_id
            LEFT JOIN audit_findings f
              ON f.id = t.finding_id
             AND f.project_id = t.project_id
            {where_sql}
            ORDER BY
                CASE t.status
                    WHEN 'running' THEN 0
                    WHEN 'pending' THEN 1
                    WHEN 'waiting_for_reviewer' THEN 2
                    WHEN 'blocked_no_independent_worker' THEN 3
                    WHEN 'failed' THEN 4
                    ELSE 5
                END,
                datetime(t.created_at) DESC,
                t.id DESC
            LIMIT ?
            """,
            params,
        ).fetchall()
    return [_queue_task_from_row(row) for row in rows]


@router.post("/api/review-tasks/{task_id}/claim", response_model=ReviewTask)
def claim_review_task(task_id: str, body: ReviewTaskWorkerRequest):
    now = utcnow()
    with get_conn() as conn:
        row = conn.execute("SELECT * FROM review_tasks WHERE id = ?", (task_id,)).fetchone()
        if row is None:
            raise HTTPException(404, "Review task not found")
        check_project_active(conn, row["project_id"])
        expire_review_tasks(conn, row["project_id"])
        row = conn.execute("SELECT * FROM review_tasks WHERE id = ?", (task_id,)).fetchone()
        assert row is not None
        if row["status"] not in ("pending", "waiting_for_reviewer", "blocked_no_independent_worker"):
            raise HTTPException(409, f"Review task is {row['status']}")
        finding = _reviewable_finding_or_409(conn, row["project_id"], row["finding_id"])
        if body.worker in _review_task_excluded_workers(row, finding["discovered_by"]):
            raise HTTPException(409, "Independent review must be performed by a different worker")
        conn.execute(
            """
            UPDATE review_tasks
            SET status = 'running',
                worker = ?,
                blocked_reason = NULL,
                started_at = COALESCE(started_at, ?),
                last_heartbeat_at = ?,
                error_message = NULL
            WHERE id = ?
              AND status IN ('pending', 'waiting_for_reviewer', 'blocked_no_independent_worker')
              AND worker IS NULL
            """,
            (body.worker, now, now, task_id),
        )
        updated = conn.execute("SELECT * FROM review_tasks WHERE id = ?", (task_id,)).fetchone()
        if updated is None or updated["status"] != "running" or updated["worker"] != body.worker:
            raise HTTPException(409, "Review task was claimed by another worker")
    return _task_from_row(updated)


@router.post("/api/review-tasks/{task_id}/heartbeat", response_model=ReviewTask)
def heartbeat_review_task(task_id: str, body: ReviewTaskWorkerRequest):
    now = utcnow()
    with get_conn() as conn:
        row = _running_task_for_worker(conn, task_id, body.worker)
        check_project_active(conn, row["project_id"])
        conn.execute(
            "UPDATE review_tasks SET last_heartbeat_at = ? WHERE id = ?",
            (now, task_id),
        )
        updated = conn.execute("SELECT * FROM review_tasks WHERE id = ?", (task_id,)).fetchone()
    assert updated is not None
    return _task_from_row(updated)


@router.post("/api/review-tasks/{task_id}/release", response_model=ReviewTask)
def release_review_task(task_id: str, body: ReviewTaskWorkerRequest):
    with get_conn() as conn:
        row = conn.execute("SELECT * FROM review_tasks WHERE id = ?", (task_id,)).fetchone()
        if row is None:
            raise HTTPException(404, "Review task not found")
        if row["status"] != "running":
            return _task_from_row(row)
        if row["worker"] != body.worker:
            raise HTTPException(409, f"Review task is claimed by {row['worker']}")
        conn.execute(
            """
            UPDATE review_tasks
            SET status = 'pending',
                worker = NULL,
                last_heartbeat_at = NULL
            WHERE id = ?
            """,
            (task_id,),
        )
        updated = conn.execute("SELECT * FROM review_tasks WHERE id = ?", (task_id,)).fetchone()
    assert updated is not None
    return _task_from_row(updated)


@router.post("/api/review-tasks/{task_id}/availability", response_model=ReviewTask)
def mark_review_task_availability(task_id: str, body: ReviewTaskAvailabilityRequest):
    with get_conn() as conn:
        row = conn.execute("SELECT * FROM review_tasks WHERE id = ?", (task_id,)).fetchone()
        if row is None:
            raise HTTPException(404, "Review task not found")
        if row["status"] in ("completed", "failed", "running"):
            return _task_from_row(row)
        conn.execute(
            """
            UPDATE review_tasks
            SET status = ?,
                worker = NULL,
                last_heartbeat_at = NULL,
                blocked_reason = ?
            WHERE id = ?
            """,
            (body.status, (body.reason or body.status)[:2000], task_id),
        )
        updated = conn.execute("SELECT * FROM review_tasks WHERE id = ?", (task_id,)).fetchone()
    assert updated is not None
    return _task_from_row(updated)


@router.post("/api/review-tasks/{task_id}/complete", response_model=ReviewTask)
def complete_review_task(task_id: str, body: CompleteReviewTaskRequest):
    now = utcnow()
    with get_conn() as conn:
        row = _running_task_for_worker(conn, task_id, body.worker)
        check_project_active(conn, row["project_id"])
        _apply_audit_finding_review(
            conn,
            row["project_id"],
            row["finding_id"],
            body.worker,
            body.decision,
        )
        conn.execute(
            """
            UPDATE review_tasks
            SET status = 'completed',
                completed_at = ?,
                last_heartbeat_at = ?,
                blocked_reason = NULL,
                error_message = NULL
            WHERE id = ?
            """,
            (now, now, task_id),
        )
        updated = conn.execute("SELECT * FROM review_tasks WHERE id = ?", (task_id,)).fetchone()
    assert updated is not None
    return _task_from_row(updated)


@router.post("/api/review-tasks/{task_id}/fail", response_model=ReviewTask)
def fail_review_task(task_id: str, body: FailReviewTaskRequest):
    now = utcnow()
    with get_conn() as conn:
        row = _running_task_for_worker(conn, task_id, body.worker)
        retry_count = int(row["retry_count"] or 0) + 1
        next_status = "failed" if retry_count >= REVIEW_TASK_RETRY_LIMIT else "pending"
        conn.execute(
            """
            UPDATE review_tasks
            SET status = ?,
                worker = NULL,
                completed_at = CASE WHEN ? = 'failed' THEN ? ELSE NULL END,
                last_heartbeat_at = CASE WHEN ? = 'failed' THEN ? ELSE NULL END,
                error_message = ?,
                retry_count = ?
            WHERE id = ?
            """,
            (
                next_status,
                next_status,
                now,
                next_status,
                now,
                body.error_message[:2000],
                retry_count,
                task_id,
            ),
        )
        updated = conn.execute("SELECT * FROM review_tasks WHERE id = ?", (task_id,)).fetchone()
    assert updated is not None
    return _task_from_row(updated)


@router.post("/api/review-tasks/{task_id}/cancel", response_model=ReviewTask)
def cancel_review_task(task_id: str, body: ReviewTaskWorkerRequest):
    now = utcnow()
    with get_conn() as conn:
        row = conn.execute("SELECT * FROM review_tasks WHERE id = ?", (task_id,)).fetchone()
        if row is None:
            raise HTTPException(404, "Review task not found")
        if row["status"] not in ("pending", "running", "waiting_for_reviewer", "blocked_no_independent_worker"):
            return _task_from_row(row)
        conn.execute(
            """
            UPDATE review_tasks
            SET status = 'failed',
                worker = NULL,
                completed_at = ?,
                last_heartbeat_at = ?,
                error_message = ?
            WHERE id = ?
            """,
            (now, now, f"Cancelled by {body.worker}", task_id),
        )
        updated = conn.execute("SELECT * FROM review_tasks WHERE id = ?", (task_id,)).fetchone()
    assert updated is not None
    return _task_from_row(updated)


@router.post("/api/review-tasks/{task_id}/retry", response_model=ReviewTask)
def retry_review_task(task_id: str, body: ReviewTaskWorkerRequest):
    now = utcnow()
    with get_conn() as conn:
        row = conn.execute("SELECT * FROM review_tasks WHERE id = ?", (task_id,)).fetchone()
        if row is None:
            raise HTTPException(404, "Review task not found")
        check_project_active(conn, row["project_id"])
        _reviewable_finding_or_409(conn, row["project_id"], row["finding_id"])
        if row["status"] not in ("failed", "blocked_no_independent_worker"):
            raise HTTPException(409, f"Review task is {row['status']}")
        conn.execute(
            """
            UPDATE review_tasks
            SET status = 'pending',
                worker = NULL,
                blocked_reason = NULL,
                started_at = NULL,
                last_heartbeat_at = NULL,
                completed_at = NULL,
                error_message = NULL,
                retry_count = 0,
                created_by = ?,
                created_at = ?
            WHERE id = ?
            """,
            (body.worker, now, task_id),
        )
        updated = conn.execute("SELECT * FROM review_tasks WHERE id = ?", (task_id,)).fetchone()
    assert updated is not None
    return _task_from_row(updated)


@router.get("/api/review-tasks/{task_id}/packet")
def get_review_task_packet(task_id: str):
    with get_conn() as conn:
        task = conn.execute("SELECT * FROM review_tasks WHERE id = ?", (task_id,)).fetchone()
        if task is None:
            raise HTTPException(404, "Review task not found")
        finding = conn.execute(
            """
            SELECT *
            FROM audit_findings
            WHERE id = ? AND project_id = ?
            """,
            (task["finding_id"], task["project_id"]),
        ).fetchone()
        if finding is None:
            raise HTTPException(404, "Audit finding not found")
        project = get_project_or_404(conn, task["project_id"])
        business_node = None
        if finding["business_node_id"]:
            business_node = conn.execute(
                "SELECT * FROM business_nodes WHERE id = ? AND project_id = ?",
                (finding["business_node_id"], task["project_id"]),
            ).fetchone()
        entrypoints = conn.execute(
            """
            SELECT id, path, language, kind, framework, method, route, handler,
                   line_start, evidence
            FROM code_entrypoints
            WHERE snapshot_id = ?
              AND (path = ? OR route = ?)
            ORDER BY path, COALESCE(line_start, 0), route
            LIMIT 20
            """,
            (finding["snapshot_id"], finding["file_path"], finding["entry_point"]),
        ).fetchall()
        symbols = conn.execute(
            """
            SELECT id, path, language, kind, name, container, signature,
                   line_start, line_end
            FROM code_symbols
            WHERE snapshot_id = ?
              AND path = ?
            ORDER BY COALESCE(line_start, 0), kind, name
            LIMIT 50
            """,
            (finding["snapshot_id"], finding["file_path"]),
        ).fetchall()
        candidates = conn.execute(
            """
            SELECT id, source, candidate_type, severity, title, description,
                   file_path, line_start, line_end, entry_point, symbol,
                   status, conclusion_summary, evidence
            FROM audit_candidates
            WHERE project_id = ?
              AND snapshot_id = ?
              AND (
                  audit_finding_id = ?
                  OR file_path = ?
                  OR business_node_id = ?
              )
            ORDER BY created_at, id
            LIMIT 50
            """,
            (
                task["project_id"],
                finding["snapshot_id"],
                finding["id"],
                finding["file_path"],
                finding["business_node_id"],
            ),
        ).fetchall()

    return {
        "task": {
            "id": task["id"],
            "project_id": task["project_id"],
            "finding_id": task["finding_id"],
            "retry_count": task["retry_count"],
        },
        "project": {
            "id": project["id"],
            "title": project["title"],
            "status": project["status"],
        },
        "finding": _finding_packet(finding),
        "source": {
            "snapshot_id": finding["snapshot_id"],
            "container_source_path": snapshot_container_path(finding["snapshot_id"]),
            "primary_snippet": _source_snippet(
                finding["snapshot_id"],
                finding["file_path"],
                finding["line_start"],
                finding["line_end"],
            ),
        },
        "code_index": {
            "entrypoints": [dict(row) for row in entrypoints],
            "symbols_same_file": [dict(row) for row in symbols],
            "related_candidates": [dict(row) for row in candidates],
        },
        "business_node": dict(business_node) if business_node is not None else None,
        "rules": {
            "decision": "Return exactly one review for this finding_id.",
            "independent_review": "The reviewer must decide from source evidence, not from the original finding text alone.",
        },
    }


def _ensure_pending_review_tasks(conn, project_id: str | None = None) -> None:
    clauses = [
        "f.status = 'pending_review'",
        "f.severity IN ('critical', 'high')",
        "p.status = 'active'",
    ]
    params: list[object] = []
    if project_id is not None:
        clauses.append("f.project_id = ?")
        params.append(project_id)
    rows = conn.execute(
        f"""
        SELECT f.id, f.project_id, f.discovered_by
        FROM audit_findings f
        JOIN projects p ON p.id = f.project_id
        WHERE {' AND '.join(clauses)}
          AND NOT EXISTS (
              SELECT 1
              FROM review_tasks t
              WHERE t.project_id = f.project_id
                AND t.finding_id = f.id
          )
        ORDER BY f.created_at, f.id
        """,
        params,
    ).fetchall()
    for row in rows:
        _ensure_review_task(
            conn,
            row["project_id"],
            row["id"],
            row["discovered_by"],
            excluded_workers=[row["discovered_by"]],
        )


def _reviewable_finding_or_409(conn, project_id: str, finding_id: str):
    finding = conn.execute(
        """
        SELECT id, status, severity, discovered_by
        FROM audit_findings
        WHERE id = ? AND project_id = ?
        """,
        (finding_id, project_id),
    ).fetchone()
    if finding is None:
        raise HTTPException(404, "Audit finding not found")
    if finding["status"] != "pending_review":
        raise HTTPException(409, f"Audit finding is {finding['status']}")
    if finding["severity"] not in ("critical", "high"):
        raise HTTPException(409, "Review tasks only accept high or critical pending findings")
    return finding


def _running_task_for_worker(conn, task_id: str, worker: str):
    row = conn.execute("SELECT * FROM review_tasks WHERE id = ?", (task_id,)).fetchone()
    if row is None:
        raise HTTPException(404, "Review task not found")
    if row["status"] != "running":
        raise HTTPException(409, f"Review task is {row['status']}")
    if row["worker"] != worker:
        raise HTTPException(409, f"Review task is claimed by {row['worker']}")
    return row


def _task_from_row(row) -> ReviewTask:
    data = dict(row)
    excluded_workers = _review_task_excluded_workers(data, data.get("discovered_by"))
    data.pop("excluded_workers_json", None)
    data["excluded_workers"] = excluded_workers
    return ReviewTask(**data)


def _queue_task_from_row(row) -> dict:
    data = _task_from_row(row).model_dump()
    data["project_title"] = row["project_title"]
    data["finding_title"] = row["finding_title"]
    data["finding_severity"] = row["finding_severity"]
    data["discovered_by"] = row["discovered_by"]
    return data


def _review_task_excluded_workers(row, discovered_by: str | None = None) -> list[str]:
    data = dict(row)
    excluded = _decode_json_list(data.get("excluded_workers_json"))
    if discovered_by:
        excluded.append(discovered_by)
    return _normalized_worker_list(excluded)


def _finding_packet(row) -> dict[str, object]:
    return {
        "id": row["id"],
        "title": row["title"],
        "category": row["category"],
        "severity": row["severity"],
        "status": row["status"],
        "cwe": row["cwe"],
        "file_path": row["file_path"],
        "line_start": row["line_start"],
        "line_end": row["line_end"],
        "symbol": row["symbol"],
        "entry_point": row["entry_point"],
        "business_node_id": row["business_node_id"],
        "description": row["description"],
        "impact": row["impact"],
        "evidence": row["evidence"],
        "proof_packets": _decode_json_list(row["proof_packets_json"]),
        "reproduction_poc": _decode_json_dict(row["reproduction_poc_json"]),
        "remediation": row["remediation"],
        "discovered_by": row["discovered_by"],
        "reviewed_by": row["reviewed_by"],
    }


def _decode_json_list(raw: str | None) -> list:
    if not raw:
        return []
    try:
        value = json.loads(raw)
    except json.JSONDecodeError:
        return []
    return value if isinstance(value, list) else []


def _decode_json_dict(raw: str | None) -> dict:
    if not raw:
        return {}
    try:
        value = json.loads(raw)
    except json.JSONDecodeError:
        return {}
    return value if isinstance(value, dict) else {}


def _safe_relative_path(value: str | None) -> PurePosixPath | None:
    if not value:
        return None
    normalized = value.replace("\\", "/").lstrip("/")
    path = PurePosixPath(normalized)
    parts = [part for part in path.parts if part not in ("", ".")]
    if not parts or any(part == ".." for part in parts):
        return None
    return PurePosixPath(*parts)
