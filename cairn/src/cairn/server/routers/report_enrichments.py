from __future__ import annotations

import json
from pathlib import PurePosixPath
import uuid

from fastapi import APIRouter, HTTPException

from cairn.server.db import get_conn
from cairn.server.report_models import (
    ClaimReportEnrichmentRequest,
    CompleteReportEnrichmentRequest,
    CreateReportEnrichmentRequest,
    FailReportEnrichmentRequest,
    ReportEnrichmentTask,
)
from cairn.server.services import check_project_active, get_project_or_404, utcnow
from cairn.server.source_service import snapshot_container_path, snapshot_path


router = APIRouter(tags=["report-enrichment"])


@router.get("/api/projects/{project_id}/report-enrichments", response_model=list[ReportEnrichmentTask])
def list_project_report_enrichments(
    project_id: str,
    finding_id: str | None = None,
    status: str | None = None,
):
    with get_conn() as conn:
        get_project_or_404(conn, project_id)
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
            FROM report_enrichment_tasks
            WHERE {' AND '.join(clauses)}
            ORDER BY created_at DESC, id DESC
            """,
            params,
        ).fetchall()
    return [_task_from_row(row) for row in rows]


@router.post("/api/projects/{project_id}/report-enrichments", response_model=ReportEnrichmentTask, status_code=201)
def create_report_enrichment(project_id: str, body: CreateReportEnrichmentRequest):
    task_id = f"rpt_{uuid.uuid4().hex[:16]}"
    now = utcnow()
    with get_conn() as conn:
        get_project_or_404(conn, project_id)
        finding = conn.execute(
            """
            SELECT id, status
            FROM audit_findings
            WHERE id = ? AND project_id = ?
            """,
            (body.finding_id, project_id),
        ).fetchone()
        if finding is None:
            raise HTTPException(404, "Audit finding not found")
        if finding["status"] != "confirmed":
            raise HTTPException(409, "Report enrichment only accepts confirmed findings")
        existing = conn.execute(
            """
            SELECT *
            FROM report_enrichment_tasks
            WHERE project_id = ?
              AND finding_id = ?
              AND status IN ('pending', 'running')
            ORDER BY created_at
            LIMIT 1
            """,
            (project_id, body.finding_id),
        ).fetchone()
        if existing is not None:
            return _task_from_row(existing)
        conn.execute(
            """
            INSERT INTO report_enrichment_tasks (
                id, project_id, finding_id, status, created_by, created_at
            )
            VALUES (?, ?, ?, 'pending', ?, ?)
            """,
            (task_id, project_id, body.finding_id, body.created_by, now),
        )
        row = conn.execute("SELECT * FROM report_enrichment_tasks WHERE id = ?", (task_id,)).fetchone()
    assert row is not None
    return _task_from_row(row)


@router.get("/api/report-enrichments/pending", response_model=list[ReportEnrichmentTask])
def list_pending_report_enrichments(project_id: str | None = None, limit: int = 10):
    if limit < 1 or limit > 100:
        raise HTTPException(400, "limit must be between 1 and 100")
    clauses = ["t.status = 'pending'", "p.status = 'active'"]
    params: list[object] = []
    if project_id:
        clauses.append("t.project_id = ?")
        params.append(project_id)
    params.append(limit)
    with get_conn() as conn:
        rows = conn.execute(
            f"""
            SELECT t.*
            FROM report_enrichment_tasks t
            JOIN projects p ON p.id = t.project_id
            WHERE {' AND '.join(clauses)}
            ORDER BY t.created_at, t.id
            LIMIT ?
            """,
            params,
        ).fetchall()
    return [_task_from_row(row) for row in rows]


@router.get("/api/report-enrichment-tasks")
def list_report_enrichment_task_queue(
    project_id: str | None = None,
    finding_id: str | None = None,
    status: str | None = None,
    limit: int = 100,
):
    if limit < 1 or limit > 500:
        raise HTTPException(400, "limit must be between 1 and 500")
    if status and status not in ("pending", "running", "completed", "failed"):
        raise HTTPException(400, "Unsupported report enrichment task status")
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
        rows = conn.execute(
            f"""
            SELECT t.*, p.title AS project_title, f.title AS finding_title,
                   f.severity AS finding_severity
            FROM report_enrichment_tasks t
            JOIN projects p ON p.id = t.project_id
            LEFT JOIN audit_findings f
              ON f.id = t.finding_id
             AND f.project_id = t.project_id
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


@router.post("/api/report-enrichments/{task_id}/claim", response_model=ReportEnrichmentTask)
def claim_report_enrichment(task_id: str, body: ClaimReportEnrichmentRequest):
    now = utcnow()
    with get_conn() as conn:
        row = conn.execute("SELECT * FROM report_enrichment_tasks WHERE id = ?", (task_id,)).fetchone()
        if row is None:
            raise HTTPException(404, "Report enrichment task not found")
        check_project_active(conn, row["project_id"])
        if row["status"] != "pending":
            raise HTTPException(409, f"Report enrichment task is {row['status']}")
        conn.execute(
            """
            UPDATE report_enrichment_tasks
            SET status = 'running',
                worker = ?,
                started_at = COALESCE(started_at, ?),
                last_heartbeat_at = ?,
                error_message = NULL
            WHERE id = ? AND status = 'pending'
            """,
            (body.worker, now, now, task_id),
        )
        updated = conn.execute("SELECT * FROM report_enrichment_tasks WHERE id = ?", (task_id,)).fetchone()
    assert updated is not None
    return _task_from_row(updated)


@router.post("/api/report-enrichments/{task_id}/heartbeat", response_model=ReportEnrichmentTask)
def heartbeat_report_enrichment(task_id: str, body: ClaimReportEnrichmentRequest):
    now = utcnow()
    with get_conn() as conn:
        row = _running_task_for_worker(conn, task_id, body.worker)
        check_project_active(conn, row["project_id"])
        conn.execute(
            "UPDATE report_enrichment_tasks SET last_heartbeat_at = ? WHERE id = ?",
            (now, task_id),
        )
        updated = conn.execute("SELECT * FROM report_enrichment_tasks WHERE id = ?", (task_id,)).fetchone()
    assert updated is not None
    return _task_from_row(updated)


@router.post("/api/report-enrichments/{task_id}/release", response_model=ReportEnrichmentTask)
def release_report_enrichment(task_id: str, body: ClaimReportEnrichmentRequest):
    with get_conn() as conn:
        row = conn.execute("SELECT * FROM report_enrichment_tasks WHERE id = ?", (task_id,)).fetchone()
        if row is None:
            raise HTTPException(404, "Report enrichment task not found")
        if row["status"] != "running":
            return _task_from_row(row)
        if row["worker"] != body.worker:
            raise HTTPException(409, f"Report enrichment task is claimed by {row['worker']}")
        conn.execute(
            """
            UPDATE report_enrichment_tasks
            SET status = 'pending',
                worker = NULL,
                last_heartbeat_at = NULL
            WHERE id = ?
            """,
            (task_id,),
        )
        updated = conn.execute("SELECT * FROM report_enrichment_tasks WHERE id = ?", (task_id,)).fetchone()
    assert updated is not None
    return _task_from_row(updated)


@router.post("/api/report-enrichments/{task_id}/complete", response_model=ReportEnrichmentTask)
def complete_report_enrichment(task_id: str, body: CompleteReportEnrichmentRequest):
    _validate_enrichment_result(body)
    now = utcnow()
    with get_conn() as conn:
        row = _running_task_for_worker(conn, task_id, body.worker)
        check_project_active(conn, row["project_id"])
        conn.execute(
            """
            UPDATE report_enrichment_tasks
            SET status = 'completed',
                completed_at = ?,
                last_heartbeat_at = ?,
                error_message = NULL,
                packet_templates_json = ?,
                reproduction_poc_json = ?,
                evidence_chain_json = ?,
                report_sections_json = ?,
                delivery_notes_json = ?
            WHERE id = ?
            """,
            (
                now,
                now,
                json.dumps(body.packet_templates, ensure_ascii=False),
                json.dumps(body.reproduction_poc, ensure_ascii=False),
                json.dumps(body.evidence_chain, ensure_ascii=False),
                json.dumps(body.report_sections, ensure_ascii=False),
                json.dumps(body.delivery_notes, ensure_ascii=False),
                task_id,
            ),
        )
        updated = conn.execute("SELECT * FROM report_enrichment_tasks WHERE id = ?", (task_id,)).fetchone()
    assert updated is not None
    return _task_from_row(updated)


@router.post("/api/report-enrichments/{task_id}/fail", response_model=ReportEnrichmentTask)
def fail_report_enrichment(task_id: str, body: FailReportEnrichmentRequest):
    now = utcnow()
    with get_conn() as conn:
        row = _running_task_for_worker(conn, task_id, body.worker)
        conn.execute(
            """
            UPDATE report_enrichment_tasks
            SET status = 'failed',
                completed_at = ?,
                last_heartbeat_at = ?,
                error_message = ?
            WHERE id = ?
            """,
            (now, now, body.error_message[:2000], task_id),
        )
        updated = conn.execute("SELECT * FROM report_enrichment_tasks WHERE id = ?", (task_id,)).fetchone()
    assert updated is not None
    return _task_from_row(updated)


@router.post("/api/report-enrichments/{task_id}/cancel", response_model=ReportEnrichmentTask)
def cancel_report_enrichment(task_id: str, body: ClaimReportEnrichmentRequest):
    now = utcnow()
    with get_conn() as conn:
        row = conn.execute("SELECT * FROM report_enrichment_tasks WHERE id = ?", (task_id,)).fetchone()
        if row is None:
            raise HTTPException(404, "Report enrichment task not found")
        if row["status"] not in ("pending", "running"):
            return _task_from_row(row)
        conn.execute(
            """
            UPDATE report_enrichment_tasks
            SET status = 'failed',
                completed_at = ?,
                last_heartbeat_at = ?,
                error_message = ?
            WHERE id = ?
            """,
            (now, now, f"Cancelled by {body.worker}", task_id),
        )
        updated = conn.execute("SELECT * FROM report_enrichment_tasks WHERE id = ?", (task_id,)).fetchone()
    assert updated is not None
    return _task_from_row(updated)


@router.post("/api/report-enrichments/{task_id}/retry", response_model=ReportEnrichmentTask)
def retry_report_enrichment(task_id: str, body: ClaimReportEnrichmentRequest):
    now = utcnow()
    with get_conn() as conn:
        row = conn.execute("SELECT * FROM report_enrichment_tasks WHERE id = ?", (task_id,)).fetchone()
        if row is None:
            raise HTTPException(404, "Report enrichment task not found")
        check_project_active(conn, row["project_id"])
        _validate_confirmed_finding(conn, row["project_id"], row["finding_id"])
        if row["status"] != "failed":
            raise HTTPException(409, f"Only failed report enrichment tasks can be retried; current status is {row['status']}")
        conn.execute(
            """
            UPDATE report_enrichment_tasks
            SET status = 'pending',
                worker = NULL,
                started_at = NULL,
                last_heartbeat_at = NULL,
                completed_at = NULL,
                error_message = NULL,
                created_by = ?,
                created_at = ?,
                packet_templates_json = '[]',
                reproduction_poc_json = '{}',
                evidence_chain_json = '[]',
                report_sections_json = '{}',
                delivery_notes_json = '[]'
            WHERE id = ?
            """,
            (body.worker, now, task_id),
        )
        updated = conn.execute("SELECT * FROM report_enrichment_tasks WHERE id = ?", (task_id,)).fetchone()
    assert updated is not None
    return _task_from_row(updated)


@router.get("/api/report-enrichments/{task_id}/packet")
def get_report_enrichment_packet(task_id: str):
    with get_conn() as conn:
        task = conn.execute("SELECT * FROM report_enrichment_tasks WHERE id = ?", (task_id,)).fetchone()
        if task is None:
            raise HTTPException(404, "Report enrichment task not found")
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
        facts = conn.execute(
            """
            SELECT id, description
            FROM facts
            WHERE project_id = ?
            ORDER BY rowid
            LIMIT 200
            """,
            (task["project_id"],),
        ).fetchall()
        intents = conn.execute(
            """
            SELECT id, to_fact_id, description, creator, worker, created_at, concluded_at
            FROM intents
            WHERE project_id = ?
            ORDER BY created_at, rowid
            LIMIT 300
            """,
            (task["project_id"],),
        ).fetchall()
        audit_log = conn.execute(
            """
            SELECT id, created_at, actor, action, target_type, target_id, summary, detail
            FROM audit_log
            WHERE target_id IN (?, ?)
               OR summary LIKE ?
               OR detail LIKE ?
            ORDER BY datetime(created_at) DESC, id DESC
            LIMIT 100
            """,
            (
                task["project_id"],
                task["finding_id"],
                f"%{task['finding_id']}%",
                f"%{task['finding_id']}%",
            ),
        ).fetchall()

    return {
        "task": {
            "id": task["id"],
            "project_id": task["project_id"],
            "finding_id": task["finding_id"],
        },
        "project": {
            "id": project["id"],
            "title": project["title"],
            "status": project["status"],
        },
        "finding": {
            "id": finding["id"],
            "title": finding["title"],
            "category": finding["category"],
            "severity": finding["severity"],
            "status": finding["status"],
            "cwe": finding["cwe"],
            "file_path": finding["file_path"],
            "line_start": finding["line_start"],
            "line_end": finding["line_end"],
            "symbol": finding["symbol"],
            "entry_point": finding["entry_point"],
            "business_node_id": finding["business_node_id"],
            "description": finding["description"],
            "impact": finding["impact"],
            "evidence": finding["evidence"],
            "proof_packets": _decode_json_list(finding["proof_packets_json"]),
            "reproduction_poc": _decode_json_dict(finding["reproduction_poc_json"]),
            "remediation": finding["remediation"],
            "discovered_by": finding["discovered_by"],
            "reviewed_by": finding["reviewed_by"],
        },
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
        },
        "timeline": {
            "facts": [dict(row) for row in facts],
            "intents": [dict(row) for row in intents],
        },
        "audit_log": [dict(row) for row in audit_log],
        "business_node": dict(business_node) if business_node is not None else None,
        "rules": {
            "proof_packets": "Do not create proof_packets. Only real captured traffic belongs there.",
            "packet_templates": "Static packet templates are allowed but must be clearly marked as source-inferred.",
        },
    }


def _running_task_for_worker(conn, task_id: str, worker: str):
    row = conn.execute("SELECT * FROM report_enrichment_tasks WHERE id = ?", (task_id,)).fetchone()
    if row is None:
        raise HTTPException(404, "Report enrichment task not found")
    if row["status"] != "running":
        raise HTTPException(409, f"Report enrichment task is {row['status']}")
    if row["worker"] != worker:
        raise HTTPException(409, f"Report enrichment task is claimed by {row['worker']}")
    return row


def _validate_confirmed_finding(conn, project_id: str, finding_id: str) -> None:
    row = conn.execute(
        """
        SELECT status
        FROM audit_findings
        WHERE id = ? AND project_id = ?
        """,
        (finding_id, project_id),
    ).fetchone()
    if row is None:
        raise HTTPException(404, "Audit finding not found")
    if row["status"] != "confirmed":
        raise HTTPException(409, "Report enrichment only accepts confirmed findings")


def _validate_enrichment_result(body: CompleteReportEnrichmentRequest) -> None:
    if not body.packet_templates and not _has_complete_reproduction_poc(body.reproduction_poc):
        raise HTTPException(422, "Report enrichment requires packet_templates or complete reproduction_poc")
    for index, packet in enumerate(body.packet_templates):
        if "response" in packet:
            raise HTTPException(422, f"packet_templates[{index}] must not contain observed response")
        missing = [
            key
            for key in ("title", "request", "expected_result")
            if not str(packet.get(key) or "").strip()
        ]
        if missing:
            raise HTTPException(422, f"packet_templates[{index}] missing: {', '.join(missing)}")


def _has_complete_reproduction_poc(poc: dict[str, object]) -> bool:
    payload = _poc_text(poc, "payload")
    request_template = (
        _poc_text(poc, "request_template")
        or _poc_text(poc, "curl")
        or _poc_text(poc, "command")
    )
    expected_result = _poc_text(poc, "expected_result") or _poc_text(poc, "expected_response")
    steps = _poc_list(poc, "steps")
    verification = _poc_text(poc, "verification")
    return bool(payload and request_template and expected_result and (steps or verification))


def _poc_text(poc: dict[str, object], key: str) -> str:
    value = poc.get(key)
    return value.strip() if isinstance(value, str) else ""


def _poc_list(poc: dict[str, object], key: str) -> list[str]:
    value = poc.get(key)
    if not isinstance(value, list):
        return []
    return [str(item).strip() for item in value if str(item).strip()]


def _task_from_row(row) -> ReportEnrichmentTask:
    data = dict(row)
    data["packet_templates"] = _decode_json_list(data.pop("packet_templates_json", None))
    data["reproduction_poc"] = _decode_json_dict(data.pop("reproduction_poc_json", None))
    data["evidence_chain"] = _decode_json_string_list(data.pop("evidence_chain_json", None))
    data["report_sections"] = _decode_json_dict(data.pop("report_sections_json", None))
    data["delivery_notes"] = _decode_json_string_list(data.pop("delivery_notes_json", None))
    return ReportEnrichmentTask(**data)


def _queue_task_from_row(row) -> dict:
    data = _task_from_row(row).model_dump()
    data["project_title"] = row["project_title"]
    data["finding_title"] = row["finding_title"]
    data["finding_severity"] = row["finding_severity"]
    return data


def _decode_json_list(raw: str | None) -> list:
    if not raw:
        return []
    try:
        value = json.loads(raw)
    except json.JSONDecodeError:
        return []
    return value if isinstance(value, list) else []


def _decode_json_string_list(raw: str | None) -> list[str]:
    values = _decode_json_list(raw)
    return [str(item).strip() for item in values if str(item).strip()]


def _decode_json_dict(raw: str | None) -> dict:
    if not raw:
        return {}
    try:
        value = json.loads(raw)
    except json.JSONDecodeError:
        return {}
    return value if isinstance(value, dict) else {}


def _source_snippet(
    snapshot_id: str,
    file_path: str | None,
    line_start: int | None,
    line_end: int | None,
) -> dict[str, object] | None:
    safe_path = _safe_relative_path(file_path)
    if safe_path is None:
        return None
    path = snapshot_path(snapshot_id) / safe_path
    if not path.is_file():
        return None
    try:
        lines = path.read_text(encoding="utf-8", errors="replace").splitlines()
    except OSError:
        return None
    if not lines:
        return {"path": str(safe_path), "start_line": 1, "end_line": 0, "content": ""}
    if line_start is None:
        start = 1
        end = min(len(lines), 80)
    else:
        start = max(1, line_start - 25)
        end = min(len(lines), (line_end or line_start) + 25)
    numbered = [
        f"{line_number}: {lines[line_number - 1]}"
        for line_number in range(start, end + 1)
    ]
    return {
        "path": str(safe_path),
        "start_line": start,
        "end_line": end,
        "content": "\n".join(numbered),
    }


def _safe_relative_path(value: str | None) -> PurePosixPath | None:
    if not value:
        return None
    normalized = value.replace("\\", "/").lstrip("/")
    path = PurePosixPath(normalized)
    parts = [part for part in path.parts if part not in ("", ".")]
    if not parts or any(part == ".." for part in parts):
        return None
    return PurePosixPath(*parts)
