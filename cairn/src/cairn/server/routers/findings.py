from __future__ import annotations

import json
import uuid

from fastapi import APIRouter, HTTPException

from cairn.server.db import get_conn
from cairn.server.services import get_project_or_404, utcnow
from cairn.server.source_models import (
    AuditFinding,
    CreateAuditFindingRequest,
    CreateToolFindingRequest,
    ReviewAuditFindingRequest,
    ToolFinding,
)


router = APIRouter(prefix="/api/projects/{project_id}", tags=["code-audit-findings"])


@router.get("/tool-findings", response_model=list[ToolFinding])
def list_tool_findings(project_id: str, snapshot_id: str | None = None, status: str | None = None):
    with get_conn() as conn:
        get_project_or_404(conn, project_id)
        clauses = ["project_id = ?"]
        params: list[object] = [project_id]
        if snapshot_id:
            clauses.append("snapshot_id = ?")
            params.append(snapshot_id)
        if status:
            clauses.append("status = ?")
            params.append(status)
        rows = conn.execute(
            f"SELECT * FROM tool_findings WHERE {' AND '.join(clauses)} ORDER BY created_at DESC, id",
            params,
        ).fetchall()
    return [ToolFinding(**dict(row)) for row in rows]


@router.post("/tool-findings", response_model=ToolFinding, status_code=201)
def create_tool_finding(project_id: str, body: CreateToolFindingRequest):
    finding_id = f"tool_{uuid.uuid4().hex[:16]}"
    created_at = utcnow()
    with get_conn() as conn:
        get_project_or_404(conn, project_id)
        _validate_snapshot(conn, project_id, body.snapshot_id)
        conn.execute(
            """
            INSERT INTO tool_findings (
                id, project_id, snapshot_id, tool_name, rule_id, severity, title,
                description, file_path, line_start, line_end, status,
                raw_artifact_path, created_at
            )
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'candidate', ?, ?)
            """,
            (
                finding_id,
                project_id,
                body.snapshot_id,
                body.tool_name,
                body.rule_id,
                body.severity,
                body.title,
                body.description,
                body.file_path,
                body.line_start,
                body.line_end,
                body.raw_artifact_path,
                created_at,
            ),
        )
        row = conn.execute("SELECT * FROM tool_findings WHERE id = ?", (finding_id,)).fetchone()
    assert row is not None
    return ToolFinding(**dict(row))


@router.get("/audit-findings", response_model=list[AuditFinding])
def list_audit_findings(project_id: str, snapshot_id: str | None = None, status: str | None = None):
    with get_conn() as conn:
        get_project_or_404(conn, project_id)
        clauses = ["project_id = ?"]
        params: list[object] = [project_id]
        if snapshot_id:
            clauses.append("snapshot_id = ?")
            params.append(snapshot_id)
        if status:
            clauses.append("status = ?")
            params.append(status)
        rows = conn.execute(
            f"SELECT * FROM audit_findings WHERE {' AND '.join(clauses)} ORDER BY created_at DESC, id",
            params,
        ).fetchall()
    return [AuditFinding(**dict(row)) for row in rows]


@router.post("/audit-findings", response_model=AuditFinding, status_code=201)
def create_audit_finding(project_id: str, body: CreateAuditFindingRequest):
    finding_id = f"finding_{uuid.uuid4().hex[:16]}"
    created_at = utcnow()
    initial_status = "pending_review" if body.severity in ("critical", "high") else "candidate"
    with get_conn() as conn:
        get_project_or_404(conn, project_id)
        _validate_snapshot(conn, project_id, body.snapshot_id)
        conn.execute(
            """
            INSERT INTO audit_findings (
                id, project_id, snapshot_id, title, category, severity, status,
                cwe, file_path, line_start, line_end, description, impact,
                evidence, remediation, discovered_by, created_at
            )
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                finding_id,
                project_id,
                body.snapshot_id,
                body.title,
                body.category,
                body.severity,
                initial_status,
                body.cwe,
                body.file_path,
                body.line_start,
                body.line_end,
                body.description,
                body.impact,
                body.evidence,
                body.remediation,
                body.discovered_by,
                created_at,
            ),
        )
        row = conn.execute("SELECT * FROM audit_findings WHERE id = ?", (finding_id,)).fetchone()
    assert row is not None
    return AuditFinding(**dict(row))


@router.post("/audit-findings/{finding_id}/review", response_model=AuditFinding)
def review_audit_finding(project_id: str, finding_id: str, body: ReviewAuditFindingRequest):
    with get_conn() as conn:
        get_project_or_404(conn, project_id)
        row = conn.execute(
            "SELECT * FROM audit_findings WHERE id = ? AND project_id = ?",
            (finding_id, project_id),
        ).fetchone()
        if row is None:
            raise HTTPException(404, "Audit finding not found")
        if body.reviewer == row["discovered_by"]:
            raise HTTPException(409, "Independent review must be performed by a different worker")
        reviewed_at = utcnow()
        conn.execute(
            """
            UPDATE audit_findings
            SET status = ?, reviewed_by = ?, reviewed_at = ?
            WHERE id = ? AND project_id = ?
            """,
            (body.decision, body.reviewer, reviewed_at, finding_id, project_id),
        )
        _sync_reportable_finding(conn, finding_id)
        updated = conn.execute(
            "SELECT * FROM audit_findings WHERE id = ? AND project_id = ?",
            (finding_id, project_id),
        ).fetchone()
    assert updated is not None
    return AuditFinding(**dict(updated))


def _validate_snapshot(conn, project_id: str, snapshot_id: str) -> None:
    row = conn.execute(
        "SELECT status FROM source_snapshots WHERE id = ? AND project_id = ?",
        (snapshot_id, project_id),
    ).fetchone()
    if row is None:
        raise HTTPException(404, "Source snapshot not found")
    if row["status"] != "ready":
        raise HTTPException(409, "Source snapshot is not ready")


def _sync_reportable_finding(conn, finding_id: str) -> None:
    row = conn.execute("SELECT * FROM audit_findings WHERE id = ?", (finding_id,)).fetchone()
    if row is None:
        return
    if row["status"] != "confirmed" or row["severity"] == "info":
        conn.execute("DELETE FROM vulnerabilities WHERE id = ?", (finding_id,))
        return

    evidence = [value for value in (row["evidence"], row["impact"]) if value]
    source_location = row["file_path"] or ""
    if row["line_start"]:
        source_location += f":{row['line_start']}"
    process = [
        {
            "type": "audit_finding",
            "id": row["id"],
            "description": source_location or row["category"],
            "worker": row["discovered_by"],
        },
        {
            "type": "independent_review",
            "id": row["id"],
            "description": "confirmed",
            "worker": row["reviewed_by"] or "",
        },
    ]
    conn.execute(
        """
        INSERT INTO vulnerabilities (
            id, project_id, fact_id, title, description, severity, discovered_at,
            source_worker, source_fact_ids_json, evidence_json, process_json, status
        )
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'confirmed')
        ON CONFLICT(id) DO UPDATE SET
            title = excluded.title,
            description = excluded.description,
            severity = excluded.severity,
            source_worker = excluded.source_worker,
            evidence_json = excluded.evidence_json,
            process_json = excluded.process_json,
            status = 'confirmed'
        """,
        (
            row["id"],
            row["project_id"],
            row["id"],
            row["title"],
            row["description"],
            row["severity"],
            row["created_at"],
            row["discovered_by"],
            json.dumps([], ensure_ascii=False),
            json.dumps(evidence, ensure_ascii=False),
            json.dumps(process, ensure_ascii=False),
        ),
    )
