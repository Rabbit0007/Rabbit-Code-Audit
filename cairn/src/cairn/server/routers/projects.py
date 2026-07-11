import json

from fastapi import APIRouter, HTTPException

from cairn.server.activity_service import record_audit, record_notification
from cairn.server.db import get_conn
from cairn.server.models import (
    CompleteRequest,
    CreateProjectRequest,
    Fact,
    Hint,
    HeartbeatRequest,
    Intent,
    ProjectDetail,
    ProjectMeta,
    ProjectSummary,
    ReopenRequest,
    ReopenResponse,
    ReasonClaimRequest,
    UpdateProjectTitleRequest,
    UpdateProjectStatusRequest,
)
from cairn.server.services import (
    build_intent_fingerprint,
    build_intents,
    check_project_completed,
    check_project_active,
    clear_project_reason,
    expire_reason_leases,
    expire_workers,
    fact_to_model,
    get_completion_intent_or_409,
    get_project_or_404,
    intent_to_model,
    next_fact_id,
    next_hint_id,
    next_intent_id,
    next_project_id,
    project_meta_from_row,
    project_reason_from_row,
    utcnow,
    validate_facts_exist,
    validate_goal_not_in_sources,
    validate_project_ready_to_complete,
)
from cairn.server.source_service import delete_snapshot_artifacts, list_snapshots

router = APIRouter(tags=["projects"])


@router.get("/projects", response_model=list[ProjectSummary])
def list_projects():
    with get_conn() as conn:
        expire_workers(conn)
        expire_reason_leases(conn)
        rows = conn.execute("""
            SELECT p.*,
                (SELECT COUNT(*) FROM facts WHERE project_id = p.id) AS fact_count,
                (SELECT COUNT(*) FROM intents WHERE project_id = p.id) AS intent_count,
                (SELECT COUNT(*) FROM intents WHERE project_id = p.id AND concluded_at IS NULL AND worker IS NOT NULL AND status = 'claimed') AS working_intent_count,
                (SELECT COUNT(*) FROM intents WHERE project_id = p.id AND concluded_at IS NULL AND worker IS NULL AND status IN ('open', 'cooldown')) AS unclaimed_intent_count,
                (SELECT COUNT(*) FROM hints WHERE project_id = p.id) AS hint_count
            FROM projects p
            ORDER BY p.created_at
        """).fetchall()
        return [
            ProjectSummary(
                id=row["id"],
                title=row["title"],
                status=row["status"],
                created_at=row["created_at"],
                reason=project_reason_from_row(row),
                fact_count=row["fact_count"],
                intent_count=row["intent_count"],
                working_intent_count=row["working_intent_count"],
                unclaimed_intent_count=row["unclaimed_intent_count"],
                hint_count=row["hint_count"],
            )
            for row in rows
        ]


@router.post("/projects", response_model=ProjectDetail, status_code=201)
def create_project(body: CreateProjectRequest):
    with get_conn() as conn:
        pid = next_project_id(conn)
        now = utcnow()

        conn.execute(
            "INSERT INTO projects (id, title, status, created_at) VALUES (?, ?, 'active', ?)",
            (pid, body.title, now),
        )
        conn.execute(
            """
            INSERT INTO facts (
                id, project_id, description, fact_type, source, confidence
            )
            VALUES (?, ?, ?, 'origin', 'user', 1.0)
            """,
            ("origin", pid, body.origin),
        )
        conn.execute(
            """
            INSERT INTO facts (
                id, project_id, description, fact_type, source, confidence
            )
            VALUES (?, ?, ?, 'goal', 'user', 1.0)
            """,
            ("goal", pid, body.goal),
        )

        hints = []
        if body.hints:
            for h in body.hints:
                hid = next_hint_id(conn, pid)
                conn.execute(
                    """
                    INSERT INTO hints (
                        id, project_id, content, creator, created_at,
                        hint_type, target, priority, expires_at, max_uses
                    )
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        hid,
                        pid,
                        h.content,
                        h.creator,
                        now,
                        h.hint_type,
                        h.target,
                        h.priority,
                        h.expires_at,
                        h.max_uses,
                    ),
                )
                hints.append(
                    Hint(
                        id=hid,
                        content=h.content,
                        creator=h.creator,
                        created_at=now,
                        hint_type=h.hint_type,
                        target=h.target,
                        priority=h.priority,
                        expires_at=h.expires_at,
                        max_uses=h.max_uses,
                    )
                )

        record_audit(
            "project.create",
            f"创建项目 {body.title}",
            target_type="project",
            target_id=pid,
            project_id=pid,
            conn=conn,
        )
        record_notification(
            f"新建项目：{body.title}",
            level="info",
            link="#/projects",
            project_id=pid,
            conn=conn,
        )
        return ProjectDetail(
            project=ProjectMeta(id=pid, title=body.title, status="active", created_at=now, reason=None),
            facts=[
                Fact(id="origin", description=body.origin, fact_type="origin", source="user", confidence=1.0),
                Fact(id="goal", description=body.goal, fact_type="goal", source="user", confidence=1.0),
            ],
            intents=[],
            hints=hints,
            sources=[],
        )


@router.get("/projects/{project_id}", response_model=ProjectDetail)
def get_project(project_id: str):
    with get_conn() as conn:
        expire_workers(conn, project_id)
        expire_reason_leases(conn, project_id)
        row = get_project_or_404(conn, project_id)

        facts = conn.execute(
            "SELECT * FROM facts WHERE project_id = ?", (project_id,)
        ).fetchall()
        hints = conn.execute(
            "SELECT * FROM hints WHERE project_id = ? ORDER BY created_at",
            (project_id,),
        ).fetchall()

        return ProjectDetail(
            project=project_meta_from_row(row),
            facts=[fact_to_model(f) for f in facts],
            intents=build_intents(conn, project_id),
            hints=[Hint(**dict(h)) for h in hints],
            sources=list_snapshots(project_id),
        )


@router.delete("/projects/{project_id}", status_code=204)
def delete_project(project_id: str):
    with get_conn() as conn:
        get_project_or_404(conn, project_id)
        snapshot_ids = [
            row["id"]
            for row in conn.execute(
                "SELECT id FROM source_snapshots WHERE project_id = ?",
                (project_id,),
            ).fetchall()
        ]
        conn.execute("DELETE FROM worker_task_history WHERE project_id = ?", (project_id,))
        conn.execute("DELETE FROM model_usage_records WHERE project_id = ?", (project_id,))
        conn.execute("DELETE FROM export_records WHERE project_id = ?", (project_id,))
        conn.execute("DELETE FROM audit_log WHERE project_id = ? OR (target_type = 'project' AND target_id = ?)", (project_id, project_id))
        conn.execute("DELETE FROM notifications WHERE project_id = ?", (project_id,))
        conn.execute("DELETE FROM projects WHERE id = ?", (project_id,))
    delete_snapshot_artifacts(snapshot_ids)
    record_audit("project.delete", "删除项目及其关联数据")
    record_notification("项目及其关联数据已删除", level="warning")


@router.put("/projects/{project_id}/title", response_model=ProjectMeta)
def update_project_title(project_id: str, body: UpdateProjectTitleRequest):
    with get_conn() as conn:
        get_project_or_404(conn, project_id)
        conn.execute(
            "UPDATE projects SET title = ? WHERE id = ?",
            (body.title, project_id),
        )
        updated = conn.execute("SELECT * FROM projects WHERE id = ?", (project_id,)).fetchone()
        meta = project_meta_from_row(updated)
    record_audit("project.rename", f"项目重命名为 {body.title}", target_type="project", target_id=project_id)
    return meta


@router.put("/projects/{project_id}/status", response_model=ProjectMeta)
def update_project_status(project_id: str, body: UpdateProjectStatusRequest):
    with get_conn() as conn:
        expire_reason_leases(conn, project_id)
        row = get_project_or_404(conn, project_id)
        current_status = row["status"]
        if current_status == "completed":
            raise HTTPException(409, "Completed projects cannot change status")
        if current_status == body.status:
            return project_meta_from_row(row)

        pause_reason = body.pause_reason if body.status == "stopped" else None
        conn.execute(
            "UPDATE projects SET status = ?, pause_reason = ? WHERE id = ?",
            (body.status, pause_reason, project_id),
        )
        if body.status == "stopped":
            conn.execute(
                """
                UPDATE intents
                SET worker = NULL,
                    status = CASE WHEN status = 'claimed' THEN 'open' ELSE status END
                WHERE project_id = ? AND concluded_at IS NULL
                """,
                (project_id,),
            )
            clear_project_reason(conn, project_id)
        updated = conn.execute("SELECT * FROM projects WHERE id = ?", (project_id,)).fetchone()
        meta = project_meta_from_row(updated)
    status_label = {"active": "运行中", "stopped": "已停止", "completed": "已完成"}.get(body.status, body.status)
    record_audit("project.status", f"项目 {row['title']} 状态变更为 {status_label}", target_type="project", target_id=project_id)
    return meta


@router.post("/projects/{project_id}/reason/claim", response_model=ProjectMeta)
def claim_project_reason(project_id: str, body: ReasonClaimRequest):
    with get_conn() as conn:
        check_project_active(conn, project_id)
        expire_reason_leases(conn, project_id)
        row = get_project_or_404(conn, project_id)
        current_worker = row["reason_worker"]
        if current_worker is not None and current_worker != body.worker:
            raise HTTPException(409, f"Project reason is currently claimed by {current_worker}")
        if current_worker == body.worker:
            return project_meta_from_row(row)

        now = utcnow()
        updated_count = conn.execute(
            """
            UPDATE projects
            SET reason_worker = ?,
                reason_trigger = ?,
                reason_started_at = ?,
                reason_last_heartbeat_at = ?
            WHERE id = ?
              AND status = 'active'
              AND reason_worker IS NULL
            """,
            (body.worker, body.trigger, now, now, project_id),
        ).rowcount
        updated = conn.execute("SELECT * FROM projects WHERE id = ?", (project_id,)).fetchone()
        if updated_count != 1:
            if updated is None:
                raise HTTPException(404, "Project not found")
            current_worker = updated["reason_worker"]
            if current_worker == body.worker:
                return project_meta_from_row(updated)
            if current_worker is not None:
                raise HTTPException(409, f"Project reason is currently claimed by {current_worker}")
            raise HTTPException(409, "Project reason claim was updated by another worker")
        return project_meta_from_row(updated)


@router.post("/projects/{project_id}/reason/heartbeat", response_model=ProjectMeta)
def heartbeat_project_reason(project_id: str, body: HeartbeatRequest):
    with get_conn() as conn:
        check_project_active(conn, project_id)
        expire_reason_leases(conn, project_id)
        row = get_project_or_404(conn, project_id)
        current_worker = row["reason_worker"]
        if current_worker is None:
            raise HTTPException(409, "Project reason is not currently claimed")
        if current_worker != body.worker:
            raise HTTPException(409, f"Project reason is currently claimed by {current_worker}")

        now = utcnow()
        conn.execute(
            "UPDATE projects SET reason_last_heartbeat_at = ? WHERE id = ?",
            (now, project_id),
        )
        updated = conn.execute("SELECT * FROM projects WHERE id = ?", (project_id,)).fetchone()
        return project_meta_from_row(updated)


@router.post("/projects/{project_id}/reason/release", response_model=ProjectMeta)
def release_project_reason(project_id: str, body: HeartbeatRequest):
    with get_conn() as conn:
        check_project_active(conn, project_id)
        expire_reason_leases(conn, project_id)
        row = get_project_or_404(conn, project_id)
        current_worker = row["reason_worker"]
        if current_worker is None:
            return project_meta_from_row(row)
        if current_worker != body.worker:
            raise HTTPException(409, f"Project reason is currently claimed by {current_worker}")

        clear_project_reason(conn, project_id)
        updated = conn.execute("SELECT * FROM projects WHERE id = ?", (project_id,)).fetchone()
        return project_meta_from_row(updated)


@router.post("/projects/{project_id}/complete", response_model=Intent)
def complete_project(project_id: str, body: CompleteRequest):
    with get_conn() as conn:
        check_project_active(conn, project_id)
        expire_reason_leases(conn, project_id)
        validate_facts_exist(conn, project_id, body.from_)
        validate_goal_not_in_sources(body.from_)
        validate_project_ready_to_complete(conn, project_id)

        now = utcnow()
        iid = next_intent_id(conn, project_id)
        fingerprint = build_intent_fingerprint(
            body.from_,
            body.description,
            target_kind="project",
            target_id="goal",
            objective="complete",
        )

        conn.execute(
            """
            INSERT INTO intents (
                id, project_id, to_fact_id, description, creator, worker,
                last_heartbeat_at, created_at, concluded_at, fingerprint, status,
                target_kind, target_id, objective
            )
            VALUES (?, ?, 'goal', ?, ?, ?, ?, ?, ?, ?, 'completed', 'project', 'goal', 'complete')
            """,
            (
                iid,
                project_id,
                body.description,
                body.worker,
                body.worker,
                now,
                now,
                now,
                fingerprint,
            ),
        )
        for fid in body.from_:
            conn.execute(
                "INSERT INTO intent_sources (intent_id, project_id, fact_id) VALUES (?, ?, ?)",
                (iid, project_id, fid),
            )
        conn.execute(
            """
            UPDATE projects
            SET status = 'completed',
                reason_worker = NULL,
                reason_trigger = NULL,
                reason_started_at = NULL,
                reason_last_heartbeat_at = NULL
            WHERE id = ?
            """,
            (project_id,),
        )
        completed_intent = conn.execute(
            "SELECT * FROM intents WHERE id = ? AND project_id = ?",
            (iid, project_id),
        ).fetchone()
        assert completed_intent is not None
        return intent_to_model(conn, completed_intent, project_id)


@router.post("/projects/{project_id}/reopen", response_model=ReopenResponse)
def reopen_project(project_id: str, body: ReopenRequest):
    with get_conn() as conn:
        expire_reason_leases(conn, project_id)
        check_project_completed(conn, project_id)
        completion = get_completion_intent_or_409(conn, project_id)

        source_rows = conn.execute(
            "SELECT fact_id FROM intent_sources WHERE intent_id = ? AND project_id = ? ORDER BY rowid",
            (completion["id"], project_id),
        ).fetchall()
        source_ids = [row["fact_id"] for row in source_rows]
        if not source_ids:
            raise HTTPException(409, "Completion intent is missing its source facts")

        now = utcnow()
        fact_id = next_fact_id(conn, project_id)
        intent_id = next_intent_id(conn, project_id)
        description = body.description
        creator = body.creator

        conn.execute(
            "DELETE FROM intents WHERE id = ? AND project_id = ?",
            (completion["id"], project_id),
        )
        conn.execute(
            """
            INSERT INTO facts (
                id, project_id, description, fact_type, source, confidence,
                parent_fact_ids_json
            )
            VALUES (?, ?, ?, 'feedback', ?, 0.9, ?)
            """,
            (
                fact_id,
                project_id,
                description,
                creator,
                json.dumps(source_ids, ensure_ascii=False),
            ),
        )
        fingerprint = build_intent_fingerprint(
            source_ids,
            "external_feedback",
            target_kind="fact",
            target_id=fact_id,
            objective="reopen",
        )
        conn.execute(
            """
            INSERT INTO intents (
                id, project_id, to_fact_id, description, creator, worker,
                last_heartbeat_at, created_at, concluded_at, fingerprint, status,
                target_kind, target_id, objective
            )
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'completed', 'fact', ?, 'reopen')
            """,
            (
                intent_id,
                project_id,
                fact_id,
                "external_feedback",
                creator,
                creator,
                now,
                now,
                now,
                fingerprint,
                fact_id,
            ),
        )
        for source_id in source_ids:
            conn.execute(
                "INSERT INTO intent_sources (intent_id, project_id, fact_id) VALUES (?, ?, ?)",
                (intent_id, project_id, source_id),
            )
        clear_project_reason(conn, project_id)
        conn.execute(
            "UPDATE projects SET status = 'active' WHERE id = ?",
            (project_id,),
        )
        updated_project = conn.execute("SELECT * FROM projects WHERE id = ?", (project_id,)).fetchone()
        updated_intent = conn.execute(
            "SELECT * FROM intents WHERE id = ? AND project_id = ?",
            (intent_id, project_id),
        ).fetchone()
        assert updated_project is not None
        assert updated_intent is not None
        return ReopenResponse(
            project=project_meta_from_row(updated_project),
            fact=Fact(
                id=fact_id,
                description=description,
                fact_type="feedback",
                source=creator,
                confidence=0.9,
                parent_fact_ids=source_ids,
            ),
            intent=intent_to_model(conn, updated_intent, project_id),
        )
