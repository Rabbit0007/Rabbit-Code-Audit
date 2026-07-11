import json
import sqlite3

from fastapi import APIRouter, HTTPException

from cairn.server.db import get_conn
from cairn.server.business_graph_service import validate_model_evidence_refs
from cairn.server.models import (
    ConcludeRequest,
    ConcludeResponse,
    CreateIntentRequest,
    HeartbeatRequest,
    Intent,
    SupersedeIntentRequest,
)
from cairn.server.services import (
    build_intent_fingerprint,
    check_project_active,
    fact_to_model,
    get_project_or_404,
    get_equivalent_open_intent,
    get_claimable_open_intent_or_404,
    get_releasable_open_intent_or_404,
    intent_to_model,
    next_fact_id,
    next_intent_id,
    utcnow,
    validate_facts_exist,
    validate_intent_creator_worker,
    validate_goal_not_in_sources,
)
router = APIRouter(tags=["intents"])


@router.post(
    "/projects/{project_id}/intents",
    response_model=Intent,
    status_code=201,
)
def create_intent(project_id: str, body: CreateIntentRequest):
    with get_conn() as conn:
        check_project_active(conn, project_id)
        validate_facts_exist(conn, project_id, body.from_)
        validate_goal_not_in_sources(body.from_)
        validate_intent_creator_worker(body.creator, body.worker)

        fingerprint = build_intent_fingerprint(
            body.from_,
            body.description,
            target_kind=body.target_kind,
            target_id=body.target_id,
            objective=body.objective,
            evidence_gap=body.evidence_gap,
        )
        existing = get_equivalent_open_intent(conn, project_id, fingerprint)
        if existing is not None:
            if (
                body.worker is not None
                and existing["worker"] is None
                and existing["status"] == "open"
            ):
                now = utcnow()
                conn.execute(
                    """
                    UPDATE intents
                    SET worker = ?, last_heartbeat_at = ?, status = 'claimed'
                    WHERE id = ? AND project_id = ? AND worker IS NULL AND to_fact_id IS NULL
                    """,
                    (body.worker, now, existing["id"], project_id),
                )
                existing = conn.execute(
                    "SELECT * FROM intents WHERE id = ? AND project_id = ?",
                    (existing["id"], project_id),
                ).fetchone()
            return intent_to_model(conn, existing, project_id)

        now = utcnow()
        iid = next_intent_id(conn, project_id)
        claimed = body.worker is not None
        try:
            conn.execute(
                """
                INSERT INTO intents (
                    id, project_id, to_fact_id, description, creator, worker,
                    last_heartbeat_at, created_at, concluded_at, fingerprint, status,
                    target_kind, target_id, objective, evidence_gap
                )
                VALUES (?, ?, NULL, ?, ?, ?, ?, ?, NULL, ?, ?, ?, ?, ?, ?)
                """,
                (
                    iid,
                    project_id,
                    body.description,
                    body.creator,
                    body.worker,
                    now if claimed else None,
                    now,
                    fingerprint,
                    "claimed" if claimed else "open",
                    body.target_kind,
                    body.target_id,
                    body.objective,
                    body.evidence_gap,
                ),
            )
        except sqlite3.IntegrityError:
            existing = get_equivalent_open_intent(conn, project_id, fingerprint)
            if existing is None:
                raise
            return intent_to_model(conn, existing, project_id)
        for fid in body.from_:
            conn.execute(
                "INSERT INTO intent_sources (intent_id, project_id, fact_id) VALUES (?, ?, ?)",
                (iid, project_id, fid),
            )

        created = conn.execute(
            "SELECT * FROM intents WHERE id = ? AND project_id = ?",
            (iid, project_id),
        ).fetchone()
        assert created is not None
        return intent_to_model(conn, created, project_id)


@router.post(
    "/projects/{project_id}/intents/{intent_id}/heartbeat",
    response_model=Intent,
)
def heartbeat(project_id: str, intent_id: str, body: HeartbeatRequest):
    with get_conn() as conn:
        check_project_active(conn, project_id)
        get_claimable_open_intent_or_404(conn, project_id, intent_id, body.worker)

        now = utcnow()
        updated_count = conn.execute(
            """
            UPDATE intents
            SET worker = ?, last_heartbeat_at = ?, status = 'claimed'
            WHERE id = ?
              AND project_id = ?
              AND to_fact_id IS NULL
              AND (worker IS NULL OR worker = ?)
            """,
            (body.worker, now, intent_id, project_id, body.worker),
        ).rowcount

        updated = conn.execute(
            "SELECT * FROM intents WHERE id = ? AND project_id = ?",
            (intent_id, project_id),
        ).fetchone()
        if updated_count != 1:
            if updated is None:
                raise HTTPException(404, "Intent not found")
            if updated["to_fact_id"] is not None:
                raise HTTPException(409, "Intent already concluded")
            if updated["worker"] is not None and updated["worker"] != body.worker:
                raise HTTPException(409, f"Intent is currently claimed by {updated['worker']}")
            raise HTTPException(409, "Intent claim was updated by another worker")
        return intent_to_model(conn, updated, project_id)


@router.post(
    "/projects/{project_id}/intents/{intent_id}/release",
    response_model=Intent,
)
def release(project_id: str, intent_id: str, body: HeartbeatRequest):
    with get_conn() as conn:
        check_project_active(conn, project_id)
        row = get_releasable_open_intent_or_404(conn, project_id, intent_id, body.worker)

        if row["worker"] == body.worker:
            conn.execute(
                "UPDATE intents SET worker = NULL, status = 'open' WHERE id = ? AND project_id = ?",
                (intent_id, project_id),
            )
            row = conn.execute(
                "SELECT * FROM intents WHERE id = ? AND project_id = ?",
                (intent_id, project_id),
            ).fetchone()

        return intent_to_model(conn, row, project_id)


@router.post(
    "/projects/{project_id}/intents/{intent_id}/supersede",
    response_model=Intent,
)
def supersede_intent(project_id: str, intent_id: str, body: SupersedeIntentRequest):
    with get_conn() as conn:
        get_project_or_404(conn, project_id)
        row = conn.execute(
            "SELECT * FROM intents WHERE id = ? AND project_id = ?",
            (intent_id, project_id),
        ).fetchone()
        if row is None:
            raise HTTPException(404, "Intent not found")
        if row["to_fact_id"] is not None:
            raise HTTPException(409, "Intent already concluded")
        if row["worker"] is not None:
            raise HTTPException(409, "Claimed intent cannot be superseded")
        if row["status"] != "superseded":
            conn.execute(
                """
                UPDATE intents
                SET status = 'superseded', superseded_by = ?, worker = NULL
                WHERE id = ? AND project_id = ? AND to_fact_id IS NULL
                """,
                (body.superseded_by, intent_id, project_id),
            )
            row = conn.execute(
                "SELECT * FROM intents WHERE id = ? AND project_id = ?",
                (intent_id, project_id),
            ).fetchone()
        return intent_to_model(conn, row, project_id)


@router.post(
    "/projects/{project_id}/intents/{intent_id}/conclude",
    response_model=ConcludeResponse,
)
def conclude(project_id: str, intent_id: str, body: ConcludeRequest):
    with get_conn() as conn:
        check_project_active(conn, project_id)
        get_claimable_open_intent_or_404(conn, project_id, intent_id, body.worker)

        now = utcnow()
        fid = next_fact_id(conn, project_id)
        source_rows = conn.execute(
            "SELECT fact_id FROM intent_sources WHERE intent_id = ? AND project_id = ? ORDER BY rowid",
            (intent_id, project_id),
        ).fetchall()
        source_ids = [row["fact_id"] for row in source_rows]
        snapshot = conn.execute(
            """
            SELECT id FROM source_snapshots
            WHERE project_id = ? AND status = 'ready'
            ORDER BY created_at DESC, id DESC
            LIMIT 1
            """,
            (project_id,),
        ).fetchone()
        evidence_refs = validate_model_evidence_refs(
            conn,
            snapshot["id"] if snapshot is not None else None,
            body.evidence_refs,
        )

        updated_count = conn.execute(
            """
            UPDATE intents
            SET to_fact_id = ?,
                worker = ?,
                last_heartbeat_at = ?,
                concluded_at = ?,
                status = 'completed'
            WHERE id = ?
              AND project_id = ?
              AND to_fact_id IS NULL
              AND (worker IS NULL OR worker = ?)
            """,
            (fid, body.worker, now, now, intent_id, project_id, body.worker),
        ).rowcount
        if updated_count != 1:
            updated = conn.execute(
                "SELECT * FROM intents WHERE id = ? AND project_id = ?",
                (intent_id, project_id),
            ).fetchone()
            if updated is None:
                raise HTTPException(404, "Intent not found")
            if updated["to_fact_id"] is not None:
                raise HTTPException(409, "Intent already concluded")
            if updated["worker"] is not None and updated["worker"] != body.worker:
                raise HTTPException(409, f"Intent is currently claimed by {updated['worker']}")
            raise HTTPException(409, "Intent conclude was updated by another worker")
        conn.execute(
            """
            INSERT INTO facts (
                id, project_id, description, fact_type, source, confidence,
                evidence_refs_json, parent_fact_ids_json
            )
            VALUES (?, ?, ?, 'observation', ?, 0.7, ?, ?)
            """,
            (
                fid,
                project_id,
                body.description,
                body.worker,
                json.dumps(evidence_refs, ensure_ascii=False),
                json.dumps(source_ids, ensure_ascii=False),
            ),
        )

        updated = conn.execute(
            "SELECT * FROM intents WHERE id = ? AND project_id = ?",
            (intent_id, project_id),
        ).fetchone()
        fact = conn.execute(
            "SELECT * FROM facts WHERE id = ? AND project_id = ?",
            (fid, project_id),
        ).fetchone()
        assert fact is not None
        return ConcludeResponse(
            fact=fact_to_model(fact),
            intent=intent_to_model(conn, updated, project_id),
        )
