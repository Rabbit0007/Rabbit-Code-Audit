from __future__ import annotations

import json
import uuid

from fastapi import APIRouter, HTTPException

from cairn.server.business_models import (
    BusinessEdge,
    BusinessGraph,
    BusinessNode,
    BusinessNodeConclusion,
    CreateBusinessEdgeRequest,
    CreateBusinessNodeRequest,
    CreateBusinessNodeConclusionRequest,
    UpdateBusinessNodeRequest,
)
from cairn.server.db import get_conn
from cairn.server.services import get_project_or_404, utcnow


router = APIRouter(prefix="/api/projects/{project_id}/business-graph", tags=["business-graph"])


@router.get("", response_model=BusinessGraph)
def get_business_graph(project_id: str) -> BusinessGraph:
    with get_conn() as conn:
        get_project_or_404(conn, project_id)
        nodes = conn.execute(
            "SELECT * FROM business_nodes WHERE project_id = ? ORDER BY created_at, id",
            (project_id,),
        ).fetchall()
        edges = conn.execute(
            "SELECT * FROM business_edges WHERE project_id = ? ORDER BY created_at, id",
            (project_id,),
        ).fetchall()
    return BusinessGraph(
        nodes=[_node_from_row(row) for row in nodes],
        edges=[_edge_from_row(row) for row in edges],
    )


@router.get("/conclusions", response_model=list[BusinessNodeConclusion])
def list_business_node_conclusions(
    project_id: str,
    business_node_id: str | None = None,
) -> list[BusinessNodeConclusion]:
    with get_conn() as conn:
        get_project_or_404(conn, project_id)
        clauses = ["project_id = ?"]
        params: list[object] = [project_id]
        if business_node_id:
            _validate_business_node(conn, project_id, business_node_id)
            clauses.append("business_node_id = ?")
            params.append(business_node_id)
        rows = conn.execute(
            f"""
            SELECT *
            FROM business_node_conclusions
            WHERE {' AND '.join(clauses)}
            ORDER BY created_at DESC, rowid DESC
            """,
            params,
        ).fetchall()
    return [_conclusion_from_row(row) for row in rows]


@router.get("/nodes/{node_id}/conclusions", response_model=list[BusinessNodeConclusion])
def list_node_conclusions(project_id: str, node_id: str) -> list[BusinessNodeConclusion]:
    with get_conn() as conn:
        get_project_or_404(conn, project_id)
        _validate_business_node(conn, project_id, node_id)
        rows = conn.execute(
            """
            SELECT *
            FROM business_node_conclusions
            WHERE project_id = ? AND business_node_id = ?
            ORDER BY created_at DESC, rowid DESC
            """,
            (project_id, node_id),
        ).fetchall()
    return [_conclusion_from_row(row) for row in rows]


@router.post("/conclusions", response_model=BusinessNodeConclusion, status_code=201)
def create_business_node_conclusion(
    project_id: str,
    body: CreateBusinessNodeConclusionRequest,
) -> BusinessNodeConclusion:
    conclusion_id = f"biz_conclusion_{uuid.uuid4().hex[:16]}"
    now = utcnow()
    with get_conn() as conn:
        get_project_or_404(conn, project_id)
        _validate_business_node(conn, project_id, body.business_node_id)
        _validate_conclusion_finding(conn, project_id, body)
        conn.execute(
            """
            INSERT INTO business_node_conclusions (
                id, project_id, business_node_id, conclusion, summary, evidence,
                audit_finding_id, created_by, created_at
            )
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                conclusion_id,
                project_id,
                body.business_node_id,
                body.conclusion,
                body.summary,
                body.evidence,
                body.audit_finding_id,
                body.created_by,
                now,
            ),
        )
        row = conn.execute(
            "SELECT * FROM business_node_conclusions WHERE id = ?",
            (conclusion_id,),
        ).fetchone()
    assert row is not None
    return _conclusion_from_row(row)


@router.post("/nodes", response_model=BusinessNode, status_code=201)
def create_business_node(project_id: str, body: CreateBusinessNodeRequest) -> BusinessNode:
    node_id = f"biz_{uuid.uuid4().hex[:16]}"
    now = utcnow()
    with get_conn() as conn:
        get_project_or_404(conn, project_id)
        conn.execute(
            """
            INSERT INTO business_nodes (
                id, project_id, node_type, title, description, risk_level,
                review_status, coverage_note, last_intent_id, risk_tags_json,
                evidence_json, created_by, created_at, updated_at
            )
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                node_id,
                project_id,
                body.node_type,
                body.title,
                body.description,
                body.risk_level,
                body.review_status,
                body.coverage_note,
                body.last_intent_id,
                json.dumps(body.risk_tags, ensure_ascii=False),
                json.dumps(body.evidence, ensure_ascii=False),
                body.created_by,
                now,
                now,
            ),
        )
        row = conn.execute("SELECT * FROM business_nodes WHERE id = ?", (node_id,)).fetchone()
    assert row is not None
    return _node_from_row(row)


@router.put("/nodes/{node_id}", response_model=BusinessNode)
def update_business_node(project_id: str, node_id: str, body: UpdateBusinessNodeRequest) -> BusinessNode:
    updates: list[str] = []
    params: list[object] = []
    for field, column in (
        ("node_type", "node_type"),
        ("title", "title"),
        ("risk_level", "risk_level"),
        ("review_status", "review_status"),
    ):
        value = getattr(body, field)
        if value is not None:
            updates.append(f"{column} = ?")
            params.append(value)
    for field, column in (
        ("description", "description"),
        ("coverage_note", "coverage_note"),
        ("last_intent_id", "last_intent_id"),
    ):
        if field in body.model_fields_set:
            updates.append(f"{column} = ?")
            params.append(getattr(body, field))
    if body.risk_tags is not None:
        updates.append("risk_tags_json = ?")
        params.append(json.dumps(body.risk_tags, ensure_ascii=False))
    if body.evidence is not None:
        updates.append("evidence_json = ?")
        params.append(json.dumps(body.evidence, ensure_ascii=False))
    if not updates:
        return _get_node_or_404(project_id, node_id)

    updates.append("updated_at = ?")
    params.append(utcnow())
    params.extend([node_id, project_id])

    with get_conn() as conn:
        get_project_or_404(conn, project_id)
        existing = conn.execute(
            "SELECT id FROM business_nodes WHERE id = ? AND project_id = ?",
            (node_id, project_id),
        ).fetchone()
        if existing is None:
            raise HTTPException(404, "Business node not found")
        conn.execute(
            f"UPDATE business_nodes SET {', '.join(updates)} WHERE id = ? AND project_id = ?",
            params,
        )
        row = conn.execute(
            "SELECT * FROM business_nodes WHERE id = ? AND project_id = ?",
            (node_id, project_id),
        ).fetchone()
    assert row is not None
    return _node_from_row(row)


@router.delete("/nodes/{node_id}", status_code=204)
def delete_business_node(project_id: str, node_id: str) -> None:
    with get_conn() as conn:
        get_project_or_404(conn, project_id)
        result = conn.execute(
            "DELETE FROM business_nodes WHERE id = ? AND project_id = ?",
            (node_id, project_id),
        )
        if result.rowcount == 0:
            raise HTTPException(404, "Business node not found")


@router.post("/edges", response_model=BusinessEdge, status_code=201)
def create_business_edge(project_id: str, body: CreateBusinessEdgeRequest) -> BusinessEdge:
    edge_id = f"biz_edge_{uuid.uuid4().hex[:16]}"
    now = utcnow()
    with get_conn() as conn:
        get_project_or_404(conn, project_id)
        _validate_edge_nodes(conn, project_id, body.from_node_id, body.to_node_id)
        conn.execute(
            """
            INSERT INTO business_edges (
                id, project_id, from_node_id, to_node_id, relation,
                description, created_by, created_at
            )
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                edge_id,
                project_id,
                body.from_node_id,
                body.to_node_id,
                body.relation,
                body.description,
                body.created_by,
                now,
            ),
        )
        row = conn.execute("SELECT * FROM business_edges WHERE id = ?", (edge_id,)).fetchone()
    assert row is not None
    return _edge_from_row(row)


@router.delete("/edges/{edge_id}", status_code=204)
def delete_business_edge(project_id: str, edge_id: str) -> None:
    with get_conn() as conn:
        get_project_or_404(conn, project_id)
        result = conn.execute(
            "DELETE FROM business_edges WHERE id = ? AND project_id = ?",
            (edge_id, project_id),
        )
        if result.rowcount == 0:
            raise HTTPException(404, "Business edge not found")


def _get_node_or_404(project_id: str, node_id: str) -> BusinessNode:
    with get_conn() as conn:
        get_project_or_404(conn, project_id)
        row = conn.execute(
            "SELECT * FROM business_nodes WHERE id = ? AND project_id = ?",
            (node_id, project_id),
        ).fetchone()
    if row is None:
        raise HTTPException(404, "Business node not found")
    return _node_from_row(row)


def _validate_business_node(conn, project_id: str, node_id: str) -> None:
    row = conn.execute(
        "SELECT id FROM business_nodes WHERE id = ? AND project_id = ?",
        (node_id, project_id),
    ).fetchone()
    if row is None:
        raise HTTPException(404, "Business node not found")


def _validate_edge_nodes(conn, project_id: str, from_node_id: str, to_node_id: str) -> None:
    rows = conn.execute(
        """
        SELECT id
        FROM business_nodes
        WHERE project_id = ? AND id IN (?, ?)
        """,
        (project_id, from_node_id, to_node_id),
    ).fetchall()
    if {row["id"] for row in rows} != {from_node_id, to_node_id}:
        raise HTTPException(404, "Business edge endpoints must belong to this project")


def _validate_conclusion_finding(
    conn,
    project_id: str,
    body: CreateBusinessNodeConclusionRequest,
) -> None:
    if not body.audit_finding_id:
        return
    row = conn.execute(
        """
        SELECT id, status, business_node_id
        FROM audit_findings
        WHERE id = ? AND project_id = ?
        """,
        (body.audit_finding_id, project_id),
    ).fetchone()
    if row is None:
        raise HTTPException(404, "Audit finding not found")
    if row["business_node_id"] != body.business_node_id:
        raise HTTPException(422, "Audit finding must reference the same business node")
    if body.conclusion == "confirmed_finding" and row["status"] != "confirmed":
        raise HTTPException(409, "Confirmed business conclusion requires a confirmed audit finding")


def _decode_json_list(raw: str | None) -> list[str]:
    if not raw:
        return []
    try:
        value = json.loads(raw)
    except json.JSONDecodeError:
        return []
    if not isinstance(value, list):
        return []
    return [str(item) for item in value if str(item).strip()]


def _node_from_row(row) -> BusinessNode:
    return BusinessNode(
        id=row["id"],
        project_id=row["project_id"],
        node_type=row["node_type"],
        title=row["title"],
        description=row["description"],
        risk_level=row["risk_level"],
        review_status=row["review_status"],
        coverage_note=row["coverage_note"],
        last_intent_id=row["last_intent_id"],
        risk_tags=_decode_json_list(row["risk_tags_json"]),
        evidence=_decode_json_list(row["evidence_json"]),
        created_by=row["created_by"],
        created_at=row["created_at"],
        updated_at=row["updated_at"],
    )


def _edge_from_row(row) -> BusinessEdge:
    return BusinessEdge(
        id=row["id"],
        project_id=row["project_id"],
        from_node_id=row["from_node_id"],
        to_node_id=row["to_node_id"],
        relation=row["relation"],
        description=row["description"],
        created_by=row["created_by"],
        created_at=row["created_at"],
    )


def _conclusion_from_row(row) -> BusinessNodeConclusion:
    return BusinessNodeConclusion(
        id=row["id"],
        project_id=row["project_id"],
        business_node_id=row["business_node_id"],
        conclusion=row["conclusion"],
        summary=row["summary"],
        evidence=row["evidence"],
        audit_finding_id=row["audit_finding_id"],
        created_by=row["created_by"],
        created_at=row["created_at"],
    )
