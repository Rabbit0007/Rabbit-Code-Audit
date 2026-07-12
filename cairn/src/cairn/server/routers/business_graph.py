from __future__ import annotations

import json
import re
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
from cairn.server.business_graph_service import (
    calibrated_model_confidence,
    reconcile_project_business_graph,
    sync_semantic_evidence_edges,
    validate_model_evidence_refs,
)
from cairn.server.db import get_conn
from cairn.server.services import (
    activate_business_node_conclusion,
    get_project_or_404,
    sync_business_node_coverage_from_conclusion,
    utcnow,
)


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


@router.post("/reconcile")
def reconcile_business_graph(project_id: str) -> dict[str, int]:
    now = utcnow()
    with get_conn() as conn:
        get_project_or_404(conn, project_id)
        snapshot_id = _source_snapshot_id(conn, project_id, None)
        return reconcile_project_business_graph(
            conn,
            project_id,
            snapshot_id,
            now=now,
        )


@router.get("/conclusions", response_model=list[BusinessNodeConclusion])
def list_business_node_conclusions(
    project_id: str,
    business_node_id: str | None = None,
    include_history: bool = False,
) -> list[BusinessNodeConclusion]:
    with get_conn() as conn:
        get_project_or_404(conn, project_id)
        clauses = ["project_id = ?"]
        params: list[object] = [project_id]
        if business_node_id:
            _validate_business_node(conn, project_id, business_node_id)
            clauses.append("business_node_id = ?")
            params.append(business_node_id)
        if not include_history:
            clauses.append("is_current = 1")
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
            WHERE project_id = ? AND business_node_id = ? AND is_current = 1
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
                audit_finding_id, is_current, created_by, created_at
            )
            VALUES (?, ?, ?, ?, ?, ?, ?, 0, ?, ?)
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
        is_current = activate_business_node_conclusion(
            conn,
            project_id,
            body.business_node_id,
            conclusion_id,
            body.conclusion,
            now=now,
        )
        if is_current:
            sync_business_node_coverage_from_conclusion(
                conn,
                project_id,
                body.business_node_id,
                body.conclusion,
                body.summary,
                body.evidence,
                now=now,
            )
        if body.evidence or body.audit_finding_id:
            conn.execute(
                """
                UPDATE business_nodes
                SET evidence_status = 'source_backed', revision = revision + 1,
                    updated_at = ?
                WHERE id = ? AND project_id = ?
                """,
                (now, body.business_node_id, project_id),
            )
        row = conn.execute(
            "SELECT * FROM business_node_conclusions WHERE id = ?",
            (conclusion_id,),
        ).fetchone()
    assert row is not None
    return _conclusion_from_row(row)


@router.post("/nodes", response_model=BusinessNode, status_code=201)
def create_business_node(project_id: str, body: CreateBusinessNodeRequest) -> BusinessNode:
    now = utcnow()
    with get_conn() as conn:
        get_project_or_404(conn, project_id)
        source_kind = _source_kind(body.created_by)
        graph_layer = _node_graph_layer(body.node_type, body.graph_layer, source_kind)
        source_snapshot_id = _source_snapshot_id(conn, project_id, body.source_snapshot_id)
        evidence = _validated_evidence_refs(
            conn,
            source_snapshot_id,
            body.evidence,
            source_kind,
        )
        evidence_status = _evidence_status(evidence, source_kind)
        confidence = _calibrated_confidence(body.confidence, evidence, source_kind)
        review_status = _review_status_for_evidence(
            body.review_status,
            evidence_status,
            source_kind,
        )
        semantic_key = _semantic_key(body.semantic_key, body.node_type, body.title)
        existing = conn.execute(
            "SELECT * FROM business_nodes WHERE project_id = ? AND semantic_key = ?",
            (project_id, semantic_key),
        ).fetchone()
        if existing is not None:
            risk_tags = _merge_string_lists(
                _decode_json_list(existing["risk_tags_json"]),
                body.risk_tags,
            )
            evidence = _merge_string_lists(
                _decode_json_list(existing["evidence_json"]),
                evidence,
            )
            contributors = _merge_string_lists(
                _decode_json_list(existing["contributors_json"]),
                [existing["created_by"], body.created_by],
            )
            merged_source_kind = _merged_source_kind(existing["source_kind"], source_kind)
            merged_evidence_status = _stronger_evidence_status(
                existing["evidence_status"],
                evidence_status,
            )
            merged_review_status = _review_status_for_evidence(
                _more_complete_review(existing["review_status"], review_status),
                merged_evidence_status,
                merged_source_kind,
            )
            conn.execute(
                """
                UPDATE business_nodes
                SET description = ?, risk_level = ?, review_status = ?,
                    coverage_note = ?, last_intent_id = ?, risk_tags_json = ?,
                    evidence_json = ?, source_snapshot_id = ?, confidence = ?,
                    graph_layer = ?, source_kind = ?, evidence_status = ?,
                    contributors_json = ?, revision = revision + 1, updated_at = ?
                WHERE id = ? AND project_id = ?
                """,
                (
                    _richer_text(existing["description"], body.description),
                    _higher_risk(existing["risk_level"], body.risk_level),
                    merged_review_status,
                    _richer_text(existing["coverage_note"], body.coverage_note),
                    body.last_intent_id or existing["last_intent_id"],
                    json.dumps(risk_tags, ensure_ascii=False),
                    json.dumps(evidence, ensure_ascii=False),
                    existing["source_snapshot_id"] or source_snapshot_id,
                    _calibrated_confidence(
                        max(float(existing["confidence"] or 0), body.confidence),
                        evidence,
                        source_kind,
                    ),
                    _higher_layer(existing["graph_layer"], graph_layer),
                    merged_source_kind,
                    merged_evidence_status,
                    json.dumps(contributors, ensure_ascii=False),
                    now,
                    existing["id"],
                    project_id,
                ),
            )
            if source_kind == "model":
                sync_semantic_evidence_edges(
                    conn,
                    project_id,
                    existing["id"],
                    existing["source_snapshot_id"] or source_snapshot_id,
                    evidence,
                    now=now,
                )
            row = conn.execute("SELECT * FROM business_nodes WHERE id = ?", (existing["id"],)).fetchone()
            assert row is not None
            return _node_from_row(row)

        node_id = f"biz_{uuid.uuid4().hex[:16]}"
        conn.execute(
            """
            INSERT INTO business_nodes (
                id, project_id, node_type, title, description, risk_level,
                review_status, coverage_note, last_intent_id, risk_tags_json,
                evidence_json, source_snapshot_id, confidence, semantic_key,
                graph_layer, source_kind, evidence_status, contributors_json,
                revision, created_by, created_at, updated_at
            )
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 1, ?, ?, ?)
            """,
            (
                node_id,
                project_id,
                body.node_type,
                body.title,
                body.description,
                body.risk_level,
                review_status,
                body.coverage_note,
                body.last_intent_id,
                json.dumps(body.risk_tags, ensure_ascii=False),
                json.dumps(evidence, ensure_ascii=False),
                source_snapshot_id,
                confidence,
                semantic_key,
                graph_layer,
                source_kind,
                evidence_status,
                json.dumps([body.created_by], ensure_ascii=False),
                body.created_by,
                now,
                now,
            ),
        )
        if source_kind == "model":
            sync_semantic_evidence_edges(
                conn,
                project_id,
                node_id,
                source_snapshot_id,
                evidence,
                now=now,
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
        if body.evidence:
            updates.append("evidence_status = 'source_backed'")
    if not updates:
        return _get_node_or_404(project_id, node_id)

    updates.append("updated_at = ?")
    params.append(utcnow())
    updates.append("revision = revision + 1")
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
    now = utcnow()
    with get_conn() as conn:
        get_project_or_404(conn, project_id)
        _validate_edge_nodes(conn, project_id, body.from_node_id, body.to_node_id)
        source_kind = _source_kind(body.created_by)
        graph_layer = "audit" if body.relation == "risk_of" else body.graph_layer
        confidence = min(body.confidence, 0.94) if source_kind == "model" else body.confidence
        existing = conn.execute(
            """
            SELECT * FROM business_edges
            WHERE project_id = ? AND from_node_id = ? AND to_node_id = ? AND relation = ?
            """,
            (project_id, body.from_node_id, body.to_node_id, body.relation),
        ).fetchone()
        if existing is not None:
            contributors = _merge_string_lists(
                _decode_json_list(existing["contributors_json"]),
                [existing["created_by"], body.created_by],
            )
            conn.execute(
                """
                UPDATE business_edges
                SET description = ?, confidence = ?, graph_layer = ?,
                    source_kind = ?, contributors_json = ?, revision = revision + 1
                WHERE id = ? AND project_id = ?
                """,
                (
                    _richer_text(existing["description"], body.description),
                    max(float(existing["confidence"] or 0), confidence),
                    _higher_layer(existing["graph_layer"], graph_layer),
                    _merged_source_kind(existing["source_kind"], source_kind),
                    json.dumps(contributors, ensure_ascii=False),
                    existing["id"],
                    project_id,
                ),
            )
            row = conn.execute("SELECT * FROM business_edges WHERE id = ?", (existing["id"],)).fetchone()
            assert row is not None
            return _edge_from_row(row)

        edge_id = f"biz_edge_{uuid.uuid4().hex[:16]}"
        conn.execute(
            """
            INSERT INTO business_edges (
                id, project_id, from_node_id, to_node_id, relation,
                description, confidence, graph_layer, source_kind,
                contributors_json, revision, created_by, created_at
            )
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 1, ?, ?)
            """,
            (
                edge_id,
                project_id,
                body.from_node_id,
                body.to_node_id,
                body.relation,
                body.description,
                confidence,
                graph_layer,
                source_kind,
                json.dumps([body.created_by], ensure_ascii=False),
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


def _merge_string_lists(*groups: list[str]) -> list[str]:
    result: list[str] = []
    for group in groups:
        for item in group:
            text = str(item).strip()
            if text and text not in result:
                result.append(text)
    return result


def _semantic_key(raw: str | None, node_type: str, title: str) -> str:
    value = raw or f"{node_type}:{title}"
    normalized = re.sub(r"[^\w:./-]+", "_", value.strip().lower(), flags=re.UNICODE).strip("_.:-/")
    if not normalized:
        normalized = f"{node_type}:{uuid.uuid4().hex[:16]}"
    if ":" not in normalized:
        normalized = f"{node_type}:{normalized}"
    return normalized[:240]


def _source_kind(created_by: str) -> str:
    value = created_by.strip().lower()
    if value in {"source_index", "indexer", "source_index_backfill"}:
        return "static_index"
    if value in {"user", "human", "manual", "admin"} or value.startswith("user:"):
        return "human"
    return "model"


def _node_graph_layer(node_type: str, requested: str, source_kind: str) -> str:
    if node_type == "risk":
        return "audit"
    if source_kind == "static_index":
        return "evidence"
    return requested


def _evidence_status(evidence: list[str], source_kind: str) -> str:
    if evidence:
        return "source_backed"
    if source_kind == "static_index":
        return "inferred"
    return "unverified"


def _review_status_for_evidence(
    requested: str,
    evidence_status: str,
    source_kind: str,
) -> str:
    if (
        requested == "covered"
        and source_kind in {"model", "mixed"}
        and evidence_status != "source_backed"
    ):
        return "investigating"
    return requested


def _validated_evidence_refs(
    conn,
    snapshot_id: str | None,
    evidence: list[str],
    source_kind: str,
) -> list[str]:
    if source_kind != "model" or snapshot_id is None:
        return evidence
    return validate_model_evidence_refs(conn, snapshot_id, evidence)


def _calibrated_confidence(requested: float, evidence: list[str], source_kind: str) -> float:
    if source_kind != "model":
        return requested
    return calibrated_model_confidence(requested, evidence)


def _source_snapshot_id(conn, project_id: str, requested: str | None) -> str | None:
    if requested:
        row = conn.execute(
            "SELECT id FROM source_snapshots WHERE id = ? AND project_id = ? AND status = 'ready'",
            (requested, project_id),
        ).fetchone()
        if row is None:
            raise HTTPException(422, "source_snapshot_id must reference a ready project snapshot")
        return requested
    row = conn.execute(
        """
        SELECT id FROM source_snapshots
        WHERE project_id = ? AND status = 'ready'
        ORDER BY created_at DESC, id DESC
        LIMIT 1
        """,
        (project_id,),
    ).fetchone()
    return row["id"] if row is not None else None


def _richer_text(existing: str | None, incoming: str | None) -> str | None:
    existing_text = existing.strip() if isinstance(existing, str) else ""
    incoming_text = incoming.strip() if isinstance(incoming, str) else ""
    return incoming_text if len(incoming_text) > len(existing_text) else existing_text or None


def _higher_risk(existing: str, incoming: str) -> str:
    order = {"unknown": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}
    return incoming if order.get(incoming, 0) > order.get(existing, 0) else existing


def _more_complete_review(existing: str, incoming: str) -> str:
    order = {"unreviewed": 0, "blocked": 1, "investigating": 2, "covered": 3}
    return incoming if order.get(incoming, 0) > order.get(existing, 0) else existing


def _higher_layer(existing: str, incoming: str) -> str:
    order = {"evidence": 0, "semantic": 1, "audit": 2}
    return incoming if order.get(incoming, 0) > order.get(existing, 0) else existing


def _merged_source_kind(existing: str, incoming: str) -> str:
    return existing if existing == incoming else "mixed"


def _stronger_evidence_status(existing: str, incoming: str) -> str:
    order = {"unverified": 0, "inferred": 1, "source_backed": 2}
    return incoming if order.get(incoming, 0) > order.get(existing, 0) else existing


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
        source_snapshot_id=row["source_snapshot_id"],
        confidence=row["confidence"],
        semantic_key=row["semantic_key"],
        graph_layer=row["graph_layer"],
        source_kind=row["source_kind"],
        evidence_status=row["evidence_status"],
        contributors=_decode_json_list(row["contributors_json"]),
        revision=row["revision"],
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
        confidence=row["confidence"],
        graph_layer=row["graph_layer"],
        source_kind=row["source_kind"],
        contributors=_decode_json_list(row["contributors_json"]),
        revision=row["revision"],
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
        is_current=bool(row["is_current"]),
        superseded_at=row["superseded_at"],
        created_by=row["created_by"],
        created_at=row["created_at"],
    )
