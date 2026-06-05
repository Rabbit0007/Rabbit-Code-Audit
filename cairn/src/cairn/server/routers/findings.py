from __future__ import annotations

import json
import re
import uuid

from fastapi import APIRouter, HTTPException

from cairn.server.db import get_conn
from cairn.server.services import get_project_or_404, utcnow
from cairn.server.source_models import (
    AuditCandidate,
    AuditFinding,
    ConcludeAuditCandidateRequest,
    CreateAuditCandidateRequest,
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
    return [_audit_finding_from_row(row) for row in rows]


@router.post("/audit-findings", response_model=AuditFinding, status_code=201)
def create_audit_finding(project_id: str, body: CreateAuditFindingRequest):
    finding_id = f"finding_{uuid.uuid4().hex[:16]}"
    created_at = utcnow()
    initial_status = "pending_review" if body.severity in ("critical", "high") else "candidate"
    with get_conn() as conn:
        get_project_or_404(conn, project_id)
        _validate_snapshot(conn, project_id, body.snapshot_id)
        inferred_business_node_id = _infer_business_node_for_finding(conn, project_id, body)
        if inferred_business_node_id and not body.business_node_id:
            body = body.model_copy(update={"business_node_id": inferred_business_node_id})
        _validate_audit_finding_quality(conn, project_id, body)
        conn.execute(
            """
            INSERT INTO audit_findings (
                id, project_id, snapshot_id, title, category, severity, status,
                cwe, file_path, line_start, line_end, symbol, entry_point,
                business_node_id, description, impact, evidence,
                proof_packets_json, reproduction_poc_json, remediation,
                discovered_by, created_at
            )
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
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
                body.symbol,
                body.entry_point,
                body.business_node_id,
                body.description,
                body.impact,
                body.evidence,
                json.dumps(body.proof_packets, ensure_ascii=False),
                json.dumps(body.reproduction_poc, ensure_ascii=False),
                body.remediation,
                body.discovered_by,
                created_at,
            ),
        )
        row = conn.execute("SELECT * FROM audit_findings WHERE id = ?", (finding_id,)).fetchone()
    assert row is not None
    return _audit_finding_from_row(row)


@router.get("/audit-candidates", response_model=list[AuditCandidate])
def list_audit_candidates(
    project_id: str,
    snapshot_id: str | None = None,
    status: str | None = None,
    severity: str | None = None,
):
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
        if severity:
            clauses.append("severity = ?")
            params.append(severity)
        rows = conn.execute(
            f"SELECT * FROM audit_candidates WHERE {' AND '.join(clauses)} ORDER BY created_at DESC, id",
            params,
        ).fetchall()
    return [AuditCandidate(**dict(row)) for row in rows]


@router.post("/audit-candidates", response_model=AuditCandidate, status_code=201)
def create_audit_candidate(project_id: str, body: CreateAuditCandidateRequest):
    candidate_id = f"cand_{uuid.uuid4().hex[:16]}"
    created_at = utcnow()
    with get_conn() as conn:
        get_project_or_404(conn, project_id)
        _validate_snapshot(conn, project_id, body.snapshot_id)
        _validate_candidate_links(conn, project_id, body)
        conn.execute(
            """
            INSERT INTO audit_candidates (
                id, project_id, snapshot_id, source, candidate_type, severity,
                title, description, file_path, line_start, line_end,
                entry_point, symbol, tool_finding_id, business_node_id,
                status, created_by, created_at, updated_at
            )
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'candidate', ?, ?, ?)
            """,
            (
                candidate_id,
                project_id,
                body.snapshot_id,
                body.source,
                body.candidate_type,
                body.severity,
                body.title,
                body.description,
                body.file_path,
                body.line_start,
                body.line_end,
                body.entry_point,
                body.symbol,
                body.tool_finding_id,
                body.business_node_id,
                body.created_by,
                created_at,
                created_at,
            ),
        )
        row = conn.execute("SELECT * FROM audit_candidates WHERE id = ?", (candidate_id,)).fetchone()
    assert row is not None
    return AuditCandidate(**dict(row))


@router.post("/audit-candidates/{candidate_id}/conclude", response_model=AuditCandidate)
def conclude_audit_candidate(
    project_id: str,
    candidate_id: str,
    body: ConcludeAuditCandidateRequest,
):
    with get_conn() as conn:
        get_project_or_404(conn, project_id)
        row = conn.execute(
            "SELECT * FROM audit_candidates WHERE id = ? AND project_id = ?",
            (candidate_id, project_id),
        ).fetchone()
        if row is None:
            raise HTTPException(404, "Audit candidate not found")
        _validate_candidate_conclusion(conn, project_id, body)
        now = utcnow()
        conn.execute(
            """
            UPDATE audit_candidates
            SET status = ?,
                conclusion_summary = ?,
                evidence = ?,
                audit_finding_id = ?,
                concluded_by = ?,
                concluded_at = ?,
                updated_at = ?
            WHERE id = ? AND project_id = ?
            """,
            (
                body.decision,
                body.summary,
                body.evidence,
                body.audit_finding_id,
                body.reviewer,
                now,
                now,
                candidate_id,
                project_id,
            ),
        )
        updated = conn.execute(
            "SELECT * FROM audit_candidates WHERE id = ? AND project_id = ?",
            (candidate_id, project_id),
        ).fetchone()
    assert updated is not None
    return AuditCandidate(**dict(updated))


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
        if body.decision == "confirmed":
            _ensure_report_enrichment_task(conn, project_id, finding_id, body.reviewer)
        updated = conn.execute(
            "SELECT * FROM audit_findings WHERE id = ? AND project_id = ?",
            (finding_id, project_id),
        ).fetchone()
    assert updated is not None
    return _audit_finding_from_row(updated)


def _validate_snapshot(conn, project_id: str, snapshot_id: str) -> None:
    row = conn.execute(
        "SELECT status FROM source_snapshots WHERE id = ? AND project_id = ?",
        (snapshot_id, project_id),
    ).fetchone()
    if row is None:
        raise HTTPException(404, "Source snapshot not found")
    if row["status"] != "ready":
        raise HTTPException(409, "Source snapshot is not ready")


def _validate_audit_finding_quality(conn, project_id: str, body: CreateAuditFindingRequest) -> None:
    if body.business_node_id:
        _validate_business_node(conn, project_id, body.business_node_id)

    if body.severity not in ("critical", "high"):
        return

    missing: list[str] = []
    if not body.file_path:
        missing.append("file_path")
    if body.line_start is None and not body.symbol:
        missing.append("line_start_or_symbol")
    if not body.entry_point:
        missing.append("entry_point")
    if not body.impact:
        missing.append("impact")
    if not body.evidence:
        missing.append("evidence")
    if not (
        _has_complete_proof_packet(body.proof_packets)
        or _has_complete_reproduction_poc(body.reproduction_poc)
    ):
        missing.append("complete_proof_packet_or_static_poc")

    business_node_count = conn.execute(
        "SELECT COUNT(*) AS count FROM business_nodes WHERE project_id = ?",
        (project_id,),
    ).fetchone()["count"]
    if business_node_count and not body.business_node_id:
        missing.append("business_node_id")

    if missing:
        raise HTTPException(
            422,
            "High or critical audit findings require concrete code evidence: " + ", ".join(missing),
        )


def _audit_finding_from_row(row) -> AuditFinding:
    data = dict(row)
    data["proof_packets"] = _decode_json_list(data.pop("proof_packets_json", None))
    data["reproduction_poc"] = _decode_json_dict(data.pop("reproduction_poc_json", None))
    return AuditFinding(**data)


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


_PROOF_PLACEHOLDER_RE = re.compile(
    r"(\.\.\.|未记录|待补充|需复测|placeholder|todo|example\.com|target\.local|"
    r"<\s*(?:target|host|hostname|payload|url|path|port|项目事实[^>]*|[^>]{0,20}待补充[^>]*)\s*>)",
    re.IGNORECASE,
)
_HTTP_REQUEST_RE = re.compile(
    r"^(GET|POST|PUT|PATCH|DELETE|HEAD|OPTIONS)\s+\S+\s+HTTP/\d(?:\.\d)?",
    re.IGNORECASE | re.MULTILINE,
)
_HTTP_HOST_RE = re.compile(r"^Host:\s*\S+", re.IGNORECASE | re.MULTILINE)
_HTTP_RESPONSE_RE = re.compile(r"^HTTP/\d(?:\.\d)?\s+\d{3}\b", re.IGNORECASE | re.MULTILINE)


def _has_complete_proof_packet(proof_packets: list[dict[str, str]]) -> bool:
    return any(_is_complete_proof_packet(packet) for packet in proof_packets)


def _is_complete_proof_packet(packet: dict[str, str]) -> bool:
    title = str(packet.get("title") or "").strip()
    request = str(packet.get("request") or "").strip()
    response = str(packet.get("response") or "").strip()
    payload = str(packet.get("payload") or "").strip()
    note = str(packet.get("note") or packet.get("verification") or "").strip()
    if not title or not request or not response or not payload:
        return False
    combined = "\n".join([title, request, response, payload, note])
    if _PROOF_PLACEHOLDER_RE.search(combined):
        return False
    is_http_request = _HTTP_REQUEST_RE.search(request) is not None
    is_command = request.lstrip().startswith(("curl ", "python ", "python3 "))
    if not is_http_request and not is_command:
        return False
    if is_http_request and (_HTTP_HOST_RE.search(request) is None or _HTTP_RESPONSE_RE.search(response) is None):
        return False
    return True


_STATIC_POC_PLACEHOLDER_RE = re.compile(r"(\.\.\.|未记录|待补充|placeholder|todo)", re.IGNORECASE)


def _has_complete_reproduction_poc(poc: dict[str, object]) -> bool:
    if not isinstance(poc, dict) or not poc:
        return False
    payload = _poc_text(poc, "payload")
    request_template = (
        _poc_text(poc, "request_template")
        or _poc_text(poc, "curl")
        or _poc_text(poc, "command")
    )
    expected_result = _poc_text(poc, "expected_result") or _poc_text(poc, "expected_response")
    steps = _poc_list(poc, "steps")
    verification = _poc_text(poc, "verification")
    combined = "\n".join([payload, request_template, expected_result, verification, *steps])
    if _STATIC_POC_PLACEHOLDER_RE.search(combined):
        return False
    return bool(payload and request_template and expected_result and (steps or verification))


def _poc_text(poc: dict[str, object], key: str) -> str:
    value = poc.get(key)
    return value.strip() if isinstance(value, str) else ""


def _poc_list(poc: dict[str, object], key: str) -> list[str]:
    value = poc.get(key)
    if not isinstance(value, list):
        return []
    return [str(item).strip() for item in value if str(item).strip()]


def _validate_candidate_links(conn, project_id: str, body: CreateAuditCandidateRequest) -> None:
    if body.business_node_id:
        _validate_business_node(conn, project_id, body.business_node_id)
    if body.tool_finding_id:
        row = conn.execute(
            "SELECT id FROM tool_findings WHERE id = ? AND project_id = ?",
            (body.tool_finding_id, project_id),
        ).fetchone()
        if row is None:
            raise HTTPException(404, "Tool finding not found")


def _infer_business_node_for_finding(
    conn,
    project_id: str,
    body: CreateAuditFindingRequest,
) -> str | None:
    if body.business_node_id:
        return body.business_node_id
    if not body.file_path:
        return None
    rows = conn.execute(
        """
        SELECT id, candidate_type, line_start, entry_point, business_node_id
        FROM audit_candidates
        WHERE project_id = ?
          AND snapshot_id = ?
          AND file_path = ?
          AND business_node_id IS NOT NULL
        """,
        (project_id, body.snapshot_id, body.file_path),
    ).fetchall()
    if not rows:
        return None

    def score(row) -> tuple[int, int, int]:
        exact_line = body.line_start is not None and row["line_start"] == body.line_start
        same_entry = bool(body.entry_point and row["entry_point"] and row["entry_point"] in body.entry_point)
        data_flow = row["candidate_type"] == "data_flow"
        return (
            0 if exact_line else 1,
            0 if same_entry else 1,
            0 if data_flow else 1,
        )

    best = sorted(rows, key=score)[0]
    return best["business_node_id"]


def _validate_candidate_conclusion(
    conn,
    project_id: str,
    body: ConcludeAuditCandidateRequest,
) -> None:
    if body.decision == "confirmed":
        if not body.audit_finding_id:
            raise HTTPException(422, "Confirmed audit candidates require audit_finding_id")
        row = conn.execute(
            "SELECT id FROM audit_findings WHERE id = ? AND project_id = ?",
            (body.audit_finding_id, project_id),
        ).fetchone()
        if row is None:
            raise HTTPException(404, "Audit finding not found")
        return
    if not body.evidence:
        raise HTTPException(422, f"{body.decision} audit candidates require evidence")
    if body.audit_finding_id:
        row = conn.execute(
            "SELECT id FROM audit_findings WHERE id = ? AND project_id = ?",
            (body.audit_finding_id, project_id),
        ).fetchone()
        if row is None:
            raise HTTPException(404, "Audit finding not found")


def _validate_business_node(conn, project_id: str, node_id: str) -> None:
    row = conn.execute(
        "SELECT id FROM business_nodes WHERE id = ? AND project_id = ?",
        (node_id, project_id),
    ).fetchone()
    if row is None:
        raise HTTPException(404, "Business node not found")


def _ensure_report_enrichment_task(conn, project_id: str, finding_id: str, reviewer: str) -> None:
    existing = conn.execute(
        """
        SELECT id
        FROM report_enrichment_tasks
        WHERE project_id = ?
          AND finding_id = ?
          AND status IN ('pending', 'running', 'completed')
        LIMIT 1
        """,
        (project_id, finding_id),
    ).fetchone()
    if existing is not None:
        return
    now = utcnow()
    task_id = f"rpt_{uuid.uuid4().hex[:16]}"
    conn.execute(
        """
        INSERT INTO report_enrichment_tasks (
            id, project_id, finding_id, status, created_by, created_at
        )
        VALUES (?, ?, ?, 'pending', ?, ?)
        """,
        (task_id, project_id, finding_id, f"review:{reviewer}", now),
    )


def _sync_reportable_finding(conn, finding_id: str) -> None:
    row = conn.execute("SELECT * FROM audit_findings WHERE id = ?", (finding_id,)).fetchone()
    if row is None:
        return
    if row["status"] != "confirmed" or row["severity"] == "info":
        conn.execute("DELETE FROM vulnerabilities WHERE id = ?", (finding_id,))
        return

    proof_packets = _decode_json_list(row["proof_packets_json"])
    reproduction_poc = _decode_json_dict(row["reproduction_poc_json"])
    evidence = [value for value in (row["evidence"], row["impact"], row["entry_point"]) if value]
    source_location = row["file_path"] or ""
    if row["line_start"]:
        source_location += f":{row['line_start']}"
    if row["symbol"]:
        source_location = f"{source_location}#{row['symbol']}" if source_location else row["symbol"]
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
            source_worker, source_fact_ids_json, evidence_json, process_json,
            proof_packets_json, reproduction_poc_json, status
        )
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'confirmed')
        ON CONFLICT(id) DO UPDATE SET
            title = excluded.title,
            description = excluded.description,
            severity = excluded.severity,
            source_worker = excluded.source_worker,
            evidence_json = excluded.evidence_json,
            process_json = excluded.process_json,
            proof_packets_json = excluded.proof_packets_json,
            reproduction_poc_json = excluded.reproduction_poc_json,
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
            json.dumps(proof_packets, ensure_ascii=False),
            json.dumps(reproduction_poc, ensure_ascii=False),
        ),
    )
