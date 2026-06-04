from __future__ import annotations

import json
import re
import sqlite3
from datetime import datetime, timezone

from fastapi import HTTPException

from cairn.server.models import Intent, ProjectMeta, ProjectReason

def utcnow() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def next_project_id(conn: sqlite3.Connection) -> str:
    conn.execute("UPDATE counters SET value = value + 1 WHERE name = 'project'")
    row = conn.execute("SELECT value FROM counters WHERE name = 'project'").fetchone()
    return f"proj_{row['value']:03d}"


def _next_scoped_id(
    conn: sqlite3.Connection, kind: str, prefix: str, project_id: str
) -> str:
    conn.execute(
        "INSERT OR IGNORE INTO scoped_counters (project_id, kind, value) VALUES (?, ?, 0)",
        (project_id, kind),
    )
    conn.execute(
        "UPDATE scoped_counters SET value = value + 1 WHERE project_id = ? AND kind = ?",
        (project_id, kind),
    )
    row = conn.execute(
        "SELECT value FROM scoped_counters WHERE project_id = ? AND kind = ?",
        (project_id, kind),
    ).fetchone()
    assert row is not None
    return f"{prefix}{row['value']:03d}"


def next_fact_id(conn: sqlite3.Connection, project_id: str) -> str:
    return _next_scoped_id(conn, "fact", "f", project_id)


def next_intent_id(conn: sqlite3.Connection, project_id: str) -> str:
    return _next_scoped_id(conn, "intent", "i", project_id)


def next_hint_id(conn: sqlite3.Connection, project_id: str) -> str:
    return _next_scoped_id(conn, "hint", "h", project_id)


def get_project_or_404(conn: sqlite3.Connection, project_id: str) -> sqlite3.Row:
    row = conn.execute("SELECT * FROM projects WHERE id = ?", (project_id,)).fetchone()
    if row is None:
        raise HTTPException(404, "Project not found")
    return row


def check_project_active(conn: sqlite3.Connection, project_id: str) -> sqlite3.Row:
    row = get_project_or_404(conn, project_id)
    if row["status"] != "active":
        raise HTTPException(403, f"Project is {row['status']}")
    return row


def check_project_hint_writable(conn: sqlite3.Connection, project_id: str) -> sqlite3.Row:
    row = get_project_or_404(conn, project_id)
    if row["status"] not in ("active", "stopped", "completed"):
        raise HTTPException(403, f"Project is {row['status']}")
    return row


def check_project_completed(conn: sqlite3.Connection, project_id: str) -> sqlite3.Row:
    row = get_project_or_404(conn, project_id)
    if row["status"] != "completed":
        raise HTTPException(403, f"Project is {row['status']}")
    return row


def validate_facts_exist(
    conn: sqlite3.Connection, project_id: str, fact_ids: list[str]
) -> None:
    for fid in fact_ids:
        row = conn.execute(
            "SELECT 1 FROM facts WHERE id = ? AND project_id = ?", (fid, project_id)
        ).fetchone()
        if row is None:
            raise HTTPException(404, f"Fact {fid} not found")


def validate_goal_not_in_sources(fact_ids: list[str]) -> None:
    if "goal" in fact_ids:
        raise HTTPException(400, "goal cannot be used in from")


def validate_project_ready_to_complete(conn: sqlite3.Connection, project_id: str) -> None:
    open_intents = conn.execute(
        """
        SELECT id, worker, description
        FROM intents
        WHERE project_id = ? AND to_fact_id IS NULL
        ORDER BY created_at, id
        LIMIT 10
        """,
        (project_id,),
    ).fetchall()
    if open_intents:
        raise HTTPException(
            409,
            {
                "message": "Project still has open intents",
                "open_intents": [
                    {
                        "id": row["id"],
                        "worker": row["worker"],
                        "description": row["description"],
                    }
                    for row in open_intents
                ],
            },
        )

    open_candidates = conn.execute(
        """
        SELECT id, title, severity, status, candidate_type, file_path, line_start, entry_point
        FROM audit_candidates
        WHERE project_id = ?
          AND severity IN ('critical', 'high', 'unknown')
          AND status IN ('candidate', 'investigating')
        ORDER BY created_at, id
        LIMIT 20
        """,
        (project_id,),
    ).fetchall()
    if open_candidates:
        raise HTTPException(
            409,
            {
                "message": (
                    "Critical, high, or unknown audit candidates require closure before completion"
                ),
                "audit_candidates": [
                    {
                        "id": row["id"],
                        "title": row["title"],
                        "severity": row["severity"],
                        "status": row["status"],
                        "candidate_type": row["candidate_type"],
                        "file_path": row["file_path"],
                        "line_start": row["line_start"],
                        "entry_point": row["entry_point"],
                    }
                    for row in open_candidates
                ],
            },
        )

    invalid_candidate_conclusions = conn.execute(
        """
        SELECT c.id, c.title, c.severity, c.status, c.candidate_type,
               c.audit_finding_id, af.status AS audit_finding_status,
               c.conclusion_summary, c.evidence
        FROM audit_candidates c
        LEFT JOIN audit_findings af
          ON af.id = c.audit_finding_id
         AND af.project_id = c.project_id
        WHERE c.project_id = ?
          AND c.severity IN ('critical', 'high', 'unknown')
          AND (
              (c.status = 'confirmed'
               AND (c.audit_finding_id IS NULL OR af.status IS NULL OR af.status != 'confirmed'))
              OR (c.status IN ('rejected', 'needs_more_evidence')
                  AND (
                      c.conclusion_summary IS NULL OR TRIM(c.conclusion_summary) = ''
                      OR c.evidence IS NULL OR TRIM(c.evidence) = ''
                  ))
          )
        ORDER BY c.updated_at, c.id
        LIMIT 20
        """,
        (project_id,),
    ).fetchall()
    if invalid_candidate_conclusions:
        raise HTTPException(
            409,
            {
                "message": (
                    "Critical, high, or unknown audit candidates require evidence-backed "
                    "conclusions before completion"
                ),
                "audit_candidates": [
                    {
                        "id": row["id"],
                        "title": row["title"],
                        "severity": row["severity"],
                        "status": row["status"],
                        "candidate_type": row["candidate_type"],
                        "audit_finding_id": row["audit_finding_id"],
                        "audit_finding_status": row["audit_finding_status"],
                    }
                    for row in invalid_candidate_conclusions
                ],
            },
        )

    pending_high_findings = conn.execute(
        """
        SELECT id, title, severity, status, file_path, line_start, entry_point,
               discovered_by, reviewed_by
        FROM audit_findings
        WHERE project_id = ?
          AND severity IN ('critical', 'high')
          AND status IN ('candidate', 'investigating', 'pending_review')
        ORDER BY created_at, id
        LIMIT 20
        """,
        (project_id,),
    ).fetchall()
    if pending_high_findings:
        raise HTTPException(
            409,
            {
                "message": "High or critical audit findings require independent review before completion",
                "audit_findings": [
                    {
                        "id": row["id"],
                        "title": row["title"],
                        "severity": row["severity"],
                        "status": row["status"],
                        "file_path": row["file_path"],
                        "line_start": row["line_start"],
                        "entry_point": row["entry_point"],
                        "discovered_by": row["discovered_by"],
                        "reviewed_by": row["reviewed_by"],
                    }
                    for row in pending_high_findings
                ],
            },
        )

    confirmed_high_findings = conn.execute(
        """
        SELECT id, title, severity, status, file_path, line_start, entry_point,
               proof_packets_json, reproduction_poc_json
        FROM audit_findings
        WHERE project_id = ?
          AND severity IN ('critical', 'high')
          AND status = 'confirmed'
        ORDER BY created_at, id
        LIMIT 200
        """,
        (project_id,),
    ).fetchall()
    proof_blockers = [
        row
        for row in confirmed_high_findings
        if not (
            _has_complete_proof_packet_json(row["proof_packets_json"])
            or _has_complete_reproduction_poc_json(row["reproduction_poc_json"])
        )
    ][:20]
    if proof_blockers:
        raise HTTPException(
            409,
            {
                "message": (
                    "Confirmed high or critical audit findings require complete proof packets "
                    "or static reproduction PoC before completion"
                ),
                "audit_findings": [
                    {
                        "id": row["id"],
                        "title": row["title"],
                        "severity": row["severity"],
                        "status": row["status"],
                        "file_path": row["file_path"],
                        "line_start": row["line_start"],
                        "entry_point": row["entry_point"],
                    }
                    for row in proof_blockers
                ],
            },
        )

    business_nodes = conn.execute(
        """
        SELECT id, title, risk_level, review_status, coverage_note
        FROM business_nodes
        WHERE project_id = ?
          AND risk_level IN ('critical', 'high', 'unknown')
        ORDER BY risk_level, created_at, id
        """,
        (project_id,),
    ).fetchall()
    coverage_blockers = [
        row for row in business_nodes if not _business_node_has_coverage(row)
    ][:20]
    if coverage_blockers:
        raise HTTPException(
            409,
            {
                "message": (
                    "Critical, high, or unknown-risk business nodes require code coverage "
                    "before completion"
                ),
                "business_nodes": [
                    {
                        "id": row["id"],
                        "title": row["title"],
                        "risk_level": row["risk_level"],
                        "review_status": row["review_status"],
                        "coverage_note": row["coverage_note"],
                    }
                    for row in coverage_blockers
                ],
            },
        )

    conclusion_blockers = []
    for row in business_nodes:
        conclusion = conn.execute(
            """
            SELECT c.*, af.status AS audit_finding_status,
                   af.business_node_id AS audit_finding_business_node_id
            FROM business_node_conclusions c
            LEFT JOIN audit_findings af
              ON af.id = c.audit_finding_id
             AND af.project_id = c.project_id
            WHERE c.project_id = ? AND c.business_node_id = ?
            ORDER BY c.created_at DESC, c.rowid DESC
            LIMIT 1
            """,
            (project_id, row["id"]),
        ).fetchone()
        reason = _business_node_conclusion_blocker_reason(conclusion, row["id"])
        if reason is not None:
            conclusion_blockers.append(
                {
                    "id": row["id"],
                    "title": row["title"],
                    "risk_level": row["risk_level"],
                    "review_status": row["review_status"],
                    "coverage_note": row["coverage_note"],
                    "reason": reason,
                    "latest_conclusion": None
                    if conclusion is None
                    else {
                        "id": conclusion["id"],
                        "conclusion": conclusion["conclusion"],
                        "audit_finding_id": conclusion["audit_finding_id"],
                    },
                }
            )
    if conclusion_blockers:
        raise HTTPException(
            409,
            {
                "message": (
                    "Critical, high, or unknown-risk business nodes require a structured "
                    "audit conclusion before completion"
                ),
                "business_nodes": conclusion_blockers[:20],
            },
        )


def _business_node_has_coverage(row: sqlite3.Row) -> bool:
    if row["review_status"] == "covered":
        return True
    return (
        row["review_status"] == "blocked"
        and row["coverage_note"] is not None
        and row["coverage_note"].strip() != ""
    )


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


def _has_complete_proof_packet_json(raw: str | None) -> bool:
    if not raw:
        return False
    try:
        packets = json.loads(raw)
    except json.JSONDecodeError:
        return False
    if not isinstance(packets, list):
        return False
    return any(_is_complete_proof_packet(packet) for packet in packets if isinstance(packet, dict))


def _is_complete_proof_packet(packet: dict) -> bool:
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


def _has_complete_reproduction_poc_json(raw: str | None) -> bool:
    if not raw:
        return False
    try:
        poc = json.loads(raw)
    except json.JSONDecodeError:
        return False
    return _has_complete_reproduction_poc(poc) if isinstance(poc, dict) else False


def _has_complete_reproduction_poc(poc: dict) -> bool:
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


def _poc_text(poc: dict, key: str) -> str:
    value = poc.get(key)
    return value.strip() if isinstance(value, str) else ""


def _poc_list(poc: dict, key: str) -> list[str]:
    value = poc.get(key)
    if not isinstance(value, list):
        return []
    return [str(item).strip() for item in value if str(item).strip()]


def _business_node_conclusion_blocker_reason(
    conclusion: sqlite3.Row | None,
    business_node_id: str,
) -> str | None:
    if conclusion is None:
        return "missing_conclusion"
    summary = conclusion["summary"]
    if summary is None or summary.strip() == "":
        return "missing_summary"
    kind = conclusion["conclusion"]
    if kind == "confirmed_finding":
        if not conclusion["audit_finding_id"]:
            return "missing_audit_finding"
        if conclusion["audit_finding_status"] != "confirmed":
            return "audit_finding_not_confirmed"
        if conclusion["audit_finding_business_node_id"] != business_node_id:
            return "audit_finding_business_node_mismatch"
        return None
    if kind in ("rejected", "needs_more_evidence"):
        evidence = conclusion["evidence"]
        if evidence is None or evidence.strip() == "":
            return "missing_evidence"
        return None
    return "invalid_conclusion"


def validate_intent_creator_worker(creator: str, worker: str | None) -> None:
    if worker is not None and worker != creator:
        raise HTTPException(400, "worker must be null or equal to creator")


def get_intent_or_404(
    conn: sqlite3.Connection, project_id: str, intent_id: str
) -> sqlite3.Row:
    row = conn.execute(
        "SELECT * FROM intents WHERE id = ? AND project_id = ?",
        (intent_id, project_id),
    ).fetchone()
    if row is None:
        raise HTTPException(404, "Intent not found")
    return row


def get_claimable_open_intent_or_404(
    conn: sqlite3.Connection, project_id: str, intent_id: str, worker: str
) -> sqlite3.Row:
    expire_workers(conn, project_id)
    row = get_intent_or_404(conn, project_id, intent_id)
    if row["to_fact_id"] is not None:
        raise HTTPException(409, "Intent already concluded")
    if row["worker"] is not None and row["worker"] != worker:
        raise HTTPException(409, f"Intent is currently claimed by {row['worker']}")
    return row


def get_releasable_open_intent_or_404(
    conn: sqlite3.Connection, project_id: str, intent_id: str, worker: str
) -> sqlite3.Row:
    expire_workers(conn, project_id)
    row = get_intent_or_404(conn, project_id, intent_id)
    if row["to_fact_id"] is not None:
        raise HTTPException(409, "Intent already concluded")
    if row["worker"] is None:
        return row
    if row["worker"] != worker:
        raise HTTPException(409, f"Intent is currently claimed by {row['worker']}")
    return row


def get_completion_intent_or_409(conn: sqlite3.Connection, project_id: str) -> sqlite3.Row:
    rows = conn.execute(
        "SELECT * FROM intents WHERE project_id = ? AND to_fact_id = 'goal'",
        (project_id,),
    ).fetchall()
    if not rows:
        raise HTTPException(409, "Completed project is missing its completion intent")
    if len(rows) != 1:
        raise HTTPException(409, "Completed project has multiple completion intents")
    return rows[0]


def intent_to_model(conn: sqlite3.Connection, row: sqlite3.Row, project_id: str) -> Intent:
    sources = conn.execute(
        "SELECT fact_id FROM intent_sources WHERE intent_id = ? AND project_id = ? ORDER BY rowid",
        (row["id"], project_id),
    ).fetchall()
    return Intent(
        id=row["id"],
        **{"from": [s["fact_id"] for s in sources]},
        to=row["to_fact_id"],
        description=row["description"],
        creator=row["creator"],
        worker=row["worker"],
        last_heartbeat_at=row["last_heartbeat_at"],
        created_at=row["created_at"],
        concluded_at=row["concluded_at"],
    )


def build_intents(conn: sqlite3.Connection, project_id: str) -> list[Intent]:
    rows = conn.execute(
        "SELECT * FROM intents WHERE project_id = ? ORDER BY created_at",
        (project_id,),
    ).fetchall()
    return [intent_to_model(conn, r, project_id) for r in rows]


def get_intent_timeout(conn: sqlite3.Connection) -> int:
    row = conn.execute("SELECT intent_timeout FROM settings WHERE rowid = 1").fetchone()
    return row["intent_timeout"]


def get_reason_timeout(conn: sqlite3.Connection) -> int:
    row = conn.execute("SELECT reason_timeout FROM settings WHERE rowid = 1").fetchone()
    return row["reason_timeout"]


def project_reason_from_row(row: sqlite3.Row) -> ProjectReason | None:
    if row["reason_worker"] is None:
        return None
    return ProjectReason(
        worker=row["reason_worker"],
        trigger=row["reason_trigger"],
        started_at=row["reason_started_at"],
        last_heartbeat_at=row["reason_last_heartbeat_at"],
    )


def project_meta_from_row(row: sqlite3.Row) -> ProjectMeta:
    return ProjectMeta(
        id=row["id"],
        title=row["title"],
        status=row["status"],
        created_at=row["created_at"],
        reason=project_reason_from_row(row),
    )


def clear_project_reason(conn: sqlite3.Connection, project_id: str) -> None:
    conn.execute(
        """
        UPDATE projects
        SET reason_worker = NULL,
            reason_trigger = NULL,
            reason_started_at = NULL,
            reason_last_heartbeat_at = NULL
        WHERE id = ?
        """,
        (project_id,),
    )


def expire_workers(conn: sqlite3.Connection, project_id: str | None = None) -> None:
    timeout = get_intent_timeout(conn)
    now = utcnow()
    where = """
        to_fact_id IS NULL
        AND worker IS NOT NULL
        AND last_heartbeat_at IS NOT NULL
        AND (julianday(?) - julianday(last_heartbeat_at)) * 86400 > ?
    """
    params: tuple = (now, timeout)
    if project_id is not None:
        params = (project_id, now, timeout)
        where = f"project_id = ? AND {where}"
    expired = conn.execute(f"SELECT 1 FROM intents WHERE {where} LIMIT 1", params).fetchone()
    if expired is None:
        return
    conn.execute(f"UPDATE intents SET worker = NULL WHERE {where}", params)


def expire_reason_leases(conn: sqlite3.Connection, project_id: str | None = None) -> None:
    timeout = get_reason_timeout(conn)
    now = utcnow()
    where = """
        reason_worker IS NOT NULL
        AND reason_last_heartbeat_at IS NOT NULL
        AND (julianday(?) - julianday(reason_last_heartbeat_at)) * 86400 > ?
    """
    params: tuple = (now, timeout)
    if project_id is not None:
        params = (project_id, now, timeout)
        where = f"id = ? AND {where}"
    expired = conn.execute(f"SELECT 1 FROM projects WHERE {where} LIMIT 1", params).fetchone()
    if expired is None:
        return
    conn.execute(
        f"""
        UPDATE projects
        SET reason_worker = NULL,
            reason_trigger = NULL,
            reason_started_at = NULL,
            reason_last_heartbeat_at = NULL
        WHERE {where}
        """,
        params,
    )
