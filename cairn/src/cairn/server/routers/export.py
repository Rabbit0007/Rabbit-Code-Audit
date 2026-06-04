from fastapi import APIRouter, HTTPException
from fastapi.responses import Response
from datetime import datetime
import json
import yaml

from cairn.server.db import get_conn
from cairn.server.services import expire_reason_leases, expire_workers, get_project_or_404
from cairn.server.source_service import list_snapshots, snapshot_container_path
from cairn.server.source_service import (
    get_source_index_summary,
    list_code_entrypoints,
    list_code_files,
    list_code_symbols,
    list_dependency_manifests,
)
from cairn.server.audit_tools import build_tool_plan

router = APIRouter(tags=["export"])


def format_export_timestamp(value: str | None) -> str | None:
    if not value:
        return value
    try:
        dt = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return value
    return dt.astimezone().strftime("%Y-%m-%d %H:%M:%S")


def _load_project_data(conn, project_id: str):
    expire_workers(conn, project_id)
    expire_reason_leases(conn, project_id)
    proj = get_project_or_404(conn, project_id)

    facts = conn.execute(
        "SELECT id, description FROM facts WHERE project_id = ?", (project_id,)
    ).fetchall()
    hints = conn.execute(
        "SELECT content, creator, created_at FROM hints WHERE project_id = ? ORDER BY created_at",
        (project_id,),
    ).fetchall()
    intents = conn.execute(
        "SELECT * FROM intents WHERE project_id = ? ORDER BY created_at",
        (project_id,),
    ).fetchall()

    sources_by_intent = {}
    for i in intents:
        rows = conn.execute(
            "SELECT fact_id FROM intent_sources WHERE intent_id = ? AND project_id = ? ORDER BY rowid",
            (i["id"], project_id),
        ).fetchall()
        sources_by_intent[i["id"]] = [r["fact_id"] for r in rows]

    return proj, facts, hints, intents, sources_by_intent


def _decode_json_list(raw: str | None) -> list:
    if not raw:
        return []
    try:
        value = json.loads(raw)
    except json.JSONDecodeError:
        return []
    if not isinstance(value, list):
        return []
    return value


def _decode_json_dict(raw: str | None) -> dict:
    if not raw:
        return {}
    try:
        value = json.loads(raw)
    except json.JSONDecodeError:
        return {}
    return value if isinstance(value, dict) else {}


def _load_business_graph(conn, project_id: str) -> dict | None:
    nodes = conn.execute(
        """
        SELECT id, node_type, title, description, risk_level, review_status,
               coverage_note, last_intent_id, risk_tags_json, evidence_json,
               created_by, created_at, updated_at
        FROM business_nodes
        WHERE project_id = ?
        ORDER BY created_at, id
        """,
        (project_id,),
    ).fetchall()
    edges = conn.execute(
        """
        SELECT id, from_node_id, to_node_id, relation, description, created_by, created_at
        FROM business_edges
        WHERE project_id = ?
        ORDER BY created_at, id
        """,
        (project_id,),
    ).fetchall()
    conclusions = conn.execute(
        """
        SELECT c.rowid AS rowid, c.id, c.business_node_id, c.conclusion,
               c.summary, c.evidence, c.audit_finding_id, c.created_by,
               c.created_at, af.status AS audit_finding_status,
               af.business_node_id AS audit_finding_business_node_id
        FROM business_node_conclusions c
        LEFT JOIN audit_findings af
          ON af.id = c.audit_finding_id
         AND af.project_id = c.project_id
        WHERE c.project_id = ?
        ORDER BY c.created_at, c.rowid
        """,
        (project_id,),
    ).fetchall()
    if not nodes and not edges:
        return None
    latest_conclusions_by_node = {}
    for row in conclusions:
        latest_conclusions_by_node[row["business_node_id"]] = row
    coverage = {
        "total_nodes": len(nodes),
        "unreviewed": 0,
        "investigating": 0,
        "covered": 0,
        "blocked": 0,
        "high_or_unknown_open": [],
        "high_or_unknown_without_conclusion": [],
        "high_or_unknown_invalid_conclusion": [],
    }
    for row in nodes:
        status = row["review_status"] or "unreviewed"
        if status in coverage:
            coverage[status] += 1
        is_high_risk = row["risk_level"] in ("critical", "high", "unknown")
        coverage_ok = status == "covered" or (
            status == "blocked"
            and row["coverage_note"] is not None
            and row["coverage_note"].strip() != ""
        )
        if is_high_risk and not coverage_ok:
            coverage["high_or_unknown_open"].append(
                {
                    "id": row["id"],
                    "title": row["title"],
                    "risk_level": row["risk_level"],
                    "review_status": status,
                    "coverage_note": row["coverage_note"],
                }
            )
        if is_high_risk:
            conclusion = latest_conclusions_by_node.get(row["id"])
            if conclusion is None:
                coverage["high_or_unknown_without_conclusion"].append(
                    {
                        "id": row["id"],
                        "title": row["title"],
                        "risk_level": row["risk_level"],
                        "review_status": status,
                    }
                )
            else:
                reason = _business_node_conclusion_blocker_reason(conclusion, row["id"])
                if reason is not None:
                    coverage["high_or_unknown_invalid_conclusion"].append(
                        {
                            "id": row["id"],
                            "title": row["title"],
                            "risk_level": row["risk_level"],
                            "review_status": status,
                            "conclusion": conclusion["conclusion"],
                            "reason": reason,
                        }
                    )
    return {
        "coverage": coverage,
        "nodes": [
            {
                "id": row["id"],
                "type": row["node_type"],
                "title": row["title"],
                "description": row["description"],
                "risk_level": row["risk_level"],
                "review_status": row["review_status"],
                "coverage_note": row["coverage_note"],
                "last_intent_id": row["last_intent_id"],
                "risk_tags": _decode_json_list(row["risk_tags_json"]),
                "evidence": _decode_json_list(row["evidence_json"]),
                "created_by": row["created_by"],
                "created_at": format_export_timestamp(row["created_at"]),
                "updated_at": format_export_timestamp(row["updated_at"]),
            }
            for row in nodes
        ],
        "edges": [
            {
                "id": row["id"],
                "from": row["from_node_id"],
                "to": row["to_node_id"],
                "relation": row["relation"],
                "description": row["description"],
                "created_by": row["created_by"],
                "created_at": format_export_timestamp(row["created_at"]),
            }
            for row in edges
        ],
        "conclusions": [
            {
                "id": row["id"],
                "business_node_id": row["business_node_id"],
                "conclusion": row["conclusion"],
                "summary": row["summary"],
                "evidence": row["evidence"],
                "audit_finding_id": row["audit_finding_id"],
                "audit_finding_status": row["audit_finding_status"],
                "created_by": row["created_by"],
                "created_at": format_export_timestamp(row["created_at"]),
            }
            for row in conclusions
        ],
    }


def _business_node_conclusion_blocker_reason(conclusion, business_node_id: str) -> str | None:
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


def _load_audit_candidates(conn, project_id: str) -> dict | None:
    rows = conn.execute(
        """
        SELECT c.*, af.status AS audit_finding_status
        FROM audit_candidates c
        LEFT JOIN audit_findings af
          ON af.id = c.audit_finding_id
         AND af.project_id = c.project_id
        WHERE c.project_id = ?
        ORDER BY c.created_at, c.id
        """,
        (project_id,),
    ).fetchall()
    pending_high_findings = conn.execute(
        """
        SELECT id, title, severity, status, file_path, line_start, entry_point,
               discovered_by, reviewed_by
        FROM audit_findings
        WHERE project_id = ?
          AND severity IN ('critical', 'high')
          AND status IN ('candidate', 'investigating', 'pending_review')
        ORDER BY created_at, id
        LIMIT 200
        """,
        (project_id,),
    ).fetchall()
    if not rows and not pending_high_findings:
        return None

    by_status: dict[str, int] = {}
    by_severity: dict[str, int] = {}
    open_required: list[dict] = []
    invalid_conclusions: list[dict] = []
    for row in rows:
        by_status[row["status"]] = by_status.get(row["status"], 0) + 1
        by_severity[row["severity"]] = by_severity.get(row["severity"], 0) + 1
        is_required = row["severity"] in ("critical", "high", "unknown")
        if is_required and row["status"] in ("candidate", "investigating"):
            open_required.append(_audit_candidate_export_row(row))
        reason = _audit_candidate_conclusion_blocker_reason(row)
        if is_required and reason is not None:
            item = _audit_candidate_export_row(row)
            item["reason"] = reason
            invalid_conclusions.append(item)

    return {
        "coverage": {
            "total": len(rows),
            "by_status": by_status,
            "by_severity": by_severity,
            "open_required": open_required[:200],
            "invalid_conclusions": invalid_conclusions[:200],
            "pending_high_findings": [dict(row) for row in pending_high_findings],
        },
        "items": [_audit_candidate_export_row(row) for row in rows[:1000]],
    }


def _audit_candidate_conclusion_blocker_reason(row) -> str | None:
    status = row["status"]
    if status in ("candidate", "investigating"):
        return None
    summary = row["conclusion_summary"]
    if summary is None or summary.strip() == "":
        return "missing_summary"
    if status == "confirmed":
        if not row["audit_finding_id"]:
            return "missing_audit_finding"
        if row["audit_finding_status"] != "confirmed":
            return "audit_finding_not_confirmed"
        return None
    if status in ("rejected", "needs_more_evidence"):
        evidence = row["evidence"]
        if evidence is None or evidence.strip() == "":
            return "missing_evidence"
        return None
    return "invalid_status"


def _audit_candidate_export_row(row) -> dict:
    return {
        "id": row["id"],
        "snapshot_id": row["snapshot_id"],
        "source": row["source"],
        "candidate_type": row["candidate_type"],
        "severity": row["severity"],
        "status": row["status"],
        "title": row["title"],
        "description": row["description"],
        "file_path": row["file_path"],
        "line_start": row["line_start"],
        "line_end": row["line_end"],
        "entry_point": row["entry_point"],
        "symbol": row["symbol"],
        "tool_finding_id": row["tool_finding_id"],
        "business_node_id": row["business_node_id"],
        "conclusion_summary": row["conclusion_summary"],
        "evidence": row["evidence"],
        "audit_finding_id": row["audit_finding_id"],
        "audit_finding_status": row["audit_finding_status"],
        "created_by": row["created_by"],
        "created_at": format_export_timestamp(row["created_at"]),
        "updated_at": format_export_timestamp(row["updated_at"]),
        "concluded_by": row["concluded_by"],
        "concluded_at": format_export_timestamp(row["concluded_at"]),
    }


def _export_yaml(conn, project_id: str) -> str:
    proj, facts, hints, intents, sources_by_intent = _load_project_data(conn, project_id)

    origin_desc = ""
    goal_desc = ""
    for f in facts:
        if f["id"] == "origin":
            origin_desc = f["description"]
        elif f["id"] == "goal":
            goal_desc = f["description"]

    data: dict = {
        "project": {
            "title": proj["title"],
            "origin": origin_desc,
            "goal": goal_desc,
        }
    }
    sources = list_snapshots(project_id)
    if sources:
        data["sources"] = [
            {
                "id": source.id,
                "type": source.source_type,
                "status": source.status,
                "repository_url": source.repository_url,
                "requested_ref": source.requested_ref,
                "resolved_commit": source.resolved_commit,
                "archive_sha256": source.archive_sha256,
                "snapshot_sha256": source.snapshot_sha256,
                "file_count": source.file_count,
                "total_bytes": source.total_bytes,
                "detected_languages": source.detected_languages,
                "container_path": snapshot_container_path(source.id),
            }
            for source in sources
        ]
        ready_source = next((source for source in sources if source.status == "ready"), None)
        if ready_source is not None:
            source_path = snapshot_container_path(ready_source.id)
            files = list_code_files(project_id, ready_source.id, limit=20_000)
            index_summary = get_source_index_summary(project_id, ready_source.id)
            data["audit_tool_plan"] = [
                item.as_dict()
                for item in build_tool_plan(ready_source, files, source_path)
            ]
            entrypoints = list_code_entrypoints(project_id, ready_source.id, limit=1000)
            manifests = list_dependency_manifests(project_id, ready_source.id, limit=1000)
            symbols = list_code_symbols(project_id, ready_source.id, limit=1000)
            data["code_index"] = {
                "summary": index_summary.model_dump(),
                "entrypoints": [item.model_dump() for item in entrypoints],
                "dependency_manifests": [item.model_dump() for item in manifests],
                "symbols_sample": [item.model_dump() for item in symbols],
            }

    tool_findings = conn.execute(
        """
        SELECT id, snapshot_id, tool_name, rule_id, severity, title, description,
               file_path, line_start, line_end, status
        FROM tool_findings
        WHERE project_id = ?
        ORDER BY created_at, id
        """,
        (project_id,),
    ).fetchall()
    if tool_findings:
        data["tool_findings"] = [dict(row) for row in tool_findings]

    audit_findings = conn.execute(
        """
        SELECT id, snapshot_id, title, category, severity, status, cwe, file_path,
               line_start, line_end, symbol, entry_point, business_node_id,
               description, impact, evidence, proof_packets_json,
               reproduction_poc_json, remediation,
               discovered_by, reviewed_by
        FROM audit_findings
        WHERE project_id = ?
        ORDER BY created_at, id
        """,
        (project_id,),
    ).fetchall()
    if audit_findings:
        data["audit_findings"] = [
            {
                **{
                    key: value
                    for key, value in dict(row).items()
                    if key not in ("proof_packets_json", "reproduction_poc_json")
                },
                "proof_packets": _decode_json_list(row["proof_packets_json"]),
                "reproduction_poc": _decode_json_dict(row["reproduction_poc_json"]),
            }
            for row in audit_findings
        ]

    audit_candidates = _load_audit_candidates(conn, project_id)
    if audit_candidates is not None:
        data["audit_candidates"] = audit_candidates

    business_graph = _load_business_graph(conn, project_id)
    if business_graph is not None:
        data["business_graph"] = business_graph

    if hints:
        data["hints"] = [
            {
                "content": h["content"],
                "creator": h["creator"],
                "created_at": format_export_timestamp(h["created_at"]),
            }
            for h in hints
        ]

    data["facts"] = [{"id": f["id"], "description": f["description"]} for f in facts]

    intent_list = []
    for i in intents:
        entry: dict = {
            "from": sources_by_intent.get(i["id"], []),
            "to": i["to_fact_id"],
            "description": i["description"],
            "creator": i["creator"],
            "worker": i["worker"],
            "created_at": format_export_timestamp(i["created_at"]),
            "concluded_at": format_export_timestamp(i["concluded_at"]),
        }
        intent_list.append(entry)

    if intent_list:
        data["intents"] = intent_list

    return yaml.dump(data, allow_unicode=True, default_flow_style=False, sort_keys=False)


def _export_timeline(conn, project_id: str) -> str:
    proj, facts, hints, intents, sources_by_intent = _load_project_data(conn, project_id)

    facts_by_id = {f["id"]: f["description"] for f in facts}

    events: list[tuple[str, int, str]] = []  # (timestamp, order, text)
    order = 0

    origin_desc = facts_by_id.get("origin", "")
    goal_desc = facts_by_id.get("goal", "")
    ts = format_export_timestamp(proj["created_at"]) or ""
    block = f"[{ts}] PROJECT CREATED\n  origin: {origin_desc}\n  goal: {goal_desc}"
    events.append((proj["created_at"] or "", order, block))
    order += 1

    for h in hints:
        ts = format_export_timestamp(h["created_at"]) or ""
        block = f"[{ts}] HINT by {h['creator']}\n  {h['content']}"
        events.append((h["created_at"] or "", order, block))
        order += 1

    for i in intents:
        src = sources_by_intent.get(i["id"], [])
        from_str = ", ".join(src)

        ts = format_export_timestamp(i["created_at"]) or ""
        meta = f"  from: {from_str}"
        if i["worker"] and not i["concluded_at"]:
            meta += f"\n  worker: {i['worker']} (in progress)"
        block = f"[{ts}] INTENT DECLARED {i['id']} by {i['creator']}\n{meta}\n  {i['description']}"
        events.append((i["created_at"] or "", order, block))
        order += 1

        if not i["concluded_at"] or not i["to_fact_id"]:
            continue

        ts = format_export_timestamp(i["concluded_at"]) or ""
        actor = i["worker"] or i["creator"]

        if i["to_fact_id"] == "goal":
            block = f"[{ts}] PROJECT COMPLETED by {actor}\n  via: {i['id']} from {from_str}"
        else:
            fact_desc = facts_by_id.get(i["to_fact_id"], "")
            block = f"[{ts}] INTENT CONCLUDED {i['id']} by {actor}\n  from: {from_str}\n  produced: {i['to_fact_id']}\n  {fact_desc}"

        events.append((i["concluded_at"] or "", order, block))
        order += 1

    events.sort(key=lambda e: (e[0], e[1]))

    return "\n\n".join(e[2] for e in events) + "\n"


@router.get("/projects/{project_id}/export")
def export_project(project_id: str, format: str = "yaml"):
    if format not in ("yaml", "timeline"):
        raise HTTPException(400, "Supported formats: yaml, timeline")

    with get_conn() as conn:
        if format == "timeline":
            text = _export_timeline(conn, project_id)
        else:
            text = _export_yaml(conn, project_id)

        return Response(content=text, media_type="text/plain")
