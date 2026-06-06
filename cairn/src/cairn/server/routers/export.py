from fastapi import APIRouter, HTTPException
from fastapi.responses import Response
from datetime import datetime
import json
import re
import yaml

from cairn.server.db import get_conn
from cairn.server.services import (
    business_node_coverage_status_for_conclusion,
    expire_reason_leases,
    expire_workers,
    get_project_or_404,
    is_high_impact_audit_candidate_row,
    is_high_impact_business_node_row,
)
from cairn.server.source_service import list_snapshots, snapshot_container_path
from cairn.server.source_service import (
    get_source_index_summary,
    list_code_entrypoints,
    list_code_files,
    list_code_relationships,
    list_code_symbols,
    list_dependency_manifests,
)
from cairn.server.audit_tools import build_tool_plan

router = APIRouter(tags=["export"])

EXPORT_PROFILES = {"full", "reason", "explore"}
REASON_CANDIDATE_LIMIT = 200
EXPLORE_CANDIDATE_LIMIT = 120
FULL_CANDIDATE_LIMIT = 1000
REASON_GRAPH_NODE_LIMIT = 200
EXPLORE_GRAPH_NODE_LIMIT = 120
CANDIDATE_ID_RE = re.compile(r"\bcand_[0-9a-fA-F]{16}\b")


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


def _load_business_graph(
    conn,
    project_id: str,
    *,
    profile: str = "full",
    focus_candidate_ids: set[str] | None = None,
) -> dict | None:
    nodes = conn.execute(
        """
        SELECT id, node_type, title, description, risk_level, review_status,
               coverage_note, last_intent_id, risk_tags_json, evidence_json,
               source_snapshot_id, confidence, created_by, created_at, updated_at
        FROM business_nodes
        WHERE project_id = ?
        ORDER BY created_at, id
        """,
        (project_id,),
    ).fetchall()
    edges = conn.execute(
        """
        SELECT id, from_node_id, to_node_id, relation, description, confidence, created_by, created_at
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
        conclusion = latest_conclusions_by_node.get(row["id"])
        status, coverage_note = _business_node_effective_review(row, conclusion)
        if status in coverage:
            coverage[status] += 1
        is_high_risk = row["risk_level"] in ("critical", "high", "unknown")
        coverage_ok = status == "covered" or (
            status == "blocked"
            and coverage_note is not None
            and coverage_note.strip() != ""
        )
        if is_high_risk and not coverage_ok:
            coverage["high_or_unknown_open"].append(
                {
                    "id": row["id"],
                    "title": row["title"],
                    "risk_level": row["risk_level"],
                    "review_status": status,
                    "coverage_note": coverage_note,
                }
            )
        if is_high_risk:
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
                reason = _business_node_conclusion_blocker_reason(
                    conclusion,
                    row["id"],
                    require_decisive=is_high_impact_business_node_row(row),
                )
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
    visible_nodes = list(nodes)
    visible_edges = list(edges)
    if profile != "full":
        visible_nodes, visible_edges = _select_business_graph_rows(
            conn,
            project_id,
            nodes,
            edges,
            profile=profile,
            focus_candidate_ids=focus_candidate_ids or set(),
        )

    omitted_nodes = max(0, len(nodes) - len(visible_nodes))
    omitted_edges = max(0, len(edges) - len(visible_edges))
    return {
        "coverage": coverage,
        "view": {
            "profile": profile,
            "nodes_included": len(visible_nodes),
            "nodes_omitted": omitted_nodes,
            "edges_included": len(visible_edges),
            "edges_omitted": omitted_edges,
        },
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
                "source_snapshot_id": row["source_snapshot_id"],
                "confidence": row["confidence"],
                "created_by": row["created_by"],
                "created_at": format_export_timestamp(row["created_at"]),
                "updated_at": format_export_timestamp(row["updated_at"]),
            }
            for row in visible_nodes
        ],
        "edges": [
            {
                "id": row["id"],
                "from": row["from_node_id"],
                "to": row["to_node_id"],
                "relation": row["relation"],
                "description": row["description"],
                "confidence": row["confidence"],
                "created_by": row["created_by"],
                "created_at": format_export_timestamp(row["created_at"]),
            }
            for row in visible_edges
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


def _business_node_effective_review(row, conclusion) -> tuple[str, str | None]:
    status = row["review_status"] or "unreviewed"
    coverage_note = row["coverage_note"]
    if conclusion is None:
        return status, coverage_note
    if (
        _business_node_conclusion_blocker_reason(
            conclusion,
            row["id"],
            require_decisive=is_high_impact_business_node_row(row),
        )
        is not None
    ):
        return status, coverage_note
    conclusion_status = business_node_coverage_status_for_conclusion(conclusion["conclusion"])
    if conclusion_status is None:
        return status, coverage_note
    if status == "covered":
        return status, coverage_note
    if status == "blocked" and coverage_note is not None and coverage_note.strip() != "":
        return status, coverage_note
    return conclusion_status, coverage_note or conclusion["summary"]


def _select_business_graph_rows(
    conn,
    project_id: str,
    nodes,
    edges,
    *,
    profile: str,
    focus_candidate_ids: set[str],
):
    node_by_id = {row["id"]: row for row in nodes}
    include_ids: set[str] = set()
    if focus_candidate_ids:
        rows = conn.execute(
            f"""
            SELECT DISTINCT business_node_id
            FROM audit_candidates
            WHERE project_id = ?
              AND id IN ({','.join('?' for _ in focus_candidate_ids)})
              AND business_node_id IS NOT NULL
            """,
            (project_id, *sorted(focus_candidate_ids)),
        ).fetchall()
        include_ids.update(row["business_node_id"] for row in rows)
    for row in nodes:
        if row["risk_level"] in ("critical", "high", "unknown") and row["review_status"] in (
            "unreviewed",
            "investigating",
            "blocked",
        ):
            include_ids.add(row["id"])
    for row in nodes:
        if row["last_intent_id"] and profile == "explore":
            include_ids.add(row["id"])
    adjacent_ids = set(include_ids)
    for edge in edges:
        if edge["from_node_id"] in include_ids:
            adjacent_ids.add(edge["to_node_id"])
        if edge["to_node_id"] in include_ids:
            adjacent_ids.add(edge["from_node_id"])
    limit = EXPLORE_GRAPH_NODE_LIMIT if profile == "explore" else REASON_GRAPH_NODE_LIMIT
    ordered_ids = [row["id"] for row in nodes if row["id"] in adjacent_ids][:limit]
    selected_ids = set(ordered_ids)
    selected_nodes = [node_by_id[node_id] for node_id in ordered_ids if node_id in node_by_id]
    selected_edges = [
        row
        for row in edges
        if row["from_node_id"] in selected_ids and row["to_node_id"] in selected_ids
    ]
    return selected_nodes, selected_edges


def _business_node_conclusion_blocker_reason(
    conclusion,
    business_node_id: str,
    *,
    require_decisive: bool = False,
) -> str | None:
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
        if require_decisive and kind == "needs_more_evidence":
            return "high_impact_needs_more_evidence"
        return None
    return "invalid_conclusion"


def _load_audit_candidates(
    conn,
    project_id: str,
    *,
    profile: str = "full",
    focus_candidate_ids: set[str] | None = None,
) -> dict | None:
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

    visible_rows = _select_audit_candidate_rows(
        rows,
        profile=profile,
        focus_candidate_ids=focus_candidate_ids or set(),
    )
    return {
        "coverage": {
            "total": len(rows),
            "by_status": by_status,
            "by_severity": by_severity,
            "open_required": open_required[:200],
            "invalid_conclusions": invalid_conclusions[:200],
            "pending_high_findings": [dict(row) for row in pending_high_findings],
        },
        "view": {
            "profile": profile,
            "items_included": len(visible_rows),
            "items_omitted": max(0, len(rows) - len(visible_rows)),
            "focused_candidate_ids": sorted(focus_candidate_ids or []),
        },
        "items": [_audit_candidate_export_row(row) for row in visible_rows],
    }


def _select_audit_candidate_rows(rows, *, profile: str, focus_candidate_ids: set[str]):
    if profile == "full":
        return list(rows[:FULL_CANDIDATE_LIMIT])
    if profile == "explore":
        focused = [row for row in rows if row["id"] in focus_candidate_ids]
        focused_files = {row["file_path"] for row in focused if row["file_path"]}
        related = [
            row
            for row in rows
            if row["id"] not in focus_candidate_ids
            and row["status"] in ("candidate", "investigating")
            and row["file_path"] in focused_files
        ]
        if focused:
            return (focused + related)[:EXPLORE_CANDIDATE_LIMIT]
        required = [
            row
            for row in rows
            if row["severity"] in ("critical", "high", "unknown")
            and row["status"] in ("candidate", "investigating")
        ]
        return required[:EXPLORE_CANDIDATE_LIMIT]
    required = [
        row
        for row in rows
        if row["severity"] in ("critical", "high", "unknown")
        and row["status"] in ("candidate", "investigating")
    ]
    invalid = [
        row
        for row in rows
        if row["severity"] in ("critical", "high", "unknown")
        and row["status"] not in ("candidate", "investigating")
        and _audit_candidate_conclusion_blocker_reason(row) is not None
    ]
    selected: list = []
    seen: set[str] = set()
    for row in [*required, *invalid]:
        if row["id"] in seen:
            continue
        selected.append(row)
        seen.add(row["id"])
        if len(selected) >= REASON_CANDIDATE_LIMIT:
            break
    return selected


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
        if status == "needs_more_evidence" and is_high_impact_audit_candidate_row(row):
            return "high_impact_needs_more_evidence"
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


def _export_yaml(conn, project_id: str, *, profile: str = "full", intent_id: str | None = None) -> str:
    proj, facts, hints, intents, sources_by_intent = _load_project_data(conn, project_id)
    focus_candidate_ids = _focus_candidate_ids(intents, intent_id)

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
    data["context_profile"] = {
        "profile": profile,
        "intent_id": intent_id,
        "focused_candidate_ids": sorted(focus_candidate_ids),
        "note": (
            "This export is intentionally scoped for the current audit phase. "
            "Use database-backed coverage sections as the source of truth; omitted graph items remain stored server-side."
        ),
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
            data["validation_strategy"] = _validation_strategy(ready_source, files)
            data["audit_tool_plan"] = [
                item.as_dict()
                for item in build_tool_plan(ready_source, files, source_path)
            ]
            index_limit = _code_index_limit(profile)
            entrypoints = list_code_entrypoints(project_id, ready_source.id, limit=index_limit)
            relationships = list_code_relationships(project_id, ready_source.id, limit=index_limit)
            manifests = list_dependency_manifests(project_id, ready_source.id, limit=index_limit)
            symbols = list_code_symbols(project_id, ready_source.id, limit=index_limit)
            data["code_index"] = {
                "summary": index_summary.model_dump(),
                "view": {
                    "profile": profile,
                    "limit": index_limit,
                    "entrypoints_included": len(entrypoints),
                    "relationships_included": len(relationships),
                    "symbols_included": len(symbols),
                    "manifests_included": len(manifests),
                },
                "entrypoints": [item.model_dump() for item in entrypoints],
                "relationships": [item.model_dump() for item in relationships],
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

    audit_candidates = _load_audit_candidates(
        conn,
        project_id,
        profile=profile,
        focus_candidate_ids=focus_candidate_ids,
    )
    if audit_candidates is not None:
        data["audit_candidates"] = audit_candidates

    business_graph = _load_business_graph(
        conn,
        project_id,
        profile=profile,
        focus_candidate_ids=focus_candidate_ids,
    )
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


def _code_index_limit(profile: str) -> int:
    if profile == "explore":
        return 300
    if profile == "reason":
        return 500
    return 1000


def _validation_strategy(source, files) -> dict:
    paths = {item.path for item in files}
    lower_paths = {path.lower() for path in paths}
    launch_indicators = sorted(
        path
        for path in paths
        if path.lower()
        in {
            "docker-compose.yml",
            "docker-compose.yaml",
            "compose.yml",
            "compose.yaml",
            "dockerfile",
            "makefile",
            "package.json",
            "pom.xml",
            "build.gradle",
            "build.gradle.kts",
            "requirements.txt",
            "pyproject.toml",
            "composer.json",
            "artisan",
            "manage.py",
        }
        or path.lower().endswith(("/docker-compose.yml", "/docker-compose.yaml", "/compose.yml", "/compose.yaml"))
    )
    has_compose = any(
        name in lower_paths
        for name in {"docker-compose.yml", "docker-compose.yaml", "compose.yml", "compose.yaml"}
    ) or any(
        path.endswith(("/docker-compose.yml", "/docker-compose.yaml", "/compose.yml", "/compose.yaml"))
        for path in lower_paths
    )
    large_project = source.file_count >= 5000 or source.total_bytes >= 200 * 1024 * 1024
    dynamic_mode = "targeted_optional" if launch_indicators and not large_project else "static_first"
    if large_project:
        dynamic_mode = "large_project_static_first"
    return {
        "default_mode": "static_first",
        "dynamic_mode": dynamic_mode,
        "policy": (
            "不要默认启动整个目标系统。动态验证只用于已确认或高价值候选的最小范围复测；"
            "大型 OA/ERP/多服务项目优先输出静态 PoC、复测步骤、账号/数据/状态前置条件。"
        ),
        "allowed_when": [
            "当前 intent 只覆盖少量已点名候选或已确认 finding",
            "源码自带 docker-compose、启动脚本、测试用例，或用户提供测试环境 URL/账号",
            "验证过程不需要 host 网络、Docker socket、模型 API key 或 Rabbit 内部 token",
        ],
        "blocked_when": [
            "需要启动完整大型系统或多服务环境但缺少依赖/账号/License",
            "需要破坏性写库、批量发包、扫描真实外部资产或访问非测试环境",
            "动态验证会替代源码证据成为唯一依据",
        ],
        "launch_indicators": launch_indicators[:50],
        "has_compose": has_compose,
        "large_project": large_project,
    }


def _focus_candidate_ids(intents, intent_id: str | None) -> set[str]:
    if not intent_id:
        return set()
    for intent in intents:
        if intent["id"] != intent_id:
            continue
        return {match.group(0).lower() for match in CANDIDATE_ID_RE.finditer(intent["description"] or "")}
    return set()


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
def export_project(project_id: str, format: str = "yaml", profile: str = "full", intent_id: str | None = None):
    if format not in ("yaml", "timeline"):
        raise HTTPException(400, "Supported formats: yaml, timeline")
    if profile not in EXPORT_PROFILES:
        raise HTTPException(400, "Supported profiles: full, reason, explore")

    with get_conn() as conn:
        if format == "timeline":
            text = _export_timeline(conn, project_id)
        else:
            text = _export_yaml(conn, project_id, profile=profile, intent_id=intent_id)

        return Response(content=text, media_type="text/plain")
