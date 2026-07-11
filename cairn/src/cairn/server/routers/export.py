from collections import Counter, deque
from fastapi import APIRouter, HTTPException
from fastapi.responses import Response
from datetime import datetime
import hashlib
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
from cairn.server.source_models import (
    CodeCapability,
    CodeEntrypoint,
    CodeFile,
    CodeRelationship,
    CodeSymbol,
    DependencyManifest,
    SourceIndexSummary,
    SourceSnapshot,
)
from cairn.server.source_service import audit_candidate_priority, snapshot_container_path
from cairn.server.audit_tools import build_tool_plan

router = APIRouter(tags=["export"])

EXPORT_PROFILES = {"full", "reason", "explore"}
REASON_CANDIDATE_LIMIT = 200
EXPLORE_CANDIDATE_LIMIT = 120
FULL_CANDIDATE_LIMIT = 1000
REASON_GRAPH_NODE_LIMIT = 200
EXPLORE_GRAPH_NODE_LIMIT = 120
REASON_CONTEXT_MAX_BYTES = 640 * 1024
EXPLORE_CONTEXT_MAX_BYTES = 480 * 1024
REASON_CONTEXT_HARD_MAX_BYTES = 1536 * 1024
EXPLORE_CONTEXT_HARD_MAX_BYTES = 1024 * 1024
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
        "SELECT * FROM facts WHERE project_id = ?", (project_id,)
    ).fetchall()
    hints = conn.execute(
        "SELECT * FROM hints WHERE project_id = ? ORDER BY created_at",
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


def _load_source_snapshots_from_conn(conn, project_id: str) -> list[SourceSnapshot]:
    rows = conn.execute(
        """
        SELECT id, project_id, source_type, original_name, repository_url,
               requested_ref, resolved_commit, archive_sha256, snapshot_sha256,
               status, file_count, total_bytes, detected_languages_json,
               created_at, error_message
        FROM source_snapshots
        WHERE project_id = ?
        ORDER BY created_at DESC
        """,
        (project_id,),
    ).fetchall()
    return [
        SourceSnapshot(
            id=row["id"],
            project_id=row["project_id"],
            source_type=row["source_type"],
            original_name=row["original_name"],
            repository_url=row["repository_url"],
            requested_ref=row["requested_ref"],
            resolved_commit=row["resolved_commit"],
            archive_sha256=row["archive_sha256"],
            snapshot_sha256=row["snapshot_sha256"],
            status=row["status"],
            file_count=row["file_count"],
            total_bytes=row["total_bytes"],
            detected_languages=_decode_json_dict(row["detected_languages_json"]),
            created_at=row["created_at"],
            error_message=row["error_message"],
        )
        for row in rows
    ]


def _load_code_files_from_conn(conn, snapshot_id: str, *, limit: int) -> list[CodeFile]:
    rows = conn.execute(
        """
        SELECT snapshot_id, path, size_bytes, sha256, language, is_binary
        FROM code_files
        WHERE snapshot_id = ?
        ORDER BY path
        LIMIT ?
        """,
        (snapshot_id, limit),
    ).fetchall()
    return [
        CodeFile(
            snapshot_id=row["snapshot_id"],
            path=row["path"],
            size_bytes=row["size_bytes"],
            sha256=row["sha256"],
            language=row["language"],
            is_binary=bool(row["is_binary"]),
        )
        for row in rows
    ]


def _load_source_index_summary_from_conn(conn, snapshot_id: str) -> SourceIndexSummary:
    symbols = conn.execute(
        "SELECT COUNT(*) AS count FROM code_symbols WHERE snapshot_id = ?",
        (snapshot_id,),
    ).fetchone()["count"]
    entrypoints = conn.execute(
        "SELECT COUNT(*) AS count FROM code_entrypoints WHERE snapshot_id = ?",
        (snapshot_id,),
    ).fetchone()["count"]
    relationships = conn.execute(
        "SELECT COUNT(*) AS count FROM code_relationships WHERE snapshot_id = ?",
        (snapshot_id,),
    ).fetchone()["count"]
    manifests = conn.execute(
        "SELECT COUNT(*) AS count FROM dependency_manifests WHERE snapshot_id = ?",
        (snapshot_id,),
    ).fetchone()["count"]
    return SourceIndexSummary(
        symbol_count=symbols,
        entrypoint_count=entrypoints,
        relationship_count=relationships,
        manifest_count=manifests,
    )


def _load_code_entrypoints_from_conn(conn, snapshot_id: str, *, limit: int) -> list[CodeEntrypoint]:
    rows = conn.execute(
        """
        SELECT id, snapshot_id, path, language, kind, framework, method, route,
               handler, line_start, evidence, confidence, source
        FROM code_entrypoints
        WHERE snapshot_id = ?
        ORDER BY path, COALESCE(line_start, 0), route, COALESCE(method, '')
        LIMIT ?
        """,
        (snapshot_id, limit),
    ).fetchall()
    return [CodeEntrypoint(**dict(row)) for row in rows]


def _load_code_relationships_from_conn(conn, snapshot_id: str, *, limit: int) -> list[CodeRelationship]:
    rows = conn.execute(
        """
        SELECT id, snapshot_id, from_path, from_symbol, to_path, to_symbol,
               relation, evidence, confidence, source, line_start
        FROM code_relationships
        WHERE snapshot_id = ?
        ORDER BY from_path, relation, to_path, COALESCE(line_start, 0)
        LIMIT ?
        """,
        (snapshot_id, limit),
    ).fetchall()
    return [CodeRelationship(**dict(row)) for row in rows]


def _load_code_capabilities_from_conn(conn, snapshot_id: str, *, limit: int) -> list[CodeCapability]:
    rows = conn.execute(
        """
        SELECT id, snapshot_id, path, symbol, category, title, line_start,
               line_end, evidence, risk_level, risk_tags_json, confidence, source
        FROM code_capabilities
        WHERE snapshot_id = ?
        ORDER BY
            CASE risk_level
                WHEN 'critical' THEN 0
                WHEN 'high' THEN 1
                WHEN 'medium' THEN 2
                WHEN 'unknown' THEN 3
                WHEN 'low' THEN 4
                ELSE 5
            END,
            path,
            COALESCE(line_start, 0),
            category
        LIMIT ?
        """,
        (snapshot_id, limit),
    ).fetchall()
    return [
        CodeCapability(
            **{
                key: value
                for key, value in dict(row).items()
                if key != "risk_tags_json"
            },
            risk_tags=_decode_json_list(row["risk_tags_json"]),
        )
        for row in rows
    ]


def _load_dependency_manifests_from_conn(conn, snapshot_id: str, *, limit: int) -> list[DependencyManifest]:
    rows = conn.execute(
        """
        SELECT id, snapshot_id, path, manifest_type, package_name,
               dependencies_json, dev_dependencies_json
        FROM dependency_manifests
        WHERE snapshot_id = ?
        ORDER BY path
        LIMIT ?
        """,
        (snapshot_id, limit),
    ).fetchall()
    return [
        DependencyManifest(
            id=row["id"],
            snapshot_id=row["snapshot_id"],
            path=row["path"],
            manifest_type=row["manifest_type"],
            package_name=row["package_name"],
            dependencies=_decode_json_list(row["dependencies_json"]),
            dev_dependencies=_decode_json_list(row["dev_dependencies_json"]),
        )
        for row in rows
    ]


def _load_code_symbols_from_conn(conn, snapshot_id: str, *, limit: int) -> list[CodeSymbol]:
    rows = conn.execute(
        """
        SELECT id, snapshot_id, path, language, kind, name, container, signature,
               line_start, line_end, confidence, source
        FROM code_symbols
        WHERE snapshot_id = ?
        ORDER BY path, COALESCE(line_start, 0), kind, name
        LIMIT ?
        """,
        (snapshot_id, limit),
    ).fetchall()
    return [CodeSymbol(**dict(row)) for row in rows]


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
               source_snapshot_id, confidence, semantic_key, graph_layer,
               source_kind, evidence_status, contributors_json, revision,
               created_by, created_at, updated_at
        FROM business_nodes
        WHERE project_id = ?
        ORDER BY created_at, id
        """,
        (project_id,),
    ).fetchall()
    edges = conn.execute(
        """
        SELECT id, from_node_id, to_node_id, relation, description, confidence,
               graph_layer, source_kind, contributors_json, revision,
               created_by, created_at
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
        WHERE c.project_id = ? AND c.is_current = 1
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
        relation_rank = {
            "guards": 0,
            "exposes": 1,
            "calls": 2,
            "uses": 3,
            "risk_of": 4,
            "depends_on": 5,
        }
        visible_edges = sorted(
            visible_edges,
            key=lambda row: (
                relation_rank.get(row["relation"], 10),
                -float(row["confidence"] or 0),
                row["id"],
            ),
        )[: 80 if profile == "explore" else 120]

    omitted_nodes = max(0, len(nodes) - len(visible_nodes))
    omitted_edges = max(0, len(edges) - len(visible_edges))
    visible_node_ids = {row["id"] for row in visible_nodes}
    if profile != "full":
        conclusions = [
            row for row in conclusions if row["business_node_id"] in visible_node_ids
        ]
    return {
        "coverage": coverage,
        "layers": {
            layer: sum(1 for row in nodes if row["graph_layer"] == layer)
            for layer in ("evidence", "semantic", "audit")
        },
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
                "description": (
                    row["description"] if profile == "full" or row["graph_layer"] != "evidence" else None
                ),
                "risk_level": row["risk_level"],
                "review_status": row["review_status"],
                "coverage_note": (
                    row["coverage_note"]
                    if profile == "full" or row["review_status"] == "blocked"
                    else None
                ),
                "last_intent_id": row["last_intent_id"],
                "risk_tags": _decode_json_list(row["risk_tags_json"]),
                "evidence": _decode_json_list(row["evidence_json"])[
                    : None if profile == "full" else 6
                ],
                "source_snapshot_id": row["source_snapshot_id"],
                "confidence": row["confidence"],
                "semantic_key": row["semantic_key"],
                "graph_layer": row["graph_layer"],
                "source_kind": row["source_kind"],
                "evidence_status": row["evidence_status"],
                **(
                    {
                        "contributors": _decode_json_list(row["contributors_json"]),
                        "revision": row["revision"],
                        "created_by": row["created_by"],
                        "created_at": format_export_timestamp(row["created_at"]),
                        "updated_at": format_export_timestamp(row["updated_at"]),
                    }
                    if profile == "full"
                    else {}
                ),
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
                "graph_layer": row["graph_layer"],
                "source_kind": row["source_kind"],
                **(
                    {
                        "contributors": _decode_json_list(row["contributors_json"]),
                        "revision": row["revision"],
                        "created_by": row["created_by"],
                        "created_at": format_export_timestamp(row["created_at"]),
                    }
                    if profile == "full"
                    else {}
                ),
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
                **(
                    {
                        "created_by": row["created_by"],
                        "created_at": format_export_timestamp(row["created_at"]),
                    }
                    if profile == "full"
                    else {}
                ),
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
        if (
            row["graph_layer"] != "evidence"
            and row["risk_level"] in ("critical", "high", "unknown")
            and row["review_status"] in (
            "unreviewed",
            "investigating",
            "blocked",
            )
        ):
            include_ids.add(row["id"])
    for row in nodes:
        if row["last_intent_id"] and profile == "explore":
            include_ids.add(row["id"])
    adjacent_ids = set(include_ids)
    evidence_neighbor_limit = 40 if profile == "explore" else 30
    evidence_neighbors: set[str] = set()
    for edge in edges:
        if edge["from_node_id"] in include_ids:
            neighbor_id = edge["to_node_id"]
            neighbor = node_by_id.get(neighbor_id)
            if neighbor is None or neighbor["graph_layer"] != "evidence":
                adjacent_ids.add(neighbor_id)
            elif len(evidence_neighbors) < evidence_neighbor_limit:
                adjacent_ids.add(neighbor_id)
                evidence_neighbors.add(neighbor_id)
        if edge["to_node_id"] in include_ids:
            neighbor_id = edge["from_node_id"]
            neighbor = node_by_id.get(neighbor_id)
            if neighbor is None or neighbor["graph_layer"] != "evidence":
                adjacent_ids.add(neighbor_id)
            elif len(evidence_neighbors) < evidence_neighbor_limit:
                adjacent_ids.add(neighbor_id)
                evidence_neighbors.add(neighbor_id)
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
    high_risk_unresolved: list[dict] = []
    invalid_conclusions: list[dict] = []
    for row in rows:
        by_status[row["status"]] = by_status.get(row["status"], 0) + 1
        by_severity[row["severity"]] = by_severity.get(row["severity"], 0) + 1
        is_required = row["severity"] in ("critical", "high", "unknown")
        if is_required and row["status"] in ("candidate", "investigating"):
            open_required.append(_audit_candidate_export_row(row))
        if _is_high_risk_unresolved_candidate(row):
            high_risk_unresolved.append(_audit_candidate_export_row(row))
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
            "high_risk_unresolved": high_risk_unresolved[:200],
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
        focused_business_nodes = {
            row["business_node_id"] for row in focused if row["business_node_id"]
        }
        related = [
            row
            for row in rows
            if row["id"] not in focus_candidate_ids
            and row["status"] in ("candidate", "investigating")
            and (
                row["file_path"] in focused_files
                or (
                    row["business_node_id"]
                    and row["business_node_id"] in focused_business_nodes
                )
            )
        ]
        if focused:
            return (_sort_candidate_rows(focused) + _sort_candidate_rows(related))[:EXPLORE_CANDIDATE_LIMIT]
        required = [
            row
            for row in rows
            if row["severity"] in ("critical", "high", "unknown")
            and row["status"] in ("candidate", "investigating")
            and not _is_navigation_only_candidate(row)
        ]
        return _sort_candidate_rows(required)[:EXPLORE_CANDIDATE_LIMIT]
    required = [
        row
        for row in rows
        if row["severity"] in ("critical", "high", "unknown")
        and row["status"] in ("candidate", "investigating")
        and not _is_navigation_only_candidate(row)
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
    for row in [*_sort_candidate_rows(required), *_sort_candidate_rows(invalid)]:
        if row["id"] in seen:
            continue
        selected.append(row)
        seen.add(row["id"])
        if len(selected) >= REASON_CANDIDATE_LIMIT:
            break
    return selected


def _is_navigation_only_candidate(row) -> bool:
    return row["source"] == "index" and row["candidate_type"] in (
        "entrypoint",
        "web_entrypoint",
    )


def _sort_candidate_rows(rows) -> list:
    return sorted(
        rows,
        key=lambda row: (
            -_candidate_priority(row)["score"],
            _candidate_status_rank(row["status"]),
            row["created_at"] or "",
            row["id"],
        ),
    )


def _candidate_status_rank(status: str | None) -> int:
    return {
        "candidate": 0,
        "investigating": 1,
        "needs_more_evidence": 2,
        "confirmed": 3,
        "rejected": 4,
    }.get(status or "", 9)


def _candidate_priority(row) -> dict:
    return audit_candidate_priority(
        candidate_type=row["candidate_type"],
        severity=row["severity"],
        status=row["status"],
        title=row["title"],
        description=row["description"],
        file_path=row["file_path"],
        line_start=row["line_start"],
        entry_point=row["entry_point"],
        symbol=row["symbol"],
    )


def _is_high_risk_unresolved_candidate(row) -> bool:
    if row["candidate_type"] not in {"data_flow", "capability_chain"}:
        return False
    if row["severity"] not in ("critical", "high", "unknown"):
        return False
    if row["status"] in ("candidate", "investigating"):
        return is_high_impact_audit_candidate_row(row) or row["candidate_type"] == "capability_chain"
    if row["status"] == "needs_more_evidence":
        return _audit_candidate_conclusion_blocker_reason(row) is not None
    return False


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
    priority = _candidate_priority(row)
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
        "risk_score": priority["score"],
        "priority_reasons": priority["reasons"],
        "cluster_key": priority["cluster_key"],
    }


def _load_code_index_audit_context(
    conn,
    project_id: str,
    snapshot_id: str,
    *,
    profile: str,
    focus_candidate_ids: set[str],
) -> dict:
    rows = conn.execute(
        """
        SELECT c.*, af.status AS audit_finding_status
        FROM audit_candidates c
        LEFT JOIN audit_findings af
          ON af.id = c.audit_finding_id
         AND af.project_id = c.project_id
        WHERE c.project_id = ?
          AND c.snapshot_id = ?
          AND c.source = 'index'
        ORDER BY c.created_at, c.id
        """,
        (project_id, snapshot_id),
    ).fetchall()
    selected = _select_audit_candidate_rows(
        rows,
        profile=profile,
        focus_candidate_ids=focus_candidate_ids,
    )
    focused = bool(focus_candidate_ids)
    if profile == "explore":
        candidate_limit = 40 if focused else 20
        file_limit = 16 if focused else 10
    elif profile == "reason":
        candidate_limit = 40
        file_limit = 12
    else:
        candidate_limit = 80
        file_limit = 20
    relationship_limit = 80 if profile == "explore" else 120 if profile == "reason" else 200
    priority_candidates = _sort_candidate_rows(selected)[:candidate_limit]
    paths = _ordered_candidate_paths(priority_candidates)[:file_limit]
    path_set = set(paths)
    entrypoint_traces = _candidate_entrypoint_traces(
        conn,
        snapshot_id,
        priority_candidates,
        max_per_candidate=4 if focused else 3,
    )
    for trace in entrypoint_traces:
        for path in trace.get("path_chain") or []:
            if isinstance(path, str) and path:
                path_set.add(path)
    if path_set:
        path_set.update(_adjacent_paths(conn, snapshot_id, path_set, limit=file_limit * 2))
    paths = [path for path in [*paths, *sorted(path_set - set(paths))] if path][:file_limit]

    entrypoints = _index_rows_for_paths(
        conn,
        snapshot_id,
        "code_entrypoints",
        paths,
        columns="id, path, method, route, handler, line_start, evidence, confidence, source",
        order_by="path, COALESCE(line_start, 0), route, COALESCE(method, '')",
        limit=80,
    )
    capabilities = _index_rows_for_paths(
        conn,
        snapshot_id,
        "code_capabilities",
        paths,
        columns="id, path, symbol, category, title, line_start, evidence, risk_level, risk_tags_json, confidence, source",
        order_by=(
            "CASE risk_level WHEN 'critical' THEN 0 WHEN 'high' THEN 1 WHEN 'medium' THEN 2 ELSE 3 END, "
            "path, COALESCE(line_start, 0), category"
        ),
        limit=120,
    )
    symbols = _index_rows_for_paths(
        conn,
        snapshot_id,
        "code_symbols",
        paths,
        columns="id, path, kind, name, container, signature, line_start, line_end, confidence, source",
        where_extra="AND kind IN ('data_object', 'class', 'function', 'method')",
        order_by="path, kind, COALESCE(line_start, 0), name",
        limit=120,
    )
    relationships = _relationship_rows_for_paths(conn, snapshot_id, paths, limit=relationship_limit)
    module_limit = 3 if profile == "explore" else 4 if profile == "reason" else 30
    if profile == "explore":
        flow_limit = 16 if focused else 10
        entrypoint_summary_limit = 4 if focused else 3
    elif profile == "reason":
        flow_limit = 18
        entrypoint_summary_limit = 4
    else:
        flow_limit = 40
        entrypoint_summary_limit = 40
    module_summaries = _business_module_summaries(conn, project_id, snapshot_id, limit=module_limit)
    compressed_business_graph = _compressed_business_graph(
        conn,
        project_id,
        snapshot_id,
        module_summaries,
        limit=module_limit,
    )
    business_flow_traces = _business_flow_traces(conn, snapshot_id, limit=flow_limit)
    entrypoint_summaries = _entrypoint_business_summaries(
        conn,
        snapshot_id,
        business_flow_traces,
        limit=entrypoint_summary_limit,
    )

    entrypoints_by_path = _group_by_path(entrypoints)
    capabilities_by_path = _group_by_path(capabilities)
    symbols_by_path = _group_by_path(symbols)
    relationships_by_path: dict[str, list] = {}
    for row in relationships:
        relationships_by_path.setdefault(row["from_path"], []).append(row)
        if row["to_path"] != row["from_path"]:
            relationships_by_path.setdefault(row["to_path"], []).append(row)
    planner_focus_packs = _planner_focus_packs(
        conn,
        project_id,
        snapshot_id,
        priority_candidates,
        entrypoint_traces,
        limit=4 if profile == "explore" else 5 if profile == "reason" else 20,
    )

    return {
        "purpose": (
            "给当前 worker 的业务理解索引上下文。先用 module_summaries 和 business_flow_traces 建立模块、"
            "入口、处理逻辑、数据对象、语义边界与依赖链，再用 priority_candidates 定位需要深入阅读的源码。"
            "索引只做导航和事实压缩，不替代 worker 自己阅读源码与判断漏洞类型。"
        ),
        "priority_model": "risk_score 只用于排序：入口可达、高影响能力、输入符号、控制/校验线索和已有结论会改变分数。",
        "focused_candidate_ids": sorted(focus_candidate_ids),
        "compressed_business_graph": compressed_business_graph,
        "module_summaries": module_summaries,
        "entrypoint_summaries": entrypoint_summaries,
        "business_flow_traces": business_flow_traces,
        "audit_packs": planner_focus_packs,
        "planner_focus_packs": planner_focus_packs,
        "priority_candidates": [_candidate_context_item(row) for row in priority_candidates],
        "candidate_entrypoint_traces": entrypoint_traces,
        "entrypoint_traces": entrypoint_traces,
        "file_slices": [
            {
                "path": path,
                "entrypoints": [_entrypoint_context_item(row) for row in entrypoints_by_path.get(path, [])[:12]],
                "capabilities": [_capability_context_item(row) for row in capabilities_by_path.get(path, [])[:12]],
                "symbols": [_symbol_context_item(row) for row in symbols_by_path.get(path, [])[:16]],
                "relationships": [_relationship_context_item(row) for row in relationships_by_path.get(path, [])[:16]],
            }
            for path in paths
        ],
        "omitted": {
            "candidate_count": max(0, len(selected) - len(priority_candidates)),
            "path_count": max(0, len(path_set) - len(paths)),
        },
    }


def _ordered_candidate_paths(rows) -> list[str]:
    paths: list[str] = []
    for row in rows:
        path = row["file_path"]
        if path and path not in paths:
            paths.append(path)
    return paths


def _candidate_entrypoint_traces(conn, snapshot_id: str, candidates, *, max_depth: int = 6, max_per_candidate: int = 3) -> list[dict]:
    target_paths = {row["file_path"] for row in candidates if row["file_path"]}
    if not target_paths:
        return []
    entrypoint_rows = conn.execute(
        """
        SELECT path, method, route, handler, line_start, confidence
        FROM code_entrypoints
        WHERE snapshot_id = ?
        ORDER BY path, COALESCE(line_start, 0), route, COALESCE(method, '')
        LIMIT 5000
        """,
        (snapshot_id,),
    ).fetchall()
    entrypoints_by_path: dict[str, list] = {}
    for row in entrypoint_rows:
        entrypoints_by_path.setdefault(row["path"], []).append(row)
    if not entrypoints_by_path:
        return []
    relationship_rows = conn.execute(
        """
        SELECT from_path, from_symbol, to_path, to_symbol, relation,
               evidence, confidence, source, line_start
        FROM code_relationships
        WHERE snapshot_id = ?
          AND relation IN ('calls', 'imports', 'uses', 'implemented_by', 'extended_by')
        ORDER BY
            CASE relation WHEN 'calls' THEN 0 WHEN 'implemented_by' THEN 1 WHEN 'extended_by' THEN 2 WHEN 'uses' THEN 3 WHEN 'imports' THEN 4 ELSE 5 END,
            confidence DESC,
            from_path,
            to_path,
            COALESCE(line_start, 0)
        LIMIT 20000
        """,
        (snapshot_id,),
    ).fetchall()
    reverse_adjacency: dict[str, list] = {}
    for row in relationship_rows:
        if row["from_path"] == row["to_path"]:
            continue
        reverse_adjacency.setdefault(row["to_path"], []).append(row)

    traces: list[dict] = []
    seen_trace_keys: set[tuple[str, str, tuple[str, ...]]] = set()
    for candidate in candidates:
        candidate_id = candidate["id"]
        target_path = candidate["file_path"]
        if not target_path:
            continue
        direct_entrypoints = entrypoints_by_path.get(target_path, [])
        for entrypoint in direct_entrypoints[:max_per_candidate]:
            item = _entrypoint_trace_item(candidate, entrypoint, [])
            key = (item["candidate_id"], item["entry_point"], tuple(item["path_chain"]))
            if key not in seen_trace_keys:
                traces.append(item)
                seen_trace_keys.add(key)
            if len([trace for trace in traces if trace["candidate_id"] == candidate_id]) >= max_per_candidate:
                break
        if len([trace for trace in traces if trace["candidate_id"] == candidate_id]) >= max_per_candidate:
            continue

        queue: list[tuple[str, list, set[str]]] = [(target_path, [], {target_path})]
        while queue:
            current_path, edges, visited = queue.pop(0)
            if len(edges) >= max_depth:
                continue
            incoming = reverse_adjacency.get(current_path, [])[:30]
            for rel in incoming:
                previous_path = rel["from_path"]
                if not previous_path or previous_path in visited:
                    continue
                next_edges = [rel, *edges]
                if previous_path in entrypoints_by_path:
                    for entrypoint in entrypoints_by_path[previous_path][:2]:
                        item = _entrypoint_trace_item(candidate, entrypoint, next_edges)
                        key = (item["candidate_id"], item["entry_point"], tuple(item["path_chain"]))
                        if key in seen_trace_keys:
                            continue
                        traces.append(item)
                        seen_trace_keys.add(key)
                        if len([trace for trace in traces if trace["candidate_id"] == candidate_id]) >= max_per_candidate:
                            break
                if len([trace for trace in traces if trace["candidate_id"] == candidate_id]) >= max_per_candidate:
                    break
                queue.append((previous_path, next_edges, visited | {previous_path}))
            if len([trace for trace in traces if trace["candidate_id"] == candidate_id]) >= max_per_candidate:
                break
    return traces[: max(20, len(candidates) * max_per_candidate)]


def _business_module_summaries(conn, project_id: str, snapshot_id: str, *, limit: int) -> list[dict]:
    modules = conn.execute(
        """
        SELECT id, node_type, title, description, risk_level, review_status,
               coverage_note, risk_tags_json, evidence_json, source_snapshot_id,
               confidence, created_by
        FROM business_nodes
        WHERE project_id = ?
          AND source_snapshot_id = ?
          AND node_type = 'feature'
          AND title LIKE '业务模块 %'
        ORDER BY confidence DESC, title, id
        LIMIT 400
        """,
        (project_id, snapshot_id),
    ).fetchall()
    if not modules:
        return []

    module_ids = [row["id"] for row in modules]
    placeholders = ",".join("?" for _ in module_ids)
    child_rows = conn.execute(
        f"""
        SELECT e.from_node_id AS module_id,
               e.relation AS module_relation,
               n.id, n.node_type, n.title, n.description, n.risk_level,
               n.review_status, n.coverage_note, n.risk_tags_json,
               n.evidence_json, n.source_snapshot_id, n.confidence,
               n.created_by
        FROM business_edges e
        JOIN business_nodes n
          ON n.id = e.to_node_id
         AND n.project_id = e.project_id
        WHERE e.project_id = ?
          AND e.from_node_id IN ({placeholders})
          AND e.relation = 'contains'
        ORDER BY e.confidence DESC, n.node_type, n.title, n.id
        """,
        (project_id, *module_ids),
    ).fetchall()

    children_by_module: dict[str, list] = {}
    for row in child_rows:
        children_by_module.setdefault(row["module_id"], []).append(row)

    scored_modules = sorted(
        modules,
        key=lambda row: (
            -_business_module_score(row, children_by_module.get(row["id"], [])),
            row["title"],
            row["id"],
        ),
    )[:limit]

    summaries: list[dict] = []
    for module in scored_modules:
        children = children_by_module.get(module["id"], [])
        counts = Counter(row["node_type"] for row in children)
        semantic_boundaries = [row for row in children if _is_semantic_boundary_node(row)]
        control_points = [
            row
            for row in children
            if row["node_type"] == "control" and not _is_semantic_boundary_node(row)
        ]
        child_ids = [row["id"] for row in children]
        internal_edges = _business_module_internal_edges(conn, project_id, child_ids, limit=28)
        relation_counts = Counter(row["relation"] for row in internal_edges)
        summaries.append(
            {
                "id": module["id"],
                "title": module["title"],
                "risk_level": module["risk_level"],
                "review_status": module["review_status"],
                "confidence": module["confidence"],
                "risk_tags": _decode_json_list(module["risk_tags_json"])[:8],
                "evidence": _decode_json_list(module["evidence_json"])[:5],
                "child_counts": dict(sorted(counts.items())),
                "entrypoints": [
                    _business_node_brief(row)
                    for row in children
                    if row["node_type"] == "endpoint"
                ][:6],
                "control_points": [_business_node_brief(row) for row in control_points[:8]],
                "data_objects": [
                    _business_node_brief(row)
                    for row in children
                    if row["node_type"] == "data_object"
                ][:8],
                "semantic_boundaries": [_business_node_brief(row) for row in semantic_boundaries[:8]],
                "risk_threads": [
                    _business_node_brief(row)
                    for row in children
                    if row["node_type"] == "risk"
                ][:8],
                "internal_relations": {
                    "relation_counts": dict(sorted(relation_counts.items())),
                    "edges": [_business_edge_brief(row) for row in internal_edges[:12]],
                },
            }
        )
    return summaries


def _compressed_business_graph(
    conn,
    project_id: str,
    snapshot_id: str,
    module_summaries: list[dict],
    *,
    limit: int,
) -> dict:
    stats = conn.execute(
        """
        SELECT
            (SELECT COUNT(*) FROM business_nodes WHERE project_id = ? AND source_snapshot_id = ?) AS node_count,
            (SELECT COUNT(*)
             FROM business_edges e
             JOIN business_nodes n
               ON n.id = e.from_node_id
              AND n.project_id = e.project_id
             WHERE e.project_id = ? AND n.source_snapshot_id = ?) AS edge_count,
            (SELECT COUNT(*)
             FROM business_nodes
             WHERE project_id = ?
               AND source_snapshot_id = ?
               AND risk_level IN ('critical', 'high', 'unknown')) AS high_risk_node_count,
            (SELECT COUNT(*)
             FROM business_nodes
             WHERE project_id = ?
               AND source_snapshot_id = ?
               AND risk_level IN ('critical', 'high', 'unknown')
               AND review_status IN ('unreviewed', 'investigating', 'blocked')) AS open_high_risk_node_count
        """,
        (
            project_id,
            snapshot_id,
            project_id,
            snapshot_id,
            project_id,
            snapshot_id,
            project_id,
            snapshot_id,
        ),
    ).fetchone()
    open_nodes = conn.execute(
        """
        SELECT id, node_type, title, description, risk_level, review_status,
               coverage_note, risk_tags_json, evidence_json, source_snapshot_id,
               confidence, created_by
        FROM business_nodes
        WHERE project_id = ?
          AND source_snapshot_id = ?
          AND risk_level IN ('critical', 'high', 'unknown')
          AND review_status IN ('unreviewed', 'investigating', 'blocked')
        ORDER BY
            CASE risk_level WHEN 'critical' THEN 0 WHEN 'high' THEN 1 WHEN 'unknown' THEN 2 ELSE 3 END,
            confidence DESC,
            title
        LIMIT ?
        """,
        (project_id, snapshot_id, max(8, limit)),
    ).fetchall()
    node_count = int(stats["node_count"] or 0)
    module_count = len(module_summaries)
    compressed_budget = module_count + int(stats["open_high_risk_node_count"] or 0)
    return {
        "node_count": node_count,
        "edge_count": int(stats["edge_count"] or 0),
        "module_count": module_count,
        "high_risk_node_count": int(stats["high_risk_node_count"] or 0),
        "open_high_risk_node_count": int(stats["open_high_risk_node_count"] or 0),
        "compressed_node_budget": compressed_budget,
        "compression_ratio": round(compressed_budget / max(1, node_count), 3) if node_count else 0.0,
        "top_modules": [
            {
                "id": item["id"],
                "title": item["title"],
                "risk_level": item["risk_level"],
                "review_status": item["review_status"],
                "child_counts": item["child_counts"],
                "semantic_boundary_count": len(item["semantic_boundaries"]),
                "risk_thread_count": len(item["risk_threads"]),
            }
            for item in module_summaries[:limit]
        ],
        "open_high_risk_nodes": [_business_node_brief(row) for row in open_nodes],
        "usage": (
            "先读 top_modules 建立业务分区，再按 open_high_risk_nodes 和 planner_focus_packs 选择审计路径；"
            "不要把压缩图当漏洞结论。"
        ),
    }


def _planner_focus_packs(
    conn,
    project_id: str,
    snapshot_id: str,
    candidates,
    entrypoint_traces: list[dict],
    *,
    limit: int,
) -> list[dict]:
    if not candidates:
        return []
    traces_by_candidate: dict[str, list[dict]] = {}
    for trace in entrypoint_traces:
        candidate_id = trace.get("candidate_id")
        if isinstance(candidate_id, str):
            traces_by_candidate.setdefault(candidate_id, []).append(trace)

    clusters: dict[str, list] = {}
    for row in candidates:
        cluster_key = _candidate_priority(row)["cluster_key"]
        clusters.setdefault(cluster_key, []).append(row)

    business_nodes = _business_nodes_for_candidates(
        conn,
        project_id,
        {row["business_node_id"] for row in candidates if row["business_node_id"]},
    )
    packs: list[dict] = []
    for cluster_key, rows in _select_planner_pack_clusters(clusters, limit=limit):
        sorted_rows = _sort_candidate_rows(rows)
        candidate_ids = {row["id"] for row in sorted_rows}
        traces = [
            trace
            for candidate_id in candidate_ids
            for trace in traces_by_candidate.get(candidate_id, [])
        ][:8]
        source_paths = _ordered_unique(
            [
                *[row["file_path"] for row in sorted_rows if row["file_path"]],
                *[
                    path
                    for trace in traces
                    for path in (trace.get("path_chain") or [])
                    if isinstance(path, str)
                ],
            ]
        )[:18]
        capabilities = _pack_boundary_capabilities(conn, snapshot_id, source_paths)
        data_objects = _pack_data_objects(conn, snapshot_id, source_paths)
        node_ids = [row["business_node_id"] for row in sorted_rows if row["business_node_id"]]
        pack_nodes = [business_nodes[node_id] for node_id in _ordered_unique(node_ids) if node_id in business_nodes]
        ordered_candidate_ids = [row["id"] for row in sorted_rows[:8]]
        capability_family = _candidate_pack_family(sorted_rows)
        packs.append(
            {
                "pack_id": _stable_audit_pack_id(snapshot_id, cluster_key, ordered_candidate_ids),
                "pack_kind": _candidate_pack_kind(sorted_rows),
                "capability_family": capability_family,
                "cluster_key": cluster_key,
                "objective": _audit_pack_objective(capability_family, sorted_rows),
                "risk_score": max(_candidate_priority(row)["score"] for row in sorted_rows),
                "priority_reasons": _ordered_unique(
                    [
                        reason
                        for row in sorted_rows
                        for reason in _candidate_priority(row)["reasons"]
                    ]
                )[:8],
                "candidate_ids": ordered_candidate_ids,
                "candidates": [_candidate_context_item(row) for row in sorted_rows[:6]],
                "source_paths": source_paths,
                "entrypoint_traces": traces,
                "business_nodes": pack_nodes,
                "semantic_boundaries": [_capability_with_path_context_item(row) for row in capabilities[:10]],
                "data_objects": [_symbol_with_path_context_item(row) for row in data_objects[:10]],
                "reading_order": _planner_reading_order(sorted_rows, traces, source_paths),
                "audit_focus": [
                    "确认入口是否外部可达，以及认证、角色、对象边界在哪里执行。",
                    "沿 handler/service/model/DAO 链读取源码，核对状态变化、敏感资产和外部系统调用。",
                    "只把索引用作导航；漏洞类型、可利用性和影响必须由源码证据闭环。",
                ],
            }
        )
    return packs


def _select_planner_pack_clusters(clusters: dict[str, list], *, limit: int) -> list[tuple[str, list]]:
    ranked = sorted(
        clusters.items(),
        key=lambda item: (
            -max(_candidate_priority(row)["score"] for row in item[1]),
            item[0],
        ),
    )
    buckets: dict[str, list[tuple[str, list]]] = {}
    family_order: list[str] = []
    for cluster_key, rows in ranked:
        family = _candidate_pack_family(rows)
        if family not in buckets:
            buckets[family] = []
            family_order.append(family)
        buckets[family].append((cluster_key, rows))

    selected: list[tuple[str, list]] = []
    while len(selected) < limit:
        progressed = False
        for family in family_order:
            bucket = buckets.get(family) or []
            if not bucket:
                continue
            selected.append(bucket.pop(0))
            progressed = True
            if len(selected) >= limit:
                break
        if not progressed:
            break
    return selected


def _stable_audit_pack_id(snapshot_id: str, cluster_key: str, candidate_ids: list[str]) -> str:
    seed = "\0".join([snapshot_id, cluster_key, *candidate_ids])
    return f"pack_{hashlib.sha1(seed.encode('utf-8')).hexdigest()[:16]}"


def _candidate_pack_kind(rows: list) -> str:
    types = {row["candidate_type"] for row in rows}
    if "capability_chain" in types:
        return "capability_family"
    if "data_flow" in types:
        return "data_flow"
    if types:
        return sorted(types)[0]
    return "audit_candidate"


def _candidate_pack_family(rows: list) -> str:
    capability_rows = [row for row in rows if row["candidate_type"] == "capability_chain"]
    if capability_rows:
        return _candidate_title_family(capability_rows[0]["title"]) or "capability_chain"
    data_flow_rows = [row for row in rows if row["candidate_type"] == "data_flow"]
    if data_flow_rows:
        return _candidate_title_family(data_flow_rows[0]["title"]) or "data_flow"
    if rows:
        return rows[0]["candidate_type"] or "audit_candidate"
    return "audit_candidate"


def _candidate_title_family(title: str | None) -> str | None:
    if not title:
        return None
    text = title.strip()
    for prefix in ("审计能力链:", "审计数据流: 外部输入到"):
        if text.startswith(prefix):
            rest = text[len(prefix) :].strip()
            if not rest:
                return None
            return rest.split()[0]
    return None


def _audit_pack_objective(capability_family: str, rows: list) -> str:
    candidate_ids = ", ".join(row["id"] for row in rows[:4])
    return (
        f"围绕 {capability_family} 阅读源码闭环候选 {candidate_ids}："
        "确认入口可达性、权限/对象边界、关键数据流、能力调用前后的校验与真实影响；"
        "索引只作为导航，不直接决定漏洞类型。"
    )


def _business_nodes_for_candidates(conn, project_id: str, node_ids: set[str]) -> dict[str, dict]:
    if not node_ids:
        return {}
    usable_ids = sorted(node_ids)[:120]
    rows = conn.execute(
        f"""
        SELECT id, node_type, title, description, risk_level, review_status,
               coverage_note, risk_tags_json, evidence_json, source_snapshot_id,
               confidence, created_by
        FROM business_nodes
        WHERE project_id = ?
          AND id IN ({','.join('?' for _ in usable_ids)})
        """,
        (project_id, *usable_ids),
    ).fetchall()
    return {row["id"]: _business_node_brief(row) for row in rows}


def _pack_boundary_capabilities(conn, snapshot_id: str, paths: list[str]) -> list:
    if not paths:
        return []
    return _index_rows_for_paths(
        conn,
        snapshot_id,
        "code_capabilities",
        paths[:30],
        columns="id, path, symbol, category, title, line_start, evidence, risk_level, risk_tags_json, confidence, source",
        where_extra=(
            "AND (risk_level IN ('critical', 'high') OR category IN ("
            "'auth_guard', 'object_scope_guard', 'object_id_lookup', 'file_upload', "
            "'file_write', 'file_read', 'archive_extract', 'process_execution', "
            "'task_execution', 'credential_access', 'external_system', 'websocket_boundary'))"
        ),
        order_by=(
            "CASE risk_level WHEN 'critical' THEN 0 WHEN 'high' THEN 1 WHEN 'medium' THEN 2 ELSE 3 END, "
            "path, COALESCE(line_start, 0), category"
        ),
        limit=80,
    )


def _pack_data_objects(conn, snapshot_id: str, paths: list[str]) -> list:
    if not paths:
        return []
    return _index_rows_for_paths(
        conn,
        snapshot_id,
        "code_symbols",
        paths[:30],
        columns="id, path, kind, name, container, signature, line_start, line_end, confidence, source",
        where_extra="AND kind = 'data_object'",
        order_by="path, COALESCE(line_start, 0), name",
        limit=80,
    )


def _planner_reading_order(candidates, traces: list[dict], source_paths: list[str]) -> list[str]:
    paths = []
    for trace in traces:
        paths.extend(path for path in trace.get("path_chain") or [] if isinstance(path, str))
    paths.extend(row["file_path"] for row in candidates if row["file_path"])
    paths.extend(source_paths)
    return _ordered_unique(paths)[:12]


def _ordered_unique(values) -> list:
    result: list = []
    seen: set = set()
    for value in values:
        if value is None or value == "" or value in seen:
            continue
        result.append(value)
        seen.add(value)
    return result


def _business_module_score(module, children: list) -> float:
    counts = Counter(row["node_type"] for row in children)
    boundary_count = sum(1 for row in children if _is_semantic_boundary_node(row))
    high_risk_count = sum(1 for row in children if row["risk_level"] in {"critical", "high", "unknown"})
    return (
        counts["endpoint"] * 6
        + counts["control"] * 3
        + counts["data_object"] * 3
        + counts["asset"] * 4
        + counts["external_system"] * 4
        + counts["risk"] * 5
        + boundary_count * 4
        + high_risk_count * 2
        + float(module["confidence"] or 0) * 2
    )


def _business_module_internal_edges(conn, project_id: str, child_ids: list[str], *, limit: int) -> list:
    if len(child_ids) < 2:
        return []
    usable_ids = child_ids[:300]
    placeholders = ",".join("?" for _ in usable_ids)
    return conn.execute(
        f"""
        SELECT id, from_node_id, to_node_id, relation, description, confidence, created_by
        FROM business_edges
        WHERE project_id = ?
          AND relation != 'contains'
          AND from_node_id IN ({placeholders})
          AND to_node_id IN ({placeholders})
        ORDER BY
            CASE relation WHEN 'calls' THEN 0 WHEN 'uses' THEN 1 WHEN 'guards' THEN 2 WHEN 'depends_on' THEN 3 ELSE 4 END,
            confidence DESC,
            from_node_id,
            to_node_id
        LIMIT ?
        """,
        (project_id, *usable_ids, *usable_ids, limit),
    ).fetchall()


def _is_semantic_boundary_node(row) -> bool:
    tags = set(_decode_json_list(row["risk_tags_json"]))
    if row["node_type"] in {"asset", "external_system"}:
        return True
    return bool(
        tags
        & {
            "权限边界",
            "对象边界",
            "文件生命周期",
            "执行边界",
            "敏感资产",
            "外部系统",
        }
    )


def _business_node_brief(row) -> dict:
    return {
        "id": row["id"],
        "type": row["node_type"],
        "title": row["title"],
        "risk_level": row["risk_level"],
        "review_status": row["review_status"],
        "risk_tags": _decode_json_list(row["risk_tags_json"]),
        "evidence": _decode_json_list(row["evidence_json"])[:3],
        "confidence": row["confidence"],
        "semantic_key": _row_value(row, "semantic_key"),
        "graph_layer": _row_value(row, "graph_layer", "semantic"),
        "evidence_status": _row_value(row, "evidence_status", "unverified"),
    }


def _business_edge_brief(row) -> dict:
    return {
        "id": row["id"],
        "from": row["from_node_id"],
        "to": row["to_node_id"],
        "relation": row["relation"],
        "description": row["description"],
        "confidence": row["confidence"],
        "graph_layer": _row_value(row, "graph_layer", "semantic"),
    }


def _row_value(row, key: str, default=None):
    return row[key] if key in row.keys() else default


def _business_flow_traces(conn, snapshot_id: str, *, limit: int, max_depth: int = 4, max_per_entrypoint: int = 2) -> list[dict]:
    entrypoint_rows = conn.execute(
        """
        SELECT path, method, route, handler, line_start, evidence, confidence, source
        FROM code_entrypoints
        WHERE snapshot_id = ?
        ORDER BY path, COALESCE(line_start, 0), route, COALESCE(method, '')
        LIMIT 3000
        """,
        (snapshot_id,),
    ).fetchall()
    if not entrypoint_rows:
        return []
    relationship_rows = conn.execute(
        """
        SELECT from_path, from_symbol, to_path, to_symbol, relation,
               evidence, confidence, source, line_start
        FROM code_relationships
        WHERE snapshot_id = ?
          AND relation IN ('calls', 'imports', 'uses', 'implemented_by', 'extended_by')
        ORDER BY
            CASE relation WHEN 'calls' THEN 0 WHEN 'implemented_by' THEN 1 WHEN 'extended_by' THEN 2 WHEN 'uses' THEN 3 WHEN 'imports' THEN 4 ELSE 5 END,
            confidence DESC,
            from_path,
            to_path,
            COALESCE(line_start, 0)
        LIMIT 20000
        """,
        (snapshot_id,),
    ).fetchall()
    adjacency: dict[str, list] = {}
    for row in relationship_rows:
        if not row["from_path"] or not row["to_path"] or row["from_path"] == row["to_path"]:
            continue
        adjacency.setdefault(row["from_path"], []).append(row)

    traces: list[dict] = []
    seen_trace_keys: set[tuple[str, tuple[str, ...]]] = set()
    max_candidates_per_entrypoint = max(24, max_per_entrypoint * 12)
    max_expansions_per_entrypoint = 240
    max_queue_size = 240
    for entrypoint in entrypoint_rows:
        entrypoint_traces: list[dict] = []
        entrypoint_seen: set[tuple[str, tuple[str, ...]]] = set()
        queue = deque([(entrypoint["path"], [], {entrypoint["path"]})])
        expansions = 0
        while queue and expansions < max_expansions_per_entrypoint:
            current_path, edges, visited = queue.popleft()
            expansions += 1
            if len(edges) >= max_depth:
                continue
            for rel in adjacency.get(current_path, [])[:24]:
                next_path = rel["to_path"]
                if not next_path or next_path in visited:
                    continue
                next_edges = [*edges, rel]
                item = _business_flow_trace_item(entrypoint, next_edges)
                key = (item["entry_point"], tuple(item["path_chain"]))
                if key not in entrypoint_seen:
                    entrypoint_traces.append(item)
                    entrypoint_seen.add(key)
                    if len(entrypoint_traces) >= max_candidates_per_entrypoint:
                        break
                if len(next_edges) < max_depth and len(queue) < max_queue_size:
                    queue.append((next_path, next_edges, visited | {next_path}))
            if len(entrypoint_traces) >= max_candidates_per_entrypoint:
                break
        for item in sorted(entrypoint_traces, key=_business_flow_trace_rank)[:max_per_entrypoint]:
            key = (item["entry_point"], tuple(item["path_chain"]))
            if key in seen_trace_keys:
                continue
            traces.append(item)
            seen_trace_keys.add(key)
            if len(traces) >= limit:
                return traces
    return traces


def _business_flow_trace_rank(item: dict) -> tuple[int, int, int, float, str]:
    hops = item.get("hops") or []
    call_count = sum(1 for hop in hops if hop.get("relation") == "calls")
    hierarchy_count = sum(1 for hop in hops if hop.get("relation") in {"implemented_by", "extended_by"})
    import_count = sum(1 for hop in hops if hop.get("relation") == "imports")
    path_chain = item.get("path_chain") or []
    return (
        -len(path_chain),
        -call_count,
        -hierarchy_count,
        import_count,
        -float(item.get("confidence") or 0),
        " -> ".join(str(path) for path in path_chain),
    )


def _entrypoint_business_summaries(conn, snapshot_id: str, traces: list[dict], *, limit: int) -> list[dict]:
    entrypoint_rows = conn.execute(
        """
        SELECT path, method, route, handler, line_start, evidence, confidence, source
        FROM code_entrypoints
        WHERE snapshot_id = ?
        ORDER BY path, COALESCE(line_start, 0), route, COALESCE(method, '')
        LIMIT 3000
        """,
        (snapshot_id,),
    ).fetchall()
    if not entrypoint_rows:
        return []
    traces_by_entrypoint: dict[str, list[dict]] = {}
    for trace in traces:
        traces_by_entrypoint.setdefault(trace["entry_point"], []).append(trace)
    summaries: list[dict] = []
    for entrypoint in entrypoint_rows[:limit]:
        label = _entrypoint_label(entrypoint["method"], entrypoint["route"])
        related_traces = traces_by_entrypoint.get(label, [])
        reachable_paths = _entrypoint_reachable_paths(conn, snapshot_id, entrypoint["path"], related_traces)
        paths = reachable_paths[:20]
        capabilities = _index_rows_for_paths(
            conn,
            snapshot_id,
            "code_capabilities",
            paths,
            columns="id, path, symbol, category, title, line_start, evidence, risk_level, risk_tags_json, confidence, source",
            order_by=(
                "CASE risk_level WHEN 'critical' THEN 0 WHEN 'high' THEN 1 WHEN 'medium' THEN 2 ELSE 3 END, "
                "path, COALESCE(line_start, 0), category"
            ),
            limit=80,
        )
        data_objects = _index_rows_for_paths(
            conn,
            snapshot_id,
            "code_symbols",
            paths,
            columns="id, path, kind, name, container, signature, line_start, line_end, confidence, source",
            where_extra="AND kind = 'data_object'",
            order_by="path, COALESCE(line_start, 0), name",
            limit=80,
        )
        relationships = _relationship_rows_for_paths(conn, snapshot_id, paths, limit=120)
        relationship_counts = Counter(row["relation"] for row in relationships)
        capability_counts = Counter(row["category"] for row in capabilities)
        boundary_capabilities = [
            row
            for row in capabilities
            if row["category"]
            in {
                "auth_guard",
                "object_scope_guard",
                "object_id_lookup",
                "file_upload",
                "file_write",
                "file_read",
                "archive_extract",
                "process_execution",
                "task_execution",
                "credential_access",
                "external_system",
                "websocket_boundary",
            }
        ]
        summaries.append(
            {
                "entry_point": label,
                "handler": entrypoint["handler"],
                "start_path": entrypoint["path"],
                "start_line": entrypoint["line_start"],
                "reachable_paths": reachable_paths[:14],
                "flow_count": len(related_traces),
                "relationship_counts": dict(sorted(relationship_counts.items())),
                "capability_counts": dict(sorted(capability_counts.items())),
                "data_objects": [_symbol_with_path_context_item(row) for row in data_objects[:10]],
                "semantic_boundaries": [_capability_with_path_context_item(row) for row in boundary_capabilities[:10]],
                "representative_flows": related_traces[:3],
            }
        )
    return sorted(
        summaries,
        key=lambda item: (
            -len(item["reachable_paths"]),
            -sum(item["relationship_counts"].values()),
            item["entry_point"],
        ),
    )


def _entrypoint_reachable_paths(conn, snapshot_id: str, start_path: str, traces: list[dict]) -> list[str]:
    paths = [start_path]
    for trace in traces:
        for path in trace.get("path_chain") or []:
            if path and path not in paths:
                paths.append(path)
    for path in _entrypoint_graph_reachable_paths(conn, snapshot_id, start_path):
        if path and path not in paths:
            paths.append(path)
    return paths


def _entrypoint_graph_reachable_paths(
    conn,
    snapshot_id: str,
    start_path: str,
    *,
    max_depth: int = 5,
    max_paths: int = 36,
    fanout: int = 24,
) -> list[str]:
    if not start_path:
        return []
    relationship_rows = conn.execute(
        """
        SELECT from_path, to_path, relation, confidence, line_start
        FROM code_relationships
        WHERE snapshot_id = ?
          AND relation IN (
            'calls', 'uses', 'imports',
            'implements', 'implemented_by', 'extends', 'extended_by'
          )
        ORDER BY
            CASE relation
                WHEN 'calls' THEN 0
                WHEN 'implemented_by' THEN 1
                WHEN 'extended_by' THEN 2
                WHEN 'uses' THEN 3
                WHEN 'implements' THEN 4
                WHEN 'extends' THEN 5
                WHEN 'imports' THEN 6
                ELSE 7
            END,
            confidence DESC,
            from_path,
            to_path,
            COALESCE(line_start, 0)
        LIMIT 50000
        """,
        (snapshot_id,),
    ).fetchall()
    adjacency: dict[str, list] = {}
    for row in relationship_rows:
        if not row["from_path"] or not row["to_path"] or row["from_path"] == row["to_path"]:
            continue
        adjacency.setdefault(row["from_path"], []).append(row)

    reachable: list[str] = [start_path]
    visited: set[str] = {start_path}
    queue: list[tuple[str, int]] = [(start_path, 0)]
    while queue and len(reachable) < max_paths:
        current_path, depth = queue.pop(0)
        if depth >= max_depth:
            continue
        for rel in adjacency.get(current_path, [])[:fanout]:
            next_path = rel["to_path"]
            if not next_path or next_path in visited:
                continue
            visited.add(next_path)
            reachable.append(next_path)
            if len(reachable) >= max_paths:
                break
            queue.append((next_path, depth + 1))
    return reachable


def _symbol_with_path_context_item(row) -> dict:
    item = _symbol_context_item(row)
    item["path"] = row["path"]
    return item


def _capability_with_path_context_item(row) -> dict:
    item = _capability_context_item(row)
    item["path"] = row["path"]
    return item


def _business_flow_trace_item(entrypoint, edges: list) -> dict:
    label = _entrypoint_label(entrypoint["method"], entrypoint["route"])
    path_chain = [entrypoint["path"]]
    hops = []
    confidence_values = [float(entrypoint["confidence"] or 0.65)]
    for edge in edges:
        if edge["to_path"] and edge["to_path"] != path_chain[-1]:
            path_chain.append(edge["to_path"])
        confidence_values.append(float(edge["confidence"] or 0.5))
        hops.append(
            {
                "from_path": edge["from_path"],
                "from_symbol": edge["from_symbol"],
                "relation": edge["relation"],
                "to_path": edge["to_path"],
                "to_symbol": edge["to_symbol"],
                "line_start": edge["line_start"],
                "evidence": edge["evidence"],
                "confidence": edge["confidence"],
                "source": edge["source"],
            }
        )
    return {
        "entry_point": label,
        "handler": entrypoint["handler"],
        "start_path": entrypoint["path"],
        "start_line": entrypoint["line_start"],
        "path_chain": path_chain,
        "hops": hops,
        "confidence": round(min(confidence_values), 3) if confidence_values else 0.0,
    }


def _entrypoint_trace_item(candidate, entrypoint, edges: list) -> dict:
    label = _entrypoint_label(entrypoint["method"], entrypoint["route"])
    path_chain = [entrypoint["path"]]
    hops = []
    confidence_values = [float(entrypoint["confidence"] or 0.65)]
    for edge in edges:
        if edge["to_path"] and edge["to_path"] != path_chain[-1]:
            path_chain.append(edge["to_path"])
        elif edge["to_path"] and edge["to_path"] == path_chain[-1]:
            pass
        confidence_values.append(float(edge["confidence"] or 0.5))
        hops.append(
            {
                "from_path": edge["from_path"],
                "from_symbol": edge["from_symbol"],
                "relation": edge["relation"],
                "to_path": edge["to_path"],
                "to_symbol": edge["to_symbol"],
                "line_start": edge["line_start"],
                "evidence": edge["evidence"],
                "confidence": edge["confidence"],
                "source": edge["source"],
            }
        )
    if not edges and candidate["file_path"] and candidate["file_path"] != path_chain[-1]:
        path_chain.append(candidate["file_path"])
    return {
        "candidate_id": candidate["id"],
        "entry_point": label,
        "target_path": candidate["file_path"],
        "target_line": candidate["line_start"],
        "path_chain": path_chain,
        "hops": hops,
        "confidence": round(min(confidence_values), 3) if confidence_values else 0.0,
    }


def _entrypoint_label(method: str | None, route: str) -> str:
    route_text = route.strip() or "/"
    return f"{method} {route_text}" if method else route_text


def _adjacent_paths(conn, snapshot_id: str, paths: set[str], *, limit: int) -> set[str]:
    if not paths:
        return set()
    placeholders = ",".join("?" for _ in paths)
    rows = conn.execute(
        f"""
        SELECT from_path, to_path
        FROM code_relationships
        WHERE snapshot_id = ?
          AND (from_path IN ({placeholders}) OR to_path IN ({placeholders}))
        ORDER BY confidence DESC, from_path, to_path
        LIMIT ?
        """,
        (snapshot_id, *sorted(paths), *sorted(paths), limit),
    ).fetchall()
    result: set[str] = set()
    for row in rows:
        if row["from_path"]:
            result.add(row["from_path"])
        if row["to_path"]:
            result.add(row["to_path"])
    return result


def _index_rows_for_paths(
    conn,
    snapshot_id: str,
    table: str,
    paths: list[str],
    *,
    columns: str,
    order_by: str,
    limit: int,
    where_extra: str = "",
):
    if not paths:
        return []
    placeholders = ",".join("?" for _ in paths)
    return conn.execute(
        f"""
        SELECT {columns}
        FROM {table}
        WHERE snapshot_id = ?
          AND path IN ({placeholders})
          {where_extra}
        ORDER BY {order_by}
        LIMIT ?
        """,
        (snapshot_id, *paths, limit),
    ).fetchall()


def _relationship_rows_for_paths(conn, snapshot_id: str, paths: list[str], *, limit: int):
    if not paths:
        return []
    placeholders = ",".join("?" for _ in paths)
    return conn.execute(
        f"""
        SELECT id, from_path, from_symbol, to_path, to_symbol, relation,
               evidence, confidence, source, line_start
        FROM code_relationships
        WHERE snapshot_id = ?
          AND (from_path IN ({placeholders}) OR to_path IN ({placeholders}))
        ORDER BY
            CASE relation WHEN 'calls' THEN 0 WHEN 'uses' THEN 1 WHEN 'imports' THEN 2 ELSE 3 END,
            confidence DESC,
            from_path,
            to_path,
            COALESCE(line_start, 0)
        LIMIT ?
        """,
        (snapshot_id, *paths, *paths, limit),
    ).fetchall()


def _group_by_path(rows) -> dict[str, list]:
    result: dict[str, list] = {}
    for row in rows:
        result.setdefault(row["path"], []).append(row)
    return result


def _candidate_context_item(row) -> dict:
    item = _audit_candidate_export_row(row)
    return {
        key: item[key]
        for key in (
            "id",
            "candidate_type",
            "severity",
            "status",
            "risk_score",
            "priority_reasons",
            "cluster_key",
            "title",
            "file_path",
            "line_start",
            "line_end",
            "entry_point",
            "symbol",
            "business_node_id",
        )
    }


def _entrypoint_context_item(row) -> dict:
    return {
        "id": row["id"],
        "method": row["method"],
        "route": row["route"],
        "handler": row["handler"],
        "line_start": row["line_start"],
        "evidence": row["evidence"],
        "confidence": row["confidence"],
        "source": row["source"],
    }


def _capability_context_item(row) -> dict:
    return {
        "id": row["id"],
        "symbol": row["symbol"],
        "category": row["category"],
        "title": row["title"],
        "line_start": row["line_start"],
        "evidence": row["evidence"],
        "risk_level": row["risk_level"],
        "risk_tags": _decode_json_list(row["risk_tags_json"]),
        "confidence": row["confidence"],
        "source": row["source"],
    }


def _symbol_context_item(row) -> dict:
    return {
        "id": row["id"],
        "kind": row["kind"],
        "name": row["name"],
        "container": row["container"],
        "signature": row["signature"],
        "line_start": row["line_start"],
        "line_end": row["line_end"],
        "confidence": row["confidence"],
        "source": row["source"],
    }


def _relationship_context_item(row) -> dict:
    return {
        "id": row["id"],
        "from_path": row["from_path"],
        "from_symbol": row["from_symbol"],
        "to_path": row["to_path"],
        "to_symbol": row["to_symbol"],
        "relation": row["relation"],
        "evidence": row["evidence"],
        "line_start": row["line_start"],
        "confidence": row["confidence"],
        "source": row["source"],
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
        "budgets": _profile_budgets(profile),
        "note": (
            "This export is intentionally scoped for the current audit phase. "
            "Use database-backed coverage sections as the source of truth; omitted graph items remain stored server-side."
        ),
    }
    sources = _load_source_snapshots_from_conn(conn, project_id)
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
            files = _load_code_files_from_conn(conn, ready_source.id, limit=20_000)
            index_summary = _load_source_index_summary_from_conn(conn, ready_source.id)
            data["validation_strategy"] = _validation_strategy(ready_source, files)
            data["audit_tool_plan"] = [
                item.as_dict()
                for item in build_tool_plan(ready_source, files, source_path)
            ]
            index_limit = _code_index_limit(profile)
            entrypoints = _load_code_entrypoints_from_conn(conn, ready_source.id, limit=index_limit)
            relationships = _load_code_relationships_from_conn(conn, ready_source.id, limit=index_limit)
            capabilities = _load_code_capabilities_from_conn(conn, ready_source.id, limit=index_limit)
            manifests = _load_dependency_manifests_from_conn(conn, ready_source.id, limit=index_limit)
            symbols = _load_code_symbols_from_conn(conn, ready_source.id, limit=index_limit)
            data["code_index"] = {
                "summary": index_summary.model_dump(),
                "view": {
                    "profile": profile,
                    "limit": index_limit,
                    "entrypoints_included": len(entrypoints),
                    "relationships_included": len(relationships),
                    "capabilities_included": len(capabilities),
                    "symbols_included": len(symbols),
                    "manifests_included": len(manifests),
                },
            }
            if profile == "full":
                data["code_index"].update(
                    {
                        "entrypoints": [item.model_dump() for item in entrypoints],
                        "relationships": [item.model_dump() for item in relationships],
                        "capabilities": [item.model_dump() for item in capabilities],
                        "dependency_manifests": [item.model_dump() for item in manifests],
                        "symbols_sample": [item.model_dump() for item in symbols],
                    }
                )
            data["code_index"]["audit_context"] = _load_code_index_audit_context(
                conn,
                project_id,
                ready_source.id,
                profile=profile,
                focus_candidate_ids=focus_candidate_ids,
            )
            if profile != "full":
                data["code_index"]["audit_context"].pop("audit_packs", None)
                data["code_index"]["audit_context"].pop(
                    "candidate_entrypoint_traces", None
                )

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
    if profile != "full":
        tool_findings = [
            row
            for row in tool_findings
            if row["status"] == "candidate" or row["severity"] in ("critical", "high")
        ][:80 if profile == "reason" else 30]
    if tool_findings:
        data["tool_findings"] = [dict(row) for row in tool_findings]

    audit_findings = conn.execute(
        """
        SELECT id, snapshot_id, cluster_key, title, category, severity, status, cwe, file_path,
               line_start, line_end, symbol, entry_point, business_node_id,
               evidence_level, description, impact, evidence, proof_packets_json,
               reproduction_poc_json, remediation,
               discovered_by, reviewed_by
        FROM audit_findings
        WHERE project_id = ?
        ORDER BY created_at, id
        """,
        (project_id,),
    ).fetchall()
    if profile != "full":
        audit_findings = _select_context_audit_findings(
            conn,
            project_id,
            audit_findings,
            profile=profile,
            focus_candidate_ids=focus_candidate_ids,
        )
    if audit_findings:
        data["audit_findings"] = [
            {
                **{
                    key: value
                    for key, value in dict(row).items()
                    if key not in ("proof_packets_json", "reproduction_poc_json")
                },
                **(
                    {
                        "proof_packets": _decode_json_list(row["proof_packets_json"]),
                        "reproduction_poc": _decode_json_dict(row["reproduction_poc_json"]),
                    }
                    if profile == "full"
                    else {}
                ),
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
                "id": h["id"],
                "content": h["content"],
                "creator": h["creator"],
                "created_at": format_export_timestamp(h["created_at"]),
                "hint_type": h["hint_type"],
                "target": h["target"],
                "priority": h["priority"],
                "expires_at": format_export_timestamp(h["expires_at"]),
                "max_uses": h["max_uses"],
                "use_count": h["use_count"],
            }
            for h in hints
        ]

    scoped_facts, scoped_intents = _scope_blackboard_history(
        facts,
        intents,
        sources_by_intent,
        profile=profile,
        intent_id=intent_id,
    )
    data["facts"] = [
        {
            "id": f["id"],
            "description": f["description"],
            "fact_type": f["fact_type"],
            "source": f["source"],
            "confidence": f["confidence"],
            "evidence_refs": _decode_json_list(f["evidence_refs_json"]),
            "parent_fact_ids": _decode_json_list(f["parent_fact_ids_json"]),
            "fingerprint": f["fingerprint"],
        }
        for f in scoped_facts
    ]

    intent_list = []
    for i in scoped_intents:
        entry: dict = {
            "id": i["id"],
            "from": sources_by_intent.get(i["id"], []),
            "to": i["to_fact_id"],
            "description": i["description"],
            "creator": i["creator"],
            "worker": i["worker"],
            "created_at": format_export_timestamp(i["created_at"]),
            "concluded_at": format_export_timestamp(i["concluded_at"]),
            "fingerprint": i["fingerprint"],
            "status": i["status"],
            "superseded_by": i["superseded_by"],
            "target_kind": i["target_kind"],
            "target_id": i["target_id"],
            "objective": i["objective"],
            "evidence_gap": i["evidence_gap"],
        }
        intent_list.append(entry)

    if intent_list:
        data["intents"] = intent_list
    data["context_profile"]["required_fact_ids"] = sorted(
        {
            "origin",
            "goal",
            *(
                fact_id
                for intent in intent_list
                if intent["status"] in ("open", "claimed", "cooldown")
                or intent["id"] == intent_id
                for fact_id in intent["from"]
            ),
        }
    )
    if profile != "full":
        _compact_coverage_details(data)

    text = yaml.dump(data, allow_unicode=True, default_flow_style=False, sort_keys=False)
    max_bytes = _context_max_bytes(profile)
    if max_bytes is not None and len(text.encode("utf-8")) > max_bytes:
        text = _fit_context_to_budget(
            data,
            profile,
            max_bytes,
            hard_max_bytes=_context_hard_max_bytes(profile),
        )
    return text


def _code_index_limit(profile: str) -> int:
    if profile == "explore":
        return 300
    if profile == "reason":
        return 500
    return 1000


def _profile_budgets(profile: str) -> dict[str, int | None]:
    if profile == "explore":
        return {
            "audit_candidate_limit": EXPLORE_CANDIDATE_LIMIT,
            "business_graph_node_limit": EXPLORE_GRAPH_NODE_LIMIT,
            "code_index_limit": _code_index_limit(profile),
            "max_context_bytes": EXPLORE_CONTEXT_MAX_BYTES,
            "hard_max_context_bytes": EXPLORE_CONTEXT_HARD_MAX_BYTES,
        }
    if profile == "reason":
        return {
            "audit_candidate_limit": REASON_CANDIDATE_LIMIT,
            "business_graph_node_limit": REASON_GRAPH_NODE_LIMIT,
            "code_index_limit": _code_index_limit(profile),
            "max_context_bytes": REASON_CONTEXT_MAX_BYTES,
            "hard_max_context_bytes": REASON_CONTEXT_HARD_MAX_BYTES,
        }
    return {
        "audit_candidate_limit": FULL_CANDIDATE_LIMIT,
        "business_graph_node_limit": None,
        "code_index_limit": _code_index_limit(profile),
        "max_context_bytes": None,
        "hard_max_context_bytes": None,
    }


def _context_max_bytes(profile: str) -> int | None:
    if profile == "explore":
        return EXPLORE_CONTEXT_MAX_BYTES
    if profile == "reason":
        return REASON_CONTEXT_MAX_BYTES
    return None


def _context_hard_max_bytes(profile: str) -> int | None:
    if profile == "explore":
        return EXPLORE_CONTEXT_HARD_MAX_BYTES
    if profile == "reason":
        return REASON_CONTEXT_HARD_MAX_BYTES
    return None


def _scope_blackboard_history(
    facts,
    intents,
    sources_by_intent: dict[str, list[str]],
    *,
    profile: str,
    intent_id: str | None,
):
    if profile == "full":
        return list(facts), list(intents)
    active_statuses = {"open", "claimed", "cooldown"}
    selected_intents = [
        row
        for row in intents
        if row["id"] == intent_id or row["status"] in active_statuses
    ]
    history_limit = 30 if profile == "reason" else 8
    for row in reversed(intents):
        if row not in selected_intents:
            selected_intents.append(row)
        if len(selected_intents) >= history_limit:
            break
    selected_intent_ids = {row["id"] for row in selected_intents}
    required_fact_ids = {"origin", "goal"}
    for selected_id in selected_intent_ids:
        required_fact_ids.update(sources_by_intent.get(selected_id, []))
    fact_by_id = {row["id"]: row for row in facts}
    pending = list(required_fact_ids)
    while pending:
        fact_id = pending.pop()
        row = fact_by_id.get(fact_id)
        if row is None:
            continue
        for parent_id in _decode_json_list(row["parent_fact_ids_json"]):
            if parent_id not in required_fact_ids:
                required_fact_ids.add(parent_id)
                pending.append(parent_id)
    fact_limit = 100 if profile == "reason" else 40
    selected_facts = [row for row in facts if row["id"] in required_fact_ids]
    for row in reversed(facts):
        if row not in selected_facts:
            selected_facts.append(row)
        if len(selected_facts) >= fact_limit:
            break
    return selected_facts, selected_intents


def _select_context_audit_findings(
    conn,
    project_id: str,
    rows,
    *,
    profile: str,
    focus_candidate_ids: set[str],
):
    if profile == "reason" or not focus_candidate_ids:
        limit = 200 if profile == "reason" else 40
        return list(rows[-limit:])
    placeholders = ",".join("?" for _ in focus_candidate_ids)
    focus_rows = conn.execute(
        f"""
        SELECT file_path, business_node_id
        FROM audit_candidates
        WHERE project_id = ? AND id IN ({placeholders})
        """,
        (project_id, *sorted(focus_candidate_ids)),
    ).fetchall()
    paths = {row["file_path"] for row in focus_rows if row["file_path"]}
    node_ids = {row["business_node_id"] for row in focus_rows if row["business_node_id"]}
    selected = [
        row
        for row in rows
        if row["file_path"] in paths
        or (row["business_node_id"] and row["business_node_id"] in node_ids)
        or row["status"] == "pending_review"
    ]
    return selected[-40:]


def _fit_context_to_budget(
    data: dict,
    profile: str,
    max_bytes: int,
    *,
    hard_max_bytes: int | None = None,
) -> str:
    """Drop only low-priority history; focused candidates and open coverage stay intact."""
    context_profile = data.get("context_profile") or {}
    focused = set(context_profile.get("focused_candidate_ids") or [])
    required_fact_ids = set(context_profile.get("required_fact_ids") or [])
    candidate_items = (data.get("audit_candidates") or {}).get("items") or []
    business_nodes = (data.get("business_graph") or {}).get("nodes") or []
    audit_findings = data.get("audit_findings") or []
    intents = data.get("intents") or []
    facts = data.get("facts") or []
    def serialize_if_fit() -> str | None:
        text = yaml.dump(data, allow_unicode=True, default_flow_style=False, sort_keys=False)
        if len(text.encode("utf-8")) <= max_bytes:
            return text
        return None

    active_intents = [
        row for row in intents if row["status"] in ("open", "claimed", "cooldown")
    ]
    completed_intents = [row for row in intents if row not in active_intents]
    intents[:] = [*active_intents, *completed_intents[-5:]]
    if text := serialize_if_fit():
        return text

    fixed_facts = [row for row in facts if row["id"] in required_fact_ids]
    other_facts = [row for row in facts if row not in fixed_facts]
    facts[:] = [*fixed_facts, *other_facts[-20:]]
    if text := serialize_if_fit():
        return text

    unresolved_findings = [row for row in audit_findings if row["status"] != "confirmed"]
    confirmed_findings = [row for row in audit_findings if row["status"] == "confirmed"]
    audit_findings[:] = [*unresolved_findings, *confirmed_findings[-20:]]
    if text := serialize_if_fit():
        return text

    unresolved_nodes = [
        row for row in business_nodes if row.get("review_status") != "covered"
    ]
    covered_nodes = [row for row in business_nodes if row.get("review_status") == "covered"]
    business_nodes[:] = [*unresolved_nodes, *covered_nodes[-20:]]
    if text := serialize_if_fit():
        return text

    required_candidates = [
        row
        for row in candidate_items
        if row.get("id") in focused
        or row.get("status") in ("candidate", "investigating")
    ]
    historical_candidates = [row for row in candidate_items if row not in required_candidates]
    candidate_items[:] = [*required_candidates, *historical_candidates[:10]]
    if text := serialize_if_fit():
        return text

    required_bytes = len(
        yaml.dump(data, allow_unicode=True, default_flow_style=False, sort_keys=False).encode(
            "utf-8"
        )
    )
    hard_max_bytes = hard_max_bytes or max_bytes
    if required_bytes <= hard_max_bytes:
        context_profile["expanded_context"] = {
            "target_bytes": max_bytes,
            "required_bytes": required_bytes,
            "hard_max_bytes": hard_max_bytes,
            "reason": "required_security_context_preserved",
        }
        expanded = yaml.dump(
            data,
            allow_unicode=True,
            default_flow_style=False,
            sort_keys=False,
        )
        if len(expanded.encode("utf-8")) <= hard_max_bytes:
            return expanded
    raise HTTPException(
        507,
        (
            f"{profile} context requires {required_bytes} bytes and exceeds {max_bytes} bytes "
            "after relevance compaction; "
            "the task was not dispatched because required security coverage would be lost"
        ),
    )


def _compact_coverage_details(data: dict) -> None:
    candidate_coverage = (data.get("audit_candidates") or {}).get("coverage") or {}
    candidate_keys = (
        "id",
        "severity",
        "status",
        "candidate_type",
        "title",
        "file_path",
        "line_start",
        "entry_point",
        "reason",
    )
    for name in (
        "open_required",
        "high_risk_unresolved",
        "invalid_conclusions",
        "pending_high_findings",
    ):
        rows = candidate_coverage.get(name)
        if isinstance(rows, list):
            candidate_coverage[name] = [
                {key: row.get(key) for key in candidate_keys if row.get(key) is not None}
                for row in rows
                if isinstance(row, dict)
            ]

    graph_coverage = (data.get("business_graph") or {}).get("coverage") or {}
    graph_keys = (
        "id",
        "node_type",
        "title",
        "risk_level",
        "review_status",
        "reason",
    )
    for name, rows in list(graph_coverage.items()):
        if isinstance(rows, list):
            graph_coverage[name] = [
                {key: row.get(key) for key in graph_keys if row.get(key) is not None}
                for row in rows
                if isinstance(row, dict)
            ]


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
        values = [intent["description"] or ""]
        if intent["target_kind"] == "audit_candidate" and intent["target_id"]:
            values.append(intent["target_id"])
        return {
            match.group(0).lower()
            for value in values
            for match in CANDIDATE_ID_RE.finditer(value)
        }
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
