from __future__ import annotations

import hashlib
import json
from pathlib import Path
import re


EVIDENCE_LINKER = "system:evidence_linker"
EVIDENCE_REF_RE = re.compile(r"^(.+?):(\d+)(.*)$")
NON_SOURCE_SUFFIXES = {
    ".7z",
    ".bz2",
    ".gz",
    ".jar",
    ".rar",
    ".tar",
    ".tgz",
    ".war",
    ".xz",
    ".zip",
}
STATIC_NODE_PRIORITY = {
    "risk": 0,
    "endpoint": 1,
    "control": 2,
    "data_object": 3,
    "asset": 4,
    "feature": 5,
}


def parse_evidence_location(value: str) -> tuple[str, int, str] | None:
    match = EVIDENCE_REF_RE.match(str(value).strip())
    if match is None:
        return None
    line_number = int(match.group(2))
    if line_number < 1:
        return None
    path = match.group(1).strip().lstrip("./")
    if not path:
        return None
    return path, line_number, match.group(3)


def validate_model_evidence_refs(conn, snapshot_id: str | None, evidence: list[str]) -> list[str]:
    if snapshot_id is None:
        return []
    validated: list[str] = []
    line_cache: dict[tuple[str, int], str | None] = {}
    for item in evidence:
        location = parse_evidence_location(item)
        if location is None:
            continue
        path, line_number, suffix = location
        row = conn.execute(
            """
            SELECT is_binary
            FROM code_files
            WHERE snapshot_id = ? AND path = ?
            LIMIT 1
            """,
            (snapshot_id, path),
        ).fetchone()
        if row is None or bool(row["is_binary"]) or Path(path).suffix.lower() in NON_SOURCE_SUFFIXES:
            continue
        cache_key = (path, line_number)
        if cache_key not in line_cache:
            line_cache[cache_key] = _snapshot_source_line(snapshot_id, path, line_number)
        if not _is_meaningful_source_line(line_cache[cache_key]):
            continue
        normalized = f"{path}:{line_number}{suffix}"
        if normalized not in validated:
            validated.append(normalized)
    return validated


def calibrated_model_confidence(requested: float, evidence: list[str]) -> float:
    if not evidence:
        ceiling = 0.35
    elif len(evidence) == 1:
        ceiling = 0.82
    elif len(evidence) == 2:
        ceiling = 0.9
    else:
        ceiling = 0.94
    return min(float(requested), ceiling)


def sync_semantic_evidence_edges(
    conn,
    project_id: str,
    node_id: str,
    snapshot_id: str | None,
    evidence: list[str],
    *,
    now: str,
) -> int:
    conn.execute(
        "DELETE FROM business_edges WHERE project_id = ? AND from_node_id = ? AND created_by = ?",
        (project_id, node_id, EVIDENCE_LINKER),
    )
    if snapshot_id is None or not evidence:
        return 0

    static_rows = conn.execute(
        """
        SELECT id, node_type, evidence_json
        FROM business_nodes
        WHERE project_id = ?
          AND source_snapshot_id = ?
          AND source_kind = 'static_index'
        """,
        (project_id, snapshot_id),
    ).fetchall()
    by_path: dict[str, list[tuple[int, object]]] = {}
    for row in static_rows:
        for value in _decode_list(row["evidence_json"]):
            location = parse_evidence_location(value)
            if location is None:
                continue
            path, line_number, _suffix = location
            by_path.setdefault(path, []).append((line_number, row))

    created = 0
    linked_targets: set[str] = set()
    for value in evidence:
        location = parse_evidence_location(value)
        if location is None:
            continue
        path, line_number, _suffix = location
        candidates = by_path.get(path, [])
        if not candidates:
            continue
        exact = [item for item in candidates if item[0] == line_number]
        pool = exact or sorted(
            candidates,
            key=lambda item: (
                abs(item[0] - line_number),
                STATIC_NODE_PRIORITY.get(item[1]["node_type"], 9),
                item[1]["id"],
            ),
        )[:1]
        if exact:
            pool = sorted(
                exact,
                key=lambda item: (
                    STATIC_NODE_PRIORITY.get(item[1]["node_type"], 9),
                    item[1]["id"],
                ),
            )[:2]
        for target_line, target in pool:
            target_id = target["id"]
            if target_id in linked_targets:
                continue
            linked_targets.add(target_id)
            confidence = 0.92 if target_line == line_number else 0.76
            edge_id = _stable_edge_id(project_id, node_id, target_id)
            result = conn.execute(
                """
                INSERT OR IGNORE INTO business_edges (
                    id, project_id, from_node_id, to_node_id, relation,
                    description, confidence, graph_layer, source_kind,
                    contributors_json, revision, created_by, created_at
                )
                VALUES (?, ?, ?, ?, 'evidenced_by', ?, ?, 'semantic', 'mixed', ?, 1, ?, ?)
                """,
                (
                    edge_id,
                    project_id,
                    node_id,
                    target_id,
                    f"业务语义通过 {path}:{line_number} 连接到静态源码证据。",
                    confidence,
                    json.dumps(["model", "source_index"], ensure_ascii=False),
                    EVIDENCE_LINKER,
                    now,
                ),
            )
            created += max(0, int(result.rowcount or 0))
    return created


def reconcile_project_business_graph(
    conn,
    project_id: str,
    snapshot_id: str | None,
    *,
    now: str,
) -> dict[str, int]:
    rows = conn.execute(
        """
        SELECT id, evidence_json, confidence, evidence_status, source_snapshot_id,
               review_status, source_kind
        FROM business_nodes
        WHERE project_id = ? AND source_kind IN ('model', 'mixed')
        """,
        (project_id,),
    ).fetchall()
    updated_nodes = 0
    linked_edges = 0
    dropped_evidence = 0
    reopened_nodes = 0
    for row in rows:
        effective_snapshot = row["source_snapshot_id"] or snapshot_id
        original = _decode_list(row["evidence_json"])
        validated = validate_model_evidence_refs(conn, effective_snapshot, original)
        dropped_evidence += max(0, len(original) - len(validated))
        status = "source_backed" if validated else "unverified"
        confidence = calibrated_model_confidence(float(row["confidence"] or 0), validated)
        review_status = row["review_status"]
        if review_status == "covered" and status != "source_backed":
            review_status = "investigating"
            reopened_nodes += 1
        changed = (
            validated != original
            or status != row["evidence_status"]
            or confidence != float(row["confidence"] or 0)
            or effective_snapshot != row["source_snapshot_id"]
            or review_status != row["review_status"]
        )
        if changed:
            conn.execute(
                """
                UPDATE business_nodes
                SET evidence_json = ?, evidence_status = ?, confidence = ?,
                    review_status = ?,
                    source_snapshot_id = ?, revision = revision + 1, updated_at = ?
                WHERE id = ? AND project_id = ?
                """,
                (
                    json.dumps(validated, ensure_ascii=False),
                    status,
                    confidence,
                    review_status,
                    effective_snapshot,
                    now,
                    row["id"],
                    project_id,
                ),
            )
            updated_nodes += 1
        linked_edges += sync_semantic_evidence_edges(
            conn,
            project_id,
            row["id"],
            effective_snapshot,
            validated,
            now=now,
        )

    capped_edges = conn.execute(
        """
        UPDATE business_edges
        SET confidence = 0.94, revision = revision + 1
        WHERE project_id = ? AND source_kind = 'model' AND confidence > 0.94
        """,
        (project_id,),
    ).rowcount
    return {
        "model_nodes": len(rows),
        "updated_nodes": updated_nodes,
        "dropped_evidence": dropped_evidence,
        "linked_edges": linked_edges,
        "capped_edges": int(capped_edges or 0),
        "reopened_nodes": reopened_nodes,
    }


def _snapshot_source_line(snapshot_id: str, relative_path: str, line_number: int) -> str | None:
    from cairn.server.source_service import snapshot_path

    root = snapshot_path(snapshot_id).resolve()
    target = (root / relative_path).resolve()
    try:
        target.relative_to(root)
    except ValueError:
        return None
    try:
        with target.open("r", encoding="utf-8", errors="replace") as handle:
            for current, line in enumerate(handle, start=1):
                if current == line_number:
                    return line.rstrip("\r\n")
    except OSError:
        return None
    return None


def _is_meaningful_source_line(line: str | None) -> bool:
    if line is None:
        return False
    text = line.strip().lstrip("\ufeff")
    if not text or text in {"<?php", "?>", "{", "}", ";"}:
        return False
    lowered = text.lower()
    if lowered.startswith(("<!doctype", "<!--", "//", "/*", "* ", "-- ")):
        return False
    if re.fullmatch(r"</?(?:html|head|body|meta|title|div|span|font|center|br)[^>]*>", text, re.IGNORECASE):
        return False
    return True


def _decode_list(raw: str | None) -> list[str]:
    if not raw:
        return []
    try:
        value = json.loads(raw)
    except json.JSONDecodeError:
        return []
    return [str(item) for item in value if str(item).strip()] if isinstance(value, list) else []


def _stable_edge_id(project_id: str, from_node_id: str, to_node_id: str) -> str:
    digest = hashlib.sha1(
        f"{project_id}\0{from_node_id}\0{to_node_id}\0evidenced_by".encode("utf-8")
    ).hexdigest()[:16]
    return f"biz_edge_{digest}"
