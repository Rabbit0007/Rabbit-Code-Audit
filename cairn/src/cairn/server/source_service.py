from __future__ import annotations

import hashlib
import ipaddress
import json
import os
import re
from dataclasses import dataclass
from pathlib import Path, PurePosixPath
import shutil
import socket
import stat
import subprocess
import tempfile
from typing import BinaryIO
from urllib.parse import urlparse
import uuid
import zipfile

from cairn.server.code_index import extract_code_index, is_likely_generic_web_script
from cairn.server import db
from cairn.server.services import get_project_or_404, utcnow
from cairn.server.source_models import (
    CodeEntrypoint,
    CodeFile,
    CodeRelationship,
    CodeSymbol,
    DependencyManifest,
    SourceIndexQuality,
    SourceIndexQualityIssue,
    SourceIndexSummary,
    SourceSnapshot,
)


MAX_ARCHIVE_BYTES = 1024 * 1024 * 1024
MAX_EXTRACTED_BYTES = 5 * 1024 * 1024 * 1024
MAX_FILE_BYTES = 100 * 1024 * 1024
MAX_FILE_COUNT = 200_000
COPY_CHUNK_BYTES = 1024 * 1024
MAX_CANDIDATE_TEXT_BYTES = 2 * 1024 * 1024

LANGUAGE_BY_SUFFIX: dict[str, str] = {
    ".c": "C",
    ".cc": "C++",
    ".cpp": "C++",
    ".cs": "C#",
    ".css": "CSS",
    ".go": "Go",
    ".htm": "HTML",
    ".html": "HTML",
    ".java": "Java",
    ".js": "JavaScript",
    ".jsx": "JavaScript",
    ".kt": "Kotlin",
    ".php": "PHP",
    ".py": "Python",
    ".rb": "Ruby",
    ".rs": "Rust",
    ".scala": "Scala",
    ".sql": "SQL",
    ".ts": "TypeScript",
    ".tsx": "TypeScript",
    ".vue": "Vue",
}
WEB_SCRIPT_SUFFIXES = {".php", ".jsp", ".jspx", ".asp", ".aspx", ".ashx"}
WEB_SCRIPT_EXCLUDED_PARTS = {
    ".git",
    ".hg",
    ".svn",
    "__pycache__",
    "build",
    "coverage",
    "dist",
    "node_modules",
    "spec",
    "target",
    "test",
    "tests",
    "vendor",
    "venv",
}
MAX_SOURCE_INDEX_CANDIDATES = 2000
MAX_DATA_FLOW_CANDIDATES_PER_FILE = 8
MAX_INPUT_TO_SINK_LINE_DISTANCE = 80

InputVariableMap = dict[str, list[int]]


@dataclass(frozen=True)
class RiskSignal:
    category: str
    title: str
    line_start: int
    line_end: int | None
    evidence: str
    source_summary: str
    symbol: str | None = None


@dataclass(frozen=True)
class SinkPattern:
    category: str
    title: str
    pattern: re.Pattern[str]


INPUT_SOURCE_PATTERNS: tuple[tuple[str, re.Pattern[str]], ...] = (
    ("HTTP 参数/请求体", re.compile(r"\$_(?:GET|POST|REQUEST|COOKIE|SERVER|FILES)\b|php://input")),
    ("HTTP 请求对象", re.compile(r"\b(?:req|request|ctx)\.(?:query|body|params|headers|cookies)\b")),
    ("SatRDA 请求对象", re.compile(r"\br\.(?:jsonBody|body|formValue|url\.query\.get|url\.rawQuery)\b|\bUrlUtils\.queryParams\s*\(\s*r\.url\.rawQuery\s*\)")),
    ("Python Web 请求", re.compile(r"\brequest\.(?:args|form|json|data|cookies|headers|GET|POST)\b")),
    ("Java Web 参数", re.compile(r"\b(?:getParameter|getHeader|getCookies)\s*\(|@(RequestParam|PathVariable|RequestBody)\b")),
    ("Go Web 参数", re.compile(r"\b(?:URL\.Query|FormValue|PostFormValue|Param)\s*\(")),
)
INPUT_VARIABLE_PATTERNS: tuple[re.Pattern[str], ...] = (
    re.compile(r"\$([A-Za-z_][\w]*)\s*=\s*.*(?:\$_(?:GET|POST|REQUEST|COOKIE|SERVER|FILES)\b|php://input)"),
    re.compile(r"\b(?:const|let|var)\s+([A-Za-z_$][\w$]*)\s*=\s*.*\b(?:req|request|ctx)\.(?:query|body|params|headers|cookies)\b"),
    re.compile(r"\b(?:const|let|var)\s+([A-Za-z_$][\w$]*)\s*=\s*.*(?:\br\.(?:jsonBody|body|formValue|url\.query\.get|url\.rawQuery)\b|\bUrlUtils\.queryParams\s*\(\s*r\.url\.rawQuery\s*\))"),
    re.compile(r"\b([A-Za-z_][\w]*)\s*=\s*request\.(?:args|form|json|data|cookies|headers|GET|POST)\b"),
    re.compile(r"\b(?:String|var)\s+([A-Za-z_][\w]*)\s*=\s*[^;]*\b(?:getParameter|getHeader)\s*\("),
    re.compile(r"\b([A-Za-z_][\w]*)\s*:=\s*[^;\n]*\b(?:URL\.Query|FormValue|PostFormValue|Param)\s*\("),
)
JS_DESTRUCTURING_PATTERN = re.compile(r"\b(?:const|let|var)\s*\{([^}]+)\}\s*=\s*([A-Za-z_$][\w$]*)")
JS_DERIVED_VARIABLE_PATTERN = re.compile(r"\b(?:const|let|var)\s+([A-Za-z_$][\w$]*)\s*=\s*(.+)")
PHP_DERIVED_VARIABLE_PATTERN = re.compile(r"\$([A-Za-z_][\w]*)\s*=\s*(.+)")
SINK_PATTERNS: tuple[SinkPattern, ...] = (
    SinkPattern(
        "SQL 注入面",
        "SQL 查询执行",
        re.compile(
            r"\b(?:mysql_query|mysqli_query|mysqli_multi_query|pg_query|sqlite_query)\s*\("
            r"|->query\s*\("
            r"|\$[A-Za-z_][\w]*\s*=\s*[^;\n]*(?:SELECT|INSERT|UPDATE|DELETE|REPLACE)\b"
            r"|\b(?:query|execute|executeQuery|executeUpdate|cursor\.execute)\s*\([^;\n]*(?:SELECT|INSERT|UPDATE|DELETE|REPLACE)\b"
            r"|\b[A-Za-z_$][\w$]*\.(?:query|execute|queryLong|queryString|syntaxFromSQL)\s*\(",
            re.IGNORECASE,
        ),
    ),
    SinkPattern(
        "命令执行面",
        "系统命令执行",
        re.compile(
            r"\b(?:system|exec|shell_exec|passthru|popen|proc_open)\s*\("
            r"|\bchild_process\.(?:exec|execFile|spawn)\s*\("
            r"|\bsubprocess\.(?:Popen|run|call|check_output)\s*\("
            r"|\bos\.system\s*\("
            r"|\bRuntime\.getRuntime\(\)\.exec\s*\("
            r"|\bProcessBuilder\s*\(",
            re.IGNORECASE,
        ),
    ),
    SinkPattern(
        "文件/包含操作面",
        "文件读取写入或动态包含",
        re.compile(
            r"\b(?:include|require|include_once|require_once)\s*\(?"
            r"|\b(?:file_get_contents|readfile|fopen|unlink|copy|move_uploaded_file)\s*\("
            r"|\bfs\.(?:readFile|writeFile|unlink|createReadStream)\s*\("
            r"|\b(?:satrda\.(?:writeFile|fileOpen)|ctx\.(?:serveContent|saveMultipartFile))\s*\("
            r"|\bopen\s*\([^;\n]*(?:request\.|req\.|\$_)",
            re.IGNORECASE,
        ),
    ),
    SinkPattern(
        "SSRF/外联请求面",
        "服务端外联请求",
        re.compile(
            r"\bcurl_exec\s*\("
            r"|\bcurl_setopt\s*\([^;\n]*CURLOPT_URL"
            r"|\brequests\.(?:get|post|put|delete|request)\s*\("
            r"|\burllib\.request\."
            r"|\bhttp\.Get\s*\("
            r"|\b(?:fetch|axios\.(?:get|post|request))\s*\(",
            re.IGNORECASE,
        ),
    ),
    SinkPattern(
        "反序列化面",
        "不可信数据反序列化",
        re.compile(
            r"\bunserialize\s*\("
            r"|\bpickle\.loads\s*\("
            r"|\byaml\.load\s*\("
            r"|\bObjectInputStream\b"
            r"|\breadObject\s*\(",
            re.IGNORECASE,
        ),
    ),
    SinkPattern(
        "响应输出面",
        "未确认编码的响应输出",
        re.compile(r"\b(?:echo|print|printf)\b|\bres\.(?:send|write|end)\s*\(|\.innerHTML\s*=", re.IGNORECASE),
    ),
)


def artifact_root() -> Path:
    configured = os.getenv("CAIRN_ARTIFACT_ROOT")
    root = Path(configured).expanduser() if configured else db.current_path().parent / "artifacts"
    root.mkdir(parents=True, exist_ok=True)
    return root


def snapshot_path(snapshot_id: str) -> Path:
    return artifact_root() / "snapshots" / snapshot_id / "source"


def snapshot_container_path(snapshot_id: str) -> str:
    return f"/audit-data/artifacts/snapshots/{snapshot_id}/source"


def import_git_source(project_id: str, repository_url: str, requested_ref: str | None) -> SourceSnapshot:
    _validate_public_git_url(repository_url)
    snapshot_id = _new_snapshot_id()
    created_at = utcnow()
    _insert_importing_snapshot(
        snapshot_id,
        project_id,
        source_type="git",
        repository_url=repository_url,
        requested_ref=requested_ref,
        original_name=None,
        created_at=created_at,
    )
    destination = snapshot_path(snapshot_id)
    try:
        with tempfile.TemporaryDirectory(prefix="rabbit-audit-git-") as temp_dir:
            checkout = Path(temp_dir) / "source"
            _run_git(["clone", "--no-local", "--no-hardlinks", repository_url, str(checkout)])
            if requested_ref:
                _run_git(["-C", str(checkout), "checkout", "--detach", requested_ref])
            else:
                _run_git(["-C", str(checkout), "checkout", "--detach"])
            resolved_commit = _run_git(["-C", str(checkout), "rev-parse", "HEAD"]).strip()
            shutil.rmtree(checkout / ".git", ignore_errors=True)
            _move_snapshot(checkout, destination)
        return _finalize_snapshot(snapshot_id, resolved_commit=resolved_commit)
    except Exception as exc:
        _mark_snapshot_failed(snapshot_id, str(exc))
        shutil.rmtree(destination.parent, ignore_errors=True)
        raise


def import_zip_source(project_id: str, original_name: str, stream: BinaryIO) -> SourceSnapshot:
    snapshot_id = _new_snapshot_id()
    created_at = utcnow()
    _insert_importing_snapshot(
        snapshot_id,
        project_id,
        source_type="zip",
        repository_url=None,
        requested_ref=None,
        original_name=original_name,
        created_at=created_at,
    )
    destination = snapshot_path(snapshot_id)
    try:
        with tempfile.TemporaryDirectory(prefix="rabbit-audit-zip-") as temp_dir:
            archive_path = Path(temp_dir) / "upload.zip"
            archive_sha256 = _copy_limited(stream, archive_path, MAX_ARCHIVE_BYTES)
            extracted = Path(temp_dir) / "source"
            extracted.mkdir()
            _safe_extract_zip(archive_path, extracted)
            source_root = _single_root_or_self(extracted)
            _move_snapshot(source_root, destination)
        return _finalize_snapshot(snapshot_id, archive_sha256=archive_sha256)
    except Exception as exc:
        _mark_snapshot_failed(snapshot_id, str(exc))
        shutil.rmtree(destination.parent, ignore_errors=True)
        raise


def list_snapshots(project_id: str) -> list[SourceSnapshot]:
    with db.get_conn() as conn:
        get_project_or_404(conn, project_id)
        rows = conn.execute(
            "SELECT * FROM source_snapshots WHERE project_id = ? ORDER BY created_at DESC",
            (project_id,),
        ).fetchall()
    return [_snapshot_from_row(row) for row in rows]


def get_snapshot(project_id: str, snapshot_id: str) -> SourceSnapshot:
    with db.get_conn() as conn:
        get_project_or_404(conn, project_id)
        row = conn.execute(
            "SELECT * FROM source_snapshots WHERE id = ? AND project_id = ?",
            (snapshot_id, project_id),
        ).fetchone()
    if row is None:
        raise ValueError("Source snapshot not found")
    return _snapshot_from_row(row)


def list_code_files(project_id: str, snapshot_id: str, limit: int = 5000) -> list[CodeFile]:
    get_snapshot(project_id, snapshot_id)
    with db.get_conn() as conn:
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


def get_source_index_summary(project_id: str, snapshot_id: str) -> SourceIndexSummary:
    snapshot = get_snapshot(project_id, snapshot_id)
    _ensure_code_index(snapshot)
    with db.get_conn() as conn:
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


def get_source_index_quality(project_id: str, snapshot_id: str) -> SourceIndexQuality:
    snapshot = get_snapshot(project_id, snapshot_id)
    _ensure_code_index(snapshot)
    summary = get_source_index_summary(project_id, snapshot_id)
    with db.get_conn() as conn:
        file_count = conn.execute(
            "SELECT COUNT(*) AS count FROM code_files WHERE snapshot_id = ?",
            (snapshot_id,),
        ).fetchone()["count"]
        code_file_count = conn.execute(
            """
            SELECT COUNT(*) AS count
            FROM code_files
            WHERE snapshot_id = ?
              AND is_binary = 0
              AND language IS NOT NULL
            """,
            (snapshot_id,),
        ).fetchone()["count"]
        framework_counts = _count_rows(
            conn.execute(
                """
                SELECT COALESCE(framework, 'unknown') AS key, COUNT(*) AS count
                FROM code_entrypoints
                WHERE snapshot_id = ?
                GROUP BY COALESCE(framework, 'unknown')
                ORDER BY count DESC, key
                """,
                (snapshot_id,),
            ).fetchall()
        )
        relationship_counts = _count_rows(
            conn.execute(
                """
                SELECT relation AS key, COUNT(*) AS count
                FROM code_relationships
                WHERE snapshot_id = ?
                GROUP BY relation
                ORDER BY count DESC, key
                """,
                (snapshot_id,),
            ).fetchall()
        )
        symbol_kind_counts = _count_rows(
            conn.execute(
                """
                SELECT kind AS key, COUNT(*) AS count
                FROM code_symbols
                WHERE snapshot_id = ?
                GROUP BY kind
                ORDER BY count DESC, key
                """,
                (snapshot_id,),
            ).fetchall()
        )
        confidence = {
            "symbols": _avg_confidence(conn, "code_symbols", snapshot_id),
            "entrypoints": _avg_confidence(conn, "code_entrypoints", snapshot_id),
            "relationships": _avg_confidence(conn, "code_relationships", snapshot_id),
        }
        low_confidence = {
            "symbols": _low_confidence_count(conn, "code_symbols", snapshot_id, 0.65),
            "entrypoints": _low_confidence_count(conn, "code_entrypoints", snapshot_id, 0.70),
            "relationships": _low_confidence_count(conn, "code_relationships", snapshot_id, 0.55),
        }
        orphan_rows = conn.execute(
            """
            SELECT e.*
            FROM code_entrypoints e
            WHERE e.snapshot_id = ?
              AND COALESCE(e.framework, '') != 'web_script'
              AND e.handler IS NOT NULL
              AND TRIM(e.handler) != ''
              AND NOT EXISTS (
                  SELECT 1
                  FROM code_relationships r
                  WHERE r.snapshot_id = e.snapshot_id
                    AND r.from_path = e.path
                    AND r.relation = 'calls'
                    AND r.from_symbol = CASE
                        WHEN e.method IS NULL THEN e.route
                        ELSE e.method || ' ' || e.route
                    END
              )
            ORDER BY e.path, COALESCE(e.line_start, 0), e.route
            LIMIT 20
            """,
            (snapshot_id,),
        ).fetchall()
        entrypoints = conn.execute(
            """
            SELECT path, method, route, handler
            FROM code_entrypoints
            WHERE snapshot_id = ?
            ORDER BY path, COALESCE(line_start, 0), route
            """,
            (snapshot_id,),
        ).fetchall()
        relationships = conn.execute(
            """
            SELECT from_path, from_symbol, to_path, to_symbol, relation
            FROM code_relationships
            WHERE snapshot_id = ?
            """,
            (snapshot_id,),
        ).fetchall()
        data_objects = conn.execute(
            """
            SELECT path, name
            FROM code_symbols
            WHERE snapshot_id = ? AND kind = 'data_object'
            """,
            (snapshot_id,),
        ).fetchall()

    data_object_count = symbol_kind_counts.get("data_object", 0)
    entrypoints_with_data_paths = _entrypoints_with_data_paths(entrypoints, relationships, data_objects)
    issues: list[SourceIndexQualityIssue] = []
    recommendations: list[str] = []
    score = 100

    def add_issue(severity: str, code: str, title: str, description: str, count: int, penalty: int, recommendation: str) -> None:
        nonlocal score
        issues.append(
            SourceIndexQualityIssue(
                severity=severity,  # type: ignore[arg-type]
                code=code,
                title=title,
                description=description,
                count=count,
            )
        )
        recommendations.append(recommendation)
        score -= penalty

    if summary.entrypoint_count == 0 and code_file_count:
        add_issue(
            "critical",
            "no_entrypoints",
            "未识别入口",
            "源码中没有可用于审计调度的入口，模型只能从文件列表开始猜测。",
            0,
            35,
            "补充对应框架的路由适配器，或检查源码是否缺少 Web/CLI 入口文件。",
        )
    if summary.relationship_count == 0 and code_file_count > 1:
        add_issue(
            "warning",
            "no_relationships",
            "未识别跨文件关系",
            "索引没有 import/call/use 关系，入口到服务/数据对象的链路会断开。",
            0,
            20,
            "优先补充当前项目主语言的 import/call 解析规则。",
        )
    orphan_count = len(orphan_rows)
    if orphan_count:
        penalty = 8 if orphan_count < max(3, summary.entrypoint_count // 4) else 14
        add_issue(
            "warning",
            "orphan_entrypoints",
            "入口缺少处理器链路",
            "部分入口没有解析到 handler 调用关系，模型需要手动追踪入口文件。",
            orphan_count,
            penalty,
            "补强对应框架的 handler 解析，尤其是多行注解、router group、依赖注入写法。",
        )
    if data_object_count == 0 and summary.entrypoint_count > 0:
        add_issue(
            "warning",
            "no_data_objects",
            "未识别数据对象",
            "入口已经识别，但没有模型、表或数据对象节点，业务资源理解会偏弱。",
            0,
            10,
            "补充 ORM/model/table 识别规则，或检查项目是否把数据访问封装在外部依赖中。",
        )
    if data_object_count and summary.entrypoint_count:
        linked_ratio = entrypoints_with_data_paths / max(1, summary.entrypoint_count)
        if linked_ratio < 0.3:
            add_issue(
                "warning",
                "weak_entrypoint_data_paths",
                "入口到数据对象链路偏弱",
                "已识别数据对象，但多数入口没有可达的数据对象关系。",
                summary.entrypoint_count - entrypoints_with_data_paths,
                12,
                "增强 endpoint -> controller/service -> model/DAO 的调用链解析。",
            )
    if low_confidence["relationships"] > max(5, summary.relationship_count // 4):
        add_issue(
            "warning",
            "low_confidence_relationships",
            "低置信关系较多",
            "大量关系来自弱启发式匹配，模型使用时需要优先核对源码证据。",
            low_confidence["relationships"],
            8,
            "对主语言引入 AST/tree-sitter 解析，降低纯正则调用匹配比例。",
        )
    if summary.manifest_count == 0 and code_file_count > 20:
        add_issue(
            "info",
            "no_dependency_manifest",
            "未识别依赖清单",
            "没有依赖清单会降低框架和组件识别质量。",
            0,
            4,
            "补充项目构建文件适配，或确认快照是否缺少依赖清单。",
        )

    score = max(0, min(100, score))
    if score >= 80:
        grade = "strong"
    elif score >= 60:
        grade = "usable"
    elif score >= 40:
        grade = "weak"
    else:
        grade = "poor"
    if not recommendations:
        recommendations.append("当前索引质量良好，可以直接用于业务图导航和审计任务拆分。")
    return SourceIndexQuality(
        snapshot_id=snapshot_id,
        score=score,
        grade=grade,
        summary=summary,
        file_count=file_count,
        code_file_count=code_file_count,
        detected_languages=snapshot.detected_languages,
        framework_counts=framework_counts,
        relationship_counts=relationship_counts,
        symbol_kind_counts=symbol_kind_counts,
        confidence=confidence,
        low_confidence=low_confidence,
        orphan_entrypoints=[CodeEntrypoint(**dict(row)) for row in orphan_rows],
        data_object_count=data_object_count,
        entrypoints_with_data_paths=entrypoints_with_data_paths,
        issues=issues,
        recommendations=list(dict.fromkeys(recommendations)),
    )


def _count_rows(rows) -> dict[str, int]:
    result: dict[str, int] = {}
    for row in rows:
        key = str(row["key"] or "").strip()
        if not key:
            continue
        result[key] = int(row["count"] or 0)
    return result


def _avg_confidence(conn, table: str, snapshot_id: str) -> float:
    row = conn.execute(
        f"SELECT AVG(confidence) AS value FROM {table} WHERE snapshot_id = ?",
        (snapshot_id,),
    ).fetchone()
    return round(float(row["value"] or 0), 3)


def _low_confidence_count(conn, table: str, snapshot_id: str, threshold: float) -> int:
    row = conn.execute(
        f"SELECT COUNT(*) AS count FROM {table} WHERE snapshot_id = ? AND confidence < ?",
        (snapshot_id, threshold),
    ).fetchone()
    return int(row["count"] or 0)


def _entrypoints_with_data_paths(entrypoints, relationships, data_objects) -> int:
    data_targets = {(row["path"], row["name"]) for row in data_objects}
    if not entrypoints or not data_targets:
        return 0

    adjacency: dict[tuple[str, str | None], set[tuple[str, str | None]]] = {}
    for row in relationships:
        if row["relation"] not in {"calls", "imports", "uses"}:
            continue
        start = (row["from_path"], row["from_symbol"])
        adjacency.setdefault(start, set()).add((row["to_path"], row["to_symbol"]))
        if row["from_symbol"] is not None:
            adjacency.setdefault((row["from_path"], None), set()).add((row["to_path"], row["to_symbol"]))

    linked = 0
    for entrypoint in entrypoints:
        label = _entrypoint_label(entrypoint["method"], entrypoint["route"])
        starts = {
            (entrypoint["path"], label),
            (entrypoint["path"], entrypoint["handler"]),
            (entrypoint["path"], None),
        }
        if any(_has_reachable_data_object(start, adjacency, data_targets) for start in starts):
            linked += 1
    return linked


def _has_reachable_data_object(
    start: tuple[str, str | None],
    adjacency: dict[tuple[str, str | None], set[tuple[str, str | None]]],
    data_targets: set[tuple[str, str]],
    *,
    max_depth: int = 4,
) -> bool:
    seen = {start}
    frontier = [(start, 0)]
    while frontier:
        node, depth = frontier.pop(0)
        path, symbol = node
        if symbol is not None and (path, symbol) in data_targets:
            return True
        if depth >= max_depth:
            continue
        next_nodes = set(adjacency.get(node, set()))
        if symbol is not None:
            next_nodes.update(adjacency.get((path, None), set()))
        for next_node in next_nodes:
            if next_node in seen:
                continue
            seen.add(next_node)
            frontier.append((next_node, depth + 1))
    return False


def list_code_symbols(project_id: str, snapshot_id: str, limit: int = 1000) -> list[CodeSymbol]:
    snapshot = get_snapshot(project_id, snapshot_id)
    _ensure_code_index(snapshot)
    with db.get_conn() as conn:
        rows = conn.execute(
            """
            SELECT *
            FROM code_symbols
            WHERE snapshot_id = ?
            ORDER BY path, COALESCE(line_start, 0), kind, name
            LIMIT ?
            """,
            (snapshot_id, limit),
        ).fetchall()
    return [CodeSymbol(**dict(row)) for row in rows]


def list_code_entrypoints(project_id: str, snapshot_id: str, limit: int = 1000) -> list[CodeEntrypoint]:
    snapshot = get_snapshot(project_id, snapshot_id)
    _ensure_code_index(snapshot)
    with db.get_conn() as conn:
        rows = conn.execute(
            """
            SELECT *
            FROM code_entrypoints
            WHERE snapshot_id = ?
            ORDER BY path, COALESCE(line_start, 0), route, COALESCE(method, '')
            LIMIT ?
            """,
            (snapshot_id, limit),
        ).fetchall()
    return [CodeEntrypoint(**dict(row)) for row in rows]


def list_code_relationships(project_id: str, snapshot_id: str, limit: int = 1000) -> list[CodeRelationship]:
    snapshot = get_snapshot(project_id, snapshot_id)
    _ensure_code_index(snapshot)
    with db.get_conn() as conn:
        rows = conn.execute(
            """
            SELECT *
            FROM code_relationships
            WHERE snapshot_id = ?
            ORDER BY from_path, relation, to_path, COALESCE(line_start, 0)
            LIMIT ?
            """,
            (snapshot_id, limit),
        ).fetchall()
    return [CodeRelationship(**dict(row)) for row in rows]


def list_dependency_manifests(project_id: str, snapshot_id: str, limit: int = 1000) -> list[DependencyManifest]:
    snapshot = get_snapshot(project_id, snapshot_id)
    _ensure_code_index(snapshot)
    with db.get_conn() as conn:
        rows = conn.execute(
            """
            SELECT *
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


def rebuild_source_index(snapshot_id: str) -> SourceIndexSummary:
    root = snapshot_path(snapshot_id)
    if not root.exists():
        raise ValueError("Source snapshot files not found")
    with db.get_conn() as conn:
        snapshot_row = conn.execute("SELECT * FROM source_snapshots WHERE id = ?", (snapshot_id,)).fetchone()
        if snapshot_row is None:
            raise ValueError("Source snapshot not found")
        if snapshot_row["status"] != "ready":
            raise ValueError("Source snapshot is not ready")
        project_id = snapshot_row["project_id"]
        files = _load_code_files(conn, snapshot_id)
        code_index = extract_code_index(snapshot_id, root, files)
        _clear_source_index_for_rebuild(conn, project_id, snapshot_id)
        _insert_code_index(conn, code_index)
        _insert_audit_candidates_from_index(conn, snapshot_id, files, code_index, root=root)
        _ensure_business_graph_seed(conn, snapshot_id)
    return get_source_index_summary(project_id, snapshot_id)


def reindex_source_snapshot(project_id: str, snapshot_id: str) -> SourceIndexSummary:
    snapshot = get_snapshot(project_id, snapshot_id)
    if snapshot.status != "ready":
        raise ValueError("Source snapshot is not ready")
    return rebuild_source_index(snapshot_id)


def _clear_source_index_for_rebuild(conn, project_id: str, snapshot_id: str) -> None:
    protected_nodes = {
        row["business_node_id"]
        for row in conn.execute(
            """
            SELECT DISTINCT business_node_id
            FROM audit_candidates
            WHERE snapshot_id = ?
              AND business_node_id IS NOT NULL
              AND status != 'candidate'
            """,
            (snapshot_id,),
        ).fetchall()
    }
    protected_nodes.update(
        row["business_node_id"]
        for row in conn.execute(
            """
            SELECT business_node_id
            FROM business_node_conclusions
            WHERE project_id = ?
            """,
            (project_id,),
        ).fetchall()
    )
    protected_nodes.update(
        row["business_node_id"]
        for row in conn.execute(
            """
            SELECT business_node_id
            FROM audit_findings
            WHERE project_id = ? AND business_node_id IS NOT NULL
            """,
            (project_id,),
        ).fetchall()
    )
    for table in ("code_relationships", "code_symbols", "code_entrypoints", "dependency_manifests"):
        conn.execute(f"DELETE FROM {table} WHERE snapshot_id = ?", (snapshot_id,))
    conn.execute(
        """
        DELETE FROM audit_candidates
        WHERE snapshot_id = ?
          AND source = 'index'
          AND created_by = 'source_index'
          AND status = 'candidate'
          AND audit_finding_id IS NULL
        """,
        (snapshot_id,),
    )
    protected_params = list(protected_nodes)
    protected_clause = ""
    if protected_params:
        protected_clause = f"AND id NOT IN ({', '.join('?' for _ in protected_params)})"
    conn.execute(
        f"""
        DELETE FROM business_nodes
        WHERE project_id = ?
          AND created_by = 'source_index'
          AND review_status = 'unreviewed'
          AND (source_snapshot_id = ? OR source_snapshot_id IS NULL)
          {protected_clause}
        """,
        [project_id, snapshot_id, *protected_params],
    )


def _validate_public_git_url(repository_url: str) -> None:
    parsed = urlparse(repository_url)
    if parsed.scheme not in ("http", "https") or not parsed.netloc:
        raise ValueError("repository_url must be a public http or https Git URL")
    if parsed.username or parsed.password:
        raise ValueError("repository_url must not contain credentials")
    hostname = parsed.hostname
    if not hostname:
        raise ValueError("repository_url must include a hostname")
    try:
        addresses = {
            ipaddress.ip_address(item[4][0])
            for item in socket.getaddrinfo(hostname, parsed.port or 443, type=socket.SOCK_STREAM)
        }
    except (OSError, ValueError) as exc:
        raise ValueError("repository_url hostname could not be resolved") from exc
    if not addresses or any(not address.is_global for address in addresses):
        raise ValueError("repository_url must resolve only to public network addresses")


def _run_git(args: list[str]) -> str:
    result = subprocess.run(
        ["git", *args],
        check=False,
        capture_output=True,
        text=True,
        timeout=900,
        env={**os.environ, "GIT_TERMINAL_PROMPT": "0"},
    )
    if result.returncode != 0:
        detail = result.stderr.strip() or result.stdout.strip() or f"git exited with {result.returncode}"
        raise RuntimeError(detail)
    return result.stdout


def _copy_limited(stream: BinaryIO, destination: Path, limit: int) -> str:
    digest = hashlib.sha256()
    total = 0
    with destination.open("wb") as handle:
        while True:
            chunk = stream.read(COPY_CHUNK_BYTES)
            if not chunk:
                break
            total += len(chunk)
            if total > limit:
                raise ValueError(f"ZIP archive exceeds {limit} bytes")
            digest.update(chunk)
            handle.write(chunk)
    if total == 0:
        raise ValueError("ZIP archive is empty")
    return digest.hexdigest()


def _safe_extract_zip(archive_path: Path, destination: Path) -> None:
    total_bytes = 0
    file_count = 0
    seen_paths: set[str] = set()
    with zipfile.ZipFile(archive_path) as archive:
        for info in archive.infolist():
            relative = _safe_zip_path(info.filename)
            if relative is None:
                continue
            normalized = relative.as_posix().casefold()
            if normalized in seen_paths:
                raise ValueError(f"ZIP contains a duplicate path: {relative.as_posix()}")
            seen_paths.add(normalized)
            mode = info.external_attr >> 16
            file_type = stat.S_IFMT(mode)
            if file_type == stat.S_IFLNK:
                raise ValueError(f"ZIP contains a symbolic link: {relative.as_posix()}")
            if file_type not in (0, stat.S_IFREG, stat.S_IFDIR):
                raise ValueError(f"ZIP contains a special file: {relative.as_posix()}")
            if info.is_dir():
                (destination / relative).mkdir(parents=True, exist_ok=True)
                continue
            file_count += 1
            total_bytes += info.file_size
            if file_count > MAX_FILE_COUNT:
                raise ValueError(f"ZIP contains more than {MAX_FILE_COUNT} files")
            if info.file_size > MAX_FILE_BYTES:
                raise ValueError(f"ZIP file exceeds {MAX_FILE_BYTES} bytes: {relative.as_posix()}")
            if total_bytes > MAX_EXTRACTED_BYTES:
                raise ValueError(f"ZIP expands beyond {MAX_EXTRACTED_BYTES} bytes")
            target = destination / relative
            target.parent.mkdir(parents=True, exist_ok=True)
            written = 0
            with archive.open(info) as source, target.open("xb") as output:
                while True:
                    chunk = source.read(COPY_CHUNK_BYTES)
                    if not chunk:
                        break
                    written += len(chunk)
                    if written > info.file_size or written > MAX_FILE_BYTES:
                        raise ValueError(f"ZIP file size mismatch: {relative.as_posix()}")
                    output.write(chunk)


def _safe_zip_path(name: str) -> PurePosixPath | None:
    normalized = name.replace("\\", "/")
    path = PurePosixPath(normalized)
    if path.is_absolute():
        raise ValueError(f"ZIP contains an absolute path: {name}")
    parts = [part for part in path.parts if part not in ("", ".")]
    if not parts:
        return None
    if any(part == ".." for part in parts):
        raise ValueError(f"ZIP path escapes the archive root: {name}")
    return PurePosixPath(*parts)


def _single_root_or_self(path: Path) -> Path:
    entries = [entry for entry in path.iterdir() if entry.name != "__MACOSX"]
    if len(entries) == 1 and entries[0].is_dir():
        return entries[0]
    return path


def _move_snapshot(source: Path, destination: Path) -> None:
    destination.parent.mkdir(parents=True, exist_ok=True)
    if destination.exists():
        raise RuntimeError(f"snapshot destination already exists: {destination}")
    shutil.move(str(source), str(destination))


def _finalize_snapshot(
    snapshot_id: str,
    *,
    resolved_commit: str | None = None,
    archive_sha256: str | None = None,
) -> SourceSnapshot:
    files, snapshot_sha256, languages, total_bytes, code_index = _index_snapshot(snapshot_id)
    with db.get_conn() as conn:
        conn.executemany(
            """
            INSERT INTO code_files (snapshot_id, path, size_bytes, sha256, language, is_binary)
            VALUES (?, ?, ?, ?, ?, ?)
            """,
            [
                (
                    item.snapshot_id,
                    item.path,
                    item.size_bytes,
                    item.sha256,
                    item.language,
                    int(item.is_binary),
                )
                for item in files
            ],
        )
        _insert_code_index(conn, code_index)
        _insert_audit_candidates_from_index(conn, snapshot_id, files, code_index, root=snapshot_path(snapshot_id))
        _ensure_business_graph_seed(conn, snapshot_id)
        conn.execute(
            """
            UPDATE source_snapshots
            SET status = 'ready',
                resolved_commit = ?,
                archive_sha256 = ?,
                snapshot_sha256 = ?,
                file_count = ?,
                total_bytes = ?,
                detected_languages_json = ?,
                error_message = NULL
            WHERE id = ?
            """,
            (
                resolved_commit,
                archive_sha256,
                snapshot_sha256,
                len(files),
                total_bytes,
                json.dumps(languages, ensure_ascii=True, sort_keys=True),
                snapshot_id,
            ),
        )
        row = conn.execute("SELECT * FROM source_snapshots WHERE id = ?", (snapshot_id,)).fetchone()
    assert row is not None
    return _snapshot_from_row(row)


def _insert_code_index(conn, code_index) -> None:
    conn.executemany(
        """
        INSERT OR IGNORE INTO code_symbols (
            id, snapshot_id, path, language, kind, name, container,
            signature, line_start, line_end, confidence, source
        )
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
        [
            (
                item.id,
                item.snapshot_id,
                item.path,
                item.language,
                item.kind,
                item.name,
                item.container,
                item.signature,
                item.line_start,
                item.line_end,
                item.confidence,
                item.source,
            )
            for item in code_index.symbols
        ],
    )
    conn.executemany(
        """
        INSERT OR IGNORE INTO code_entrypoints (
            id, snapshot_id, path, language, kind, framework, method,
            route, handler, line_start, evidence, confidence, source
        )
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
        [
            (
                item.id,
                item.snapshot_id,
                item.path,
                item.language,
                item.kind,
                item.framework,
                item.method,
                item.route,
                item.handler,
                item.line_start,
                item.evidence,
                item.confidence,
                item.source,
            )
            for item in code_index.entrypoints
        ],
    )
    conn.executemany(
        """
        INSERT OR IGNORE INTO code_relationships (
            id, snapshot_id, from_path, from_symbol, to_path, to_symbol,
            relation, evidence, confidence, source, line_start
        )
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
        [
            (
                item.id,
                item.snapshot_id,
                item.from_path,
                item.from_symbol,
                item.to_path,
                item.to_symbol,
                item.relation,
                item.evidence,
                item.confidence,
                item.source,
                item.line_start,
            )
            for item in code_index.relationships
        ],
    )
    conn.executemany(
        """
        INSERT OR IGNORE INTO dependency_manifests (
            id, snapshot_id, path, manifest_type, package_name,
            dependencies_json, dev_dependencies_json
        )
        VALUES (?, ?, ?, ?, ?, ?, ?)
        """,
        [
            (
                item.id,
                item.snapshot_id,
                item.path,
                item.manifest_type,
                item.package_name,
                json.dumps(item.dependencies, ensure_ascii=False),
                json.dumps(item.dev_dependencies, ensure_ascii=False),
            )
            for item in code_index.manifests
        ],
    )


def _insert_audit_candidates_from_index(
    conn,
    snapshot_id: str,
    files: list[CodeFile],
    code_index,
    *,
    root: Path | None = None,
) -> None:
    row = conn.execute(
        """
        SELECT s.project_id, p.status AS project_status
        FROM source_snapshots s
        JOIN projects p ON p.id = s.project_id
        WHERE s.id = ?
        """,
        (snapshot_id,),
    ).fetchone()
    if row is None:
        return
    project_id = row["project_id"]
    project_completed = row["project_status"] == "completed"
    created_at = utcnow()
    candidates: list[tuple[object, ...]] = []
    seen: set[tuple[str, str | None, int | None, str | None]] = set()

    def add_candidate(
        *,
        source: str,
        candidate_type: str,
        title: str,
        description: str,
        file_path: str | None,
        line_start: int | None,
        line_end: int | None = None,
        entry_point: str | None = None,
        symbol: str | None = None,
    ) -> None:
        if len(candidates) >= MAX_SOURCE_INDEX_CANDIDATES:
            return
        key = (candidate_type, file_path, line_start, entry_point)
        if key in seen:
            return
        seen.add(key)
        candidate_id = _stable_candidate_id(snapshot_id, source, candidate_type, file_path, line_start, entry_point, title)
        status = "needs_more_evidence" if project_completed else "candidate"
        conclusion_summary = None
        evidence = None
        concluded_by = None
        concluded_at = None
        if project_completed:
            conclusion_summary = (
                "项目完成后由源码索引回填该待审计面，未重新判定漏洞，"
                "仅作为后续确认覆盖线索保留。"
            )
            evidence = _candidate_backfill_evidence(file_path, line_start, description)
            concluded_by = "source_index_backfill"
            concluded_at = created_at
        candidates.append(
            (
                candidate_id,
                project_id,
                snapshot_id,
                source,
                candidate_type,
                "unknown",
                title,
                description,
                file_path,
                line_start,
                line_end,
                entry_point,
                symbol,
                status,
                conclusion_summary,
                evidence,
                "source_index",
                created_at,
                created_at,
                concluded_by,
                concluded_at,
            )
        )

    source_root = root or snapshot_path(snapshot_id)
    indexed_entrypoint_paths: set[str] = set()
    entrypoint_by_path: dict[str, str] = {}
    for entrypoint in code_index.entrypoints:
        if not _is_candidate_source_path(entrypoint.path):
            continue
        indexed_entrypoint_paths.add(entrypoint.path)
        label = _entrypoint_label(entrypoint.method, entrypoint.route)
        entrypoint_by_path.setdefault(entrypoint.path, label)
        add_candidate(
            source="index",
            candidate_type="entrypoint",
            title=f"审计入口: {label}",
            description=(
                f"代码索引识别到入口 {label}，位于 {entrypoint.path}。"
                "需要按真实数据流和访问控制进行安全审计。"
            ),
            file_path=entrypoint.path,
            line_start=entrypoint.line_start,
            entry_point=label,
            symbol=entrypoint.handler,
        )

    for file in files:
        if file.is_binary or file.path in indexed_entrypoint_paths:
            continue
        text = _read_candidate_text(source_root / file.path)
        if not _is_web_script_candidate_path(file.path, text):
            continue
        route = f"/{file.path}"
        add_candidate(
            source="index",
            candidate_type="web_entrypoint",
            title=f"审计 Web 脚本: {file.path}",
            description=(
                f"{file.path} 是可能被 Web 服务器直接暴露的脚本文件。"
                "需要确认入口参数、权限控制、敏感操作和外部数据流是否安全。"
            ),
            file_path=file.path,
            line_start=1,
            entry_point=route,
        )

    for file in files:
        if file.is_binary or not _is_candidate_source_path(file.path):
            continue
        text = _read_candidate_text(source_root / file.path)
        if text is None:
            continue
        entry_point = entrypoint_by_path.get(file.path)
        if entry_point is None and _is_web_script_candidate_path(file.path, text):
            entry_point = f"/{file.path}"
        for signal in _extract_risk_signals(text):
            add_candidate(
                source="index",
                candidate_type="data_flow",
                title=f"审计数据流: {signal.category} {file.path}:{signal.line_start}",
                description=(
                    f"源码索引发现 {file.path}:{signal.line_start} 存在 {signal.title}，"
                    f"同时在同一文件识别到 {signal.source_summary}。"
                    "该候选只表示需要审计，不代表已确认漏洞；请检查输入可达性、净化/参数化、"
                    "权限控制和真实影响，并输出结构化 findings 或 candidate_conclusions。"
                    f" 代码证据：{signal.evidence}"
                ),
                file_path=file.path,
                line_start=signal.line_start,
                line_end=signal.line_end,
                entry_point=entry_point,
                symbol=signal.symbol,
            )

    if not candidates:
        return
    conn.executemany(
        """
        INSERT OR IGNORE INTO audit_candidates (
            id, project_id, snapshot_id, source, candidate_type, severity,
            title, description, file_path, line_start, line_end, entry_point,
            symbol, status, conclusion_summary, evidence, created_by,
            created_at, updated_at, concluded_by, concluded_at
        )
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
        candidates,
    )


def _ensure_business_graph_seed(conn, snapshot_id: str) -> None:
    row = conn.execute(
        "SELECT project_id FROM source_snapshots WHERE id = ?",
        (snapshot_id,),
    ).fetchone()
    if row is None:
        return
    project_id = row["project_id"]
    now = utcnow()
    endpoint_by_path: dict[str, list[str]] = {}
    endpoint_by_label: dict[str, str] = {}
    control_by_ref: dict[tuple[str, str], str] = {}
    controls_by_path: dict[str, list[str]] = {}
    data_by_ref: dict[tuple[str, str], str] = {}
    data_by_path: dict[str, list[str]] = {}

    entrypoints = conn.execute(
        """
        SELECT path, method, route, handler, line_start, evidence, confidence, source
        FROM code_entrypoints
        WHERE snapshot_id = ?
        ORDER BY path, COALESCE(line_start, 0), route, COALESCE(method, '')
        """,
        (snapshot_id,),
    ).fetchall()
    data_symbols = conn.execute(
        """
        SELECT path, name, signature, line_start, confidence, source
        FROM code_symbols
        WHERE snapshot_id = ?
          AND kind = 'data_object'
        ORDER BY path, COALESCE(line_start, 0), name
        """,
        (snapshot_id,),
    ).fetchall()
    relationships = conn.execute(
        """
        SELECT from_path, from_symbol, to_path, to_symbol, relation,
               evidence, confidence, source, line_start
        FROM code_relationships
        WHERE snapshot_id = ?
        ORDER BY from_path, relation, to_path, COALESCE(line_start, 0)
        """,
        (snapshot_id,),
    ).fetchall()

    def ensure_feature(entrypoint) -> str | None:
        feature_key = _route_feature_key(entrypoint["route"])
        if feature_key is None:
            return None
        node_id = _stable_business_id("biz", snapshot_id, "feature", feature_key)
        evidence = _business_evidence(entrypoint["path"], entrypoint["line_start"], entrypoint["evidence"])
        _insert_business_node_seed(
            conn,
            project_id,
            snapshot_id=snapshot_id,
            node_id=node_id,
            node_type="feature",
            title=f"业务功能 {_feature_title(feature_key)}",
            description=(
                f"源码索引根据路由 {entrypoint['route']} 归纳出的业务功能分组。"
                "该节点用于把相关入口聚合到同一审计上下文。"
            ),
            risk_level="medium",
            review_status="unreviewed",
            coverage_note="索引自动生成的功能聚合节点，供大模型理解业务边界。",
            risk_tags=["业务功能"],
            evidence=evidence,
            confidence=min(0.78, max(0.45, float(entrypoint["confidence"] or 0.7))),
            created_by="source_index",
            now=now,
        )
        return node_id

    def ensure_control(path: str | None, symbol: str | None, evidence_text: str | None, line_start: int | None, confidence: float) -> str | None:
        if not path or not symbol:
            return None
        clean_symbol = symbol.strip()[:160]
        if not clean_symbol:
            return None
        key = (path, clean_symbol)
        existing = control_by_ref.get(key)
        if existing:
            return existing
        node_id = _stable_business_id("biz", snapshot_id, "control", path, clean_symbol)
        evidence = _business_evidence(path, line_start, evidence_text)
        _insert_business_node_seed(
            conn,
            project_id,
            snapshot_id=snapshot_id,
            node_id=node_id,
            node_type="control",
            title=f"处理逻辑 {clean_symbol}",
            description=(
                f"源码索引识别到 {path} 中的处理逻辑 {clean_symbol}。"
                "该节点用于连接入口、服务调用和数据对象。"
            ),
            risk_level="medium",
            review_status="unreviewed",
            coverage_note="索引自动生成的处理逻辑节点，供审计路径导航使用。",
            risk_tags=["处理逻辑"],
            evidence=evidence,
            confidence=min(0.82, max(0.45, confidence)),
            created_by="source_index",
            now=now,
        )
        control_by_ref[key] = node_id
        controls_by_path.setdefault(path, []).append(node_id)
        return node_id

    def ensure_data_object(path: str | None, name: str | None, evidence_text: str | None, line_start: int | None, confidence: float) -> str | None:
        if not path or not name:
            return None
        clean_name = name.strip()[:160]
        if not clean_name:
            return None
        key = (path, clean_name)
        existing = data_by_ref.get(key)
        if existing:
            return existing
        node_id = _stable_business_id("biz", snapshot_id, "data_object", path, clean_name)
        evidence = _business_evidence(path, line_start, evidence_text)
        _insert_business_node_seed(
            conn,
            project_id,
            snapshot_id=snapshot_id,
            node_id=node_id,
            node_type="data_object",
            title=f"数据对象 {clean_name}",
            description=(
                f"源码索引从 {path} 识别到数据对象 {clean_name}。"
                "该节点用于帮助大模型理解业务资源、表或模型。"
            ),
            risk_level="medium",
            review_status="unreviewed",
            coverage_note="索引自动生成的数据对象节点，供业务图和数据流审计使用。",
            risk_tags=["数据对象"],
            evidence=evidence,
            confidence=min(0.86, max(0.45, confidence)),
            created_by="source_index",
            now=now,
        )
        data_by_ref[key] = node_id
        data_by_path.setdefault(path, []).append(node_id)
        return node_id

    for symbol in data_symbols:
        ensure_data_object(
            symbol["path"],
            symbol["name"],
            symbol["signature"],
            symbol["line_start"],
            float(symbol["confidence"] or 0.65),
        )

    for entrypoint in entrypoints:
        if not _is_candidate_source_path(entrypoint["path"]):
            continue
        label = _entrypoint_label(entrypoint["method"], entrypoint["route"])
        node_id = _stable_business_id(
            "biz",
            snapshot_id,
            "endpoint",
            entrypoint["path"],
            label,
            entrypoint["handler"],
            entrypoint["line_start"],
        )
        endpoint_by_path.setdefault(entrypoint["path"], []).append(node_id)
        endpoint_by_label[label] = node_id
        evidence = _business_evidence(entrypoint["path"], entrypoint["line_start"], entrypoint["evidence"])
        _insert_business_node_seed(
            conn,
            project_id,
            snapshot_id=snapshot_id,
            node_id=node_id,
            node_type="endpoint",
            title=f"入口 {label}",
            description=(
                f"源码索引识别到入口 {label}，处理器为 {entrypoint['handler'] or '未命名'}。"
                "该节点用于业务图导航和覆盖跟踪，不代表漏洞结论。"
            ),
            risk_level="medium",
            review_status="unreviewed",
            coverage_note="索引自动生成的入口节点，供审计调度和可视化使用。",
            risk_tags=["入口"],
            evidence=evidence,
            confidence=min(0.9, max(0.45, float(entrypoint["confidence"] or 0.75))),
            created_by="source_index",
            now=now,
        )
        feature_id = ensure_feature(entrypoint)
        if feature_id:
            _insert_business_edge_seed(
                conn,
                project_id,
                from_node_id=feature_id,
                to_node_id=node_id,
                relation="exposes",
                description="业务功能暴露该入口。",
                confidence=0.74,
                created_by="source_index",
                now=now,
            )
        control_id = ensure_control(
            entrypoint["path"],
            entrypoint["handler"],
            entrypoint["evidence"],
            entrypoint["line_start"],
            float(entrypoint["confidence"] or 0.7),
        )
        if control_id:
            _insert_business_edge_seed(
                conn,
                project_id,
                from_node_id=node_id,
                to_node_id=control_id,
                relation="calls",
                description="入口路由调用对应处理逻辑。",
                confidence=min(0.86, max(0.45, float(entrypoint["confidence"] or 0.7))),
                created_by="source_index",
                now=now,
            )
        for data_id in data_by_path.get(entrypoint["path"], []):
            _insert_business_edge_seed(
                conn,
                project_id,
                from_node_id=control_id or node_id,
                to_node_id=data_id,
                relation="uses",
                description="入口处理逻辑与同文件数据对象相关。",
                confidence=0.62,
                created_by="source_index",
                now=now,
            )
        conn.execute(
            """
            UPDATE audit_candidates
            SET business_node_id = ?, updated_at = ?
            WHERE snapshot_id = ?
              AND business_node_id IS NULL
              AND candidate_type IN ('entrypoint', 'web_entrypoint')
              AND file_path = ?
              AND entry_point = ?
            """,
            (node_id, now, snapshot_id, entrypoint["path"], label),
        )

    for relationship in relationships:
        source_nodes = controls_by_path.get(relationship["from_path"]) or endpoint_by_path.get(relationship["from_path"]) or []
        source_id = None
        if relationship["from_symbol"]:
            source_id = endpoint_by_label.get(relationship["from_symbol"]) or control_by_ref.get(
                (relationship["from_path"], relationship["from_symbol"])
            )
        if source_id is None and source_nodes:
            source_id = source_nodes[0]
        if source_id is None:
            continue
        target_data_id = None
        if relationship["to_symbol"]:
            target_data_id = data_by_ref.get((relationship["to_path"], relationship["to_symbol"]))
        if target_data_id is not None:
            _insert_business_edge_seed(
                conn,
                project_id,
                from_node_id=source_id,
                to_node_id=target_data_id,
                relation="uses",
                description="源码关系显示处理逻辑使用该数据对象。",
                confidence=min(0.78, max(0.4, float(relationship["confidence"] or 0.55))),
                created_by="source_index",
                now=now,
            )
            continue
        if relationship["relation"] in {"imports", "calls"}:
            for data_id in data_by_path.get(relationship["to_path"], []):
                _insert_business_edge_seed(
                    conn,
                    project_id,
                    from_node_id=source_id,
                    to_node_id=data_id,
                    relation="uses",
                    description="源码关系显示入口路径依赖包含数据对象的文件。",
                    confidence=min(0.68, max(0.35, float(relationship["confidence"] or 0.5))),
                    created_by="source_index",
                    now=now,
                )
        if relationship["relation"] == "calls" and relationship["to_symbol"]:
            target_control_id = ensure_control(
                relationship["to_path"],
                relationship["to_symbol"],
                relationship["evidence"],
                relationship["line_start"],
                float(relationship["confidence"] or 0.55),
            )
            if target_control_id:
                _insert_business_edge_seed(
                    conn,
                    project_id,
                    from_node_id=source_id,
                    to_node_id=target_control_id,
                    relation="calls",
                    description="源码索引识别到处理逻辑之间的调用关系。",
                    confidence=min(0.68, max(0.35, float(relationship["confidence"] or 0.55))),
                    created_by="source_index",
                    now=now,
                )

    candidates = conn.execute(
        """
        SELECT id, candidate_type, title, description, file_path, line_start,
               line_end, entry_point, symbol, business_node_id
        FROM audit_candidates
        WHERE snapshot_id = ?
          AND source = 'index'
          AND candidate_type = 'data_flow'
        ORDER BY created_at, id
        """,
        (snapshot_id,),
    ).fetchall()
    for candidate in candidates:
        node_id = _stable_business_id("biz", snapshot_id, "risk", candidate["id"])
        evidence = _business_evidence(candidate["file_path"], candidate["line_start"], candidate["description"])
        risk_tag = _candidate_risk_tag(candidate["title"])
        _insert_business_node_seed(
            conn,
            project_id,
            snapshot_id=snapshot_id,
            node_id=node_id,
            node_type="risk",
            title=f"待审计风险面 {candidate['title']}",
            description=(
                f"{candidate['description']} "
                "该节点由源码索引生成，只表示需要 worker 读取源码确认，不代表已确认漏洞。"
            ),
            risk_level="unknown",
            review_status="unreviewed",
            coverage_note="索引自动生成的高价值待审计风险面，需要源码证据闭环。",
            risk_tags=[risk_tag] if risk_tag else ["待审计风险面"],
            evidence=evidence,
            confidence=0.72,
            created_by="source_index",
            now=now,
        )
        conn.execute(
            """
            UPDATE audit_candidates
            SET business_node_id = ?, updated_at = ?
            WHERE id = ? AND snapshot_id = ? AND business_node_id IS NULL
            """,
            (node_id, now, candidate["id"], snapshot_id),
        )
        endpoint_ids = endpoint_by_path.get(candidate["file_path"] or "") or []
        endpoint_id = endpoint_by_label.get(candidate["entry_point"] or "") or (endpoint_ids[0] if endpoint_ids else None)
        if endpoint_id:
            _insert_business_edge_seed(
                conn,
                project_id,
                from_node_id=endpoint_id,
                to_node_id=node_id,
                relation="risk_of",
                description="入口关联到索引发现的待审计风险面。",
                confidence=0.7,
                created_by="source_index",
                now=now,
            )
        for control_id in controls_by_path.get(candidate["file_path"] or "", []):
            _insert_business_edge_seed(
                conn,
                project_id,
                from_node_id=control_id,
                to_node_id=node_id,
                relation="risk_of",
                description="处理逻辑关联到索引发现的待审计风险面。",
                confidence=0.66,
                created_by="source_index",
                now=now,
            )
        for data_id in data_by_path.get(candidate["file_path"] or "", []):
            _insert_business_edge_seed(
                conn,
                project_id,
                from_node_id=data_id,
                to_node_id=node_id,
                relation="risk_of",
                description="数据对象关联到索引发现的待审计风险面。",
                confidence=0.6,
                created_by="source_index",
                now=now,
            )


def _insert_business_node_seed(
    conn,
    project_id: str,
    *,
    snapshot_id: str,
    node_id: str,
    node_type: str,
    title: str,
    description: str,
    risk_level: str,
    review_status: str,
    coverage_note: str,
    risk_tags: list[str],
    evidence: list[str],
    confidence: float,
    created_by: str,
    now: str,
) -> None:
    conn.execute(
        """
        INSERT OR IGNORE INTO business_nodes (
            id, project_id, node_type, title, description, risk_level,
            review_status, coverage_note, last_intent_id, risk_tags_json,
            evidence_json, source_snapshot_id, confidence, created_by, created_at, updated_at
        )
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, NULL, ?, ?, ?, ?, ?, ?, ?)
        """,
        (
            node_id,
            project_id,
            node_type,
            title[:200],
            description[:2000],
            risk_level,
            review_status,
            coverage_note[:1000],
            json.dumps(risk_tags, ensure_ascii=False),
            json.dumps(evidence[:5], ensure_ascii=False),
            snapshot_id,
            confidence,
            created_by,
            now,
            now,
        ),
    )


def _insert_business_edge_seed(
    conn,
    project_id: str,
    *,
    from_node_id: str,
    to_node_id: str,
    relation: str,
    description: str,
    confidence: float,
    created_by: str,
    now: str,
) -> None:
    edge_id = _stable_business_id("bedge", project_id, from_node_id, to_node_id, relation)
    conn.execute(
        """
        INSERT OR IGNORE INTO business_edges (
            id, project_id, from_node_id, to_node_id, relation,
            description, confidence, created_by, created_at
        )
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (
            edge_id,
            project_id,
            from_node_id,
            to_node_id,
            relation,
            description,
            confidence,
            created_by,
            now,
        ),
    )


def _business_evidence(path: str | None, line_start: int | None, detail: str | None) -> list[str]:
    if not path:
        return []
    location = f"{path}:{line_start}" if line_start else path
    if detail:
        return [f"{location} {detail[:220]}"]
    return [location]


ROUTE_GROUP_PREFIXES = {"api", "v1", "v2", "v3", "rest", "admin"}


def _route_feature_key(route: str | None) -> str | None:
    if not route:
        return None
    text = route.split("?", 1)[0].strip("/")
    if not text:
        return None
    for part in text.split("/"):
        clean = part.strip()
        if not clean or clean.startswith("{") or clean.startswith(":") or clean.startswith("<"):
            continue
        if clean.lower() in ROUTE_GROUP_PREFIXES:
            continue
        return clean[:80]
    return None


def _feature_title(key: str) -> str:
    text = key.replace("_", " ").replace("-", " ").strip()
    return text or key


def _candidate_backfill_evidence(file_path: str | None, line_start: int | None, description: str) -> str:
    location = f"{file_path}:{line_start}" if file_path and line_start else file_path or "source index"
    return f"{location} {description[:500]}"


def _candidate_risk_tag(title: str | None) -> str | None:
    if not title:
        return None
    match = re.search(r"审计数据流:\s*([^\s]+)", title)
    if match:
        return match.group(1)
    return None


def _stable_business_id(prefix: str, *parts: object) -> str:
    digest = hashlib.sha1("\0".join("" if part is None else str(part) for part in parts).encode("utf-8")).hexdigest()
    return f"{prefix}_{digest[:16]}"


def _stable_candidate_id(*parts: object) -> str:
    digest = hashlib.sha1("\0".join("" if part is None else str(part) for part in parts).encode("utf-8")).hexdigest()
    return f"cand_{digest[:16]}"


def _entrypoint_label(method: str | None, route: str) -> str:
    route_text = route.strip() or "/"
    return f"{method} {route_text}" if method else route_text


def _is_candidate_source_path(path: str) -> bool:
    parts = PurePosixPath(path).parts
    return not any(part in WEB_SCRIPT_EXCLUDED_PARTS for part in parts)


def _is_web_script_candidate_path(path: str, text: str | None = None) -> bool:
    if PurePosixPath(path).suffix.lower() not in WEB_SCRIPT_SUFFIXES:
        return False
    if not _is_candidate_source_path(path):
        return False
    return is_likely_generic_web_script(path, text)


def _read_candidate_text(path: Path) -> str | None:
    try:
        if path.stat().st_size > MAX_CANDIDATE_TEXT_BYTES:
            return None
        return path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return None


def _extract_risk_signals(text: str) -> list[RiskSignal]:
    sources = _collect_input_sources(text)
    if not sources:
        return []
    input_variables = _collect_input_variables(text)
    signals: list[RiskSignal] = []
    seen: set[tuple[str, int]] = set()
    for lineno, raw_line in enumerate(text.splitlines(), start=1):
        line = raw_line.strip()
        if not line or line.startswith(("//", "#")):
            continue
        for sink in SINK_PATTERNS:
            if not sink.pattern.search(line):
                continue
            if not _sink_line_is_tied_to_input(line, lineno, input_variables):
                continue
            key = (sink.category, lineno)
            if key in seen:
                continue
            nearby_sources = _nearby_input_sources(sources, lineno)
            seen.add(key)
            signals.append(
                RiskSignal(
                    category=sink.category,
                    title=sink.title,
                    line_start=lineno,
                    line_end=lineno,
                    evidence=line[:260],
                    source_summary=_source_summary(nearby_sources or sources[:3]),
                    symbol=_best_input_symbol(line, lineno, input_variables),
                )
            )
            if len(signals) >= MAX_DATA_FLOW_CANDIDATES_PER_FILE:
                return signals
    return signals


def _collect_input_sources(text: str) -> list[tuple[int, str]]:
    sources: list[tuple[int, str]] = []
    for lineno, raw_line in enumerate(text.splitlines(), start=1):
        line = raw_line.strip()
        if not line or line.startswith(("//", "#")):
            continue
        if any(pattern.search(line) for _label, pattern in INPUT_SOURCE_PATTERNS):
            sources.append((lineno, line[:180]))
            if len(sources) >= 12:
                break
    return sources


def _collect_input_variables(text: str) -> InputVariableMap:
    variables: InputVariableMap = {}
    lines = text.splitlines()
    for lineno, line in enumerate(lines, start=1):
        stripped = line.strip()
        for pattern in INPUT_VARIABLE_PATTERNS:
            match = pattern.search(stripped)
            if match:
                _add_input_variable(variables, match.group(1), lineno)
    changed = True
    while changed:
        changed = False
        for lineno, line in enumerate(lines, start=1):
            stripped = line.strip()
            destructured = JS_DESTRUCTURING_PATTERN.search(stripped)
            if destructured and _has_nearby_input_variable(destructured.group(2), lineno, variables):
                for name in re.findall(r"\b([A-Za-z_$][\w$]*)\b", destructured.group(1)):
                    if _add_input_variable(variables, name, lineno):
                        changed = True
            derived = JS_DERIVED_VARIABLE_PATTERN.search(stripped)
            if derived and _expression_uses_nearby_input(derived.group(2), lineno, variables, php=False):
                if _add_input_variable(variables, derived.group(1), lineno):
                    changed = True
                continue
            php_derived = PHP_DERIVED_VARIABLE_PATTERN.search(stripped)
            if (
                php_derived
                and not any(sink.pattern.search(stripped) for sink in SINK_PATTERNS)
                and _expression_uses_nearby_input(php_derived.group(2), lineno, variables, php=True)
            ):
                if _add_input_variable(variables, php_derived.group(1), lineno):
                    changed = True
    return variables


def _add_input_variable(variables: InputVariableMap, name: str, lineno: int) -> bool:
    if not name:
        return False
    locations = variables.setdefault(name, [])
    if lineno in locations:
        return False
    locations.append(lineno)
    locations.sort()
    return True


def _has_nearby_input_variable(name: str, lineno: int, variables: InputVariableMap) -> bool:
    return any(
        0 <= lineno - source_lineno <= MAX_INPUT_TO_SINK_LINE_DISTANCE
        for source_lineno in variables.get(name, [])
    )


def _expression_uses_nearby_input(
    expression: str,
    lineno: int,
    variables: InputVariableMap,
    *,
    php: bool,
) -> bool:
    for variable in variables:
        if php:
            pattern = rf"\${re.escape(variable)}\b"
        else:
            pattern = rf"\b{re.escape(variable)}\b"
        if re.search(pattern, expression) and _has_nearby_input_variable(variable, lineno, variables):
            return True
    return False


def _nearby_input_sources(sources: list[tuple[int, str]], sink_lineno: int) -> list[tuple[int, str]]:
    nearby = [
        (lineno, line)
        for lineno, line in sources
        if 0 <= sink_lineno - lineno <= MAX_INPUT_TO_SINK_LINE_DISTANCE
    ]
    return nearby[:3]


def _source_summary(sources: list[tuple[int, str]]) -> str:
    first_items = [f"第 {lineno} 行 `{line}`" for lineno, line in sources[:3]]
    if len(sources) > 3:
        first_items.append(f"另有 {len(sources) - 3} 处输入读取")
    return "、".join(first_items)


def _sink_line_is_tied_to_input(line: str, lineno: int, input_variables: InputVariableMap) -> bool:
    if any(pattern.search(line) for _label, pattern in INPUT_SOURCE_PATTERNS):
        return True
    for variable in input_variables:
        if not _has_nearby_input_variable(variable, lineno, input_variables):
            continue
        if re.search(rf"(?:\${re.escape(variable)}\b|\b{re.escape(variable)}\b)", line):
            return True
    return False


def _best_input_symbol(line: str, lineno: int, input_variables: InputVariableMap) -> str | None:
    for variable in sorted(input_variables):
        if not _has_nearby_input_variable(variable, lineno, input_variables):
            continue
        if re.search(rf"(?:\${re.escape(variable)}\b|\b{re.escape(variable)}\b)", line):
            return variable
    return None


def _ensure_code_index(snapshot: SourceSnapshot) -> None:
    if snapshot.status != "ready":
        return
    root = snapshot_path(snapshot.id)
    if not root.exists():
        return
    with db.get_conn() as conn:
        existing = conn.execute(
            """
            SELECT
                (SELECT COUNT(*) FROM code_symbols WHERE snapshot_id = ?) +
                (SELECT COUNT(*) FROM code_entrypoints WHERE snapshot_id = ?) +
                (SELECT COUNT(*) FROM dependency_manifests WHERE snapshot_id = ?) AS count
            """,
            (snapshot.id, snapshot.id, snapshot.id),
        ).fetchone()["count"]
        if existing:
            _ensure_snapshot_audit_candidates(conn, snapshot, root)
            _ensure_business_graph_seed(conn, snapshot.id)
            return
        files = _load_code_files(conn, snapshot.id)
        code_index = extract_code_index(snapshot.id, root, files)
        _insert_code_index(conn, code_index)
        _insert_audit_candidates_from_index(conn, snapshot.id, files, code_index, root=root)
        _ensure_business_graph_seed(conn, snapshot.id)


def _ensure_snapshot_audit_candidates(conn, snapshot: SourceSnapshot, root: Path) -> None:
    existing = conn.execute(
        "SELECT COUNT(*) AS count FROM audit_candidates WHERE snapshot_id = ?",
        (snapshot.id,),
    ).fetchone()["count"]
    if existing:
        return
    files = _load_code_files(conn, snapshot.id)
    code_index = extract_code_index(snapshot.id, root, files)
    _insert_audit_candidates_from_index(conn, snapshot.id, files, code_index, root=root)
    _ensure_business_graph_seed(conn, snapshot.id)


def _load_code_files(conn, snapshot_id: str) -> list[CodeFile]:
    rows = conn.execute(
        """
        SELECT snapshot_id, path, size_bytes, sha256, language, is_binary
        FROM code_files
        WHERE snapshot_id = ?
        ORDER BY path
        """,
        (snapshot_id,),
    ).fetchall()
    files = [
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
    return files


def _index_snapshot(snapshot_id: str):
    root = snapshot_path(snapshot_id)
    files: list[CodeFile] = []
    languages: dict[str, int] = {}
    manifest_digest = hashlib.sha256()
    total_bytes = 0
    for path in sorted(root.rglob("*")):
        if path.is_symlink():
            relative = path.relative_to(root).as_posix()
            raise ValueError(f"Source snapshot contains a symbolic link: {relative}")
        if not path.is_file():
            continue
        relative = path.relative_to(root).as_posix()
        size = path.stat().st_size
        if len(files) >= MAX_FILE_COUNT:
            raise ValueError(f"Source snapshot contains more than {MAX_FILE_COUNT} files")
        if size > MAX_FILE_BYTES:
            raise ValueError(f"Source file exceeds {MAX_FILE_BYTES} bytes: {relative}")
        if total_bytes + size > MAX_EXTRACTED_BYTES:
            raise ValueError(f"Source snapshot exceeds {MAX_EXTRACTED_BYTES} bytes")
        digest, is_binary = _hash_file(path)
        language = _detect_language(path, is_binary)
        if language:
            languages[language] = languages.get(language, 0) + 1
        total_bytes += size
        manifest_digest.update(f"{relative}\0{size}\0{digest}\n".encode("utf-8"))
        files.append(
            CodeFile(
                snapshot_id=snapshot_id,
                path=relative,
                size_bytes=size,
                sha256=digest,
                language=language,
                is_binary=is_binary,
            )
        )
    code_index = extract_code_index(snapshot_id, root, files)
    return files, manifest_digest.hexdigest(), languages, total_bytes, code_index


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


def _hash_file(path: Path) -> tuple[str, bool]:
    digest = hashlib.sha256()
    first = b""
    with path.open("rb") as handle:
        while True:
            chunk = handle.read(COPY_CHUNK_BYTES)
            if not chunk:
                break
            if not first:
                first = chunk[:8192]
            digest.update(chunk)
    return digest.hexdigest(), b"\0" in first


def _detect_language(path: Path, is_binary: bool) -> str | None:
    language = LANGUAGE_BY_SUFFIX.get(path.suffix.lower())
    if language or is_binary:
        return language
    try:
        sample = path.read_bytes()[:4096].decode("utf-8", errors="ignore")
    except OSError:
        return None
    stripped = sample.lstrip()
    if stripped.startswith("<?php") or "<?php" in sample[:512]:
        return "PHP"
    if stripped.lower().startswith(("<!doctype html", "<html")):
        return "HTML"
    return None


def _new_snapshot_id() -> str:
    return f"snap_{uuid.uuid4().hex[:16]}"


def _insert_importing_snapshot(
    snapshot_id: str,
    project_id: str,
    *,
    source_type: str,
    repository_url: str | None,
    requested_ref: str | None,
    original_name: str | None,
    created_at: str,
) -> None:
    with db.get_conn() as conn:
        get_project_or_404(conn, project_id)
        conn.execute(
            """
            INSERT INTO source_snapshots (
                id, project_id, source_type, original_name, repository_url,
                requested_ref, status, created_at
            )
            VALUES (?, ?, ?, ?, ?, ?, 'importing', ?)
            """,
            (
                snapshot_id,
                project_id,
                source_type,
                original_name,
                repository_url,
                requested_ref,
                created_at,
            ),
        )


def _mark_snapshot_failed(snapshot_id: str, error_message: str) -> None:
    with db.get_conn() as conn:
        conn.execute(
            "UPDATE source_snapshots SET status = 'failed', error_message = ? WHERE id = ?",
            (error_message[:2000], snapshot_id),
        )


def _snapshot_from_row(row) -> SourceSnapshot:
    try:
        languages = json.loads(row["detected_languages_json"] or "{}")
    except json.JSONDecodeError:
        languages = {}
    return SourceSnapshot(
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
        detected_languages=languages if isinstance(languages, dict) else {},
        created_at=row["created_at"],
        error_message=row["error_message"],
    )
