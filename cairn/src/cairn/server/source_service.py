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
    CodeCapability,
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
MAX_SIGNAL_FRAGMENT_CHARS = 140
MAX_AUDIT_CANDIDATE_DESCRIPTION_CHARS = 1600
MAX_CODE_CAPABILITIES_PER_FILE = 20
MAX_CAPABILITY_CHAIN_CANDIDATES = 120
MAX_PRIORITY_REASON_COUNT = 6
HIGH_IMPACT_RISK_SIGNAL_CATEGORIES = {
    "文件读写/加载能力",
    "系统进程能力",
    "对象反序列化能力",
}
HIGH_IMPACT_CAPABILITY_CATEGORIES = {
    "archive_extract",
    "file_upload",
    "file_write",
    "process_execution",
    "task_execution",
    "credential_access",
}
CAPABILITY_CATEGORY_TITLES = {
    "archive_extract": "归档解压/展开能力",
    "file_upload": "文件上传入口/接收能力",
    "file_read": "文件读取能力",
    "file_write": "文件写入/删除能力",
    "process_execution": "系统进程/命令执行能力",
    "task_execution": "后台任务/Runner 执行能力",
    "template_render": "模板/YAML/解释器能力",
    "credential_access": "凭据/令牌访问能力",
    "auth_guard": "认证/权限边界",
    "object_scope_guard": "对象归属/租户边界",
    "external_system": "外部系统/基础设施调用能力",
    "websocket_boundary": "WebSocket/长连接边界",
    "object_id_lookup": "对象 ID 查询/资源定位能力",
}
CAPABILITY_TAGS_BY_CATEGORY = {
    "archive_extract": ["文件能力", "归档展开"],
    "file_upload": ["文件能力", "上传入口"],
    "file_read": ["文件能力", "读取"],
    "file_write": ["文件能力", "写入"],
    "process_execution": ["执行能力", "进程"],
    "task_execution": ["执行能力", "后台任务"],
    "template_render": ["解释器能力", "模板"],
    "credential_access": ["敏感资产", "凭据"],
    "auth_guard": ["权限边界", "认证授权"],
    "object_scope_guard": ["对象边界", "租户/归属"],
    "external_system": ["外部系统", "基础设施"],
    "websocket_boundary": ["入口边界", "长连接"],
    "object_id_lookup": ["对象边界", "资源定位"],
}
CONTROL_PLANE_KEYWORDS = (
    "admin",
    "ops",
    "operation",
    "playbook",
    "ansible",
    "celery",
    "task",
    "job",
    "runner",
    "terminal",
    "command",
    "asset",
    "credential",
    "secret",
    "token",
    "ldap",
    "k8s",
    "kubernetes",
    "websocket",
    "upload",
    "import",
    "plugin",
    "automation",
)
UPLOAD_CONTEXT_RE = re.compile(
    r"\b(?:upload|multipart|form-data|request\.FILES|files\[|serializer\.save|UploadedFile|move_uploaded_file|saveMultipartFile)\b",
    re.IGNORECASE,
)

InputVariableMap = dict[str, list[int]]


@dataclass(frozen=True)
class RiskSignal:
    category: str
    title: str
    line_start: int
    line_end: int | None
    evidence: str
    source_summary: str
    control_summary: str | None = None
    context_summary: str | None = None
    symbol: str | None = None


@dataclass(frozen=True)
class CodeCapabilityFact:
    id: str
    snapshot_id: str
    path: str
    symbol: str | None
    category: str
    title: str
    line_start: int
    line_end: int | None
    evidence: str
    risk_level: str
    risk_tags: tuple[str, ...]
    confidence: float = 0.65
    source: str = "heuristic:capability"


@dataclass(frozen=True)
class SinkPattern:
    category: str
    title: str
    pattern: re.Pattern[str]


INPUT_SOURCE_PATTERNS: tuple[tuple[str, re.Pattern[str]], ...] = (
    ("HTTP 参数/请求体", re.compile(r"\$_(?:GET|POST|REQUEST|COOKIE|SERVER|FILES)\b|php://input")),
    ("HTTP 请求对象", re.compile(r"\b(?:req|request|ctx)\.(?:query|body|params|headers|cookies|file|files)\b")),
    ("SatRDA 请求对象", re.compile(r"\br\.(?:jsonBody|body|formValue|url\.query\.get|url\.rawQuery)\b|\bUrlUtils\.queryParams\s*\(\s*r\.url\.rawQuery\s*\)")),
    ("Python Web 请求", re.compile(r"\brequest\.(?:args|form|json|data|cookies|headers|GET|POST|FILES|files|query_params)\b")),
    ("Java Web 参数", re.compile(r"\b(?:getParameter|getHeader|getCookies|getPart|getParts|getInputStream)\s*\(|@(RequestParam|PathVariable|RequestBody|RequestPart)\b|\bMultipartFile\b")),
    ("Go Web 参数", re.compile(r"\b(?:URL\.Query|FormValue|PostFormValue|Param|Query|PostForm|FormFile|MultipartReader)\s*\(")),
)
CONTROL_SIGNAL_PATTERNS: tuple[tuple[str, re.Pattern[str]], ...] = (
    (
        "会话/鉴权/权限线索",
        re.compile(
            r"\b(?:getSession|session\.get|isAuthenticated|authenticate|authorize|hasRole|hasPermission|"
            r"checkRole|checkPermission|requireAuth|login|logout|jwt|token|principal|userId|roleId)\b"
            r"|@(?:PreAuthorize|RolesAllowed|Secured)\b",
            re.IGNORECASE,
        ),
    ),
    (
        "边界/规范化/白名单线索",
        re.compile(
            r"\b(?:normalize|realpath|resolve|basename|secure_filename|allowed|whitelist|blacklist|"
            r"validate|sanitize|escape|parameter|prepared|bind|limit|size|extension|mime|contentType)\b",
            re.IGNORECASE,
        ),
    ),
)
INPUT_VARIABLE_PATTERNS: tuple[re.Pattern[str], ...] = (
    re.compile(r"\$([A-Za-z_][\w]*)\s*=\s*.*(?:\$_(?:GET|POST|REQUEST|COOKIE|SERVER|FILES)\b|php://input)"),
    re.compile(r"\b(?:const|let|var)\s+([A-Za-z_$][\w$]*)\s*=\s*.*\b(?:req|request|ctx)\.(?:query|body|params|headers|cookies|file|files)\b"),
    re.compile(r"\b(?:const|let|var)\s+([A-Za-z_$][\w$]*)\s*=\s*.*(?:\br\.(?:jsonBody|body|formValue|url\.query\.get|url\.rawQuery)\b|\bUrlUtils\.queryParams\s*\(\s*r\.url\.rawQuery\s*\))"),
    re.compile(r"\b([A-Za-z_][\w]*)\s*=\s*request\.(?:args|form|json|data|cookies|headers|GET|POST|FILES|files|query_params)\b"),
    re.compile(r"\b(?:String|var|Part|MultipartFile|InputStream)\s+([A-Za-z_][\w]*)\s*=\s*[^;]*\b(?:getParameter|getHeader|getPart|getInputStream)\s*\("),
    re.compile(r"\b([A-Za-z_][\w]*)\s*:=\s*[^;\n]*\b(?:URL\.Query|FormValue|PostFormValue|Param|Query|PostForm|FormFile|MultipartReader)\s*\("),
)
JS_DESTRUCTURING_PATTERN = re.compile(r"\b(?:const|let|var)\s*\{([^}]+)\}\s*=\s*([A-Za-z_$][\w$]*)")
JS_DERIVED_VARIABLE_PATTERN = re.compile(r"\b(?:const|let|var)\s+([A-Za-z_$][\w$]*)\s*=\s*(.+)")
PHP_DERIVED_VARIABLE_PATTERN = re.compile(r"\$([A-Za-z_][\w]*)\s*=\s*(.+)")
SINK_PATTERNS: tuple[SinkPattern, ...] = (
    SinkPattern(
        "数据库执行能力",
        "数据库查询/更新能力",
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
        "系统进程能力",
        "系统命令/进程调用能力",
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
        "文件读写/加载能力",
        "文件读写/加载能力",
        re.compile(
            r"\b(?:include|require|include_once|require_once)\s*\(?"
            r"|\b(?:file_get_contents|readfile|fopen|unlink|copy|move_uploaded_file)\s*\("
            r"|\bfs\.(?:readFile|writeFile|unlink|createReadStream|createWriteStream)\s*\("
            r"|\b(?:satrda\.(?:writeFile|fileOpen)|ctx\.(?:serveContent|saveMultipartFile))\s*\("
            r"|\b(?:default_storage|FileSystemStorage\([^)]*\)|storage)\.save\s*\("
            r"|\b(?:shutil\.copyfileobj|Files\.(?:copy|write|move)|FileOutputStream|FileInputStream)\b"
            r"|\b(?:transferTo|SaveUploadedFile|io\.Copy)\s*\("
            r"|\bopen\s*\([^;\n]*(?:request\.|req\.|\$_)",
            re.IGNORECASE,
        ),
    ),
    SinkPattern(
        "服务端外联能力",
        "服务端网络请求能力",
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
        "对象反序列化能力",
        "对象反序列化能力",
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
        "响应渲染输出能力",
        "响应输出/渲染能力",
        re.compile(r"\b(?:echo|print|printf)\b|\bres\.(?:send|write|end)\s*\(|\.innerHTML\s*=", re.IGNORECASE),
    ),
)
CAPABILITY_PATTERNS: tuple[tuple[str, re.Pattern[str]], ...] = (
    (
        "file_upload",
        re.compile(
            r"\b(?:request\.FILES|UploadedFile|FileField|ImageField|MultiPartParser|multipart/form-data)\b"
            r"|\b(?:MultipartFile|@RequestPart|getPart|getParts)\b"
            r"|\b(?:FormFile|MultipartReader|SaveUploadedFile)\s*\("
            r"|\b(?:multer|busboy|formidable)\b"
            r"|\b(?:move_uploaded_file|saveMultipartFile)\s*\(",
            re.IGNORECASE,
        ),
    ),
    (
        "archive_extract",
        re.compile(
            r"\bzipfile\.ZipFile\b|\.extract(?:all)?\s*\(|\bZipArchive\b|->extractTo\s*\("
            r"|\b(?:ZipInputStream|ArchiveInputStream|TarArchiveInputStream)\b"
            r"|\b(?:adm-zip|unzipper|decompress|extract-zip)\b",
            re.IGNORECASE,
        ),
    ),
    (
        "file_write",
        re.compile(
            r"\bopen\s*\([^;\n]*(?:['\"][wax]\+?['\"]|mode\s*=\s*['\"][wax]\+?['\"])"
            r"|\b(?:os\.(?:rename|remove|unlink)|shutil\.rmtree|Path\([^)]*\)\.write_text|Path\([^)]*\)\.write_bytes)\s*\("
            r"|\b(?:default_storage|FileSystemStorage\([^)]*\)|storage)\.save\s*\(|\bshutil\.copyfileobj\s*\("
            r"|\b(?:file_put_contents|move_uploaded_file|unlink|rename|copy)\s*\("
            r"|\bfs\.(?:writeFile|unlink|rm|rename|createWriteStream)\s*\("
            r"|\b(?:os|ioutil)\.WriteFile\s*\(|\bFiles\.(?:write|delete|move|copy)\s*\("
            r"|\bFileOutputStream\s*\(|\b(?:transferTo|SaveUploadedFile|io\.Copy)\s*\(",
            re.IGNORECASE,
        ),
    ),
    (
        "file_read",
        re.compile(
            r"\bopen\s*\([^;\n]*(?:['\"]r\+?['\"]|mode\s*=\s*['\"]r\+?['\"])"
            r"|\b(?:Path\([^)]*\)\.read_text|Path\([^)]*\)\.read_bytes)\s*\("
            r"|\b(?:file_get_contents|readfile|fopen)\s*\("
            r"|\bfs\.(?:readFile|createReadStream)\s*\("
            r"|\b(?:os|ioutil)\.ReadFile\s*\(|\bFiles\.(?:readString|readAllBytes|lines)\s*\("
            r"|\bFileInputStream\s*\(",
            re.IGNORECASE,
        ),
    ),
    (
        "process_execution",
        re.compile(
            r"\b(?:subprocess\.(?:Popen|run|call|check_output)|os\.system)\s*\("
            r"|\b(?:system|exec|shell_exec|passthru|popen|proc_open)\s*\("
            r"|\bchild_process\.(?:exec|execFile|spawn)\s*\("
            r"|\bRuntime\.getRuntime\(\)\.exec\s*\(|\bProcessBuilder\s*\("
            r"|\bexec\.Command\s*\(|\bCommand::new\s*\(",
            re.IGNORECASE,
        ),
    ),
    (
        "task_execution",
        re.compile(
            r"\b(?:Celery|celery_app\.task|shared_task|AsyncResult|background_task)\b|\.apply_async\s*\(|\.delay\s*\("
            r"|\b[A-Za-z_][\w]*Runner\s*\(|\brunner\.(?:run|start)\s*\("
            r"|\b(?:queue|dispatch|enqueue|schedule)\s*\("
            r"|\b(?:rq|dramatiq|huey|apscheduler|bull|sidekiq)\b",
            re.IGNORECASE,
        ),
    ),
    (
        "template_render",
        re.compile(
            r"\b(?:jinja2?|Template|render_template|render_to_string)\b"
            r"|\byaml\.(?:load|safe_load)\s*\(|\bunserialize\s*\(|\bpickle\.loads\s*\("
            r"|\bObjectInputStream\b|\breadObject\s*\(",
            re.IGNORECASE,
        ),
    ),
    (
        "credential_access",
        re.compile(
            r"\b(?:secret|token|credential|password|passwd|private_key|access_key|api_key|session_key)\b"
            r"|settings\.[A-Z_]*(?:SECRET|TOKEN|KEY|PASSWORD)[A-Z_]*",
            re.IGNORECASE,
        ),
    ),
    (
        "auth_guard",
        re.compile(
            r"\b(?:permission_classes|authentication_classes|IsAuthenticated|BasePermission|has_permission|"
            r"has_object_permission|check_object_permissions|rbac_perms|required_permissions|has_perm|"
            r"user\.has_perm|login_required|permission_required|authenticate|authorize|policy|"
            r"requireAuth|require_auth|current_user|request\.user|principal)\b"
            r"|@(?:PreAuthorize|RolesAllowed|Secured)\b"
            r"|\b(?:middleware|can|Gate::allows)\s*\(",
            re.IGNORECASE,
        ),
    ),
    (
        "object_scope_guard",
        re.compile(
            r"\b(?:tenant|tenant_id|org_id|organization_id|account_id|workspace_id|owner_id|user_id|"
            r"asset_id|resource_id|project_id)\b"
            r"|\b(?:filter|where|get_queryset|scoped_queryset)\s*\([^;\n]*(?:user|owner|tenant|org|account|workspace)"
            r"|\bhas_object_permission\b|\bcheck_object_permissions\s*\(",
            re.IGNORECASE,
        ),
    ),
    (
        "external_system",
        re.compile(
            r"\b(?:ldap|LDAP|kubernetes|Kubernetes|k8s|boto3|paramiko|ansible|docker|DockerClient|"
            r"redis|RabbitMQ|Kafka|Elasticsearch|S3|Vault|Consul)\b"
            r"|\b(?:requests|httpx|urllib\.request|axios|fetch|http\.Get|curl_exec)\b",
            re.IGNORECASE,
        ),
    ),
    (
        "websocket_boundary",
        re.compile(r"\b(?:websocket|WebSocket|AsyncWebsocketConsumer|SocketHandler|ws://|wss://)\b", re.IGNORECASE),
    ),
    (
        "object_id_lookup",
        re.compile(
            r"\bget_object_or_404\s*\(|\.objects\.(?:get|filter)\s*\([^;\n]*(?:id|pk)\s*="
            r"|\bfindById\s*\(|\bfind_by_id\s*\(|\bwhere\s*\([^;\n]*(?:id|pk)",
            re.IGNORECASE,
        ),
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
        capability_paths = {
            row["path"]
            for row in conn.execute(
                """
                SELECT DISTINCT path
                FROM code_capabilities
                WHERE snapshot_id = ?
                """,
                (snapshot_id,),
            ).fetchall()
            if row["path"]
        }
        candidate_rows = conn.execute(
            """
            SELECT candidate_type, severity, status, title, description,
                   file_path, line_start, entry_point, symbol
            FROM audit_candidates
            WHERE snapshot_id = ?
              AND source = 'index'
            """,
            (snapshot_id,),
        ).fetchall()
        business_graph_size = conn.execute(
            """
            SELECT
                (SELECT COUNT(*)
                 FROM business_nodes
                 WHERE source_snapshot_id = ?) AS nodes,
                (SELECT COUNT(*)
                 FROM business_edges e
                 JOIN business_nodes n
                   ON n.id = e.from_node_id
                  AND n.project_id = e.project_id
                 WHERE n.source_snapshot_id = ?) AS edges
            """,
            (snapshot_id, snapshot_id),
        ).fetchone()
        business_module_stats = conn.execute(
            """
            SELECT
                COUNT(*) AS module_count,
                SUM(
                    CASE
                        WHEN NOT EXISTS (
                            SELECT 1
                            FROM business_edges e
                            WHERE e.project_id = n.project_id
                              AND e.from_node_id = n.id
                              AND e.relation = 'contains'
                        )
                        THEN 1 ELSE 0
                    END
                ) AS island_count
            FROM business_nodes n
            WHERE n.source_snapshot_id = ?
              AND n.node_type = 'feature'
              AND n.title LIKE '业务模块 %'
            """,
            (snapshot_id,),
        ).fetchone()

    data_object_count = symbol_kind_counts.get("data_object", 0)
    entrypoints_with_data_paths = _entrypoints_with_data_paths(entrypoints, relationships, data_objects)
    entrypoints_with_business_flows = _entrypoints_with_business_flows(entrypoints, relationships)
    entrypoints_with_capability_paths = _entrypoints_with_reachable_paths(entrypoints, relationships, capability_paths)
    candidate_count = len(candidate_rows)
    high_impact_candidate_count = sum(
        1
        for row in candidate_rows
        if _candidate_priority_from_values(
            candidate_type=row["candidate_type"],
            severity=row["severity"],
            status=row["status"],
            title=row["title"],
            description=row["description"],
            file_path=row["file_path"],
            line_start=row["line_start"],
            entry_point=row["entry_point"],
            symbol=row["symbol"],
        )["score"]
        >= 75
    )
    candidate_status_counts = _count_rows_from_values(row["status"] for row in candidate_rows)
    candidate_type_counts = _count_rows_from_values(row["candidate_type"] for row in candidate_rows)
    candidate_file_count = len({row["file_path"] for row in candidate_rows if row["file_path"]})
    candidate_density = round(candidate_count / max(1, code_file_count), 3)
    business_graph_node_count = int((business_graph_size or {})["nodes"] or 0)
    business_graph_edge_count = int((business_graph_size or {})["edges"] or 0)
    business_module_count = int((business_module_stats or {})["module_count"] or 0)
    business_module_island_count = int((business_module_stats or {})["island_count"] or 0)
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
    if summary.entrypoint_count and entrypoints_with_business_flows / max(1, summary.entrypoint_count) < 0.35:
        add_issue(
            "warning",
            "weak_entrypoint_business_flows",
            "入口业务流偏弱",
            "多数入口没有跨处理逻辑、服务或数据对象的可达链路，模型仍需要从入口文件手动追踪业务。",
            summary.entrypoint_count - entrypoints_with_business_flows,
            10,
            "优先补强 import 作用域、对象方法调用、依赖注入和框架 handler 解析。",
        )
    if business_module_count == 0 and summary.entrypoint_count > 0:
        add_issue(
            "warning",
            "no_business_modules",
            "未形成业务模块",
            "入口存在但业务图没有模块聚合，模型难以先按业务域理解大项目。",
            0,
            8,
            "按路径、路由前缀和语义能力生成模块聚合节点，并为入口、处理逻辑、数据对象建立 contains 关系。",
        )
    elif business_module_island_count > max(2, business_module_count // 3):
        add_issue(
            "warning",
            "business_module_islands",
            "孤立业务模块较多",
            "部分业务模块没有包含入口、处理逻辑或数据对象，说明模块聚合边不足。",
            business_module_island_count,
            6,
            "检查模块 key 归纳和 contains 边生成逻辑，减少只有标题但没有业务事实的模块。",
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
    if candidate_count > max(180, code_file_count * 3):
        add_issue(
            "warning",
            "candidate_noise_high",
            "候选线索密度偏高",
            "索引候选相对代码文件数量过多，worker 容易在重复或低价值线索上消耗轮次。",
            candidate_count,
            8,
            "继续按风险链签名聚类候选，并优先调度高分候选的紧凑上下文包。",
        )
    if high_impact_candidate_count > max(60, max(1, summary.entrypoint_count) * 2):
        add_issue(
            "warning",
            "high_impact_candidate_noise",
            "高优先级候选偏多",
            "大量候选都被标成高优先级，会削弱排序信号，需要进一步区分入口可达性、权限边界和真实能力影响。",
            high_impact_candidate_count,
            8,
            "为候选保留可解释优先级原因，让 worker 先处理入口可达且含高影响能力的路径。",
        )
    if business_graph_node_count > max(500, code_file_count * 4):
        add_issue(
            "warning",
            "business_graph_too_large",
            "业务图规模偏大",
            "业务图节点数量相对源码规模偏大，直接投喂给模型会增加噪声。",
            business_graph_node_count,
            6,
            "在 explore/reason 上下文中只导出聚焦候选相邻节点，完整业务图留在服务端作为可视化和覆盖状态。",
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
        candidate_count=candidate_count,
        high_impact_candidate_count=high_impact_candidate_count,
        candidate_status_counts=candidate_status_counts,
        candidate_type_counts=candidate_type_counts,
        candidate_file_count=candidate_file_count,
        candidate_density_per_code_file=candidate_density,
        business_graph_node_count=business_graph_node_count,
        business_graph_edge_count=business_graph_edge_count,
        business_module_count=business_module_count,
        business_module_island_count=business_module_island_count,
        entrypoints_with_business_flows=entrypoints_with_business_flows,
        entrypoints_with_capability_paths=entrypoints_with_capability_paths,
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


def _count_rows_from_values(values) -> dict[str, int]:
    result: dict[str, int] = {}
    for value in values:
        key = str(value or "").strip()
        if not key:
            continue
        result[key] = result.get(key, 0) + 1
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


def audit_candidate_priority(
    *,
    candidate_type: str | None,
    severity: str | None,
    status: str | None,
    title: str | None,
    description: str | None,
    file_path: str | None,
    line_start: int | None,
    entry_point: str | None,
    symbol: str | None,
) -> dict[str, object]:
    return _candidate_priority_from_values(
        candidate_type=candidate_type,
        severity=severity,
        status=status,
        title=title,
        description=description,
        file_path=file_path,
        line_start=line_start,
        entry_point=entry_point,
        symbol=symbol,
    )


def _candidate_priority_from_values(
    *,
    candidate_type: str | None,
    severity: str | None,
    status: str | None,
    title: str | None,
    description: str | None,
    file_path: str | None,
    line_start: int | None,
    entry_point: str | None,
    symbol: str | None,
) -> dict[str, object]:
    text = f"{title or ''}\n{description or ''}".lower()
    reasons: list[str] = []
    candidate_type = candidate_type or "unknown"
    severity = severity or "unknown"

    score = {
        "critical": 88,
        "high": 76,
        "medium": 58,
        "low": 38,
        "info": 24,
        "unknown": 42,
    }.get(severity, 42)

    if candidate_type == "capability_chain":
        score += 8
        reasons.append("高影响源码能力链")
    elif candidate_type == "data_flow":
        score += 6
        reasons.append("外部输入相关数据流")
    elif candidate_type in {"entrypoint", "web_entrypoint"}:
        score = max(score, 34)
        reasons.append("可审计入口")

    if any(marker in text for marker in ("文件读写/加载能力", "文件写入", "归档解压", "upload", "上传", "路径穿越", "任意文件")):
        score += 10
        reasons.append("文件/上传影响面")
    if any(marker in text for marker in ("数据库执行能力", "数据库查询", "sql", "query", "execute")):
        score += 10
        reasons.append("数据库影响面")
    if any(marker in text for marker in ("系统进程能力", "命令", "process", "runner", "后台任务", "task_execution")):
        score += 12
        reasons.append("执行/任务影响面")
    if any(marker in text for marker in ("对象反序列化", "unserialize", "pickle", "yaml.load", "objectinputstream")):
        score += 10
        reasons.append("反序列化影响面")
    if any(marker in text for marker in ("credential", "secret", "token", "password", "凭据", "令牌")):
        score += 7
        reasons.append("敏感资产相关")
    if any(marker in text for marker in ("认证/权限边界", "权限边界", "rbac", "permission", "authorize", "policy")):
        score += 6
        reasons.append("权限边界相关")
    if any(marker in text for marker in ("对象归属", "租户边界", "对象边界", "tenant", "owner", "workspace")):
        score += 6
        reasons.append("对象/租户边界相关")
    if any(marker in text for marker in ("外部系统", "基础设施", "kubernetes", "ldap", "ansible", "docker")):
        score += 5
        reasons.append("外部系统相关")
    if entry_point:
        score += 6
        reasons.append("入口可达")
    if symbol:
        score += 3
        reasons.append("含输入/处理符号")
    if "控制/校验：邻近片段未抽取到明显控制语句" in (description or ""):
        score += 5
        reasons.append("邻近未见控制/校验")
    if status in {"confirmed", "rejected"}:
        score -= 35
        reasons.append("已有结论")
    elif status == "needs_more_evidence":
        score -= 10
        reasons.append("需要补证")

    score = max(0, min(100, score))
    deduped_reasons = list(dict.fromkeys(reasons))[:MAX_PRIORITY_REASON_COUNT]
    return {
        "score": score,
        "reasons": deduped_reasons,
        "cluster_key": audit_candidate_cluster_key(
            candidate_type=candidate_type,
            severity=severity,
            title=title,
            file_path=file_path,
            line_start=line_start,
            entry_point=entry_point,
            symbol=symbol,
        ),
    }


def audit_candidate_cluster_key(
    *,
    candidate_type: str | None,
    severity: str | None,
    title: str | None,
    file_path: str | None,
    line_start: int | None,
    entry_point: str | None,
    symbol: str | None,
) -> str:
    category = _candidate_category_from_title(title)
    if candidate_type in {"data_flow", "capability_chain"}:
        parts = [
            candidate_type or "unknown",
            file_path or "unknown_path",
            entry_point or "unknown_entry",
            category or severity or "unknown_risk",
            symbol or "unknown_symbol",
        ]
    else:
        parts = [
            candidate_type or "unknown",
            file_path or "unknown_path",
            entry_point or "unknown_entry",
            str(line_start or 0),
        ]
    return hashlib.sha1("\0".join(parts).lower().encode("utf-8")).hexdigest()[:16]


def _candidate_category_from_title(title: str | None) -> str | None:
    if not title:
        return None
    for prefix in ("审计数据流: 外部输入到", "审计能力链:"):
        if title.startswith(prefix):
            rest = title[len(prefix) :].strip()
            return rest.split()[0] if rest else None
    return None


def _entrypoints_with_data_paths(entrypoints, relationships, data_objects) -> int:
    data_targets = {(row["path"], row["name"]) for row in data_objects}
    if not entrypoints or not data_targets:
        return 0

    adjacency: dict[tuple[str, str | None], set[tuple[str, str | None]]] = {}
    for row in relationships:
        if row["relation"] not in {"calls", "imports", "uses", "implemented_by", "extended_by"}:
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


def _entrypoints_with_business_flows(entrypoints, relationships) -> int:
    target_paths = {
        row["to_path"]
        for row in relationships
        if row["relation"] in {"calls", "imports", "uses"}
        and row["to_path"]
        and row["to_path"] != row["from_path"]
    }
    return _entrypoints_with_reachable_paths(entrypoints, relationships, target_paths)


def _entrypoints_with_reachable_paths(entrypoints, relationships, target_paths: set[str]) -> int:
    if not entrypoints or not target_paths:
        return 0
    adjacency: dict[str, set[str]] = {}
    for row in relationships:
        if row["relation"] not in {"calls", "imports", "uses", "implemented_by", "extended_by"}:
            continue
        from_path = row["from_path"]
        to_path = row["to_path"]
        if not from_path or not to_path:
            continue
        adjacency.setdefault(from_path, set()).add(to_path)

    linked = 0
    for entrypoint in entrypoints:
        if _path_reaches_any(entrypoint["path"], adjacency, target_paths):
            linked += 1
    return linked


def _path_reaches_any(
    start_path: str,
    adjacency: dict[str, set[str]],
    target_paths: set[str],
    *,
    max_depth: int = 4,
) -> bool:
    if start_path in target_paths:
        return True
    seen = {start_path}
    frontier = [(start_path, 0)]
    while frontier:
        path, depth = frontier.pop(0)
        if depth >= max_depth:
            continue
        for next_path in sorted(adjacency.get(path, set())):
            if next_path in target_paths:
                return True
            if next_path in seen:
                continue
            seen.add(next_path)
            frontier.append((next_path, depth + 1))
    return False


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


def list_code_capabilities(project_id: str, snapshot_id: str, limit: int = 1000) -> list[CodeCapability]:
    snapshot = get_snapshot(project_id, snapshot_id)
    _ensure_code_index(snapshot)
    with db.get_conn() as conn:
        rows = conn.execute(
            """
            SELECT *
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
                **dict(row),
                "risk_tags": _decode_json_list(row["risk_tags_json"]),
            }
        )
        for row in rows
    ]


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
        _insert_code_capabilities(conn, snapshot_id, files, root=root, code_index=code_index)
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
    for table in ("code_relationships", "code_symbols", "code_entrypoints", "code_capabilities", "dependency_manifests"):
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
        _insert_code_capabilities(conn, snapshot_id, files, root=snapshot_path(snapshot_id), code_index=code_index)
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


def _insert_code_capabilities(
    conn,
    snapshot_id: str,
    files: list[CodeFile],
    *,
    root: Path,
    code_index,
) -> None:
    facts = _extract_code_capabilities(snapshot_id, files, root=root, code_index=code_index)
    if not facts:
        return
    conn.executemany(
        """
        INSERT OR IGNORE INTO code_capabilities (
            id, snapshot_id, path, symbol, category, title, line_start, line_end,
            evidence, risk_level, risk_tags_json, confidence, source
        )
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
        [
            (
                item.id,
                item.snapshot_id,
                item.path,
                item.symbol,
                item.category,
                item.title,
                item.line_start,
                item.line_end,
                item.evidence,
                item.risk_level,
                json.dumps(list(item.risk_tags), ensure_ascii=False),
                item.confidence,
                item.source,
            )
            for item in facts
        ],
    )


def _extract_code_capabilities(
    snapshot_id: str,
    files: list[CodeFile],
    *,
    root: Path,
    code_index,
) -> list[CodeCapabilityFact]:
    symbols_by_path: dict[str, list] = {}
    for symbol in code_index.symbols:
        symbols_by_path.setdefault(symbol.path, []).append(symbol)
    reachable_entrypoints = _entrypoint_labels_by_target_path(code_index)
    facts: list[CodeCapabilityFact] = []
    seen: set[tuple[str, str, int, str]] = set()
    for file in files:
        if file.is_binary or not _is_candidate_source_path(file.path):
            continue
        text = _read_candidate_text(root / file.path)
        if text is None:
            continue
        file_count = 0
        lines = text.splitlines()
        for lineno, raw_line in enumerate(lines, start=1):
            line = raw_line.strip()
            if not line or line.startswith(("//", "#")):
                continue
            for category, pattern in CAPABILITY_PATTERNS:
                if not pattern.search(line):
                    continue
                key = (file.path, category, lineno, line[:120])
                if key in seen:
                    continue
                seen.add(key)
                symbol = _symbol_for_line(symbols_by_path.get(file.path, []), lineno)
                context = _context_window(lines, lineno, radius=4)
                reachable = reachable_entrypoints.get(file.path, [])
                tags = _capability_risk_tags(file.path, category, line, context, reachable)
                risk_level = _capability_risk_level(category, file.path, line, context, tags, reachable)
                confidence = _capability_confidence(category, tags, reachable)
                title = CAPABILITY_CATEGORY_TITLES.get(category, category)
                facts.append(
                    CodeCapabilityFact(
                        id=_stable_business_id("cap", snapshot_id, file.path, category, lineno, line),
                        snapshot_id=snapshot_id,
                        path=file.path,
                        symbol=symbol,
                        category=category,
                        title=title,
                        line_start=lineno,
                        line_end=lineno,
                        evidence=_clip_text(line, MAX_SIGNAL_FRAGMENT_CHARS),
                        risk_level=risk_level,
                        risk_tags=tuple(tags),
                        confidence=confidence,
                    )
                )
                file_count += 1
                if file_count >= MAX_CODE_CAPABILITIES_PER_FILE:
                    break
            if file_count >= MAX_CODE_CAPABILITIES_PER_FILE:
                break
    return facts


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
    existing_candidate_ids = _load_existing_index_candidate_ids(conn, snapshot_id)

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
        severity: str = "unknown",
        dedupe_key: tuple[object, ...] | None = None,
    ) -> None:
        if len(candidates) >= MAX_SOURCE_INDEX_CANDIDATES:
            return
        key = dedupe_key or (candidate_type, file_path, line_start, entry_point)
        if key in seen:
            return
        seen.add(key)
        candidate_id = existing_candidate_ids.get(
            (source, candidate_type, file_path, line_start, entry_point)
        ) or _stable_candidate_id(snapshot_id, source, candidate_type, file_path, line_start, entry_point)
        status = "needs_more_evidence" if project_completed else "candidate"
        conclusion_summary = None
        evidence = None
        concluded_by = None
        concluded_at = None
        if project_completed:
            conclusion_summary = (
                "项目完成后由源码索引回填该待审计数据流，未重新判定漏洞，"
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
                severity,
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
            severity = _risk_signal_candidate_severity(signal)
            add_candidate(
                source="index",
                candidate_type="data_flow",
                title=f"审计数据流: 外部输入到{signal.category} {file.path}:{signal.line_start}",
                description=_audit_candidate_signal_description(file.path, entry_point, signal),
                file_path=file.path,
                line_start=signal.line_start,
                line_end=signal.line_end,
                entry_point=entry_point,
                symbol=signal.symbol,
                severity=severity,
                dedupe_key=_risk_signal_candidate_key(file.path, entry_point, signal),
            )

    reachable_entrypoints = _entrypoint_labels_by_target_path(code_index)
    capability_rows = conn.execute(
        """
        SELECT *
        FROM code_capabilities
        WHERE snapshot_id = ?
          AND risk_level IN ('critical', 'high')
        ORDER BY
            CASE risk_level WHEN 'critical' THEN 0 WHEN 'high' THEN 1 ELSE 2 END,
            path,
            COALESCE(line_start, 0),
            category
        LIMIT ?
        """,
        (snapshot_id, MAX_CAPABILITY_CHAIN_CANDIDATES),
    ).fetchall()
    for capability in capability_rows:
        tags = _decode_json_list(capability["risk_tags_json"])
        entrypoints = reachable_entrypoints.get(capability["path"], [])
        entry_point = entrypoints[0] if entrypoints else None
        add_candidate(
            source="index",
            candidate_type="capability_chain",
            title=(
                f"审计能力链: {capability['title']} "
                f"{capability['path']}:{capability['line_start']}"
            ),
            description=_capability_chain_candidate_description(capability, tags, entrypoints),
            file_path=capability["path"],
            line_start=capability["line_start"],
            line_end=capability["line_end"],
            entry_point=entry_point,
            symbol=capability["symbol"],
            severity=capability["risk_level"],
            dedupe_key=_capability_candidate_key(capability, entry_point),
        )

    if not candidates:
        return
    conn.executemany(
        """
        INSERT INTO audit_candidates (
            id, project_id, snapshot_id, source, candidate_type, severity,
            title, description, file_path, line_start, line_end, entry_point,
            symbol, status, conclusion_summary, evidence, created_by,
            created_at, updated_at, concluded_by, concluded_at
        )
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        ON CONFLICT(id) DO UPDATE SET
            severity = excluded.severity,
            title = excluded.title,
            description = excluded.description,
            line_end = excluded.line_end,
            entry_point = excluded.entry_point,
            symbol = excluded.symbol,
            updated_at = excluded.updated_at
        """,
        candidates,
    )


def _load_existing_index_candidate_ids(conn, snapshot_id: str) -> dict[tuple[str, str, str | None, int | None, str | None], str]:
    rows = conn.execute(
        """
        SELECT id, source, candidate_type, file_path, line_start, entry_point
        FROM audit_candidates
        WHERE snapshot_id = ?
          AND source = 'index'
        ORDER BY created_at, id
        """,
        (snapshot_id,),
    ).fetchall()
    result: dict[tuple[str, str, str | None, int | None, str | None], str] = {}
    for row in rows:
        key = (row["source"], row["candidate_type"], row["file_path"], row["line_start"], row["entry_point"])
        result.setdefault(key, row["id"])
    return result


def _risk_signal_candidate_key(file_path: str, entry_point: str | None, signal: RiskSignal) -> tuple[object, ...]:
    return (
        "data_flow",
        file_path,
        entry_point or "",
        signal.category,
        signal.symbol or "",
    )


def _capability_candidate_key(capability, entry_point: str | None) -> tuple[object, ...]:
    return (
        "capability_chain",
        capability["path"],
        entry_point or "",
        capability["category"],
        capability["symbol"] or "",
    )


def _audit_candidate_signal_description(file_path: str, entry_point: str | None, signal: RiskSignal) -> str:
    priority = _risk_signal_priority(signal, entry_point)
    parts = [
        (
            f"事实：{file_path}:{signal.line_start} 的外部输入数据流进入 `{signal.title}`。"
        ),
        f"入口：{entry_point or '未从索引确定具体入口'}。",
        f"输入：{signal.source_summary}。",
        f"能力证据：第 {signal.line_start} 行 `{signal.evidence}`。",
        _priority_summary(priority),
    ]
    if signal.context_summary:
        parts.append(f"局部代码切片：{signal.context_summary}。")
    if signal.control_summary:
        parts.append(f"控制/校验：{signal.control_summary}。")
    else:
        parts.append("控制/校验：邻近片段未抽取到明显控制语句，需以 worker 源码阅读为准。")
    if signal.category in HIGH_IMPACT_RISK_SIGNAL_CATEGORIES:
        parts.append(
            "高影响能力提示：请优先确认该输入是否可绕过认证/权限、是否可控路径或目标、"
            "是否存在路径穿越/扩展名或内容边界缺失，以及写入/加载/执行结果是否能被后续入口、"
            "模板、插件、解释器或静态资源服务触发。"
        )
    parts.append(
        "该候选是数据流事实，不是漏洞类型判断；worker 需要重新阅读源码，"
        "基于输入可达性、控制流顺序、边界校验和真实影响自行归纳漏洞类型，"
        "并输出结构化 findings 或 candidate_conclusions。"
    )
    return _clip_text(" ".join(parts), MAX_AUDIT_CANDIDATE_DESCRIPTION_CHARS)


def _capability_chain_candidate_description(capability, tags: list[str], entrypoints: list[str]) -> str:
    location = f"{capability['path']}:{capability['line_start']}"
    priority = _capability_priority(capability, tags, entrypoints)
    parts = [
        f"事实：{location} 存在 `{capability['title']}`。",
        f"能力证据：`{capability['evidence'] or '未提供'}`。",
        f"入口可达：{'; '.join(entrypoints[:5]) if entrypoints else '索引未直接确定入口，需要先从路由、调用关系或任务入口定位可达性'}。",
        f"风险标签：{', '.join(tags[:8]) if tags else '未标注'}。",
        _priority_summary(priority),
        "审计要求：不得仅确认路由或能力调用存在；必须读取实现链、认证/权限、对象查询、路径/内容控制、落盘位置和后续加载/执行点。",
        "该候选是源码能力链事实，不是漏洞类型判断；worker 需要基于可达性、控制边界和真实影响自行归纳漏洞类型，并输出 findings 或 candidate_conclusions。",
    ]
    return _clip_text(" ".join(parts), MAX_AUDIT_CANDIDATE_DESCRIPTION_CHARS)


def _risk_signal_priority(signal: RiskSignal, entry_point: str | None) -> dict[str, object]:
    description = " ".join(
        part
        for part in (
            signal.source_summary,
            signal.control_summary,
            signal.context_summary,
            signal.evidence,
        )
        if part
    )
    return _candidate_priority_from_values(
        candidate_type="data_flow",
        severity=_risk_signal_candidate_severity(signal),
        status="candidate",
        title=f"审计数据流: 外部输入到{signal.category}",
        description=description,
        file_path=None,
        line_start=signal.line_start,
        entry_point=entry_point,
        symbol=signal.symbol,
    )


def _capability_priority(capability, tags: list[str], entrypoints: list[str]) -> dict[str, object]:
    return _candidate_priority_from_values(
        candidate_type="capability_chain",
        severity=capability["risk_level"],
        status="candidate",
        title=f"审计能力链: {capability['title']}",
        description=" ".join([capability["evidence"] or "", " ".join(tags)]),
        file_path=capability["path"],
        line_start=capability["line_start"],
        entry_point=entrypoints[0] if entrypoints else None,
        symbol=capability["symbol"],
    )


def _priority_summary(priority: dict[str, object]) -> str:
    reasons = priority.get("reasons")
    reason_text = "、".join(str(item) for item in reasons) if isinstance(reasons, list) else ""
    if not reason_text:
        reason_text = "基础排序信号"
    return f"索引优先级：{priority.get('score', 0)}/100（{reason_text}）。该分数只用于审计排序，不代表漏洞结论。"


def _risk_signal_candidate_severity(signal: RiskSignal) -> str:
    if signal.category in HIGH_IMPACT_RISK_SIGNAL_CATEGORIES:
        return "high"
    return "unknown"


def _entrypoint_labels_by_target_path(code_index) -> dict[str, list[str]]:
    labels_by_source: dict[tuple[str, str], str] = {}
    labels_by_path: dict[str, list[str]] = {}
    adjacency: dict[str, set[str]] = {}
    for entrypoint in code_index.entrypoints:
        label = _entrypoint_label(entrypoint.method, entrypoint.route)
        labels_by_source[(entrypoint.path, label)] = label
        labels_by_path.setdefault(entrypoint.path, [])
        if label not in labels_by_path[entrypoint.path]:
            labels_by_path[entrypoint.path].append(label)
    for relationship in code_index.relationships:
        if relationship.relation not in {"calls", "imports", "uses", "implemented_by", "extended_by"}:
            continue
        adjacency.setdefault(relationship.from_path, set()).add(relationship.to_path)
    for entrypoint in code_index.entrypoints:
        label = _entrypoint_label(entrypoint.method, entrypoint.route)
        seen = {entrypoint.path}
        frontier = [(entrypoint.path, 0)]
        while frontier:
            path, depth = frontier.pop(0)
            labels = labels_by_path.setdefault(path, [])
            if label not in labels:
                labels.append(label)
            if depth >= 3:
                continue
            for next_path in sorted(adjacency.get(path, set())):
                if next_path in seen:
                    continue
                seen.add(next_path)
                frontier.append((next_path, depth + 1))
    return labels_by_path


def _symbol_for_line(symbols: list, lineno: int) -> str | None:
    containing = [
        symbol
        for symbol in symbols
        if symbol.line_start is not None
        and symbol.line_start <= lineno
        and (symbol.line_end is None or lineno <= symbol.line_end)
    ]
    if containing:
        containing.sort(key=lambda item: (item.line_end or lineno) - (item.line_start or lineno))
        return containing[0].name
    before = [symbol for symbol in symbols if symbol.line_start is not None and symbol.line_start <= lineno]
    if before:
        before.sort(key=lambda item: item.line_start or 0, reverse=True)
        return before[0].name
    return None


def _context_window(lines: list[str], lineno: int, *, radius: int = 4) -> str:
    start = max(1, lineno - radius)
    end = min(len(lines), lineno + radius)
    return "\n".join(lines[index - 1] for index in range(start, end + 1))


def _capability_risk_tags(
    path: str,
    category: str,
    evidence: str,
    context: str,
    reachable_entrypoints: list[str],
) -> list[str]:
    tags: list[str] = []
    for tag in CAPABILITY_TAGS_BY_CATEGORY.get(category, []):
        _append_unique(tags, tag)
    haystack = f"{path}\n{evidence}\n{context}\n{' '.join(reachable_entrypoints)}"
    lower = haystack.lower()
    if any(keyword in lower for keyword in CONTROL_PLANE_KEYWORDS):
        _append_unique(tags, "控制面")
    if reachable_entrypoints:
        _append_unique(tags, "入口可达")
    if UPLOAD_CONTEXT_RE.search(haystack):
        _append_unique(tags, "上传持久化")
    if category in {"file_upload", "file_write", "archive_extract"} and any(
        marker in lower for marker in ("media_root", "upload", "uploads", "tmp", "data_dir", "storage", "static")
    ):
        _append_unique(tags, "文件生命周期")
    if re.search(r"\b(?:rbac|permission|authorize|auth|role|policy|is_authenticated)\b", haystack, re.IGNORECASE):
        _append_unique(tags, "权限边界")
    if re.search(r"\b(?:id|pk|uuid|object_id|resource_id|tenant|org|owner|account|workspace)\b", haystack, re.IGNORECASE):
        _append_unique(tags, "对象边界")
    if category == "external_system":
        _append_unique(tags, "外部依赖")
    return tags


def _capability_risk_level(
    category: str,
    path: str,
    evidence: str,
    context: str,
    tags: list[str],
    reachable_entrypoints: list[str],
) -> str:
    high_context = bool(
        {"控制面", "上传持久化", "入口可达", "权限边界"} & set(tags)
    )
    if category in {"process_execution", "task_execution"}:
        return "high"
    if category == "file_upload":
        return "high" if high_context else "medium"
    if category == "archive_extract":
        return "high" if high_context else "medium"
    if category == "file_write":
        return "high" if high_context else "medium"
    if category == "credential_access":
        secret_context = re.search(
            r"\b(?:secret|token|credential|private_key|access_key|api_key|session_key)\b|settings\.",
            f"{path}\n{evidence}\n{context}",
            re.IGNORECASE,
        )
        return "high" if secret_context and ("控制面" in tags or reachable_entrypoints) else "medium"
    if category == "file_read":
        return "high" if {"控制面", "入口可达", "对象边界"} <= set(tags) else "medium"
    if category in {"template_render", "websocket_boundary"}:
        return "high" if high_context else "medium"
    if category == "auth_guard":
        return "medium" if reachable_entrypoints or "控制面" in tags else "low"
    if category == "object_scope_guard":
        return "medium" if reachable_entrypoints or "权限边界" in tags else "low"
    if category == "external_system":
        return "medium" if {"控制面", "入口可达", "权限边界"} & set(tags) else "low"
    if category == "object_id_lookup":
        return "medium" if reachable_entrypoints or "控制面" in tags else "unknown"
    return "unknown"


def _capability_confidence(category: str, tags: list[str], reachable_entrypoints: list[str]) -> float:
    confidence = 0.66
    if category in HIGH_IMPACT_CAPABILITY_CATEGORIES:
        confidence += 0.05
    if "入口可达" in tags or reachable_entrypoints:
        confidence += 0.08
    if "上传持久化" in tags or "控制面" in tags:
        confidence += 0.06
    return min(0.88, confidence)


def _append_unique(items: list[str], value: str) -> None:
    if value and value not in items:
        items.append(value)


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
    semantic_by_path: dict[str, list[str]] = {}
    module_by_key: dict[str, str] = {}
    modules_by_path: dict[str, list[str]] = {}

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
    capabilities = conn.execute(
        """
        SELECT path, symbol, category, title, line_start, line_end, evidence,
               risk_level, risk_tags_json, confidence, source
        FROM code_capabilities
        WHERE snapshot_id = ?
        ORDER BY
            CASE risk_level
                WHEN 'critical' THEN 0
                WHEN 'high' THEN 1
                WHEN 'medium' THEN 2
                WHEN 'low' THEN 3
                ELSE 4
            END,
            path,
            category,
            COALESCE(line_start, 0)
        """,
        (snapshot_id,),
    ).fetchall()

    def ensure_module(path: str | None, route: str | None = None, evidence_text: str | None = None, line_start: int | None = None) -> str | None:
        module_key = _business_module_key(path, route)
        if module_key is None:
            return None
        existing = module_by_key.get(module_key)
        if existing is not None:
            if path:
                modules = modules_by_path.setdefault(path, [])
                if existing not in modules:
                    modules.append(existing)
            return existing
        node_id = _stable_business_id("biz", snapshot_id, "module", module_key)
        risk_level = "medium" if any(keyword in module_key.lower() for keyword in CONTROL_PLANE_KEYWORDS) else "unknown"
        _insert_business_node_seed(
            conn,
            project_id,
            snapshot_id=snapshot_id,
            node_id=node_id,
            node_type="feature",
            title=f"业务模块 {_feature_title(module_key)}",
            description=(
                f"源码索引根据路径/路由归纳出的业务模块 {module_key}。"
                "该节点用于把入口、处理逻辑、资产和风险链按模块聚合，帮助大项目审计先建立业务视角。"
            ),
            risk_level=risk_level,
            review_status="unreviewed",
            coverage_note="索引自动生成的模块聚合节点，供 worker 选择审计范围和理解业务边界。",
            risk_tags=["业务模块"],
            evidence=_business_evidence(path, line_start, evidence_text),
            confidence=0.7,
            created_by="source_index",
            now=now,
        )
        module_by_key[module_key] = node_id
        if path:
            modules_by_path.setdefault(path, []).append(node_id)
        return node_id

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
        module_id = ensure_module(path, evidence_text=evidence_text, line_start=line_start)
        if module_id:
            _insert_business_edge_seed(
                conn,
                project_id,
                from_node_id=module_id,
                to_node_id=node_id,
                relation="contains",
                description="业务模块包含该处理逻辑。",
                confidence=0.66,
                created_by="source_index",
                now=now,
            )
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
        module_id = ensure_module(path, evidence_text=evidence_text, line_start=line_start)
        if module_id:
            _insert_business_edge_seed(
                conn,
                project_id,
                from_node_id=module_id,
                to_node_id=node_id,
                relation="contains",
                description="业务模块包含该数据对象。",
                confidence=0.66,
                created_by="source_index",
                now=now,
            )
        return node_id

    def ensure_semantic_capability(capability) -> str | None:
        category = capability["category"]
        config = _semantic_capability_config(category)
        if config is None:
            return None
        path = capability["path"]
        if not path:
            return None
        symbol = capability["symbol"]
        node_id = _stable_business_id("biz", snapshot_id, "semantic_capability", path, category, symbol)
        tags = _decode_json_list(capability["risk_tags_json"])
        for tag in config["risk_tags"]:
            if tag not in tags:
                tags.append(tag)
        evidence = _business_evidence(path, capability["line_start"], capability["evidence"])
        title = f"{config['title_prefix']} {capability['title'] or CAPABILITY_CATEGORY_TITLES.get(category, category)}"
        _insert_business_node_seed(
            conn,
            project_id,
            snapshot_id=snapshot_id,
            node_id=node_id,
            node_type=config["node_type"],
            title=title,
            description=(
                f"源码索引在 {path} 识别到 {capability['title']}。"
                f"符号：{symbol or '未定位'}。"
                "该节点用于把权限、对象、文件、任务或外部系统边界提升为业务语义，"
                "帮助 worker 沿业务链路审计，不代表漏洞结论。"
            ),
            risk_level=_semantic_capability_risk_level(category, capability["risk_level"]),
            review_status="unreviewed",
            coverage_note="索引自动生成的业务语义边界节点，需要结合入口、对象和能力链验证。",
            risk_tags=tags[:8],
            evidence=evidence,
            confidence=min(0.86, max(0.45, float(capability["confidence"] or 0.65))),
            created_by="source_index",
            now=now,
        )
        nodes = semantic_by_path.setdefault(path, [])
        if node_id not in nodes:
            nodes.append(node_id)
        module_id = ensure_module(path, evidence_text=capability["evidence"], line_start=capability["line_start"])
        if module_id:
            _insert_business_edge_seed(
                conn,
                project_id,
                from_node_id=module_id,
                to_node_id=node_id,
                relation="contains",
                description="业务模块包含该业务语义边界。",
                confidence=0.65,
                created_by="source_index",
                now=now,
            )
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
        module_id = ensure_module(entrypoint["path"], entrypoint["route"], entrypoint["evidence"], entrypoint["line_start"])
        if module_id:
            _insert_business_edge_seed(
                conn,
                project_id,
                from_node_id=module_id,
                to_node_id=node_id,
                relation="contains",
                description="业务模块包含该入口。",
                confidence=0.72,
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
            if module_id:
                _insert_business_edge_seed(
                    conn,
                    project_id,
                    from_node_id=module_id,
                    to_node_id=control_id,
                    relation="contains",
                    description="业务模块包含该处理逻辑。",
                    confidence=0.66,
                    created_by="source_index",
                    now=now,
                )
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
            if source_id is None and relationship["relation"] in {"implements", "extends", "implemented_by", "extended_by"}:
                source_id = ensure_control(
                    relationship["from_path"],
                    relationship["from_symbol"],
                    relationship["evidence"],
                    relationship["line_start"],
                    float(relationship["confidence"] or 0.55),
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
        if relationship["relation"] in {"imports", "calls", "implemented_by", "extended_by"}:
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
        if relationship["relation"] in {"calls", "implements", "extends", "implemented_by", "extended_by"} and relationship["to_symbol"]:
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
                    relation=relationship["relation"],
                    description=_business_relationship_description(relationship["relation"]),
                    confidence=min(0.68, max(0.35, float(relationship["confidence"] or 0.55))),
                    created_by="source_index",
                    now=now,
                )

    for capability in capabilities:
        semantic_id = ensure_semantic_capability(capability)
        if not semantic_id:
            continue
        source_ids = controls_by_path.get(capability["path"]) or endpoint_by_path.get(capability["path"]) or []
        if not source_ids:
            continue
        relation = _semantic_capability_edge_relation(capability["category"])
        reverse = capability["category"] in {"auth_guard", "object_scope_guard"}
        for source_id in source_ids[:3]:
            if reverse:
                from_id, to_id = semantic_id, source_id
            else:
                from_id, to_id = source_id, semantic_id
            _insert_business_edge_seed(
                conn,
                project_id,
                from_node_id=from_id,
                to_node_id=to_id,
                relation=relation,
                description=_semantic_capability_edge_description(capability["category"]),
                confidence=min(0.76, max(0.42, float(capability["confidence"] or 0.65))),
                created_by="source_index",
                now=now,
            )

    candidates = conn.execute(
        """
        SELECT id, candidate_type, severity, title, description, file_path, line_start,
               line_end, entry_point, symbol, business_node_id
        FROM audit_candidates
        WHERE snapshot_id = ?
          AND source = 'index'
          AND candidate_type IN ('data_flow', 'capability_chain')
        ORDER BY created_at, id
        """,
        (snapshot_id,),
    ).fetchall()
    for candidate in candidates:
        node_id = _candidate_risk_node_id(snapshot_id, candidate)
        evidence = _business_evidence(candidate["file_path"], candidate["line_start"], candidate["description"])
        risk_tag = _candidate_risk_tag(candidate["title"]) or _candidate_capability_risk_tag(candidate["title"])
        risk_level = _candidate_business_risk_level(candidate["severity"], candidate["title"])
        node_title_prefix = "待审计能力链" if candidate["candidate_type"] == "capability_chain" else "待审计数据流"
        _insert_business_node_seed(
            conn,
            project_id,
            snapshot_id=snapshot_id,
            node_id=node_id,
            node_type="risk",
            title=f"{node_title_prefix} {candidate['title']}",
            description=(
                f"{candidate['description']} "
                "该节点由源码索引按风险链聚合生成，只表示需要 worker 读取源码确认，不预设最终漏洞类型。"
            ),
            risk_level=risk_level,
            review_status="unreviewed",
            coverage_note=f"索引自动生成的高价值{node_title_prefix[3:]}聚合节点，需要源码证据闭环。",
            risk_tags=[risk_tag] if risk_tag else [node_title_prefix],
            evidence=evidence,
            confidence=0.72,
            created_by="source_index",
            now=now,
        )
        for module_id in modules_by_path.get(candidate["file_path"] or "", []):
            _insert_business_edge_seed(
                conn,
                project_id,
                from_node_id=module_id,
                to_node_id=node_id,
                relation="contains",
                description="业务模块包含该待审计风险链。",
                confidence=0.66,
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
                description="入口关联到索引发现的待审计数据流。",
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
                description="处理逻辑关联到索引发现的待审计数据流。",
                confidence=0.66,
                created_by="source_index",
                now=now,
            )
        for semantic_id in semantic_by_path.get(candidate["file_path"] or "", [])[:6]:
            _insert_business_edge_seed(
                conn,
                project_id,
                from_node_id=semantic_id,
                to_node_id=node_id,
                relation="risk_of",
                description="业务语义边界关联到索引发现的待审计风险链。",
                confidence=0.64,
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
                description="数据对象关联到索引发现的待审计数据流。",
                confidence=0.6,
                created_by="source_index",
                now=now,
            )


def _candidate_risk_node_id(snapshot_id: str, candidate) -> str:
    cluster_key = audit_candidate_cluster_key(
        candidate_type=candidate["candidate_type"],
        severity=candidate["severity"],
        title=candidate["title"],
        file_path=candidate["file_path"],
        line_start=candidate["line_start"],
        entry_point=candidate["entry_point"],
        symbol=candidate["symbol"],
    )
    return _stable_business_id("biz", snapshot_id, "risk_cluster", cluster_key)


def _semantic_capability_config(category: str) -> dict[str, object] | None:
    if category == "auth_guard":
        return {
            "node_type": "control",
            "title_prefix": "权限边界",
            "risk_tags": ["权限边界", "认证授权"],
        }
    if category in {"object_scope_guard", "object_id_lookup"}:
        return {
            "node_type": "asset",
            "title_prefix": "对象边界",
            "risk_tags": ["对象边界", "租户/归属"],
        }
    if category in {"file_upload", "file_write", "file_read", "archive_extract"}:
        return {
            "node_type": "asset",
            "title_prefix": "文件生命周期",
            "risk_tags": ["文件生命周期", "文件能力"],
        }
    if category in {"process_execution", "task_execution", "template_render", "websocket_boundary"}:
        return {
            "node_type": "control",
            "title_prefix": "执行边界",
            "risk_tags": ["执行边界"],
        }
    if category == "credential_access":
        return {
            "node_type": "asset",
            "title_prefix": "敏感资产",
            "risk_tags": ["敏感资产", "凭据"],
        }
    if category == "external_system":
        return {
            "node_type": "external_system",
            "title_prefix": "外部系统",
            "risk_tags": ["外部系统", "基础设施"],
        }
    return None


def _semantic_capability_risk_level(category: str, raw_level: str | None) -> str:
    if raw_level in {"critical", "high", "medium", "low"}:
        return raw_level
    if category in {"file_upload", "file_write", "archive_extract", "process_execution", "task_execution"}:
        return "high"
    if category in {"auth_guard", "object_scope_guard", "object_id_lookup", "credential_access", "external_system"}:
        return "medium"
    return "unknown"


def _semantic_capability_edge_relation(category: str) -> str:
    if category in {"auth_guard", "object_scope_guard", "object_id_lookup"}:
        return "guards"
    if category == "external_system":
        return "depends_on"
    return "uses"


def _semantic_capability_edge_description(category: str) -> str:
    if category == "auth_guard":
        return "认证/权限边界保护该入口或处理逻辑。"
    if category in {"object_scope_guard", "object_id_lookup"}:
        return "对象归属、租户或资源定位边界约束该处理逻辑。"
    if category in {"file_upload", "file_write", "file_read", "archive_extract"}:
        return "处理逻辑使用文件生命周期相关能力。"
    if category in {"process_execution", "task_execution"}:
        return "处理逻辑依赖后台任务或执行边界。"
    if category == "external_system":
        return "处理逻辑依赖外部系统或基础设施接口。"
    return "处理逻辑关联到源码索引识别的业务语义能力。"


def _business_relationship_description(relation: str) -> str:
    if relation == "calls":
        return "源码索引识别到处理逻辑之间的调用关系。"
    if relation == "implements":
        return "源码类型层次显示该处理逻辑实现接口或契约。"
    if relation == "implemented_by":
        return "源码类型层次显示该接口或契约由目标处理逻辑实现。"
    if relation == "extends":
        return "源码类型层次显示该处理逻辑继承父类或基类。"
    if relation == "extended_by":
        return "源码类型层次显示该父类或基类被目标处理逻辑继承。"
    return "源码索引识别到处理逻辑之间的结构关系。"


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
MODULE_PATH_PREFIXES = {
    ".",
    "app",
    "apps",
    "backend",
    "cmd",
    "demo",
    "internal",
    "java",
    "lib",
    "main",
    "pkg",
    "python",
    "server",
    "src",
    "web",
}


def _business_module_key(path: str | None, route: str | None = None) -> str | None:
    route_key = _route_feature_key(route)
    if route_key and route_key.lower() not in ROUTE_GROUP_PREFIXES:
        return route_key[:80]
    if not path:
        return None
    parts = [part for part in PurePosixPath(path).parts if part not in ("", ".")]
    for index, part in enumerate(parts):
        clean = part.strip()
        if not clean:
            continue
        lower = clean.lower()
        if lower in MODULE_PATH_PREFIXES:
            continue
        if "." in clean and index == len(parts) - 1:
            stem = PurePosixPath(clean).stem
            if stem and stem.lower() not in {"index", "main", "app", "server"}:
                return stem[:80]
            continue
        if re.fullmatch(r"v\d+", lower):
            continue
        if clean.startswith("__"):
            continue
        return clean[:80]
    if parts:
        stem = PurePosixPath(parts[-1]).stem
        return stem[:80] if stem else None
    return None


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


def _clip_text(text: str, limit: int) -> str:
    value = " ".join(text.split())
    if len(value) <= limit:
        return value
    if limit <= 3:
        return value[:limit]
    return value[: limit - 3].rstrip() + "..."


def _candidate_risk_tag(title: str | None) -> str | None:
    if not title:
        return None
    match = re.search(r"审计数据流:\s*([^\s]+)", title)
    if match:
        return match.group(1)
    return None


def _candidate_capability_risk_tag(title: str | None) -> str | None:
    if not title:
        return None
    match = re.search(r"审计能力链:\s*([^\s]+)", title)
    if match:
        return match.group(1)
    return None


def _candidate_business_risk_level(severity: str | None, title: str | None) -> str:
    if severity in ("critical", "high"):
        return severity
    risk_tag = _candidate_risk_tag(title)
    if risk_tag in HIGH_IMPACT_RISK_SIGNAL_CATEGORIES:
        return "high"
    if _candidate_capability_risk_tag(title):
        return "high" if severity == "high" else "unknown"
    return "unknown"


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
                    evidence=_clip_text(line, MAX_SIGNAL_FRAGMENT_CHARS),
                    source_summary=_source_summary(nearby_sources or sources[:3]),
                    control_summary=_control_summary(text, lineno),
                    context_summary=_context_summary(text, lineno),
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
            sources.append((lineno, _clip_text(line, MAX_SIGNAL_FRAGMENT_CHARS)))
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
    first_items = [f"第 {lineno} 行 `{_clip_text(line, MAX_SIGNAL_FRAGMENT_CHARS)}`" for lineno, line in sources[:3]]
    if len(sources) > 3:
        first_items.append(f"另有 {len(sources) - 3} 处输入读取")
    return "、".join(first_items)


def _control_summary(text: str, sink_lineno: int) -> str | None:
    lines = text.splitlines()
    start = max(1, sink_lineno - 12)
    end = min(len(lines), sink_lineno + 12)
    items: list[str] = []
    for lineno in range(start, end + 1):
        stripped = lines[lineno - 1].strip()
        if not stripped or stripped.startswith(("//", "#")):
            continue
        for label, pattern in CONTROL_SIGNAL_PATTERNS:
            if pattern.search(stripped):
                items.append(f"{label}: 第 {lineno} 行 `{_clip_text(stripped, MAX_SIGNAL_FRAGMENT_CHARS)}`")
                break
        if len(items) >= 3:
            break
    return "、".join(items) if items else None


def _context_summary(text: str, sink_lineno: int) -> str | None:
    lines = text.splitlines()
    start = max(1, sink_lineno - 2)
    end = min(len(lines), sink_lineno + 2)
    items: list[str] = []
    for lineno in range(start, end + 1):
        stripped = lines[lineno - 1].strip()
        if not stripped:
            continue
        items.append(f"第 {lineno} 行 `{_clip_text(stripped, MAX_SIGNAL_FRAGMENT_CHARS)}`")
    return "、".join(items) if items else None


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
            _ensure_snapshot_capabilities(conn, snapshot, root)
            _ensure_snapshot_audit_candidates(conn, snapshot, root)
            _ensure_business_graph_seed(conn, snapshot.id)
            return
        files = _load_code_files(conn, snapshot.id)
        code_index = extract_code_index(snapshot.id, root, files)
        _insert_code_index(conn, code_index)
        _insert_code_capabilities(conn, snapshot.id, files, root=root, code_index=code_index)
        _insert_audit_candidates_from_index(conn, snapshot.id, files, code_index, root=root)
        _ensure_business_graph_seed(conn, snapshot.id)


def _ensure_snapshot_capabilities(conn, snapshot: SourceSnapshot, root: Path) -> None:
    existing = conn.execute(
        "SELECT COUNT(*) AS count FROM code_capabilities WHERE snapshot_id = ?",
        (snapshot.id,),
    ).fetchone()["count"]
    capability_candidates = conn.execute(
        """
        SELECT COUNT(*) AS count
        FROM audit_candidates
        WHERE snapshot_id = ?
          AND source = 'index'
          AND candidate_type = 'capability_chain'
        """,
        (snapshot.id,),
    ).fetchone()["count"]
    high_capabilities = conn.execute(
        """
        SELECT COUNT(*) AS count
        FROM code_capabilities
        WHERE snapshot_id = ?
          AND risk_level IN ('critical', 'high')
        """,
        (snapshot.id,),
    ).fetchone()["count"]
    if existing and (capability_candidates or not high_capabilities):
        return
    files = _load_code_files(conn, snapshot.id)
    code_index = extract_code_index(snapshot.id, root, files)
    if not existing:
        _insert_code_capabilities(conn, snapshot.id, files, root=root, code_index=code_index)
    if not capability_candidates:
        _insert_audit_candidates_from_index(conn, snapshot.id, files, code_index, root=root)


def _ensure_snapshot_audit_candidates(conn, snapshot: SourceSnapshot, root: Path) -> None:
    existing = conn.execute(
        "SELECT COUNT(*) AS count FROM audit_candidates WHERE snapshot_id = ?",
        (snapshot.id,),
    ).fetchone()["count"]
    if existing:
        return
    files = _load_code_files(conn, snapshot.id)
    code_index = extract_code_index(snapshot.id, root, files)
    _insert_code_capabilities(conn, snapshot.id, files, root=root, code_index=code_index)
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
