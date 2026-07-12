"""Vulnerability report router.

This is an additive router exposing the ``/api/vulnerabilities`` endpoints. Task
4.3 implements the *list* and *summary* endpoints; task 4.4 adds the *export*
and *refresh* endpoints on this same router.

The router is read-only with respect to existing core tables: it reads from the
``vulnerabilities`` table (created by :mod:`cairn.server.product_db` and
populated by :mod:`cairn.server.vulnerability_extraction`) joined with the
``projects`` table to resolve each finding's ``project_name``.

Response shapes follow :mod:`cairn.server.vulnerabilities_models`.
"""

from __future__ import annotations

import csv
import base64
import hashlib
import io
import json
import re
import zipfile
from pathlib import Path
from urllib.parse import urlsplit
from xml.sax.saxutils import escape as xml_escape

from fastapi import APIRouter, HTTPException, Query
from fastapi.responses import Response
from reportlab.lib.colors import HexColor
from reportlab.lib.pagesizes import A4
from reportlab.pdfbase import pdfmetrics
from reportlab.pdfbase.ttfonts import TTFont
from reportlab.pdfgen import canvas

from datetime import datetime, timezone

from cairn.server.activity_service import record_audit
from cairn.server.db import get_conn
from cairn.server.vulnerabilities_models import (
    ExportRecord,
    Severity,
    Vulnerability,
    VulnerabilitySummary,
    VulnerabilityStatus,
    VulnerabilityStatusUpdate,
)
router = APIRouter(prefix="/api/vulnerabilities", tags=["vulnerabilities"])

_MISSING_PROOF_MESSAGE = (
    "缺少原始证明数据包，不能作为交付证明；"
    "需复测补充完整 payload、请求数据包、响应/回显。"
)
_STATIC_POC_NOTE = (
    "以下 PoC 基于源码静态推导，适合作为复现步骤和复测模板；"
    "它不是动态抓包结果。"
)
_REPORT_ENRICHMENT_PACKET_NOTE = (
    "以下验证请求根据已确认漏洞、审计日志、时间线和源码证据静态推测，"
    "不是实测抓包；不能替代真实 proof_packets。"
)
_REPORT_ENRICHMENT_POC_NOTE = (
    "以下 PoC 来自报告补充阶段，仅用于指导复测和交付说明；"
    "没有写回漏洞确认记录。"
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

# Display ordering for the report: most severe first, then most recently
# discovered, with the id as a final deterministic tiebreaker. Implemented as a
# SQL ``CASE`` so the ordering is applied in the database rather than in Python.
_SEVERITY_RANK_SQL = (
    "CASE v.severity "
    "WHEN 'critical' THEN 0 "
    "WHEN 'high' THEN 1 "
    "WHEN 'medium' THEN 2 "
    "WHEN 'low' THEN 3 "
    "ELSE 4 END"
)


def _decode_json_list(raw: str | None) -> list:
    if not raw:
        return []
    try:
        value = json.loads(raw)
    except json.JSONDecodeError:
        return []
    return value if isinstance(value, list) else []


def _vulnerability_select(where_sql: str) -> str:
    return f"""
            SELECT
                v.id          AS id,
                v.project_id  AS project_id,
                p.title       AS project_name,
                v.fact_id     AS fact_id,
                v.title       AS title,
                v.description AS description,
                v.severity    AS severity,
                COALESCE(v.status, 'confirmed') AS status,
                v.discovered_at AS discovered_at,
                v.source_intent_id AS source_intent_id,
                v.source_intent_description AS source_intent_description,
                v.source_worker AS source_worker,
                v.source_fact_ids_json AS source_fact_ids_json,
                v.evidence_json AS evidence_json,
                v.process_json AS process_json,
                v.proof_packets_json AS proof_packets_json,
                v.reproduction_poc_json AS reproduction_poc_json
            FROM vulnerabilities v
            JOIN projects p ON p.id = v.project_id
            {where_sql}
            ORDER BY {_SEVERITY_RANK_SQL}, v.discovered_at DESC, v.id
            """


def _remove_non_audit_report_rows() -> int:
    """Delete legacy report rows not backed by confirmed audit findings.

    Modern code-audit reporting writes ``vulnerabilities.id`` from
    ``audit_findings.id`` via the audit-finding review flow. Older keyword/fact
    extraction could leave rows in the same table without a corresponding audit
    finding; refresh is the operator-facing reconciliation point that removes
    those stale rows.
    """
    with get_conn() as conn:
        cursor = conn.execute(
            """
            DELETE FROM vulnerabilities
            WHERE id NOT IN (SELECT id FROM audit_findings)
            """
        )
        return int(cursor.rowcount if cursor.rowcount is not None else 0)


def _row_to_vulnerability(row) -> Vulnerability:
    data = dict(row)
    data["source_fact_ids"] = _decode_json_list(data.pop("source_fact_ids_json", None))
    data["evidence"] = _decode_json_list(data.pop("evidence_json", None))
    data["process"] = _decode_json_list(data.pop("process_json", None))
    data["proof_packets"] = _decode_json_list(data.pop("proof_packets_json", None))
    data["reproduction_poc"] = _decode_json_dict(data.pop("reproduction_poc_json", None))
    return Vulnerability(**data)


def _decode_json_dict(raw: str | None) -> dict:
    if not raw:
        return {}
    try:
        value = json.loads(raw)
    except json.JSONDecodeError:
        return {}
    return value if isinstance(value, dict) else {}


_SEVERITY_RANK = {"critical": 0, "high": 1, "medium": 2, "low": 3}


def _unique(items: list[str]) -> list[str]:
    seen: set[str] = set()
    result: list[str] = []
    for item in items:
        value = str(item or "").strip()
        if value and value not in seen:
            seen.add(value)
            result.append(value)
    return result


def _fact_rank(fact_id: str | None) -> int:
    match = re.search(r"\d+", fact_id or "")
    return int(match.group(0)) if match else -1


def _all_report_text(vulns: list[Vulnerability]) -> str:
    """Join only reportable text from one project/vulnerability group."""
    parts: list[str] = []
    for vuln in vulns:
        parts.extend([vuln.title, vuln.description, *vuln.evidence])
    return "\n".join(_unique(parts))


def _vulnerability_signature(vuln: Vulnerability) -> str:
    text = f"{vuln.title}\n{vuln.description}"
    cve = re.search(r"\bCVE-\d{4}-\d+\b", text, re.IGNORECASE)
    if cve:
        return f"cve:{cve.group(0).upper()}"
    lower = text.lower()
    if "sql 注入" in text or "sql injection" in lower or "sqli" in lower:
        return "class:sql-injection"
    if "jboss" in lower and ("/invoker" in lower or "反序列化" in text):
        return "class:jboss-invoker-rce"
    if "远程命令执行" in text or "命令执行" in text or "rce" in lower:
        return "class:remote-command-execution"
    return "title:" + re.sub(r"\s+", " ", vuln.title.lower()).strip()


def _confirmation_score(vuln: Vulnerability) -> tuple[int, int]:
    text = f"{vuln.title}\n{vuln.description}\n" + "\n".join(vuln.evidence)
    score = 0
    for pattern, weight in (
        (r"已成功验证|目标已达成|成功执行|任意命令执行", 40),
        (r"root\s*权限|uid=0|whoami\s*(?:output|输出)?[:：]?\s*root", 35),
        (r"已确认|确认存在|核心发现|利用路径已确认", 20),
        (r"尚未拿到|未获得|目标尚未达成|失败|不可用", -30),
    ):
        if re.search(pattern, text, re.IGNORECASE):
            score += weight
    return (score, _fact_rank(vuln.fact_id))


def _merge_process(vulns: list[Vulnerability]) -> list[dict[str, str]]:
    merged: list[dict[str, str]] = []
    seen: set[tuple[str, str, str]] = set()
    ordered = sorted(vulns, key=lambda item: _fact_rank(item.fact_id))
    for vuln in ordered:
        for step in vuln.process:
            key = (
                str(step.get("type", "")),
                str(step.get("id", "")),
                str(step.get("description", "")),
            )
            if key in seen:
                continue
            seen.add(key)
            merged.append(step)
    return merged


def _merge_stored_proof_packets(vulns: list[Vulnerability]) -> list[dict[str, str]]:
    merged: list[dict[str, str]] = []
    seen: set[tuple[str, str, str]] = set()
    ordered = sorted(vulns, key=lambda item: _fact_rank(item.fact_id))
    for vuln in ordered:
        for packet in vuln.proof_packets or []:
            if not isinstance(packet, dict):
                continue
            normalized = {
                str(key): str(value).strip()
                for key, value in packet.items()
                if value is not None and str(value).strip()
            }
            if not _is_complete_proof_packet(normalized):
                continue
            key = (
                normalized.get("title", ""),
                normalized.get("request", ""),
                normalized.get("payload", ""),
            )
            if key in seen:
                continue
            seen.add(key)
            merged.append(normalized)
    return merged


def _merge_reproduction_poc(vulns: list[Vulnerability]) -> dict[str, object]:
    ordered = sorted(vulns, key=lambda item: _fact_rank(item.fact_id))
    fallback: dict[str, object] = {}
    for vuln in ordered:
        poc = vuln.reproduction_poc or {}
        if not isinstance(poc, dict) or not poc:
            continue
        normalized = _normalize_reproduction_poc(poc)
        if not normalized:
            continue
        if _is_complete_reproduction_poc(normalized):
            return normalized
        if not fallback:
            fallback = normalized
    return fallback


def _normalize_reproduction_poc(poc: dict) -> dict[str, object]:
    normalized: dict[str, object] = {}
    for key, value in poc.items():
        name = str(key).strip()
        if not name or value is None:
            continue
        if isinstance(value, list):
            items = [str(item).strip() for item in value if str(item).strip()]
            if items:
                normalized[name] = items
            continue
        text = str(value).strip()
        if text:
            normalized[name] = text
    return normalized


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


def _is_complete_reproduction_poc(poc: dict[str, object]) -> bool:
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


def _load_report_enrichments(vulnerabilities: list[Vulnerability]) -> dict[str, dict[str, object]]:
    finding_ids = _unique(
        [
            finding_id
            for vuln in vulnerabilities
            for finding_id in [*(vuln.related_fact_ids or []), vuln.fact_id, vuln.id]
        ]
    )
    if not finding_ids:
        return {}
    placeholders = ",".join("?" for _ in finding_ids)
    with get_conn() as conn:
        rows = conn.execute(
            f"""
            SELECT id, project_id, finding_id, worker, completed_at, created_at,
                   packet_templates_json, reproduction_poc_json,
                   evidence_chain_json, report_sections_json, delivery_notes_json
            FROM report_enrichment_tasks
            WHERE status = 'completed'
              AND finding_id IN ({placeholders})
            ORDER BY finding_id,
                     datetime(completed_at) DESC,
                     datetime(created_at) DESC,
                     id DESC
            """,
            finding_ids,
        ).fetchall()
    latest: dict[str, dict[str, object]] = {}
    for row in rows:
        finding_id = str(row["finding_id"])
        if finding_id in latest:
            continue
        latest[finding_id] = {
            "id": row["id"],
            "project_id": row["project_id"],
            "finding_id": finding_id,
            "worker": row["worker"],
            "completed_at": row["completed_at"],
            "created_at": row["created_at"],
            "packet_templates": _decode_json_list(row["packet_templates_json"]),
            "reproduction_poc": _decode_json_dict(row["reproduction_poc_json"]),
            "evidence_chain": [
                str(item).strip()
                for item in _decode_json_list(row["evidence_chain_json"])
                if str(item).strip()
            ],
            "report_sections": _decode_json_dict(row["report_sections_json"]),
            "delivery_notes": [
                str(item).strip()
                for item in _decode_json_list(row["delivery_notes_json"])
                if str(item).strip()
            ],
        }
    return latest


def _load_audit_finding_report_details(vulnerabilities: list[Vulnerability]) -> dict[str, dict[str, object]]:
    finding_ids = _unique(
        [
            finding_id
            for vuln in vulnerabilities
            for finding_id in [*(vuln.related_fact_ids or []), vuln.fact_id, vuln.id]
        ]
    )
    if not finding_ids:
        return {}
    placeholders = ",".join("?" for _ in finding_ids)
    with get_conn() as conn:
        rows = conn.execute(
            f"""
            SELECT id, category, severity, status, evidence_level, cwe,
                   file_path, line_start, line_end, symbol, entry_point,
                   impact, evidence, remediation, reviewed_by, reviewed_at
            FROM audit_findings
            WHERE id IN ({placeholders})
            """,
            finding_ids,
        ).fetchall()
    return {
        row["id"]: {
            "id": row["id"],
            "category": row["category"],
            "severity": row["severity"],
            "status": row["status"],
            "evidence_level": row["evidence_level"],
            "cwe": row["cwe"],
            "file_path": row["file_path"],
            "line_start": row["line_start"],
            "line_end": row["line_end"],
            "symbol": row["symbol"],
            "entry_point": row["entry_point"],
            "impact": row["impact"],
            "evidence": row["evidence"],
            "remediation": row["remediation"],
            "reviewed_by": row["reviewed_by"],
            "reviewed_at": row["reviewed_at"],
        }
        for row in rows
    }


def _audit_detail_for_vulnerability(
    vuln: Vulnerability, details: dict[str, dict[str, object]]
) -> dict[str, object]:
    for finding_id in _unique([vuln.fact_id, vuln.id, *(vuln.related_fact_ids or [])]):
        detail = details.get(finding_id)
        if detail is not None:
            return detail
    return {}


def _remediation_text(vuln: Vulnerability, detail: dict[str, object]) -> str:
    remediation = str(detail.get("remediation") or "").strip()
    if remediation:
        return remediation
    return "未记录明确修复建议；需结合该条发现的代码证据、入口点和影响面补充修复动作。"


def _finding_location(detail: dict[str, object]) -> str:
    path = str(detail.get("file_path") or "").strip()
    if not path:
        return "未记录"
    start = detail.get("line_start")
    end = detail.get("line_end")
    if start and end and end != start:
        return f"{path}:{start}-{end}"
    return f"{path}:{start}" if start else path


def _fixed_acceptance_criteria(
    vuln: Vulnerability,
    detail: dict[str, object],
) -> list[str]:
    category = str(detail.get("category") or "").lower()
    family_criteria = {
        "sql_injection": "使用原 payload 复测时，输入不得改变 SQL 语义；查询必须参数化且不返回额外数据、SQL 错误或可控时间差。",
        "xss": "原 payload 在所有输出上下文中必须被正确编码，不得形成可执行 HTML、属性或 JavaScript。",
        "open_redirect": "外部或协议相对跳转目标必须被拒绝，响应只能跳转到经过白名单校验的站内地址。",
        "authorization": "低权限账号访问他人对象或越权动作必须被拒绝，且目标对象状态保持不变。",
        "command_injection": "元字符和命令替换 payload 不得影响进程参数边界，不得产生额外命令执行副作用。",
        "path_traversal": "目录穿越 payload 必须被拒绝，规范化后的路径必须始终位于允许根目录内。",
        "ssrf": "内网、环回、云元数据和非白名单目标必须被拒绝，并在重定向后再次校验目标。",
    }
    criteria = [
        family_criteria.get(
            category,
            "按原复测步骤执行时，不再出现报告描述的未授权行为、敏感数据泄露或危险操作。",
        ),
        "正常业务请求仍可完成，修复不得依赖前端校验或仅隐藏错误信息。",
        "增加覆盖原 payload、边界值和编码变体的自动化回归测试，并保存测试结果。",
    ]
    if detail.get("file_path"):
        criteria.append(f"复核修复提交已覆盖源码位置 `{_finding_location(detail)}` 及其同类调用点。")
    return criteria


def _report_enrichments_for_vulnerability(
    vuln: Vulnerability, enrichments: dict[str, dict[str, object]]
) -> list[dict[str, object]]:
    finding_ids = _unique([*(vuln.related_fact_ids or []), vuln.fact_id, vuln.id])
    return [enrichments[finding_id] for finding_id in finding_ids if finding_id in enrichments]


def _poc_text(poc: dict[str, object], key: str) -> str:
    value = poc.get(key)
    return value.strip() if isinstance(value, str) else ""


def _poc_list(poc: dict[str, object], key: str) -> list[str]:
    value = poc.get(key)
    if not isinstance(value, list):
        return []
    return [str(item).strip() for item in value if str(item).strip()]


_FILESYSTEM_PATH_PREFIXES = (
    "/bin/",
    "/dev/",
    "/etc/",
    "/home/",
    "/opt/",
    "/proc/",
    "/root/",
    "/tmp/",
    "/usr/",
    "/var/",
)


def _project_origin(project_id: str) -> str:
    """Return the origin fact for exactly one project, when available."""
    with get_conn() as conn:
        row = conn.execute(
            "SELECT description FROM facts WHERE project_id = ? AND id = 'origin'",
            (project_id,),
        ).fetchone()
    return str(row["description"] or "").strip() if row else ""


def _project_fact_text(vulns: list[Vulnerability]) -> str:
    """Load raw descriptions only for the selected project's finding facts."""
    if not vulns:
        return ""
    project_id = vulns[0].project_id
    fact_ids = _unique(
        [vuln.fact_id for vuln in vulns if vuln.project_id == project_id]
    )
    if not fact_ids:
        return ""
    placeholders = ",".join("?" for _ in fact_ids)
    with get_conn() as conn:
        rows = conn.execute(
            f"SELECT description FROM facts "
            f"WHERE project_id = ? AND id IN ({placeholders}) ORDER BY id",
            (project_id, *fact_ids),
        ).fetchall()
    return "\n".join(str(row["description"] or "") for row in rows)


def _clean_endpoint(value: str) -> str:
    endpoint = value.strip("`'\"*()[]{}<>，。；;：:")
    if not endpoint.startswith("/") or endpoint.startswith("//"):
        return ""
    if endpoint.lower().startswith(_FILESYSTEM_PATH_PREFIXES):
        return ""
    return endpoint


def _local_context(text: str, start: int, end: int) -> str:
    """Return the bullet/sentence that contains a candidate endpoint."""
    line_left = text.rfind("\n", 0, start)
    line_right = text.find("\n", end)
    if line_left >= 0 or line_right >= 0:
        line_right = line_right if line_right >= 0 else len(text)
        line = text[line_left + 1 : line_right].strip()
        if line:
            if line.startswith("-") and line_left > 0:
                preceding = text[:line_left].splitlines()
                for previous in reversed(preceding[-6:]):
                    previous = previous.strip()
                    if not previous:
                        continue
                    if previous.startswith("-"):
                        continue
                    if re.search(
                        r"未授权|漏洞|泄露|发现|确认|攻击面",
                        previous,
                        re.IGNORECASE,
                    ):
                        return previous + "\n" + line
                    break
            return line

    left = max(text.rfind("。", 0, start), text.rfind("；", 0, start))
    right_candidates = [
        position
        for position in (
            text.find("\n", end),
            text.find("。", end),
            text.find("；", end),
        )
        if position >= 0
    ]
    right = min(right_candidates) if right_candidates else len(text)
    return text[left + 1 : right].strip()


def _endpoint_candidates(text: str) -> list[tuple[str, int, str]]:
    """Extract and score HTTP endpoint candidates from report facts."""
    candidates: dict[str, tuple[int, str]] = {}
    patterns = (
        r"https?://[^\s`'\"<>，。；;）)]+",
        r"(?<![\w./:])/(?!/)[A-Za-z0-9._~!$&'()*+,;=:@%/?#\[\]-]+",
    )
    for pattern in patterns:
        for match in re.finditer(pattern, text, re.IGNORECASE):
            raw = match.group(0)
            if raw.lower().startswith(("http://", "https://")):
                parsed = urlsplit(raw)
                raw = parsed.path or "/"
                if parsed.query:
                    raw += "?" + parsed.query
            endpoint = _clean_endpoint(raw)
            if not endpoint:
                continue
            context = _local_context(text, match.start(), match.end())
            if re.search(
                rf"rtsp://[^\s`'\"<>，。；;）)]*{re.escape(endpoint)}",
                context,
                re.IGNORECASE,
            ):
                continue
            score = 5
            for positive, weight in (
                (
                    r"无需认证|未授权|直接返回|回显|成功|已确认|漏洞|泄露|"
                    r"枚举|错误响应不同|密码提示",
                    30,
                ),
                (r"\b(?:GET|POST|PUT|PATCH|DELETE)\b|请求|响应|状态码|JSON", 16),
                (r"返回\s*(?:HTTP\s*)?2\d\d|\b2\d\d\s+OK\b", 12),
            ):
                if re.search(positive, context, re.IGNORECASE):
                    score += weight
            for negative, weight in (
                (
                    r"404|不存在|失败|不可利用|未发现|无法|未能|错误结论|"
                    r"修正|未被使用|不参与",
                    35,
                ),
                (
                    r"需认证|需要认证|受保护|重定向至登录|未授权访问.*未|"
                    r"为空|需特定",
                    24,
                ),
            ):
                if re.search(negative, context, re.IGNORECASE):
                    score -= weight
            if endpoint.endswith((".action", ".jsp", ".php", ".json")):
                score += 8
            previous = candidates.get(endpoint)
            if previous is None or score > previous[0]:
                candidates[endpoint] = (score, context)
    return sorted(
        ((endpoint, score, context) for endpoint, (score, context) in candidates.items()),
        key=lambda item: (-item[1], -len(item[0]), item[0]),
    )


def _target_host(project_id: str, text: str, endpoint: str, context: str) -> str:
    """Resolve a host only from the current group's text or project origin."""
    urls = re.findall(r"https?://[^\s`'\"<>，。；;）)]+", text, re.IGNORECASE)
    matching = [url for url in urls if endpoint and endpoint.split("?", 1)[0] in url]
    for raw in [*matching, *urls, _project_origin(project_id)]:
        if not raw:
            continue
        parsed = urlsplit(raw)
        if parsed.netloc:
            host = parsed.netloc
            if ":" not in host:
                port_match = re.search(
                    r"(?:^|[^\d])(\d{2,5})\s+(?:DStatus|SS|HTTP|HTTPS|Web|API)",
                    context,
                    re.IGNORECASE,
                )
                if port_match:
                    host += ":" + port_match.group(1)
            return host
    return "<项目事实未记录目标主机>"


def _request_method(context: str, endpoint: str) -> str:
    escaped = re.escape(endpoint.split("?", 1)[0])
    for pattern in (
        rf"\b(GET|POST|PUT|PATCH|DELETE)\b[^。\n]{{0,100}}{escaped}",
        rf"{escaped}[^。\n]{{0,100}}\b(GET|POST|PUT|PATCH|DELETE)\b",
        r"\b(GET|POST|PUT|PATCH|DELETE)\s+请求\b",
    ):
        match = re.search(pattern, context, re.IGNORECASE)
        if match:
            return match.group(1).upper()
    return "GET"


def _request_parameters(context: str) -> list[tuple[str, str]]:
    """Extract concrete name=value examples close to the selected endpoint."""
    params: list[tuple[str, str]] = []
    seen: set[str] = set()
    for match in re.finditer(
        r"(?<![\w.-])([A-Za-z_][\w.\[\]-]*)=([^&\s`，。,；;）)]+)",
        context,
    ):
        name, value = match.group(1), match.group(2).strip("'\"")
        if name.lower() in {"http", "https", "uid", "gid", "euid"} or name in seen:
            continue
        seen.add(name)
        params.append((name, value))
        if len(params) >= 6:
            break
    return params


def _response_body(context: str) -> str:
    """Extract an exact response example when the fact recorded one."""
    json_match = re.search(r"\{[^{}\n]{2,800}\}", context)
    if json_match:
        return json_match.group(0)
    for pattern in (
        r"返回\s*[`'\"“]([^`'\"”\n]{1,500})[`'\"”]",
        r"响应(?:为|内容为|回显)?\s*[`'\"“]([^`'\"”\n]{1,500})[`'\"”]",
        r"→\s*(\[[^\]\n]{1,500}\])",
    ):
        match = re.search(pattern, context, re.IGNORECASE)
        if match:
            return match.group(1)
    behavior = re.search(
        r"[^。\n]{0,120}(?:无需认证|未授权|直接返回|回显|泄露|枚举)[^。\n]{0,220}",
        context,
        re.IGNORECASE,
    )
    if behavior:
        return f"<事实仅记录响应行为：{behavior.group(0).strip()}>"
    return "<事实未记录原始响应体，需复测补充>"


def _reconstructed_http_packets(vulns: list[Vulnerability]) -> list[dict[str, str]]:
    """Build reproducible HTTP proofs from same-project confirmed facts."""
    if not vulns:
        return []
    project_id = vulns[0].project_id
    scoped = [vuln for vuln in vulns if vuln.project_id == project_id]
    raw_fact_text = _project_fact_text(scoped)
    report_text = _all_report_text(scoped)
    text = "\n".join(part for part in (report_text, raw_fact_text) if part)
    candidate_text = raw_fact_text or report_text
    candidates = [
        candidate for candidate in _endpoint_candidates(candidate_text) if candidate[1] > 0
    ]
    if not candidates:
        return []
    top_score = candidates[0][1]
    candidates = [
        candidate
        for candidate in candidates
        if candidate[1] >= max(5, top_score - 12)
    ]
    candidates = [
        candidate
        for candidate in candidates
        if not (
            candidate[0].endswith("/")
            and any(
                other[0] != candidate[0]
                and other[0].startswith(candidate[0])
                and other[1] >= candidate[1]
                for other in candidates
            )
        )
    ]
    fact_ids = ", ".join(_unique([vuln.fact_id for vuln in scoped]))
    packets: list[dict[str, str]] = []
    for endpoint, _score, context in candidates[:3]:
        params = _request_parameters(context)
        if (
            not params
            and "login" in endpoint.lower()
            and re.search(
                r"用户名|密码|登录接口|认证错误|loginName|loginSecretKey",
                context,
                re.IGNORECASE,
            )
        ):
            params = _request_parameters(raw_fact_text)
        method = _request_method(context, endpoint)
        if method == "GET" and params and "login" in endpoint.lower():
            method = "POST"

        request_target = endpoint
        body = ""
        if params:
            encoded = "&".join(f"{name}={value}" for name, value in params)
            if method == "GET" and "?" not in request_target:
                request_target += "?" + encoded
            elif method != "GET":
                body = encoded
        elif method != "GET":
            body = "<根据事实补充请求参数或载荷>"

        host = _target_host(project_id, text, endpoint, context)
        request_lines = [
            f"{method} {request_target} HTTP/1.1",
            f"Host: {host}",
            "Accept: application/json, text/plain, */*",
            "Connection: close",
        ]
        if body:
            request_lines.extend(
                [
                    "Content-Type: application/x-www-form-urlencoded",
                    f"Content-Length: {len(body.encode('utf-8'))}",
                    "",
                    body,
                ]
            )

        status_match = re.search(
            r"(?:返回|HTTP(?:/\d(?:\.\d)?)?\s*)\s*(\d{3})(?:\s+OK)?",
            context,
            re.IGNORECASE,
        )
        status = status_match.group(1) if status_match else "<事实未记录状态码>"
        response_body = _response_body(context)
        content_type = (
            "application/json"
            if "json" in context.lower() or response_body.startswith(("{", "["))
            else "text/plain"
        )
        packets.append(
            {
                "title": f"{endpoint.split('?', 1)[0]} 漏洞证明（依据事实重构）",
                "request": "\n".join(request_lines),
                "response": (
                    f"HTTP/1.1 {status}\n"
                    f"Content-Type: {content_type}\n\n"
                    f"{response_body}"
                ),
                "note": (
                    f"该数据包仅依据当前项目 {project_id} 的确认事实 {fact_ids} 重构，"
                    "不是原始抓包。事实未记录的字段使用占位符，复测时应以真实请求和响应替换。"
                ),
            }
        )
    return packets


def _proof_packets(vulns: list[Vulnerability]) -> list[dict[str, str]]:
    """Return only stored, complete proof packets.

    Older fact-derived report rows do not contain original traffic. The report
    must not invent request/response packets from prose because that produces
    placeholder material that looks deliverable but is not reproducible.
    """
    return _merge_stored_proof_packets(vulns)


def _evidence_score(text: str) -> int:
    value = text or ""
    score = 0
    for pattern, weight in (
        (r"whoami\s+output|id\s+output|uid=0|root\s*权限", 80),
        (r"已成功验证|目标已达成|成功执行|任意命令执行", 70),
        (r"无需认证|相关端点|/invoker|Content-Type|ysoserial|CommonsCollections", 30),
        (r"CVE-\d{4}-\d+|SQL 注入|反序列化|远程命令执行", 20),
        (r"尚未|未获得|失败|不可用|No \\.ser|pre-staged|Sub-path|failed|not achieved", -60),
        (r" expects | would | requires manually |ClassNotFoundException|NullPointerException", -40),
    ):
        if re.search(pattern, value, re.IGNORECASE):
            score += weight
    return score


def _select_evidence(items: list[str], winner: Vulnerability) -> list[str]:
    candidates = _unique([winner.description, *items])
    ranked = sorted(
        enumerate(candidates),
        key=lambda pair: (-_evidence_score(pair[1]), pair[0]),
    )
    selected: list[str] = []
    for _idx, item in ranked:
        if _evidence_score(item) < 0 and selected:
            continue
        selected.append(item)
        if len(selected) >= 6:
            break
    return selected or [winner.description]


def _merge_vulnerabilities(vulnerabilities: list[Vulnerability]) -> list[Vulnerability]:
    groups: dict[tuple[str, str], list[Vulnerability]] = {}
    for vuln in vulnerabilities:
        key = (vuln.project_id, _vulnerability_signature(vuln))
        groups.setdefault(key, []).append(vuln)

    merged: list[Vulnerability] = []
    for (_project_id, signature), items in groups.items():
        winner = max(items, key=_confirmation_score)
        related_fact_ids = _unique([item.fact_id for item in items])
        related_source_ids = _unique(
            [source_id for item in items for source_id in item.source_fact_ids]
        )
        evidence = _select_evidence(
            [evidence for item in items for evidence in item.evidence],
            winner,
        )
        process = _merge_process(items)
        proof_packets = _proof_packets(items)
        reproduction_poc = _merge_reproduction_poc(items)

        description = winner.description
        if len(items) > 1:
            description = (
                f"{description} 已合并同一项目内 {len(items)} 个相关探索事实"
                f"（{', '.join(related_fact_ids)}），最终确认事实为 {winner.fact_id}。"
            )

        merged.append(
            winner.model_copy(
                update={
                    "id": f"vuln_{winner.project_id}_{re.sub(r'[^a-zA-Z0-9]+', '_', signature).strip('_').lower()}",
                    "status": "confirmed" if any(item.status == "confirmed" for item in items) else "ignored",
                    "description": description,
                    "source_fact_ids": related_source_ids,
                    "related_fact_ids": related_fact_ids,
                    "evidence": evidence,
                    "process": process,
                    "proof_packets": proof_packets,
                    "reproduction_poc": reproduction_poc,
                }
            )
        )

    return sorted(
        merged,
        key=lambda item: (
            _SEVERITY_RANK.get(item.severity, 99),
            -_confirmation_score(item)[0],
            str(item.discovered_at or ""),
            item.id,
        ),
    )


@router.get("", response_model=list[Vulnerability])
def list_vulnerabilities(
    severity: Severity | None = Query(
        default=None,
        description="Optional severity filter (critical, high, medium, low).",
    ),
    project_id: str | None = Query(
        default=None,
        description="Optional project filter; restricts results to one project.",
    ),
    status: VulnerabilityStatus | None = Query(
        default=None,
        description="Optional review status filter (confirmed or ignored).",
    ),
) -> list[Vulnerability]:
    """List vulnerabilities, optionally filtered by severity and/or project.

    The ``severity`` and ``project_id`` query parameters are independent filters
    combined with AND logic (requirements 7.1, 7.2, 7.3): a vulnerability is
    included only when it satisfies *every* active filter. When neither filter
    is supplied the complete list is returned (requirement 7.5).

    ``severity`` is validated against the allowed levels by FastAPI, so an
    unsupported value yields a 422 validation error. When ``project_id`` refers
    to a project that does not exist, the request is rejected with a 404 rather
    than silently returning an empty list (design error handling: "Project not
    found (filter)"). A valid filter that simply matches nothing returns an
    empty list (requirement 7.4).

    Each result includes the finding's ``title``, ``severity`` and source
    ``project_name`` (requirement 6.3), resolved by joining ``vulnerabilities``
    with ``projects``.
    """
    clauses: list[str] = []
    params: list[str] = []

    if severity is not None:
        clauses.append("v.severity = ?")
        params.append(severity)

    if project_id is not None:
        clauses.append("v.project_id = ?")
        params.append(project_id)

    if status is not None:
        clauses.append("COALESCE(v.status, 'confirmed') = ?")
        params.append(status)

    where_sql = ""
    if clauses:
        where_sql = "WHERE " + " AND ".join(clauses)

    with get_conn() as conn:
        if project_id is not None:
            exists = conn.execute(
                "SELECT 1 FROM projects WHERE id = ?", (project_id,)
            ).fetchone()
            if exists is None:
                raise HTTPException(status_code=404, detail="Project not found")

        rows = conn.execute(_vulnerability_select(where_sql), params).fetchall()

    return _merge_vulnerabilities([_row_to_vulnerability(row) for row in rows])


@router.get("/summary", response_model=VulnerabilitySummary)
def vulnerabilities_summary() -> VulnerabilitySummary:
    """Return the total vulnerability counts grouped by severity level.

    Provides the per-severity totals shown on the report page (requirement
    6.3). When no vulnerabilities exist, every severity count is zero — the
    :class:`VulnerabilitySummary` field defaults guarantee a complete object
    with all four levels present (requirement 6.7).
    """
    counts = {"critical": 0, "high": 0, "medium": 0, "low": 0}

    with get_conn() as conn:
        rows = conn.execute(_vulnerability_select(""), []).fetchall()

    for vuln in _merge_vulnerabilities([_row_to_vulnerability(row) for row in rows]):
        if vuln.severity in counts:
            counts[vuln.severity] += 1

    return VulnerabilitySummary(**counts)


# Columns emitted, in order, for each vulnerability in a CSV export. Mirrors the
# fields required by requirement 8.2 (severity, title, description, project name,
# discovery date).
_CSV_COLUMNS = (
    "severity",
    "title",
    "description",
    "project_name",
    "discovered_at",
    "fact_id",
    "related_fact_ids",
    "evidence",
    "proof_packets",
)

# Severity levels in display order, used to render the summary section so the
# per-level counts always appear in a stable, most-severe-first order.
_SUMMARY_ORDER = ("critical", "high", "medium", "low")


def _query_filtered_vulnerabilities(
    severity: str | None,
    project_id: str | None,
    vulnerability_id: str | None = None,
    vulnerability_ids: list[str] | None = None,
    status: str | None = None,
) -> list[Vulnerability]:
    """Load vulnerabilities matching the active filters for export.

    This mirrors the filtering and ordering of :func:`list_vulnerabilities`
    (AND-combined ``severity`` / ``project_id`` filters, most-severe-first
    ordering) so an export reflects exactly what the user is viewing
    (requirement 8.1). It is a self-contained helper rather than a shared call
    into the list endpoint to keep that endpoint untouched.

    A ``project_id`` that does not exist yields a 404, consistent with the list
    endpoint; a valid filter that matches nothing yields an empty list, which
    the export layer renders as a summary-only file (requirement 8.5).
    """
    clauses: list[str] = []
    params: list[str] = []

    if severity is not None:
        clauses.append("v.severity = ?")
        params.append(severity)

    if project_id is not None:
        clauses.append("v.project_id = ?")
        params.append(project_id)

    if status is not None:
        clauses.append("COALESCE(v.status, 'confirmed') = ?")
        params.append(status)

    where_sql = ""
    if clauses:
        where_sql = "WHERE " + " AND ".join(clauses)

    with get_conn() as conn:
        if project_id is not None:
            exists = conn.execute(
                "SELECT 1 FROM projects WHERE id = ?", (project_id,)
            ).fetchone()
            if exists is None:
                raise HTTPException(status_code=404, detail="Project not found")

        rows = conn.execute(_vulnerability_select(where_sql), params).fetchall()

    vulnerabilities = _merge_vulnerabilities([_row_to_vulnerability(row) for row in rows])
    if vulnerability_id is not None:
        vulnerabilities = [v for v in vulnerabilities if v.id == vulnerability_id]
        if not vulnerabilities:
            raise HTTPException(status_code=404, detail="Vulnerability not found")
    if vulnerability_ids is not None:
        wanted = set(vulnerability_ids)
        vulnerabilities = [v for v in vulnerabilities if v.id in wanted]
        if not vulnerabilities:
            raise HTTPException(status_code=404, detail="Vulnerabilities not found")
    return vulnerabilities


def _summarize(vulnerabilities: list[Vulnerability]) -> dict[str, int]:
    """Compute per-severity counts over an already-filtered result set.

    Counting the filtered rows (rather than re-querying the whole table)
    guarantees the summary totals sum to the number of exported vulnerabilities
    (requirement 8.3). When the list is empty every count is zero, producing the
    summary-only export of requirement 8.5.
    """
    counts = {level: 0 for level in _SUMMARY_ORDER}
    for vuln in vulnerabilities:
        if vuln.severity in counts:
            counts[vuln.severity] += 1
    return counts


def _render_json_export(vulnerabilities: list[Vulnerability]) -> str:
    """Render the JSON export body.

    The summary counts are placed in a top-level ``summary`` object and the
    findings (each carrying severity, description and project name, among the
    full set of fields) in a ``vulnerabilities`` array (requirements 8.1, 8.3).
    """
    payload = {
        "summary": _summarize(vulnerabilities),
        "vulnerabilities": [vuln.model_dump() for vuln in vulnerabilities],
    }
    return json.dumps(payload, indent=2, ensure_ascii=False)


def _csv_cell(value) -> str:
    if isinstance(value, (list, dict)):
        return json.dumps(value, ensure_ascii=False)
    return str(value or "")


def _render_csv_export(vulnerabilities: list[Vulnerability]) -> str:
    """Render the CSV export body.

    A summary section (per-severity counts) is written as header rows that
    precede the data rows (requirement 8.3), followed by a blank separator row,
    the column header, and one row per vulnerability with the severity, title,
    description, project name and discovery date columns (requirement 8.2).
    With zero vulnerabilities only the summary section and column header are
    emitted (requirement 8.5).
    """
    counts = _summarize(vulnerabilities)

    buffer = io.StringIO()
    writer = csv.writer(buffer)

    # Summary section as leading header rows.
    writer.writerow(["summary"])
    writer.writerow(["severity", "count"])
    for level in _SUMMARY_ORDER:
        writer.writerow([level, counts[level]])

    # Blank separator row between the summary section and the data table.
    writer.writerow([])

    # Data table: column header followed by one row per vulnerability.
    writer.writerow(list(_CSV_COLUMNS))
    for vuln in vulnerabilities:
        writer.writerow([_csv_cell(getattr(vuln, column)) for column in _CSV_COLUMNS])

    return buffer.getvalue()


def _md_escape(text: str) -> str:
    return str(text or "").replace("|", "\\|")


def _append_static_poc_lines(lines: list[str], poc: dict[str, object]) -> None:
    environment_setup = _poc_list(poc, "environment_setup")
    if environment_setup:
        lines.extend(["环境准备：", ""])
        for step_index, step in enumerate(environment_setup, start=1):
            lines.append(f"{step_index}. {step}")
        lines.append("")
    payload = _poc_text(poc, "payload")
    if payload:
        lines.extend(["Payload：", "", "```text", payload, "```", ""])
    steps = _poc_list(poc, "steps")
    if steps:
        lines.extend(["复现步骤：", ""])
        for step_index, step in enumerate(steps, start=1):
            lines.append(f"{step_index}. {step}")
        lines.append("")
    request_template = (
        _poc_text(poc, "request_template")
        or _poc_text(poc, "curl")
        or _poc_text(poc, "command")
    )
    if request_template:
        lines.extend(["请求/命令模板：", "", "```bash", request_template, "```", ""])
    expected_result = _poc_text(poc, "expected_result") or _poc_text(poc, "expected_response")
    if expected_result:
        lines.extend(["预期结果：", "", expected_result, ""])
    verification = _poc_text(poc, "verification")
    if verification:
        lines.extend(["判断标准：", "", verification, ""])
    fixed_result = _poc_text(poc, "fixed_result") or _poc_text(
        poc, "remediated_expected_result"
    )
    if fixed_result:
        lines.extend(["修复后验收标准：", "", fixed_result, ""])
    prerequisites = _poc_list(poc, "prerequisites")
    if prerequisites:
        lines.extend(["利用前提：", ""])
        for item in prerequisites:
            lines.append(f"- {item}")
        lines.append("")
    limitations = _poc_list(poc, "limitations")
    if limitations:
        lines.extend(["限制与说明：", ""])
        for item in limitations:
            lines.append(f"- {item}")
        lines.append("")
    cleanup_steps = _poc_list(poc, "cleanup_steps")
    if cleanup_steps:
        lines.extend(["复测后清理：", ""])
        for step_index, step in enumerate(cleanup_steps, start=1):
            lines.append(f"{step_index}. {step}")
        lines.append("")


def _append_report_enrichment_packet_templates(
    lines: list[str], report_enrichments: list[dict[str, object]]
) -> None:
    packet_items: list[tuple[str, dict[str, str]]] = []
    for enrichment in report_enrichments:
        finding_id = str(enrichment.get("finding_id") or "")
        for packet in enrichment.get("packet_templates") or []:
            if isinstance(packet, dict):
                packet_items.append((finding_id, packet))
    if not packet_items:
        return

    lines.extend(["#### 静态推测验证请求", "", f"> {_REPORT_ENRICHMENT_PACKET_NOTE}", ""])
    for packet_index, (finding_id, packet) in enumerate(packet_items, start=1):
        title = packet.get("title") or "静态推测验证请求"
        lines.extend([f"**静态请求 {packet_index}：{title}**", ""])
        if finding_id:
            lines.extend([f"来源 finding：`{_md_escape(finding_id)}`", ""])
        payload = str(packet.get("payload") or "").strip()
        if payload:
            lines.extend(["Payload：", "", "```text", payload, "```", ""])
        request = str(packet.get("request") or "").strip()
        if request:
            lines.extend(["请求模板：", "", "```http", request, "```", ""])
        expected_result = str(packet.get("expected_result") or "").strip()
        if expected_result:
            lines.extend(["预期结果：", "", expected_result, ""])
        verification = str(packet.get("verification") or "").strip()
        if verification:
            lines.extend(["判断标准：", "", verification, ""])
        note = str(packet.get("note") or "").strip()
        if note:
            lines.extend(["说明：", "", note, ""])


def _append_report_enrichment_pocs(
    lines: list[str], report_enrichments: list[dict[str, object]]
) -> None:
    poc_items = [
        (str(enrichment.get("finding_id") or ""), enrichment.get("reproduction_poc"))
        for enrichment in report_enrichments
        if isinstance(enrichment.get("reproduction_poc"), dict) and enrichment.get("reproduction_poc")
    ]
    if not poc_items:
        return

    lines.extend(["#### 报告补充静态 PoC", "", f"> {_REPORT_ENRICHMENT_POC_NOTE}", ""])
    for poc_index, (finding_id, poc) in enumerate(poc_items, start=1):
        if len(poc_items) > 1:
            lines.extend([f"**补充 PoC {poc_index}**", ""])
        if finding_id:
            lines.extend([f"来源 finding：`{_md_escape(finding_id)}`", ""])
        _append_static_poc_lines(lines, poc)


def _append_report_enrichment_notes(
    lines: list[str], report_enrichments: list[dict[str, object]]
) -> None:
    if not any(
        enrichment.get("evidence_chain")
        or enrichment.get("report_sections")
        or enrichment.get("delivery_notes")
        for enrichment in report_enrichments
    ):
        return
    lines.extend(["#### 报告补充说明", ""])
    for enrichment in report_enrichments:
        finding_id = str(enrichment.get("finding_id") or "")
        if len(report_enrichments) > 1 and finding_id:
            lines.extend([f"**来源 finding：`{_md_escape(finding_id)}`**", ""])
        evidence_chain = enrichment.get("evidence_chain") or []
        if evidence_chain:
            lines.extend(["证据链：", ""])
            for item in evidence_chain:
                lines.append(f"- {item}")
            lines.append("")
        report_sections = enrichment.get("report_sections") or {}
        if isinstance(report_sections, dict) and report_sections:
            lines.extend(["报告正文补充：", ""])
            for key, value in report_sections.items():
                title = str(key).strip()
                if not title:
                    continue
                lines.append(f"**{title}**")
                if isinstance(value, list):
                    for item in value:
                        lines.append(f"- {item}")
                else:
                    lines.append(str(value))
                lines.append("")
        delivery_notes = enrichment.get("delivery_notes") or []
        if delivery_notes:
            lines.extend(["交付说明：", ""])
            for item in delivery_notes:
                lines.append(f"- {item}")
            lines.append("")


def _render_markdown_export(vulnerabilities: list[Vulnerability]) -> str:
    """Render a penetration-test style Markdown report.

    Markdown is the most faithful lightweight format for this product report:
    tables stay readable, request/response proof packets fit naturally in
    fenced code blocks, and users can convert the file to PDF/Word later with a
    dedicated renderer.
    """
    counts = _summarize(vulnerabilities)
    report_enrichments = _load_report_enrichments(vulnerabilities)
    audit_details = _load_audit_finding_report_details(vulnerabilities)
    delivery_quality = _delivery_quality(vulnerabilities, report_enrichments)
    coverage = _load_delivery_coverage(vulnerabilities)
    source_inventory = _source_inventory(vulnerabilities)
    report_id = _delivery_report_id(vulnerabilities)
    project_count = len(_unique([v.project_id for v in vulnerabilities]))
    severity_scope = "、".join(
        _SEVERITY_LABELS.get(level, level)
        for level in _SUMMARY_ORDER
        if counts[level] > 0
    ) or "无漏洞"
    lines: list[str] = [
        f"# {_report_title(vulnerabilities)}",
        "",
        "> Rabbit Code Audit 自动生成的代码审计交付报告。报告仅包含系统已确认的发现，"
        "并区分静态源码证据与真实动态证明材料。",
        "",
        f"**报告编号：`{report_id}`　版本：`1.0`　生成时间："
        f"`{datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M:%S UTC')}`**",
        "",
        "## 目录",
        "",
        "- [执行摘要](#执行摘要)",
        "- [审计范围与方法](#审计范围与方法)",
        "- [报告概览](#报告概览)",
        "- [交付质量与剩余风险](#交付质量与剩余风险)",
        "- [漏洞清单](#漏洞清单)",
        "- [修复建议汇总](#修复建议汇总)",
    ]
    for project_id, project_name, _items in _project_groups(vulnerabilities):
        anchor = f"项目{project_name}{project_id}".lower()
        lines.append(f"- [项目：{project_name}（{project_id}）](#{anchor})")
    lines.extend(
        [
            "",
            "---",
            "",
        "## 执行摘要",
        "",
        f"本报告共记录 **{len(vulnerabilities)}** 项已确认代码安全发现，"
        f"其中严重 {counts['critical']} 项、高危 {counts['high']} 项、"
        f"中危 {counts['medium']} 项、低危 {counts['low']} 项。",
        "",
        "交付结论基于源码索引、业务图、数据流审计、自动复核和已保存证据形成。"
        "未标记为真实响应的请求、PoC 和预期结果均属于源码静态推导，"
        "复测人员应在授权测试环境执行本报告中的步骤并记录实际结果。",
        "",
        "## 审计范围与方法",
        "",
        f"- **报告生成时间**：{datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M:%S UTC')}",
        f"- **项目范围**：{project_count} 个项目",
        "- **审计方法**：源码静态索引、入口与调用关系分析、业务图建模、"
        "候选数据流验证、自动独立 Worker 复核、报告证据补全",
        "- **证据口径**：L3 表示源码证据和静态 PoC 已闭环；L5 仅用于真实动态验证或等价实测证据",
        "- **范围限制**：未提供的运行配置、生产网关策略、外部依赖、账号权限和真实数据不在静态结论覆盖范围内",
        "- **复测要求**：仅在取得授权的隔离测试环境执行，先备份数据并准备可回滚账号",
        "",
        "### 源码版本与完整性",
        "",
        "| 项目 | 快照 | Git Commit / Ref | 快照 SHA-256 | 文件数 |",
        "| --- | --- | --- | --- | ---: |",
        *[
            f"| {_md_escape(str(item['project_name']))} | `{item['snapshot_id']}` | "
            f"`{_md_escape(str(item.get('resolved_commit') or item.get('requested_ref') or 'ZIP'))}` | "
            f"`{_md_escape(str(item.get('snapshot_sha256') or item.get('archive_sha256') or '未记录'))}` | "
            f"{item.get('file_count') or 0} |"
            for item in source_inventory
        ],
        "",
        "## 交付质量与剩余风险",
        "",
        "| 质量指标 | 数量 |",
        "| --- | ---: |",
        f"| 可按静态 PoC 复测的漏洞 | {delivery_quality['retestable']} / {delivery_quality['total']} |",
        f"| 含真实动态证明数据包 | {delivery_quality['dynamic_proof']} |",
        f"| 缺少完整复测材料 | {delivery_quality['missing_retest']} |",
        f"| 未闭合严重/高危/未知候选 | {coverage['open_required_candidates']} |",
        f"| 未覆盖高风险业务节点 | {coverage['open_high_risk_business_nodes']} |",
        f"| 待自动复核 Finding | {coverage['pending_review_findings']} |",
        f"| 待报告补全任务 | {coverage['pending_report_tasks']} |",
        "",
        (
            "**交付状态：可作为已确认漏洞的复测交付件。**"
            if delivery_quality["missing_retest"] == 0
            else "**交付状态：部分漏洞缺少完整复测材料，报告中已逐项标记。**"
        ),
        "",
        (
            "> 注意：当前仍存在未闭合候选或业务覆盖缺口，本报告不应表述为全量审计终稿。"
            if coverage["open_required_candidates"]
            or coverage["open_high_risk_business_nodes"]
            or coverage["pending_review_findings"]
            else "> 当前数据库中未发现阻止全量审计结论的高风险覆盖缺口。"
        ),
        "",
        "---",
        "",
        "## 报告概览",
        "",
        "**摘要页**",
        "",
        "| 指标 | 数量 |",
        "| --- | ---: |",
        f"| 项目数 | {project_count} |",
        f"| 漏洞总数 | {len(vulnerabilities)} |",
        f"| 严重 | {counts['critical']} |",
        f"| 高危 | {counts['high']} |",
        f"| 中危 | {counts['medium']} |",
        f"| 低危 | {counts['low']} |",
        "",
        f"本次导出范围覆盖 {project_count} 个项目，风险级别范围为：{severity_scope}。",
        "",
        ]
    )
    if not vulnerabilities:
        lines.extend(["当前范围内没有漏洞。", ""])
        return "\n".join(lines)

    lines.extend(
        [
            "---",
            "",
            "## 漏洞清单",
            "",
            "| ID | 漏洞名称 | 项目 | 严重程度 | 确认事实 | 发现时间 |",
            "| --- | --- | --- | --- | --- | --- |",
        ]
    )
    for index, vuln in enumerate(vulnerabilities, start=1):
        lines.append(
            f"| H-{index:02d} | {_md_escape(vuln.title)} | "
            f"{_md_escape(vuln.project_name)} (`{_md_escape(vuln.project_id)}`) | "
            f"{_SEVERITY_LABELS.get(vuln.severity, vuln.severity)} | "
            f"`{_md_escape(vuln.fact_id)}` | {_md_escape(vuln.discovered_at)} |"
        )
    lines.append("")

    lines.extend(["---", "", "## 修复建议汇总", ""])
    for index, vuln in enumerate(vulnerabilities, start=1):
        detail = _audit_detail_for_vulnerability(vuln, audit_details)
        location = str(detail.get("file_path") or "").strip()
        if location and detail.get("line_start"):
            location = f"{location}:{detail['line_start']}"
        cwe = str(detail.get("cwe") or "").strip()
        lines.extend(
            [
                f"{index}. **{vuln.title}**",
                f"   - 严重程度：{_SEVERITY_LABELS.get(vuln.severity, vuln.severity)}",
                f"   - 项目：{vuln.project_name}（`{vuln.project_id}`）",
                f"   - 位置：{_md_escape(location or '未记录')}",
                f"   - CWE：{_md_escape(cwe or '未记录')}",
                f"   - 建议：{_md_escape(_remediation_text(vuln, detail))}",
                "",
            ]
        )

    for project_id, project_name, items in _project_groups(vulnerabilities):
        lines.extend(["---", "", f"## 项目：{project_name}（`{project_id}`）", ""])
        for index, vuln in enumerate(items, start=1):
            vuln_report_enrichments = _report_enrichments_for_vulnerability(vuln, report_enrichments)
            audit_detail = _audit_detail_for_vulnerability(vuln, audit_details)
            lines.extend(
                [
                    f"### {index}. {vuln.title}",
                    "",
                    f"> 风险级别：**{_SEVERITY_LABELS.get(vuln.severity, vuln.severity)}**；确认事实：`{_md_escape(vuln.fact_id)}`。",
                    "",
                    "| 字段 | 内容 |",
                    "| --- | --- |",
                    f"| 严重程度 | {_SEVERITY_LABELS.get(vuln.severity, vuln.severity)} |",
                    f"| 确认事实 | `{_md_escape(vuln.fact_id)}` |",
                    f"| 关联事实 | {_md_escape(', '.join(vuln.related_fact_ids or [vuln.fact_id]))} |",
                    f"| 来源意图 | {_md_escape(vuln.source_intent_id or '未记录')} |",
                    f"| 工作节点 | {_md_escape(vuln.source_worker or '未记录')} |",
                    f"| 发现时间 | {_md_escape(vuln.discovered_at)} |",
                    f"| Finding ID | `{_md_escape(str(audit_detail.get('id') or vuln.fact_id))}` |",
                    f"| 漏洞分类 | {_md_escape(str(audit_detail.get('category') or '未记录'))} |",
                    f"| CWE | {_md_escape(str(audit_detail.get('cwe') or '未记录'))} |",
                    f"| OWASP Top 10 | {_md_escape(_owasp_category(audit_detail.get('cwe')))} |",
                    "| CVSS v3.1 | 未定向评分；需结合部署环境、权限前提和实际影响确定向量 |",
                    f"| 证据等级 | {_md_escape(str(audit_detail.get('evidence_level') or '未记录'))} |",
                    f"| 证据 SHA-256 | `{_evidence_sha256(vuln, audit_detail)}` |",
                    f"| 自动复核节点 | {_md_escape(str(audit_detail.get('reviewed_by') or '未记录'))} |",
                    f"| 入口 | {_md_escape(str(audit_detail.get('entry_point') or '未记录'))} |",
                    f"| 源码位置 | {_md_escape(_finding_location(audit_detail))} |",
                    "",
                    "#### 漏洞描述",
                    "",
                    vuln.description or "未记录",
                    "",
                    "#### 关键证据",
                    "",
                ]
            )
            for evidence in vuln.evidence or ["未记录"]:
                lines.append(f"- {evidence}")
            lines.append("")

            detail_evidence = str(audit_detail.get("evidence") or "").strip()
            if detail_evidence and detail_evidence not in (vuln.evidence or []):
                lines.extend(["源码闭环证据：", "", f"- {detail_evidence}", ""])

            lines.extend(
                [
                    "#### 风险影响",
                    "",
                    str(audit_detail.get("impact") or "未单独记录影响说明；请结合漏洞描述和受影响入口评估。"),
                    "",
                    "#### 修复建议",
                    "",
                    _remediation_text(vuln, audit_detail),
                    "",
                    "#### 修复验收标准",
                    "",
                ]
            )
            for criterion in _fixed_acceptance_criteria(vuln, audit_detail):
                lines.append(f"- {criterion}")
            lines.append("")

            lines.extend(["#### 漏洞证明数据包", ""])
            packets = vuln.proof_packets or []
            if not packets:
                lines.extend([_MISSING_PROOF_MESSAGE, ""])
            for packet_index, packet in enumerate(packets, start=1):
                lines.extend(
                    [
                        f"**证明 {packet_index}：{packet.get('title') or '漏洞证明'}**",
                        "",
                        "Payload：",
                        "",
                        "```text",
                        str(packet.get("payload") or "未记录"),
                        "```",
                        "",
                        "请求数据包：",
                        "",
                        "```http",
                        str(packet.get("request") or "未记录"),
                        "```",
                        "",
                        "响应/回显：",
                        "",
                        "```text",
                        str(packet.get("response") or "未记录"),
                        "```",
                    ]
                )
                if packet.get("note"):
                    lines.extend(["", f"说明：{packet['note']}"])
                lines.append("")

            _append_report_enrichment_packet_templates(lines, vuln_report_enrichments)

            lines.extend(["#### 复测操作手册", "", "##### 静态复现 PoC", ""])
            poc = vuln.reproduction_poc or {}
            if poc:
                lines.extend([f"> {_STATIC_POC_NOTE}", ""])
                _append_static_poc_lines(lines, poc)
            else:
                if vuln_report_enrichments:
                    lines.extend(["确认记录未写入静态复现 PoC。", ""])
                else:
                    lines.extend(["未记录静态复现 PoC。", ""])

            _append_report_enrichment_pocs(lines, vuln_report_enrichments)
            _append_report_enrichment_notes(lines, vuln_report_enrichments)

            lines.extend(
                [
                    "#### 复测记录模板",
                    "",
                    "- 复测环境：`________________`",
                    "- 复测时间：`________________`",
                    "- 执行人员：`________________`",
                    "- 实际请求/命令：`________________`",
                    "- 实际响应/结果：`________________`",
                    "- 结论：`[ ] 已修复  [ ] 未修复  [ ] 条件不足`",
                    "- 附件/抓包编号：`________________`",
                    "",
                ]
            )

            lines.extend(["#### 漏洞浮现过程", ""])
            for step_index, step in enumerate(vuln.process or [], start=1):
                label = step.get("label") or step.get("type") or "过程"
                step_id = step.get("id") or ""
                worker = f"；节点：{step.get('worker')}" if step.get("worker") else ""
                time = f"；时间：{step.get('time')}" if step.get("time") else ""
                lines.append(
                    f"{step_index}. **{label} `{step_id}`**{worker}{time}："
                    f"{step.get('description') or '无描述'}"
                )
            lines.append("")
    return "\n".join(lines).rstrip() + "\n"


_SEVERITY_LABELS = {
    "critical": "严重",
    "high": "高危",
    "medium": "中危",
    "low": "低危",
}


def _report_title(vulnerabilities: list[Vulnerability]) -> str:
    if len(vulnerabilities) == 1:
        return f"{vulnerabilities[0].project_name} - 单项代码审计报告"
    projects = _unique([v.project_name for v in vulnerabilities])
    if len(projects) == 1:
        return f"{projects[0]} - 代码审计报告"
    return "Rabbit Code Audit 代码审计报告"


def _delivery_report_id(vulnerabilities: list[Vulnerability]) -> str:
    payload = "\0".join(
        sorted(
            f"{vuln.project_id}:{vuln.fact_id}:{vuln.discovered_at}"
            for vuln in vulnerabilities
        )
    )
    digest = hashlib.sha256(payload.encode("utf-8")).hexdigest()[:12].upper()
    return f"RCA-{digest}"


def _source_inventory(vulnerabilities: list[Vulnerability]) -> list[dict[str, object]]:
    project_ids = _unique([item.project_id for item in vulnerabilities])
    if not project_ids:
        return []
    placeholders = ",".join("?" for _ in project_ids)
    with get_conn() as conn:
        rows = conn.execute(
            f"""
            SELECT s.project_id, p.title AS project_name, s.id AS snapshot_id,
                   s.source_type, s.original_name, s.repository_url,
                   s.requested_ref, s.resolved_commit, s.archive_sha256,
                   s.snapshot_sha256, s.file_count, s.total_bytes, s.created_at
            FROM source_snapshots s
            JOIN projects p ON p.id = s.project_id
            WHERE s.project_id IN ({placeholders}) AND s.status = 'ready'
              AND s.created_at = (
                  SELECT MAX(s2.created_at) FROM source_snapshots s2
                  WHERE s2.project_id = s.project_id AND s2.status = 'ready'
              )
            ORDER BY s.project_id
            """,
            project_ids,
        ).fetchall()
    return [dict(row) for row in rows]


def _owasp_category(cwe: object) -> str:
    value = str(cwe or "").upper()
    number_match = re.search(r"CWE-(\d+)", value)
    number = int(number_match.group(1)) if number_match else None
    groups = {
        "A01:2021 访问控制失效": {22, 23, 35, 200, 201, 284, 285, 352, 639, 862, 863},
        "A02:2021 加密机制失效": {259, 295, 319, 321, 326, 327, 328, 330},
        "A03:2021 注入": {74, 77, 78, 79, 89, 90, 91, 94, 917},
        "A05:2021 安全配置错误": {16, 209, 548, 611},
        "A07:2021 身份识别和身份验证失败": {287, 288, 307, 384, 798},
        "A08:2021 软件和数据完整性失效": {345, 353, 494, 502, 829},
        "A09:2021 安全日志和监控失效": {117, 223, 532, 778},
        "A10:2021 服务端请求伪造": {918},
    }
    for label, numbers in groups.items():
        if number in numbers:
            return label
    return "需结合业务场景映射"


def _evidence_sha256(vuln: Vulnerability, detail: dict[str, object]) -> str:
    payload = {
        "finding_id": detail.get("id") or vuln.fact_id,
        "title": vuln.title,
        "evidence": vuln.evidence,
        "proof_packets": vuln.proof_packets,
        "reproduction_poc": vuln.reproduction_poc,
        "location": _finding_location(detail),
    }
    encoded = json.dumps(payload, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


def _delivery_quality(
    vulnerabilities: list[Vulnerability],
    report_enrichments: dict[str, dict[str, object]],
) -> dict[str, int]:
    retestable = 0
    dynamic_proof = 0
    for vuln in vulnerabilities:
        if any(_is_complete_proof_packet(packet) for packet in (vuln.proof_packets or [])):
            dynamic_proof += 1
        pocs = [vuln.reproduction_poc]
        pocs.extend(
            enrichment.get("reproduction_poc")
            for enrichment in _report_enrichments_for_vulnerability(
                vuln, report_enrichments
            )
        )
        if any(
            isinstance(poc, dict) and _is_complete_reproduction_poc(poc)
            for poc in pocs
        ):
            retestable += 1
    return {
        "total": len(vulnerabilities),
        "retestable": retestable,
        "missing_retest": max(0, len(vulnerabilities) - retestable),
        "dynamic_proof": dynamic_proof,
    }


def _load_delivery_coverage(
    vulnerabilities: list[Vulnerability],
) -> dict[str, int]:
    project_ids = _unique([vuln.project_id for vuln in vulnerabilities])
    empty = {
        "open_required_candidates": 0,
        "open_high_risk_business_nodes": 0,
        "pending_review_findings": 0,
        "pending_report_tasks": 0,
    }
    if not project_ids:
        return empty
    placeholders = ",".join("?" for _ in project_ids)
    with get_conn() as conn:
        open_candidates = conn.execute(
            f"""
            SELECT COUNT(*) AS count
            FROM audit_candidates
            WHERE project_id IN ({placeholders})
              AND severity IN ('critical', 'high', 'unknown')
              AND status IN ('candidate', 'investigating', 'needs_more_evidence')
              AND NOT (
                  source = 'index'
                  AND candidate_type IN ('entrypoint', 'web_entrypoint')
              )
            """,
            project_ids,
        ).fetchone()["count"]
        open_nodes = conn.execute(
            f"""
            SELECT COUNT(*) AS count
            FROM business_nodes
            WHERE project_id IN ({placeholders})
              AND graph_layer != 'evidence'
              AND risk_level IN ('critical', 'high', 'unknown')
              AND review_status != 'covered'
            """,
            project_ids,
        ).fetchone()["count"]
        pending_findings = conn.execute(
            f"""
            SELECT COUNT(*) AS count
            FROM audit_findings
            WHERE project_id IN ({placeholders})
              AND status = 'pending_review'
            """,
            project_ids,
        ).fetchone()["count"]
        pending_reports = conn.execute(
            f"""
            SELECT COUNT(*) AS count
            FROM report_enrichment_tasks
            WHERE project_id IN ({placeholders})
              AND status IN ('pending', 'running')
            """,
            project_ids,
        ).fetchone()["count"]
    return {
        "open_required_candidates": int(open_candidates),
        "open_high_risk_business_nodes": int(open_nodes),
        "pending_review_findings": int(pending_findings),
        "pending_report_tasks": int(pending_reports),
    }


def _project_groups(vulnerabilities: list[Vulnerability]) -> list[tuple[str, str, list[Vulnerability]]]:
    groups: dict[str, tuple[str, list[Vulnerability]]] = {}
    for vuln in vulnerabilities:
        title, items = groups.setdefault(vuln.project_id, (vuln.project_name, []))
        items.append(vuln)
    return [(project_id, title, items) for project_id, (title, items) in groups.items()]


def _export_filename(vulnerabilities: list[Vulnerability], extension: str) -> str:
    if len(vulnerabilities) == 1:
        base = f"{vulnerabilities[0].project_id}-{vulnerabilities[0].fact_id}"
    else:
        projects = _unique([v.project_id for v in vulnerabilities])
        base = projects[0] if len(projects) == 1 else "vulnerabilities"
    safe = re.sub(r"[^A-Za-z0-9_.-]+", "-", base).strip("-") or "vulnerabilities"
    return f"{safe}.{extension}"


@router.patch("/{vulnerability_id}/status", response_model=Vulnerability)
def update_vulnerability_status(
    vulnerability_id: str, payload: VulnerabilityStatusUpdate
) -> Vulnerability:
    """Mark a merged vulnerability as confirmed or ignored.

    The UI shows merged report findings. Updating a merged finding therefore
    applies the requested review state to every raw fact row that contributed to
    that merged report item.
    """
    all_vulnerabilities = _query_filtered_vulnerabilities(None, None)
    target = next((vuln for vuln in all_vulnerabilities if vuln.id == vulnerability_id), None)
    if target is None:
        raise HTTPException(status_code=404, detail="Vulnerability not found")

    fact_ids = target.related_fact_ids or [target.fact_id]
    placeholders = ",".join("?" for _ in fact_ids)
    with get_conn() as conn:
        audit_finding = conn.execute(
            "SELECT id FROM audit_findings WHERE id = ?",
            (vulnerability_id,),
        ).fetchone()
        if audit_finding is not None and payload.status == "ignored":
            conn.execute(
                "UPDATE audit_findings SET status = 'rejected' WHERE id = ?",
                (vulnerability_id,),
            )
        conn.execute(
            f"""
            UPDATE vulnerabilities
            SET status = ?
            WHERE project_id = ? AND fact_id IN ({placeholders})
            """,
            [payload.status, target.project_id, *fact_ids],
        )

    status_label = "已忽略" if payload.status == "ignored" else "已确认"
    record_audit(
        "vulnerability.status",
        f"漏洞「{target.title}」标记为{status_label}",
        target_type="vulnerability",
        target_id=vulnerability_id,
    )
    return target.model_copy(update={"status": payload.status})


def _report_lines(vulnerabilities: list[Vulnerability]) -> list[str]:
    counts = _summarize(vulnerabilities)
    lines = [
        "Rabbit 代码审计报告",
        "",
        "报告概览",
        f"严重：{counts['critical']}  高危：{counts['high']}  中危：{counts['medium']}  低危：{counts['low']}",
        f"漏洞总数：{len(vulnerabilities)}",
        "",
    ]
    if not vulnerabilities:
        lines.append("当前筛选条件下没有漏洞。")
        return lines

    for index, vuln in enumerate(vulnerabilities, start=1):
        lines.extend(
            [
                f"{index}. {vuln.title}",
                f"严重程度：{_SEVERITY_LABELS.get(vuln.severity, vuln.severity)}",
                f"项目：{vuln.project_name}（{vuln.project_id}）",
                f"确认事实：{vuln.fact_id}",
                f"关联事实：{', '.join(vuln.related_fact_ids or [vuln.fact_id])}",
                f"发现时间：{vuln.discovered_at}",
                "漏洞描述：",
                vuln.description,
                "关键证据：",
            ]
        )
        for evidence in vuln.evidence or ["未记录"]:
            lines.append(f"- {evidence}")
        if vuln.proof_packets:
            lines.append("漏洞证明数据包：")
            for packet_index, packet in enumerate(vuln.proof_packets, start=1):
                lines.append(f"证明 {packet_index}：{packet.get('title') or '漏洞证明'}")
                lines.append("请求：")
                lines.extend(str(packet.get("request") or "未记录").splitlines())
                lines.append("响应/回显：")
                lines.extend(str(packet.get("response") or "未记录").splitlines())
                note = packet.get("note")
                if note:
                    lines.append(f"说明：{note}")
        else:
            lines.extend(["漏洞证明数据包：", "未记录真实请求/响应数据包。"])
        if vuln.process:
            lines.append("漏洞浮现过程：")
            for step_index, step in enumerate(vuln.process, start=1):
                step_type = step.get("type", "过程")
                step_id = step.get("id", "")
                desc = step.get("description", "")
                lines.append(f"{step_index}. {step_type} {step_id}：{desc}")
        lines.append("")
    return lines


def _report_plain_lines(vulnerabilities: list[Vulnerability]) -> list[str]:
    counts = _summarize(vulnerabilities)
    audit_details = _load_audit_finding_report_details(vulnerabilities)
    report_enrichments = _load_report_enrichments(vulnerabilities)
    delivery_quality = _delivery_quality(vulnerabilities, report_enrichments)
    coverage = _load_delivery_coverage(vulnerabilities)
    source_inventory = _source_inventory(vulnerabilities)
    lines = [
        _report_title(vulnerabilities),
        f"报告编号：{_delivery_report_id(vulnerabilities)}  版本：1.0",
        "执行摘要",
        f"本报告记录 {len(vulnerabilities)} 项系统已确认代码安全发现。",
        "证据口径：静态 PoC 和预期结果来自源码推导；真实动态请求/响应会单独标记。",
        "审计方法：源码索引、业务图、数据流验证、自动复核和报告证据补全。",
        "复测要求：仅在授权隔离测试环境执行，先备份数据并准备回滚方案。",
        "交付质量与剩余风险",
        f"静态可复测：{delivery_quality['retestable']}/{delivery_quality['total']}  "
        f"动态证明：{delivery_quality['dynamic_proof']}  "
        f"缺少复测材料：{delivery_quality['missing_retest']}",
        f"未闭合高风险候选：{coverage['open_required_candidates']}  "
        f"未覆盖高风险业务节点：{coverage['open_high_risk_business_nodes']}  "
        f"待自动复核：{coverage['pending_review_findings']}",
        "",
        "报告概览",
        f"漏洞总数：{len(vulnerabilities)}",
        f"严重：{counts['critical']}    高危：{counts['high']}    中危：{counts['medium']}    低危：{counts['low']}",
        "",
        "源码版本与完整性",
        *[
            f"{item['project_name']} | 快照={item['snapshot_id']} | "
            f"Commit/Ref={item.get('resolved_commit') or item.get('requested_ref') or 'ZIP'} | "
            f"SHA-256={item.get('snapshot_sha256') or item.get('archive_sha256') or '未记录'} | "
            f"文件数={item.get('file_count') or 0}"
            for item in source_inventory
        ],
        "",
    ]
    if not vulnerabilities:
        return lines + ["当前范围内没有漏洞。"]

    lines.extend(["漏洞清单", "ID | 漏洞名称 | 项目 | 严重程度 | 确认事实", "-" * 72])
    for index, vuln in enumerate(vulnerabilities, start=1):
        lines.append(
            f"{index:02d} | {vuln.title} | {vuln.project_name}({vuln.project_id}) | "
            f"{_SEVERITY_LABELS.get(vuln.severity, vuln.severity)} | {vuln.fact_id}"
        )
    lines.append("")

    for project_id, project_name, items in _project_groups(vulnerabilities):
        lines.extend([f"项目：{project_name}（{project_id}）", "-" * 72])
        for index, vuln in enumerate(items, start=1):
            detail = _audit_detail_for_vulnerability(vuln, audit_details)
            enrichments = _report_enrichments_for_vulnerability(vuln, report_enrichments)
            lines.extend(
                [
                    f"{index}. {vuln.title}",
                    f"严重程度：{_SEVERITY_LABELS.get(vuln.severity, vuln.severity)}",
                    f"确认事实：{vuln.fact_id}",
                    f"关联事实：{', '.join(vuln.related_fact_ids or [vuln.fact_id])}",
                    f"发现时间：{vuln.discovered_at}",
                    f"漏洞分类：{detail.get('category') or '未记录'}",
                    f"CWE：{detail.get('cwe') or '未记录'}",
                    f"OWASP Top 10：{_owasp_category(detail.get('cwe'))}",
                    "CVSS v3.1：未定向评分；需结合部署环境、权限前提和实际影响确定向量",
                    f"证据等级：{detail.get('evidence_level') or '未记录'}",
                    f"证据 SHA-256：{_evidence_sha256(vuln, detail)}",
                    f"自动复核节点：{detail.get('reviewed_by') or '未记录'}",
                    f"入口：{detail.get('entry_point') or '未记录'}",
                    f"源码位置：{_finding_location(detail)}",
                    "漏洞描述：",
                    vuln.description,
                    "风险影响：",
                    str(detail.get("impact") or "未单独记录影响说明。"),
                    "关键证据：",
                ]
            )
            for evidence in vuln.evidence or ["未记录"]:
                lines.append(f"- {evidence}")
            lines.extend(["修复建议：", _remediation_text(vuln, detail), "修复验收标准："])
            lines.extend(f"- {item}" for item in _fixed_acceptance_criteria(vuln, detail))
            lines.append("漏洞证明数据包：")
            packets = vuln.proof_packets or []
            if not packets:
                lines.append("未记录真实请求/响应数据包。")
            for packet_index, packet in enumerate(packets, start=1):
                lines.extend(
                    [
                        f"证明 {packet_index}：{packet.get('title') or '漏洞证明'}",
                        "请求：",
                        str(packet.get("request") or "未记录"),
                        "响应/回显：",
                        str(packet.get("response") or "未记录"),
                    ]
                )
                if packet.get("note"):
                    lines.append(f"说明：{packet['note']}")
            lines.extend(_plain_retest_guide(vuln, enrichments))
            lines.extend(
                [
                    "复测记录模板：",
                    "环境=________ 时间=________ 执行人=________",
                    "结论=[ ]已修复 [ ]未修复 [ ]条件不足  附件编号=________",
                ]
            )
            lines.append("漏洞浮现过程：")
            for step_index, step in enumerate(vuln.process or [], start=1):
                lines.append(
                    f"{step_index}. {step.get('label') or step.get('type') or '过程'} "
                    f"{step.get('id') or ''}：{step.get('description') or '无描述'}"
                )
            lines.append("")
    return lines


def _plain_retest_guide(
    vuln: Vulnerability,
    report_enrichments: list[dict[str, object]],
) -> list[str]:
    pocs: list[dict[str, object]] = []
    if vuln.reproduction_poc:
        pocs.append(vuln.reproduction_poc)
    for enrichment in report_enrichments:
        poc = enrichment.get("reproduction_poc")
        if isinstance(poc, dict) and poc:
            pocs.append(poc)
    lines = ["复测操作手册："]
    if not pocs:
        return [*lines, "当前证据未形成可执行静态 PoC；请根据源码位置补充授权测试环境参数。"]
    for index, poc in enumerate(pocs, start=1):
        lines.append(f"复测方案 {index}：")
        for title, key in (
            ("环境准备", "environment_setup"),
            ("利用前提", "prerequisites"),
            ("执行步骤", "steps"),
        ):
            values = _poc_list(poc, key)
            if values:
                lines.append(f"{title}：")
                lines.extend(f"- {value}" for value in values)
        request_template = (
            _poc_text(poc, "request_template")
            or _poc_text(poc, "curl")
            or _poc_text(poc, "command")
        )
        if request_template:
            lines.extend(["请求/命令：", request_template])
        for title, keys in (
            ("漏洞存在时预期结果", ("expected_result", "expected_response")),
            ("修复后验收结果", ("fixed_result", "remediated_expected_result")),
            ("判断标准", ("verification",)),
        ):
            value = next((_poc_text(poc, key) for key in keys if _poc_text(poc, key)), "")
            if value:
                lines.extend([f"{title}：", value])
        cleanup = _poc_list(poc, "cleanup_steps")
        if cleanup:
            lines.append("复测后清理：")
            lines.extend(f"- {value}" for value in cleanup)
    return lines


_PDF_FONT_NAME = "RabbitNotoSansSC"
_PDF_FONT_PATH = (
    Path(__file__).resolve().parents[2]
    / "assets"
    / "fonts"
    / "NotoSansSC-Regular.ttf"
)


def _ensure_pdf_font() -> None:
    try:
        pdfmetrics.getFont(_PDF_FONT_NAME)
    except KeyError:
        if not _PDF_FONT_PATH.is_file():
            raise RuntimeError(f"Bundled PDF font is missing: {_PDF_FONT_PATH}")
        pdfmetrics.registerFont(TTFont(_PDF_FONT_NAME, str(_PDF_FONT_PATH)))


def _wrap_pdf_text(text: str, font_size: float, max_width: float) -> list[str]:
    """Wrap mixed Chinese and source text by rendered width, without truncation."""
    if not text:
        return [""]
    lines: list[str] = []
    current: list[str] = []
    current_width = 0.0
    for char in text:
        if char == "\n":
            lines.append("".join(current).rstrip())
            current = []
            current_width = 0.0
            continue
        char_width = pdfmetrics.stringWidth(char, _PDF_FONT_NAME, font_size)
        if current and current_width + char_width > max_width:
            lines.append("".join(current).rstrip())
            current = [] if char.isspace() else [char]
            current_width = 0.0 if char.isspace() else char_width
        else:
            current.append(char)
            current_width += char_width
    if current or not lines:
        lines.append("".join(current).rstrip())
    return lines


def _render_pdf_export(vulnerabilities: list[Vulnerability]) -> bytes:
    _ensure_pdf_font()
    buffer = io.BytesIO()
    report = canvas.Canvas(
        buffer,
        pagesize=A4,
        pageCompression=1,
        invariant=False,
    )
    report.setTitle(_report_title(vulnerabilities))
    report.setAuthor("Rabbit Code Audit")
    report.setSubject("代码安全审计交付报告")

    page_width, page_height = A4
    margin_x = 46
    content_width = page_width - margin_x * 2
    report_id = _delivery_report_id(vulnerabilities)
    generated_at = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")

    # Formal cover page.
    report.setFillColor(HexColor("#0F4C81"))
    report.rect(0, page_height - 76, page_width, 76, stroke=0, fill=1)
    report.setFillColor(HexColor("#0F172A"))
    report.setFont(_PDF_FONT_NAME, 24)
    report.drawString(margin_x, page_height - 190, _report_title(vulnerabilities))
    report.setFillColor(HexColor("#475569"))
    report.setFont(_PDF_FONT_NAME, 11)
    cover_lines = [
        f"报告编号：{report_id}",
        "报告版本：1.0",
        f"漏洞数量：{len(vulnerabilities)}",
        f"生成时间：{generated_at}",
        "生成系统：Rabbit Code Audit",
        "交付口径：静态推导与真实动态证据分开标记",
    ]
    cover_y = page_height - 250
    for line in cover_lines:
        report.drawString(margin_x, cover_y, line)
        cover_y -= 25
    report.setFillColor(HexColor("#64748B"))
    report.setFont(_PDF_FONT_NAME, 9)
    report.drawString(margin_x, 58, "仅限授权安全审计与复测使用")
    report.showPage()

    page_number = 2

    def draw_page_frame() -> float:
        report.setFillColor(HexColor("#0F4C81"))
        report.rect(0, page_height - 36, page_width, 36, stroke=0, fill=1)
        report.setFillColor(HexColor("#FFFFFF"))
        report.setFont(_PDF_FONT_NAME, 9)
        report.drawString(margin_x, page_height - 24, _report_title(vulnerabilities))
        report.setFillColor(HexColor("#64748B"))
        report.drawRightString(page_width - margin_x, 28, f"Rabbit Code Audit | {page_number}")
        return page_height - 62

    y = draw_page_frame()
    major_headings = {"执行摘要", "审计范围与方法", "报告概览", "漏洞清单"}
    report_lines = _report_plain_lines(vulnerabilities)
    if report_lines and report_lines[0] == _report_title(vulnerabilities):
        report_lines = report_lines[1:]

    for line in report_lines:
        is_major = line in major_headings or line.startswith("项目：")
        is_subheading = bool(line) and line.endswith("：") and len(line) <= 24
        font_size = 14 if is_major else (11 if is_subheading else 9.5)
        line_height = 20 if is_major else (16 if is_subheading else 13.5)
        before = 8 if is_major else (4 if is_subheading else 0)
        fragments = _wrap_pdf_text(line, font_size, content_width)
        required_height = before + line_height * max(1, len(fragments))
        if y - required_height < 48:
            report.showPage()
            page_number += 1
            y = draw_page_frame()
        y -= before
        report.setFillColor(HexColor("#0F4C81") if is_major else HexColor("#0F172A"))
        report.setFont(_PDF_FONT_NAME, font_size)
        for fragment in fragments:
            if fragment:
                report.drawString(margin_x, y, fragment)
            y -= line_height

    report.save()
    return buffer.getvalue()


_DOCX_FONT_XML = (
    '<w:rFonts w:ascii="Arial Unicode MS" w:hAnsi="Arial Unicode MS" '
    'w:eastAsia="Arial Unicode MS" w:cs="Arial Unicode MS"/>'
    '<w:lang w:val="zh-CN" w:eastAsia="zh-CN"/>'
)


def _docx_paragraph(text: str, style: str | None = None, color: str | None = None) -> str:
    style_xml = f'<w:pStyle w:val="{style}"/>' if style else ""
    color_xml = f'<w:color w:val="{color}"/>' if color else ""
    return (
        "<w:p>"
        f"<w:pPr>{style_xml}</w:pPr>"
        f"<w:r><w:rPr>{_DOCX_FONT_XML}{color_xml}</w:rPr>"
        f"<w:t xml:space=\"preserve\">{xml_escape(text)}</w:t></w:r>"
        "</w:p>"
    )


def _docx_table(
    rows: list[list[str]],
    header: bool = False,
    widths: list[int] | None = None,
) -> str:
    column_count = max((len(row) for row in rows), default=1)
    if widths is not None:
        if len(widths) != column_count or sum(widths) != 9360:
            raise ValueError("DOCX table widths must match the columns and total 9360 twips")
    elif column_count == 2:
        widths = [2500, 6860]
    else:
        base = 9360 // column_count
        widths = [base] * column_count
        widths[-1] += 9360 - sum(widths)
    grid = "".join(f'<w:gridCol w:w="{width}"/>' for width in widths)
    xml = [
        '<w:tbl><w:tblPr><w:tblStyle w:val="TableGrid"/>'
        '<w:tblW w:w="9360" w:type="dxa"/><w:tblLayout w:type="fixed"/>'
        '<w:tblInd w:w="120" w:type="dxa"/></w:tblPr>'
        f"<w:tblGrid>{grid}</w:tblGrid>"
    ]
    for row_index, row in enumerate(rows):
        repeat = "<w:tblHeader/>" if header and row_index == 0 else ""
        xml.append(f"<w:tr><w:trPr><w:cantSplit/>{repeat}</w:trPr>")
        for cell_index, cell in enumerate(row):
            shade = '<w:shd w:fill="F3F7FB"/>' if header and row_index == 0 else ""
            xml.append(
                f'<w:tc><w:tcPr><w:tcW w:w="{widths[cell_index]}" w:type="dxa"/><w:vAlign w:val="center"/>'
                + shade
                + f"</w:tcPr><w:p><w:r><w:rPr>{_DOCX_FONT_XML}</w:rPr>"
                + '<w:t xml:space="preserve">'
                + xml_escape(str(cell or ""))
                + "</w:t></w:r></w:p></w:tc>"
            )
        xml.append("</w:tr>")
    xml.append("</w:tbl>")
    return "".join(xml)


def _docx_pre_block(text: str) -> str:
    rows = [[line] for line in str(text or "未记录").splitlines() or ["未记录"]]
    return _docx_table(rows)


def _render_docx_export(vulnerabilities: list[Vulnerability]) -> bytes:
    counts = _summarize(vulnerabilities)
    audit_details = _load_audit_finding_report_details(vulnerabilities)
    report_enrichments = _load_report_enrichments(vulnerabilities)
    delivery_quality = _delivery_quality(vulnerabilities, report_enrichments)
    coverage = _load_delivery_coverage(vulnerabilities)
    source_inventory = _source_inventory(vulnerabilities)
    delivery_ready = not (
        delivery_quality["missing_retest"]
        or coverage["open_required_candidates"]
        or coverage["open_high_risk_business_nodes"]
        or coverage["pending_review_findings"]
        or coverage["pending_report_tasks"]
    )
    body: list[str] = [
        _docx_paragraph(_report_title(vulnerabilities), style="Title", color="0F172A"),
        _docx_paragraph(
            f"报告编号：{_delivery_report_id(vulnerabilities)}　版本：1.0　"
            f"生成时间：{datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M:%S UTC')}"
        ),
        _docx_paragraph("执行摘要", style="Heading1"),
        _docx_paragraph(
            f"本报告记录 {len(vulnerabilities)} 项系统已确认代码安全发现。"
            "静态 PoC 与预期结果来自源码推导，真实动态请求/响应会单独标记。"
        ),
        _docx_paragraph(f"交付状态：{'可交付' if delivery_ready else '有条件交付'}", style="Heading2"),
        _docx_paragraph("交付质量与剩余风险", style="Heading1"),
        _docx_table(
            [
                ["指标", "数量"],
                ["静态可复测", f"{delivery_quality['retestable']} / {delivery_quality['total']}"],
                ["真实动态证明", str(delivery_quality["dynamic_proof"])],
                ["缺少完整复测材料", str(delivery_quality["missing_retest"])],
                ["未闭合高风险候选", str(coverage["open_required_candidates"])],
                ["未覆盖高风险业务节点", str(coverage["open_high_risk_business_nodes"])],
                ["待自动复核 Finding", str(coverage["pending_review_findings"])],
            ],
            header=True,
        ),
        _docx_paragraph("审计范围与方法", style="Heading1"),
        _docx_paragraph(
            "采用源码索引、业务图、数据流验证、自动复核和报告证据补全。"
            "仅应在授权隔离测试环境执行复测，并提前准备数据备份和回滚方案。"
        ),
        _docx_paragraph("源码版本与完整性", style="Heading2"),
        _docx_table(
            [["项目 / 快照", "Commit / Ref", "SHA-256", "文件数"]]
            + [
                [
                    f"{item['project_name']}\n{item['snapshot_id']}",
                    str(item.get("resolved_commit") or item.get("requested_ref") or "ZIP"),
                    str(item.get("snapshot_sha256") or item.get("archive_sha256") or "未记录"),
                    str(item.get("file_count") or 0),
                ]
                for item in source_inventory
            ],
            header=True,
            widths=[2500, 1500, 4360, 1000],
        ) if source_inventory else _docx_paragraph("当前导出范围未记录 ready 源码快照。"),
        _docx_paragraph("报告概览", style="Heading1"),
        _docx_table(
            [
                ["总漏洞数", "严重", "高危", "中危", "低危"],
                [str(len(vulnerabilities)), str(counts["critical"]), str(counts["high"]), str(counts["medium"]), str(counts["low"])],
            ],
            header=True,
        ),
    ]
    if vulnerabilities:
        body.extend(
            [
                _docx_paragraph("漏洞清单", style="Heading1"),
                _docx_table(
                    [["ID", "漏洞名称 / 项目", "严重程度", "源码位置"]]
                    + [
                        [
                            f"H-{idx:02d}",
                            f"{v.title}\n{v.project_name} ({v.project_id})",
                            _SEVERITY_LABELS.get(v.severity, v.severity),
                            _finding_location(
                                _audit_detail_for_vulnerability(v, audit_details)
                            ),
                        ]
                        for idx, v in enumerate(vulnerabilities, start=1)
                    ],
                    header=True,
                    widths=[900, 3760, 1100, 3600],
                ),
            ]
        )
    for project_id, project_name, items in _project_groups(vulnerabilities):
        body.append(_docx_paragraph(f"项目：{project_name}（{project_id}）", style="Heading1"))
        for idx, vuln in enumerate(items, start=1):
            detail = _audit_detail_for_vulnerability(vuln, audit_details)
            enrichments = _report_enrichments_for_vulnerability(vuln, report_enrichments)
            body.extend(
                [
                    _docx_paragraph(f"{idx}. {vuln.title}", style="Heading2"),
                    _docx_table(
                        [
                            ["字段", "内容"],
                            ["严重程度", _SEVERITY_LABELS.get(vuln.severity, vuln.severity)],
                            ["确认事实", vuln.fact_id],
                            ["关联事实", ", ".join(vuln.related_fact_ids or [vuln.fact_id])],
                            ["发现时间", vuln.discovered_at],
                            ["工作节点", vuln.source_worker or "未记录"],
                            ["漏洞分类", str(detail.get("category") or "未记录")],
                            ["CWE", str(detail.get("cwe") or "未记录")],
                            ["OWASP Top 10", _owasp_category(detail.get("cwe"))],
                            ["CVSS v3.1", "未定向评分；需结合部署环境、权限前提和实际影响确定向量"],
                            ["证据等级", str(detail.get("evidence_level") or "未记录")],
                            ["证据 SHA-256", _evidence_sha256(vuln, detail)],
                            ["自动复核节点", str(detail.get("reviewed_by") or "未记录")],
                            ["入口", str(detail.get("entry_point") or "未记录")],
                            ["源码位置", _finding_location(detail)],
                        ],
                        header=True,
                    ),
                    _docx_paragraph("漏洞描述", style="Heading3"),
                    _docx_paragraph(vuln.description),
                    _docx_paragraph("关键证据", style="Heading3"),
                ]
            )
            body.append(_docx_table([["证据"]] + [[item] for item in (vuln.evidence or ["未记录"])], header=True))
            body.extend(
                [
                    _docx_paragraph("风险影响", style="Heading3"),
                    _docx_paragraph(str(detail.get("impact") or "未单独记录影响说明。")),
                    _docx_paragraph("修复建议", style="Heading3"),
                    _docx_paragraph(_remediation_text(vuln, detail)),
                    _docx_paragraph("修复验收标准", style="Heading3"),
                    _docx_table(
                        [["验收项"]]
                        + [[item] for item in _fixed_acceptance_criteria(vuln, detail)],
                        header=True,
                    ),
                ]
            )
            body.append(_docx_paragraph("漏洞证明数据包", style="Heading3"))
            packets = vuln.proof_packets or []
            if not packets:
                body.append(_docx_paragraph("未记录真实请求/响应数据包。"))
            for packet_index, packet in enumerate(packets, start=1):
                body.append(_docx_paragraph(f"证明 {packet_index}：{packet.get('title') or '漏洞证明'}", style="Heading4"))
                body.append(_docx_paragraph("请求数据包", style="Heading4"))
                body.append(_docx_pre_block(packet.get("request") or "未记录"))
                body.append(_docx_paragraph("响应/回显", style="Heading4"))
                body.append(_docx_pre_block(packet.get("response") or "未记录"))
                if packet.get("note"):
                    body.append(_docx_paragraph(f"说明：{packet['note']}"))
            body.append(_docx_paragraph("复测操作手册", style="Heading3"))
            for line in _plain_retest_guide(vuln, enrichments)[1:]:
                body.append(_docx_paragraph(line))
            body.extend(
                [
                    _docx_paragraph("复测记录模板", style="Heading3"),
                    _docx_table(
                        [
                            ["字段", "记录"],
                            ["复测环境", ""],
                            ["复测时间", ""],
                            ["执行人员", ""],
                            ["实际请求/命令", ""],
                            ["实际响应/结果", ""],
                            ["结论", "已修复 / 未修复 / 条件不足"],
                            ["附件/抓包编号", ""],
                        ],
                        header=True,
                    ),
                ]
            )
            body.append(_docx_paragraph("漏洞浮现过程", style="Heading3"))
            body.append(
                _docx_table(
                    [["步骤", "类型/ID", "说明"]]
                    + [
                        [
                            str(step_index),
                            f"{step.get('label') or step.get('type') or '过程'} {step.get('id') or ''}",
                            step.get("description") or "无描述",
                        ]
                        for step_index, step in enumerate(vuln.process or [], start=1)
                    ],
                    header=True,
                )
            )
    if not vulnerabilities:
        body.append(_docx_paragraph("当前范围内没有漏洞。"))
    document_xml = (
        '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
        '<w:document xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main" '
        'xmlns:r="http://schemas.openxmlformats.org/officeDocument/2006/relationships">'
        "<w:body>"
        + "".join(body)
        + '<w:sectPr><w:footerReference w:type="default" r:id="rId1"/>'
        '<w:pgSz w:w="11906" w:h="16838"/><w:pgMar w:top="1440" w:right="1440" w:bottom="1440" w:left="1440"/></w:sectPr>'
        "</w:body></w:document>"
    )
    styles_xml = (
        '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
        '<w:styles xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main">'
        '<w:docDefaults><w:rPrDefault><w:rPr>'
        + _DOCX_FONT_XML
        +
        '<w:sz w:val="21"/><w:szCs w:val="21"/></w:rPr></w:rPrDefault>'
        '<w:pPrDefault><w:pPr><w:spacing w:after="120" w:line="320" w:lineRule="auto"/></w:pPr></w:pPrDefault>'
        '</w:docDefaults>'
        '<w:style w:type="paragraph" w:default="1" w:styleId="Normal"><w:name w:val="Normal"/></w:style>'
        '<w:style w:type="paragraph" w:styleId="Title"><w:name w:val="Title"/>'
        '<w:rPr>' + _DOCX_FONT_XML + '<w:b/><w:sz w:val="40"/></w:rPr></w:style>'
        '<w:style w:type="paragraph" w:styleId="Heading1"><w:name w:val="Heading 1"/><w:pPr><w:spacing w:before="360" w:after="120"/></w:pPr><w:rPr>' + _DOCX_FONT_XML + '<w:b/><w:sz w:val="30"/><w:color w:val="0F4C81"/></w:rPr></w:style>'
        '<w:style w:type="paragraph" w:styleId="Heading2"><w:name w:val="Heading 2"/><w:pPr><w:spacing w:before="280" w:after="80"/></w:pPr><w:rPr>' + _DOCX_FONT_XML + '<w:b/><w:sz w:val="24"/></w:rPr></w:style>'
        '<w:style w:type="paragraph" w:styleId="Heading3"><w:name w:val="Heading 3"/><w:pPr><w:spacing w:before="220" w:after="80"/></w:pPr><w:rPr>' + _DOCX_FONT_XML + '<w:b/><w:sz w:val="21"/><w:color w:val="334155"/></w:rPr></w:style>'
        '<w:style w:type="paragraph" w:styleId="Heading4"><w:name w:val="Heading 4"/><w:pPr><w:spacing w:before="160" w:after="80"/></w:pPr><w:rPr>' + _DOCX_FONT_XML + '<w:b/><w:sz w:val="20"/></w:rPr></w:style>'
        '<w:style w:type="table" w:styleId="TableGrid"><w:name w:val="Table Grid"/><w:tblPr><w:tblBorders><w:top w:val="single" w:sz="4" w:color="D7DEE8"/><w:left w:val="single" w:sz="4" w:color="D7DEE8"/><w:bottom w:val="single" w:sz="4" w:color="D7DEE8"/><w:right w:val="single" w:sz="4" w:color="D7DEE8"/><w:insideH w:val="single" w:sz="4" w:color="D7DEE8"/><w:insideV w:val="single" w:sz="4" w:color="D7DEE8"/></w:tblBorders><w:tblCellMar><w:top w:w="120" w:type="dxa"/><w:left w:w="120" w:type="dxa"/><w:bottom w:w="120" w:type="dxa"/><w:right w:w="120" w:type="dxa"/></w:tblCellMar></w:tblPr></w:style>'
        "</w:styles>"
    )
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w", zipfile.ZIP_DEFLATED) as docx:
        docx.writestr(
            "[Content_Types].xml",
            '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
            '<Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types">'
            '<Default Extension="rels" ContentType="application/vnd.openxmlformats-package.relationships+xml"/>'
            '<Default Extension="xml" ContentType="application/xml"/>'
            '<Override PartName="/word/document.xml" ContentType="application/vnd.openxmlformats-officedocument.wordprocessingml.document.main+xml"/>'
            '<Override PartName="/word/styles.xml" ContentType="application/vnd.openxmlformats-officedocument.wordprocessingml.styles+xml"/>'
            '<Override PartName="/word/footer1.xml" ContentType="application/vnd.openxmlformats-officedocument.wordprocessingml.footer+xml"/>'
            "</Types>",
        )
        docx.writestr(
            "_rels/.rels",
            '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
            '<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">'
            '<Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/officeDocument" Target="word/document.xml"/>'
            "</Relationships>",
        )
        docx.writestr("word/document.xml", document_xml)
        docx.writestr("word/styles.xml", styles_xml)
        docx.writestr(
            "word/_rels/document.xml.rels",
            '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
            '<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">'
            '<Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/footer" Target="footer1.xml"/>'
            "</Relationships>",
        )
        docx.writestr(
            "word/footer1.xml",
            '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
            '<w:ftr xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main">'
            '<w:p><w:pPr><w:jc w:val="center"/></w:pPr><w:r><w:t>Rabbit Code Audit | </w:t></w:r>'
            '<w:fldSimple w:instr="PAGE"><w:r><w:t>1</w:t></w:r></w:fldSimple></w:p></w:ftr>',
        )
    return buffer.getvalue()


def _render_delivery_bundle(vulnerabilities: list[Vulnerability]) -> bytes:
    generated_at = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    report_id = _delivery_report_id(vulnerabilities)
    report_enrichments = _load_report_enrichments(vulnerabilities)
    delivery_quality = _delivery_quality(vulnerabilities, report_enrichments)
    coverage = _load_delivery_coverage(vulnerabilities)
    source_inventory = _source_inventory(vulnerabilities)
    project_ids = _unique([item.project_id for item in vulnerabilities])
    project_names = _unique([item.project_name for item in vulnerabilities])

    files: list[tuple[str, str, bytes]] = [
        (
            "01-code-audit-report.docx",
            "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
            _render_docx_export(vulnerabilities),
        ),
        ("01-code-audit-report.pdf", "application/pdf", _render_pdf_export(vulnerabilities)),
        (
            "01-code-audit-report.md",
            "text/markdown; charset=utf-8",
            _render_markdown_export(vulnerabilities).encode("utf-8"),
        ),
        (
            "02-findings.json",
            "application/json",
            _render_json_export(vulnerabilities).encode("utf-8"),
        ),
    ]

    warnings: list[str] = []
    if delivery_quality["missing_retest"]:
        warnings.append(f"{delivery_quality['missing_retest']} 项漏洞缺少完整静态复测材料")
    if coverage["open_required_candidates"]:
        warnings.append(f"{coverage['open_required_candidates']} 条严重/高危/未知候选尚未闭合")
    if coverage["open_high_risk_business_nodes"]:
        warnings.append(f"{coverage['open_high_risk_business_nodes']} 个高风险业务节点尚未覆盖")
    if coverage["pending_review_findings"]:
        warnings.append(f"{coverage['pending_review_findings']} 条 Finding 尚待自动复核")
    if coverage["pending_report_tasks"]:
        warnings.append(f"{coverage['pending_report_tasks']} 个报告材料任务尚未完成")

    readme = "\n".join(
        [
            "Rabbit Code Audit 审计交付包",
            "",
            f"报告编号：{report_id}",
            f"生成时间：{generated_at}",
            f"交付状态：{'可交付' if not warnings else '有条件交付'}",
            "",
            "文件说明：",
            "- 01-code-audit-report.docx：正式可编辑报告",
            "- 01-code-audit-report.pdf：正式只读报告",
            "- 01-code-audit-report.md：完整技术报告与代码块原文",
            "- 02-findings.json：结构化漏洞数据",
            "- MANIFEST.json：范围、源码快照、交付状态和文件 SHA-256",
            "",
            "证据口径：静态 PoC 和预期结果来自源码推导；真实动态请求/响应会在报告中单独标记。",
            "复测要求：仅在授权隔离环境执行，执行前准备数据备份和回滚方案。",
            "完整性校验：对交付包内文件计算 SHA-256，并与 MANIFEST.json 对照。",
            "",
            *( ["交付注意事项：", *[f"- {item}" for item in warnings]] if warnings else [] ),
            "",
        ]
    ).encode("utf-8")
    files.append(("README.txt", "text/plain; charset=utf-8", readme))

    manifest_files = [
        {
            "path": path,
            "media_type": media_type,
            "size_bytes": len(body),
            "sha256": hashlib.sha256(body).hexdigest(),
        }
        for path, media_type, body in files
    ]
    manifest = {
        "schema_version": "rabbit-code-audit-delivery/v1",
        "report_id": report_id,
        "report_version": "1.0",
        "generated_at": generated_at,
        "title": _report_title(vulnerabilities),
        "delivery_status": "ready" if not warnings else "conditional",
        "warnings": warnings,
        "scope": {
            "project_ids": project_ids,
            "project_names": project_names,
            "finding_count": len(vulnerabilities),
            "finding_ids": [item.id for item in vulnerabilities],
            "severity_summary": _summarize(vulnerabilities),
        },
        "delivery_quality": delivery_quality,
        "coverage": coverage,
        "source_snapshots": source_inventory,
        "canonical_report": "01-code-audit-report.md",
        "digest_algorithm": "SHA-256",
        "files": manifest_files,
    }
    manifest_body = json.dumps(manifest, ensure_ascii=False, indent=2).encode("utf-8")

    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w", zipfile.ZIP_DEFLATED) as archive:
        for path, _media_type, body in files:
            archive.writestr(path, body)
        archive.writestr("MANIFEST.json", manifest_body)
    return buffer.getvalue()


def _describe_export_scope(vulnerabilities: list[Vulnerability], project_id: str | None) -> tuple[str, str | None, str | None]:
    """Return a human-readable scope label plus the resolved project id/name."""
    if len(vulnerabilities) == 1:
        only = vulnerabilities[0]
        return f"{only.project_name} · {only.fact_id}", only.project_id, only.project_name
    project_ids = {item.project_id for item in vulnerabilities}
    if project_id and len(project_ids) == 1:
        name = vulnerabilities[0].project_name if vulnerabilities else project_id
        return f"{name}（{len(vulnerabilities)} 条）", project_id, name
    if len(project_ids) == 1 and vulnerabilities:
        only_name = vulnerabilities[0].project_name
        return f"{only_name}（{len(vulnerabilities)} 条）", vulnerabilities[0].project_id, only_name
    return f"全部漏洞（{len(vulnerabilities)} 条）", None, None


def _record_export(
    vulnerabilities: list[Vulnerability],
    *,
    fmt: str,
    filename: str,
    project_id: str | None,
    severity: str | None,
    status: str | None,
    content_sha256: str,
) -> None:
    """Persist a single export action to the ``export_records`` table.

    Best-effort: a logging failure must never break the actual download, so any
    database error is swallowed.
    """
    scope, resolved_project_id, project_name = _describe_export_scope(vulnerabilities, project_id)
    try:
        with get_conn() as conn:
            conn.execute(
                """
                INSERT INTO export_records
                    (created_at, format, filename, scope, vulnerability_count,
                     project_id, project_name, severity, status, content_sha256)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    datetime.now(timezone.utc).isoformat(),
                    fmt,
                    filename,
                    scope,
                    len(vulnerabilities),
                    resolved_project_id,
                    project_name,
                    severity,
                    status,
                    content_sha256,
                ),
            )
    except Exception:  # pragma: no cover - logging must not break the download
        pass
    record_audit(
        "vulnerability.export",
        f"导出代码审计报告（{fmt.upper()}）· {scope}",
        target_type="export",
        target_id=filename,
    )


@router.get("/export-records", response_model=list[ExportRecord])
def list_export_records(limit: int = Query(default=50, ge=1, le=200)) -> list[ExportRecord]:
    """Return the most recent export actions, newest first (导出记录 page)."""
    with get_conn() as conn:
        rows = conn.execute(
            """
            SELECT id, created_at, format, filename, scope, vulnerability_count,
                   project_id, project_name, severity, status, content_sha256
            FROM export_records
            ORDER BY datetime(created_at) DESC, id DESC
            LIMIT ?
            """,
            (limit,),
        ).fetchall()
    return [ExportRecord(**dict(row)) for row in rows]


@router.delete("/export-records/{record_id}")
def delete_export_record(record_id: int) -> dict[str, str]:
    """Delete a single export record from history."""
    with get_conn() as conn:
        conn.execute("DELETE FROM export_records WHERE id = ?", (record_id,))
    return {"status": "deleted"}


@router.delete("/export-records")
def clear_export_records() -> dict[str, str]:
    """Clear all export records."""
    with get_conn() as conn:
        conn.execute("DELETE FROM export_records")
    return {"status": "cleared"}


def _export_integrity(body: str | bytes) -> tuple[str, str]:
    raw = body.encode("utf-8") if isinstance(body, str) else body
    digest = hashlib.sha256(raw).digest()
    return digest.hex(), base64.b64encode(digest).decode("ascii")


def _download_headers(filename: str, body: str | bytes) -> tuple[dict[str, str], str]:
    hexdigest, encoded = _export_integrity(body)
    return (
        {
            "Content-Disposition": f'attachment; filename="{filename}"',
            "Digest": f"sha-256={encoded}",
            "X-Content-SHA256": hexdigest,
        },
        hexdigest,
    )


@router.get("/export")
def export_vulnerabilities(
    format: str = Query(
        default="json",
        description="Export format; one of 'json', 'csv', 'md', 'pdf', 'docx', 'bundle', or 'zip'.",
    ),
    severity: str | None = Query(
        default=None,
        description="Optional severity filter (critical, high, medium, low).",
    ),
    project_id: str | None = Query(
        default=None,
        description="Optional project filter; restricts the export to one project.",
    ),
    vulnerability_id: str | None = Query(
        default=None,
        description="Optional vulnerability id; restricts the export to one finding.",
    ),
    vulnerability_ids: str | None = Query(
        default=None,
        description="Comma-separated merged vulnerability ids to export.",
    ),
    status: str | None = Query(
        default=None,
        description="Optional review status filter (confirmed or ignored).",
    ),
) -> Response:
    """Export vulnerabilities as a downloadable JSON or CSV file.

    The export respects the active ``severity`` and ``project_id`` filters so it
    contains exactly the vulnerabilities the user is currently viewing
    (requirement 8.1) and embeds a summary of per-severity totals (requirement
    8.3). JSON places the summary in a top-level ``summary`` object; CSV writes
    it as header rows ahead of the data rows.

    An unsupported ``format`` is rejected with a 422 naming the supported
    formats (requirement 8.4). When the filters match nothing, a valid file
    containing only the summary (all counts zero) is returned (requirement 8.5).

    ``severity`` is validated here (rather than via a ``Literal`` query type) so
    an unsupported severity yields the same shaped result as the list endpoint;
    an unknown severity simply matches nothing and produces a summary-only file.
    """
    normalized = format.lower()
    if normalized not in ("json", "csv", "md", "markdown", "pdf", "docx", "word", "bundle", "zip"):
        raise HTTPException(status_code=422, detail="Supported formats: json, csv, md, pdf, docx, bundle")

    selected_ids = [item.strip() for item in (vulnerability_ids or "").split(",") if item.strip()] or None
    vulnerabilities = _query_filtered_vulnerabilities(
        severity,
        project_id,
        vulnerability_id,
        vulnerability_ids=selected_ids,
        status=status,
    )

    if normalized == "json":
        body = _render_json_export(vulnerabilities)
        filename = _export_filename(vulnerabilities, "json")
        headers, content_sha256 = _download_headers(filename, body)
        _record_export(vulnerabilities, fmt="json", filename=filename, project_id=project_id, severity=severity, status=status, content_sha256=content_sha256)
        return Response(
            content=body,
            media_type="application/json",
            headers=headers,
        )

    if normalized in ("md", "markdown"):
        body = _render_markdown_export(vulnerabilities)
        filename = _export_filename(vulnerabilities, "md")
        headers, content_sha256 = _download_headers(filename, body)
        _record_export(vulnerabilities, fmt="md", filename=filename, project_id=project_id, severity=severity, status=status, content_sha256=content_sha256)
        return Response(
            content=body,
            media_type="text/markdown; charset=utf-8",
            headers=headers,
        )

    if normalized == "pdf":
        body = _render_pdf_export(vulnerabilities)
        filename = _export_filename(vulnerabilities, "pdf")
        headers, content_sha256 = _download_headers(filename, body)
        _record_export(vulnerabilities, fmt="pdf", filename=filename, project_id=project_id, severity=severity, status=status, content_sha256=content_sha256)
        return Response(
            content=body,
            media_type="application/pdf",
            headers=headers,
        )

    if normalized in ("docx", "word"):
        body = _render_docx_export(vulnerabilities)
        filename = _export_filename(vulnerabilities, "docx")
        headers, content_sha256 = _download_headers(filename, body)
        _record_export(vulnerabilities, fmt="docx", filename=filename, project_id=project_id, severity=severity, status=status, content_sha256=content_sha256)
        return Response(
            content=body,
            media_type="application/vnd.openxmlformats-officedocument.wordprocessingml.document",
            headers=headers,
        )

    if normalized in ("bundle", "zip"):
        body = _render_delivery_bundle(vulnerabilities)
        filename = _export_filename(vulnerabilities, "zip")
        headers, content_sha256 = _download_headers(filename, body)
        _record_export(vulnerabilities, fmt="bundle", filename=filename, project_id=project_id, severity=severity, status=status, content_sha256=content_sha256)
        return Response(
            content=body,
            media_type="application/zip",
            headers=headers,
        )

    body = _render_csv_export(vulnerabilities)
    filename = _export_filename(vulnerabilities, "csv")
    headers, content_sha256 = _download_headers(filename, body)
    _record_export(vulnerabilities, fmt="csv", filename=filename, project_id=project_id, severity=severity, status=status, content_sha256=content_sha256)
    return Response(
        content=body,
        media_type="text/csv",
        headers=headers,
    )


@router.post("/refresh")
def refresh_vulnerabilities() -> VulnerabilitySummary:
    """Return the current report summary.

    Code-audit reports are populated only when an audit finding is independently
    confirmed. Facts remain navigation evidence and are never promoted by a
    keyword classifier.
    """
    removed = _remove_non_audit_report_rows()
    if removed:
        try:
            record_audit(
                "vulnerability.refresh",
                f"清理旧版事实分类报告项（{removed} 条）",
                target_type="vulnerability",
            )
        except Exception:
            pass
    return vulnerabilities_summary()
