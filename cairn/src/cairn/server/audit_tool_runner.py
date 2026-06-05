from __future__ import annotations

from dataclasses import dataclass
import hashlib
import json
from pathlib import Path
import shutil
import subprocess
import time
from typing import Any

from cairn.server import db
from cairn.server.audit_tools import AuditToolPlan, build_tool_plan
from cairn.server.services import utcnow
from cairn.server.source_models import CodeFile
from cairn.server.source_service import artifact_root, get_snapshot, list_code_files, snapshot_path


@dataclass(frozen=True)
class ParsedToolFinding:
    tool_name: str
    rule_id: str | None
    severity: str
    title: str
    description: str
    file_path: str | None = None
    line_start: int | None = None
    line_end: int | None = None
    raw_artifact_path: str | None = None


@dataclass(frozen=True)
class ToolRunSummary:
    tool_name: str
    status: str
    finding_count: int = 0
    detail: str | None = None
    raw_artifact_path: str | None = None


def run_audit_tools_for_project(
    project_id: str,
    *,
    snapshot_id: str | None = None,
    timeout_per_tool: int = 180,
    selected_tools: set[str] | None = None,
) -> list[ToolRunSummary]:
    snapshot = _ready_snapshot(project_id, snapshot_id)
    files = list_code_files(project_id, snapshot.id, limit=20_000)
    source_root = snapshot_path(snapshot.id)
    plans = build_tool_plan(snapshot, files, str(source_root))
    summaries: list[ToolRunSummary] = []
    for plan in plans:
        if selected_tools and plan.name not in selected_tools:
            continue
        summaries.append(_run_one_tool(project_id, snapshot.id, source_root, files, plan, timeout_per_tool))
    return summaries


def parse_tool_output(tool_name: str, output: str, *, raw_artifact_path: str | None = None) -> list[ParsedToolFinding]:
    try:
        payload = json.loads(output)
    except json.JSONDecodeError:
        return []
    if tool_name == "semgrep":
        return _parse_semgrep(payload, raw_artifact_path)
    if tool_name == "gitleaks":
        return _parse_gitleaks(payload, raw_artifact_path)
    if tool_name == "bandit":
        return _parse_bandit(payload, raw_artifact_path)
    if tool_name == "trivy":
        return _parse_trivy(payload, raw_artifact_path)
    if tool_name == "osv-scanner":
        return _parse_osv(payload, raw_artifact_path)
    return []


def persist_tool_findings(project_id: str, snapshot_id: str, findings: list[ParsedToolFinding]) -> None:
    _persist_tool_findings(project_id, snapshot_id, findings)


def _ready_snapshot(project_id: str, snapshot_id: str | None):
    if snapshot_id:
        snapshot = get_snapshot(project_id, snapshot_id)
        if snapshot.status != "ready":
            raise ValueError("Source snapshot is not ready")
        return snapshot
    with db.get_conn() as conn:
        row = conn.execute(
            """
            SELECT id
            FROM source_snapshots
            WHERE project_id = ? AND status = 'ready'
            ORDER BY created_at DESC
            LIMIT 1
            """,
            (project_id,),
        ).fetchone()
    if row is None:
        raise ValueError("No ready source snapshot is available")
    return get_snapshot(project_id, row["id"])


def _run_one_tool(
    project_id: str,
    snapshot_id: str,
    source_root: Path,
    files: list[CodeFile],
    plan: AuditToolPlan,
    timeout_per_tool: int,
) -> ToolRunSummary:
    executable = plan.command[0]
    if shutil.which(executable) is None:
        return ToolRunSummary(plan.name, "skipped", detail=f"{executable} is not installed")
    started = time.strftime("%Y%m%d%H%M%S")
    artifact_dir = artifact_root() / "tool-runs" / snapshot_id
    artifact_dir.mkdir(parents=True, exist_ok=True)
    raw_path = artifact_dir / f"{plan.name}-{started}.json"
    try:
        result = subprocess.run(
            plan.command,
            cwd=str(source_root) if _should_run_from_source_root(plan) else None,
            capture_output=True,
            text=True,
            timeout=timeout_per_tool,
            check=False,
        )
    except subprocess.TimeoutExpired:
        return ToolRunSummary(plan.name, "timeout", detail=f"timed out after {timeout_per_tool}s")
    output = result.stdout.strip() or result.stderr.strip()
    raw_path.write_text(output, encoding="utf-8", errors="replace")
    parsed = parse_tool_output(plan.name, output, raw_artifact_path=str(raw_path))
    if parsed:
        _persist_tool_findings(project_id, snapshot_id, parsed)
    status = "success" if result.returncode == 0 else "completed_with_errors"
    detail = None if result.returncode == 0 else f"exit_code={result.returncode}"
    return ToolRunSummary(plan.name, status, finding_count=len(parsed), detail=detail, raw_artifact_path=str(raw_path))


def _should_run_from_source_root(plan: AuditToolPlan) -> bool:
    return plan.name in {"gosec", "govulncheck"}


def _persist_tool_findings(project_id: str, snapshot_id: str, findings: list[ParsedToolFinding]) -> None:
    now = utcnow()
    with db.get_conn() as conn:
        for finding in findings:
            tool_id = _stable_id(
                "tool",
                project_id,
                snapshot_id,
                finding.tool_name,
                finding.rule_id,
                finding.file_path,
                finding.line_start,
                finding.title,
            )
            conn.execute(
                """
                INSERT OR IGNORE INTO tool_findings (
                    id, project_id, snapshot_id, tool_name, rule_id, severity,
                    title, description, file_path, line_start, line_end, status,
                    raw_artifact_path, created_at
                )
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'candidate', ?, ?)
                """,
                (
                    tool_id,
                    project_id,
                    snapshot_id,
                    finding.tool_name,
                    finding.rule_id,
                    finding.severity,
                    finding.title,
                    finding.description,
                    finding.file_path,
                    finding.line_start,
                    finding.line_end,
                    finding.raw_artifact_path,
                    now,
                ),
            )
            candidate_id = _stable_id("cand", project_id, snapshot_id, "tool", tool_id)
            conn.execute(
                """
                INSERT OR IGNORE INTO audit_candidates (
                    id, project_id, snapshot_id, source, candidate_type, severity,
                    title, description, file_path, line_start, line_end,
                    tool_finding_id, status, created_by, created_at, updated_at
                )
                VALUES (?, ?, ?, 'tool', 'tool_finding', ?, ?, ?, ?, ?, ?, ?, 'candidate', 'audit_tool_runner', ?, ?)
                """,
                (
                    candidate_id,
                    project_id,
                    snapshot_id,
                    finding.severity,
                    finding.title,
                    finding.description,
                    finding.file_path,
                    finding.line_start,
                    finding.line_end,
                    tool_id,
                    now,
                    now,
                ),
            )


def _parse_semgrep(payload: Any, raw_artifact_path: str | None) -> list[ParsedToolFinding]:
    results = payload.get("results") if isinstance(payload, dict) else None
    if not isinstance(results, list):
        return []
    findings: list[ParsedToolFinding] = []
    for item in results:
        if not isinstance(item, dict):
            continue
        extra = item.get("extra") if isinstance(item.get("extra"), dict) else {}
        start = item.get("start") if isinstance(item.get("start"), dict) else {}
        end = item.get("end") if isinstance(item.get("end"), dict) else {}
        rule_id = _text(item.get("check_id"))
        message = _text(extra.get("message")) or rule_id or "semgrep finding"
        findings.append(
            ParsedToolFinding(
                tool_name="semgrep",
                rule_id=rule_id,
                severity=_map_severity(extra.get("severity")),
                title=message[:180],
                description=message,
                file_path=_text(item.get("path")),
                line_start=_int(start.get("line")),
                line_end=_int(end.get("line")),
                raw_artifact_path=raw_artifact_path,
            )
        )
    return findings


def _parse_gitleaks(payload: Any, raw_artifact_path: str | None) -> list[ParsedToolFinding]:
    if not isinstance(payload, list):
        return []
    findings: list[ParsedToolFinding] = []
    for item in payload:
        if not isinstance(item, dict):
            continue
        rule_id = _text(item.get("RuleID"))
        description = _text(item.get("Description")) or rule_id or "gitleaks secret candidate"
        findings.append(
            ParsedToolFinding(
                tool_name="gitleaks",
                rule_id=rule_id,
                severity="high",
                title=description[:180],
                description=description,
                file_path=_text(item.get("File")),
                line_start=_int(item.get("StartLine")),
                line_end=_int(item.get("EndLine")),
                raw_artifact_path=raw_artifact_path,
            )
        )
    return findings


def _parse_bandit(payload: Any, raw_artifact_path: str | None) -> list[ParsedToolFinding]:
    results = payload.get("results") if isinstance(payload, dict) else None
    if not isinstance(results, list):
        return []
    findings: list[ParsedToolFinding] = []
    for item in results:
        if not isinstance(item, dict):
            continue
        issue_text = _text(item.get("issue_text")) or "bandit finding"
        line_range = item.get("line_range")
        line_end = None
        if isinstance(line_range, list) and line_range:
            line_end = _int(line_range[-1])
        findings.append(
            ParsedToolFinding(
                tool_name="bandit",
                rule_id=_text(item.get("test_id")),
                severity=_map_severity(item.get("issue_severity")),
                title=issue_text[:180],
                description=issue_text,
                file_path=_text(item.get("filename")),
                line_start=_int(item.get("line_number")),
                line_end=line_end,
                raw_artifact_path=raw_artifact_path,
            )
        )
    return findings


def _parse_trivy(payload: Any, raw_artifact_path: str | None) -> list[ParsedToolFinding]:
    results = payload.get("Results") if isinstance(payload, dict) else None
    if not isinstance(results, list):
        return []
    findings: list[ParsedToolFinding] = []
    for result in results:
        if not isinstance(result, dict):
            continue
        target = _text(result.get("Target"))
        for key in ("Vulnerabilities", "Misconfigurations", "Secrets"):
            items = result.get(key)
            if not isinstance(items, list):
                continue
            for item in items:
                if not isinstance(item, dict):
                    continue
                rule_id = _text(item.get("VulnerabilityID") or item.get("ID") or item.get("RuleID"))
                title = _text(item.get("Title")) or _text(item.get("PkgName")) or rule_id or "trivy finding"
                description = _text(item.get("Description")) or title
                findings.append(
                    ParsedToolFinding(
                        tool_name="trivy",
                        rule_id=rule_id,
                        severity=_map_severity(item.get("Severity")),
                        title=title[:180],
                        description=description,
                        file_path=target,
                        raw_artifact_path=raw_artifact_path,
                    )
                )
    return findings


def _parse_osv(payload: Any, raw_artifact_path: str | None) -> list[ParsedToolFinding]:
    results = payload.get("results") if isinstance(payload, dict) else None
    if not isinstance(results, list):
        return []
    findings: list[ParsedToolFinding] = []
    for result in results:
        if not isinstance(result, dict):
            continue
        source = result.get("source") if isinstance(result.get("source"), dict) else {}
        file_path = _text(source.get("path") or result.get("path"))
        packages = result.get("packages")
        if not isinstance(packages, list):
            continue
        for package in packages:
            if not isinstance(package, dict):
                continue
            vulnerabilities = package.get("vulnerabilities")
            if not isinstance(vulnerabilities, list):
                continue
            package_info = package.get("package") if isinstance(package.get("package"), dict) else {}
            package_name = _text(package_info.get("name"))
            for vuln in vulnerabilities:
                if not isinstance(vuln, dict):
                    continue
                rule_id = _text(vuln.get("id"))
                summary = _text(vuln.get("summary")) or rule_id or "osv vulnerability"
                findings.append(
                    ParsedToolFinding(
                        tool_name="osv-scanner",
                        rule_id=rule_id,
                        severity=_osv_severity(vuln),
                        title=summary[:180],
                        description=f"{package_name}: {summary}" if package_name else summary,
                        file_path=file_path,
                        raw_artifact_path=raw_artifact_path,
                    )
                )
    return findings


def _osv_severity(vuln: dict) -> str:
    severity = vuln.get("severity")
    if isinstance(severity, list):
        text = " ".join(str(item.get("score") or item.get("type") or "") for item in severity if isinstance(item, dict))
        if any(token in text.upper() for token in ("CRITICAL", "9.", "10.")):
            return "critical"
        if any(token in text.upper() for token in ("HIGH", "8.", "7.")):
            return "high"
    return "medium"


def _map_severity(value: Any) -> str:
    text = str(value or "").strip().upper()
    if text in {"CRITICAL", "BLOCKER"}:
        return "critical"
    if text in {"HIGH", "ERROR"}:
        return "high"
    if text in {"MEDIUM", "WARNING", "WARN", "MODERATE"}:
        return "medium"
    if text in {"LOW", "INFO", "INFORMATIONAL"}:
        return "low"
    return "info"


def _text(value: Any) -> str | None:
    if value is None:
        return None
    text = str(value).strip()
    return text or None


def _int(value: Any) -> int | None:
    try:
        number = int(value)
    except (TypeError, ValueError):
        return None
    return number if number > 0 else None


def _stable_id(prefix: str, *parts: object) -> str:
    digest = hashlib.sha1("\0".join("" if part is None else str(part) for part in parts).encode("utf-8")).hexdigest()
    return f"{prefix}_{digest[:16]}"
