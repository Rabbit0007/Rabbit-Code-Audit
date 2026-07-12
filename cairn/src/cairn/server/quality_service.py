from __future__ import annotations

from datetime import datetime, timezone
from difflib import SequenceMatcher
import json
import re
import uuid

from cairn.server.db import get_conn
from cairn.server.quality_models import (
    BenchmarkExpectation,
    BenchmarkMatch,
    BenchmarkMiss,
    BenchmarkRunRequest,
    BenchmarkRunResult,
)


def _now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _text(value: object) -> str:
    return re.sub(r"\s+", " ", str(value or "").strip().lower())


def _path(value: object) -> str:
    return _text(value).replace("\\", "/").lstrip("./")


def _match_score(expectation: BenchmarkExpectation, finding: dict) -> tuple[float, list[str]]:
    checks: list[tuple[str, bool, float]] = []
    if expectation.file_path:
        checks.append(("file_path", _path(expectation.file_path) == _path(finding.get("file_path")), 0.34))
    if expectation.category:
        checks.append(("category", _text(expectation.category) == _text(finding.get("category")), 0.22))
    if expectation.cwe:
        checks.append(("cwe", _text(expectation.cwe) == _text(finding.get("cwe")), 0.18))
    if expectation.entry_point:
        checks.append(("entry_point", _text(expectation.entry_point) == _text(finding.get("entry_point")), 0.16))
    title_score = SequenceMatcher(None, _text(expectation.title), _text(finding.get("title"))).ratio()
    checks.append(("title", title_score >= 0.55, 0.10 if len(checks) else 1.0))
    failed_identity = any(not matched for name, matched, _weight in checks if name in {"file_path", "cwe"})
    if failed_identity:
        return 0.0, []
    matched_on = [name for name, matched, _weight in checks if matched]
    score = sum(weight for _name, matched, weight in checks if matched)
    return round(min(1.0, score), 4), matched_on


def _ratio(numerator: int, denominator: int) -> float:
    return round(numerator / denominator, 4) if denominator else 1.0


def run_quality_benchmark(project_id: str, body: BenchmarkRunRequest) -> BenchmarkRunResult:
    with get_conn() as conn:
        project = conn.execute("SELECT id FROM projects WHERE id = ?", (project_id,)).fetchone()
        if project is None:
            raise ValueError("project not found")
        if body.snapshot_id:
            snapshot = conn.execute(
                "SELECT id FROM source_snapshots WHERE id = ? AND project_id = ? AND status = 'ready'",
                (body.snapshot_id, project_id),
            ).fetchone()
            if snapshot is None:
                raise ValueError("ready snapshot not found")
        rows = conn.execute(
            """
            SELECT id, title, category, cwe, file_path, entry_point
            FROM audit_findings
            WHERE project_id = ? AND status = 'confirmed'
              AND (? IS NULL OR snapshot_id = ?)
            ORDER BY created_at, id
            """,
            (project_id, body.snapshot_id, body.snapshot_id),
        ).fetchall()
        findings = [dict(row) for row in rows]
        node_rows = conn.execute(
            """
            SELECT title, description, evidence_json
            FROM business_nodes
            WHERE project_id = ? AND node_type = 'endpoint'
            """,
            (project_id,),
        ).fetchall()

    candidates: list[tuple[float, int, int, list[str]]] = []
    for expected_index, expectation in enumerate(body.expectations):
        for finding_index, finding in enumerate(findings):
            score, matched_on = _match_score(expectation, finding)
            if score >= 0.55:
                candidates.append((score, expected_index, finding_index, matched_on))
    candidates.sort(key=lambda item: (-item[0], item[1], item[2]))
    matched_expected: set[int] = set()
    matched_findings: set[int] = set()
    matches: list[BenchmarkMatch] = []
    for score, expected_index, finding_index, matched_on in candidates:
        if expected_index in matched_expected or finding_index in matched_findings:
            continue
        matched_expected.add(expected_index)
        matched_findings.add(finding_index)
        matches.append(
            BenchmarkMatch(
                expectation_id=body.expectations[expected_index].id,
                finding_id=findings[finding_index]["id"],
                score=score,
                matched_on=matched_on,
            )
        )

    misses = [
        BenchmarkMiss(id=item.id, title=item.title, reason="未找到位置和类型相符的已确认 Finding")
        for index, item in enumerate(body.expectations)
        if index not in matched_expected
    ]
    unexpected = [finding["id"] for index, finding in enumerate(findings) if index not in matched_findings]
    true_positive = len(matches)
    false_positive = len(unexpected)
    false_negative = len(misses)
    precision = _ratio(true_positive, true_positive + false_positive)
    recall = _ratio(true_positive, true_positive + false_negative)
    f1 = round(2 * precision * recall / (precision + recall), 4) if precision + recall else 0.0
    required_indexes = {index for index, item in enumerate(body.expectations) if item.required}
    required_matched = len(required_indexes & matched_expected)
    required_recall = _ratio(required_matched, len(required_indexes))

    node_corpus = "\n".join(
        _text(f"{row['title']} {row['description']} {row['evidence_json']}") for row in node_rows
    )
    missing_entrypoints = [item for item in body.expected_business_entrypoints if _text(item) not in node_corpus]
    entrypoint_coverage = _ratio(
        len(body.expected_business_entrypoints) - len(missing_entrypoints),
        len(body.expected_business_entrypoints),
    )
    status = "pass" if required_recall == 1.0 and not missing_entrypoints else "warning" if true_positive else "fail"
    run_id = f"bench_{uuid.uuid4().hex[:16]}"
    created_at = _now()
    result = BenchmarkRunResult(
        id=run_id,
        project_id=project_id,
        snapshot_id=body.snapshot_id,
        suite_name=body.suite_name,
        created_at=created_at,
        status=status,
        true_positive=true_positive,
        false_positive=false_positive,
        false_negative=false_negative,
        precision=precision,
        recall=recall,
        f1=f1,
        required_recall=required_recall,
        business_entrypoint_coverage=entrypoint_coverage,
        matches=matches,
        misses=misses,
        unexpected_finding_ids=unexpected,
        missing_business_entrypoints=missing_entrypoints,
    )
    with get_conn() as conn:
        conn.execute(
            """
            INSERT INTO quality_benchmark_runs (
                id, project_id, snapshot_id, suite_name, expectations_json, result_json, created_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?)
            """,
            (
                run_id,
                project_id,
                body.snapshot_id,
                body.suite_name,
                json.dumps(body.model_dump(), ensure_ascii=False),
                json.dumps(result.model_dump(), ensure_ascii=False),
                created_at,
            ),
        )
    return result


def list_quality_benchmarks(project_id: str, limit: int = 50) -> list[BenchmarkRunResult]:
    with get_conn() as conn:
        rows = conn.execute(
            """
            SELECT result_json FROM quality_benchmark_runs
            WHERE project_id = ? ORDER BY created_at DESC LIMIT ?
            """,
            (project_id, limit),
        ).fetchall()
    return [BenchmarkRunResult.model_validate(json.loads(row["result_json"])) for row in rows]

