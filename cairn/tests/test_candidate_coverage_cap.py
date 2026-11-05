"""Regression tests for the large-codebase candidate-generation fixes.

Covers four changes:
  * the source-index candidate cap now ranks before truncating, keeps bug-signal
    (data_flow / capability_chain) candidates ahead of bare route listings, and
    emits a ``coverage_gap`` candidate instead of silently dropping real findings;
  * a normal (non-truncated) import emits no ``coverage_gap``;
  * the Go request-input pattern no longer treats a constant ``db.Query(...)`` /
    ORM ``.Query(`` as external input (the old bare ``Query(`` false positive);
  * dependency / build / generated trees and minified bundles are excluded from
    candidate generation, while monorepo ``packages/`` source is kept.
"""

from __future__ import annotations

import io
import zipfile

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from cairn.server import source_service
from cairn.server.routers import (
    business_graph,
    export,
    findings,
    intents,
    projects,
    review_tasks,
    sources,
    vulnerabilities,
)
from cairn.server.source_service import _extract_risk_signals, _is_candidate_source_path

INDEX_CANDIDATE_TYPES = {
    "data_flow",
    "capability_chain",
    "entrypoint",
    "web_entrypoint",
    "coverage_gap",
}


def _client(temp_db) -> TestClient:
    app = FastAPI()
    for router in (
        projects,
        intents,
        sources,
        findings,
        review_tasks,
        business_graph,
        export,
        vulnerabilities,
    ):
        app.include_router(router.router)
    return TestClient(app)


def _create_project(client: TestClient) -> str:
    response = client.post(
        "/projects",
        json={"title": "audit", "origin": "src", "goal": "scope", "hints": []},
    )
    assert response.status_code == 201
    return response.json()["project"]["id"]


def _zip_bytes(files: dict[str, bytes]) -> bytes:
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w") as archive:
        for name, content in files.items():
            archive.writestr(name, content)
    return buffer.getvalue()


def _sqli_php(idx: int) -> bytes:
    return (
        "<?php\n"
        "$id=$_GET['id'];\n"
        f"$sql=\"SELECT * FROM users WHERE id=$id AND svc={idx}\";\n"
        "$result=mysql_query($sql);\n"
    ).encode()


# --------------------------------------------------------------------------- #
# Go request-input false-positive fix
# --------------------------------------------------------------------------- #
def test_go_constant_db_query_is_not_external_input():
    # A hardcoded DB query with NO HTTP input must yield no risk signal. The old
    # bare `Query(` input pattern treated `db.Query(` as input and flagged it.
    text = """
func listUsers(db *sql.DB) {
    rows, err := db.Query("SELECT * FROM users WHERE active = 1")
    _ = rows
    _ = err
}
"""
    assert _extract_risk_signals(text) == []


def test_go_request_input_to_sql_is_still_detected():
    text = """
func getUser(c *gin.Context) {
    id := c.Query("id")
    rows, err := db.Query("SELECT * FROM users WHERE id=" + id)
    _ = rows
    _ = err
}
"""
    categories = {signal.category for signal in _extract_risk_signals(text)}
    assert "数据库执行能力" in categories


# --------------------------------------------------------------------------- #
# Candidate path exclusion
# --------------------------------------------------------------------------- #
@pytest.mark.parametrize(
    ("path", "expected"),
    [
        ("src/app/handler.go", True),
        ("internal/user/Service.java", True),
        ("packages/core/src/main.ts", True),  # monorepo source must stay in scope
        ("node_modules/lib/index.js", False),
        ("third_party/foo/bar.go", False),
        ("Pods/AFNetworking/AFN.m", False),
        ("web/assets/app.min.js", False),
        ("public/vendor.bundle.js", False),
        ("src/app.js.map", False),
    ],
)
def test_candidate_source_path_exclusions(path: str, expected: bool):
    assert _is_candidate_source_path(path) is expected


# --------------------------------------------------------------------------- #
# Ranking + coverage_gap honesty marker
# --------------------------------------------------------------------------- #
def test_candidate_cap_keeps_bug_signals_and_emits_coverage_gap(temp_db, monkeypatch, tmp_path):
    monkeypatch.setenv("CAIRN_ARTIFACT_ROOT", str(tmp_path / "artifacts"))
    # Tiny cap so three real SQL-injection sinks overflow it.
    monkeypatch.setattr(source_service, "MAX_SOURCE_INDEX_CANDIDATES", 2)
    client = _client(temp_db)
    project_id = _create_project(client)

    payload = _zip_bytes({f"demo/svc{i}/index.php": _sqli_php(i) for i in range(3)})
    response = client.post(
        f"/api/projects/{project_id}/sources/zip",
        files={"archive": ("many.zip", payload, "application/zip")},
    )
    assert response.status_code in (200, 201)

    candidates = client.get(f"/api/projects/{project_id}/audit-candidates").json()

    gaps = [c for c in candidates if c["candidate_type"] == "coverage_gap"]
    assert len(gaps) == 1
    assert gaps[0]["severity"] == "high"
    assert gaps[0]["status"] == "candidate"
    assert "丢弃" in gaps[0]["title"]

    # Bug-signal candidates survive the cap ahead of bare entrypoint listings.
    assert [c for c in candidates if c["candidate_type"] == "data_flow"]

    # The honesty marker counts toward the cap; total index candidates never
    # exceed it.
    index_items = [c for c in candidates if c["candidate_type"] in INDEX_CANDIDATE_TYPES]
    assert len(index_items) <= 2


def test_candidate_priority_orders_type_severity_then_reachability():
    from cairn.server.source_service import _candidate_priority

    # bug signals outrank bare route listings
    assert _candidate_priority("data_flow", "high", "GET /x") < _candidate_priority(
        "entrypoint", "high", "GET /x"
    )
    # higher severity kept first
    assert _candidate_priority("data_flow", "critical", None) < _candidate_priority(
        "data_flow", "high", None
    )
    # reachability breaks ties: an entry-point-tied sink outranks an untied one
    assert _candidate_priority("data_flow", "high", "GET /x") < _candidate_priority(
        "data_flow", "high", None
    )
    # the coverage-gap honesty marker is never dropped
    assert _candidate_priority("coverage_gap", "high", None) < _candidate_priority(
        "data_flow", "critical", "GET /x"
    )


def test_normal_import_emits_no_coverage_gap(temp_db, monkeypatch, tmp_path):
    monkeypatch.setenv("CAIRN_ARTIFACT_ROOT", str(tmp_path / "artifacts"))
    client = _client(temp_db)
    project_id = _create_project(client)

    payload = _zip_bytes({"demo/app.php": _sqli_php(0)})
    client.post(
        f"/api/projects/{project_id}/sources/zip",
        files={"archive": ("one.zip", payload, "application/zip")},
    )

    candidates = client.get(f"/api/projects/{project_id}/audit-candidates").json()
    assert not [c for c in candidates if c["candidate_type"] == "coverage_gap"]
    assert [c for c in candidates if c["candidate_type"] == "data_flow"]
