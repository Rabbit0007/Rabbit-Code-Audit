"""Completion is blocked while a configured replay was never run.

Only fires when the project has a validation target, so projects that never use
replay are unaffected (the backward-compat case is covered explicitly).
"""

from __future__ import annotations

import io
import json
import zipfile

import pytest
from fastapi import FastAPI, HTTPException
from fastapi.testclient import TestClient

from cairn.server import db
from cairn.server.routers import findings, projects, sources
from cairn.server.services import utcnow, validate_project_ready_to_complete

PLAN = json.dumps({"oracle": "sql_error", "requests": {"attack": {"path": "/x?q=1%27"}, "baseline": {"path": "/x?q=1"}}})
POC = json.dumps(
    {
        "payload": "q=1'",
        "request_template": "curl 'http://target/x?q=1%27'",
        "steps": ["send it", "watch the error"],
        "expected_result": "a database error appears",
        "verification": "error only with the quote",
    }
)


@pytest.fixture
def client(temp_db):
    app = FastAPI()
    app.include_router(projects.router)
    app.include_router(sources.router)
    app.include_router(findings.router)
    return TestClient(app)


def _project_with_snapshot(client) -> tuple[str, str]:
    project_id = client.post(
        "/projects", json={"title": "a", "origin": "s", "goal": "g", "hints": []}
    ).json()["project"]["id"]
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w") as archive:
        archive.writestr("app.py", b"print('ok')")
    snapshot_id = client.post(
        f"/api/projects/{project_id}/sources/zip",
        files={"archive": ("d.zip", buffer.getvalue(), "application/zip")},
    ).json()["id"]
    return project_id, snapshot_id


def _insert_confirmed_finding(project_id, snapshot_id, *, replay_verdict=None):
    with db.get_conn() as conn:
        conn.execute(
            """
            INSERT INTO audit_findings (
                id, project_id, snapshot_id, title, category, severity, status,
                evidence_level, file_path, line_start, entry_point, description,
                impact, evidence, reproduction_poc_json, verification_plan_json,
                replay_verdict, discovered_by, reviewed_by, created_at
            )
            VALUES (?, ?, ?, ?, 'sql_injection', 'high', 'confirmed', 'L3', 'app/x.py', 10,
                    'GET /x', 'd', 'read', 'concat SQL', ?, ?, ?, 'worker-a', 'worker-b', ?)
            """,
            ("finding_vbc", project_id, snapshot_id, "SQLi", POC, PLAN, replay_verdict, utcnow()),
        )


def _complete_error(project_id) -> dict | None:
    with db.get_conn() as conn:
        try:
            validate_project_ready_to_complete(conn, project_id)
        except HTTPException as exc:
            return {"status": exc.status_code, "detail": exc.detail}
    return None


def test_completion_blocked_when_plan_not_replayed(client):
    project_id, snapshot_id = _project_with_snapshot(client)
    _insert_confirmed_finding(project_id, snapshot_id, replay_verdict=None)
    client.put(f"/api/projects/{project_id}/audit-validation-target", json={"base_url": "http://127.0.0.1:9"})

    error = _complete_error(project_id)
    assert error is not None
    assert error["status"] == 409
    assert "verification plan must be replayed" in error["detail"]["message"]
    assert error["detail"]["audit_findings"][0]["id"] == "finding_vbc"


def test_completion_not_blocked_by_this_guard_once_replayed(client):
    project_id, snapshot_id = _project_with_snapshot(client)
    _insert_confirmed_finding(project_id, snapshot_id, replay_verdict="confirmed")
    client.put(f"/api/projects/{project_id}/audit-validation-target", json={"base_url": "http://127.0.0.1:9"})

    error = _complete_error(project_id)
    # Other guards may still fire, but not this one.
    if error is not None:
        assert "verification plan must be replayed" not in error["detail"].get("message", "")


def test_guard_inert_without_validation_target(client):
    project_id, snapshot_id = _project_with_snapshot(client)
    _insert_confirmed_finding(project_id, snapshot_id, replay_verdict=None)
    # No target configured -> this guard must not fire.
    error = _complete_error(project_id)
    if error is not None:
        assert "verification plan must be replayed" not in error["detail"].get("message", "")
