from __future__ import annotations

from fastapi import FastAPI
from fastapi.testclient import TestClient
import pytest

from cairn.server import activity_service, db
from cairn.server.routers import projects
from cairn.server.services import expire_reason_leases, expire_workers, utcnow


def _app(temp_db) -> FastAPI:
    app = FastAPI()
    app.include_router(projects.router)
    return app


def _client(temp_db) -> TestClient:
    return TestClient(_app(temp_db))


def test_create_project_records_activity_without_opening_nested_connection(temp_db, monkeypatch):
    def fail_get_conn():
        raise AssertionError("activity logging opened a nested database connection")

    monkeypatch.setattr(activity_service, "get_conn", fail_get_conn)
    client = _client(temp_db)

    response = client.post(
        "/projects",
        json={
            "title": "lock-safe project",
            "origin": "source",
            "goal": "audit",
            "hints": [],
        },
    )

    assert response.status_code == 201
    project_id = response.json()["project"]["id"]
    with db.get_conn() as conn:
        audit = conn.execute(
            "SELECT action, target_id FROM audit_log WHERE action = 'project.create'",
        ).fetchone()
        notification = conn.execute(
            "SELECT title FROM notifications WHERE title = '新建项目：lock-safe project'",
        ).fetchone()
    assert audit["target_id"] == project_id
    assert notification["title"] == "新建项目：lock-safe project"


@pytest.mark.parametrize("project_scoped", [False, True])
def test_expire_workers_does_not_write_when_no_intent_lease_is_expired(temp_db, project_scoped):
    now = utcnow()
    with db.get_conn() as conn:
        conn.execute(
            "INSERT INTO projects (id, title, status, created_at) VALUES ('proj_lock', 'Lock', 'active', ?)",
            (now,),
        )
        conn.execute(
            """
            INSERT INTO intents (
                id, project_id, to_fact_id, description, creator, worker,
                last_heartbeat_at, created_at, concluded_at
            )
            VALUES ('i001', 'proj_lock', NULL, 'active work', 'worker', 'worker', ?, ?, NULL)
            """,
            (now, now),
        )
        statements: list[str] = []
        conn.set_trace_callback(statements.append)
        expire_workers(conn, "proj_lock" if project_scoped else None)
        conn.set_trace_callback(None)

    updates = [statement for statement in statements if statement.strip().upper().startswith("UPDATE INTENTS")]
    assert updates == []


@pytest.mark.parametrize("project_scoped", [False, True])
def test_expire_reason_leases_does_not_write_when_no_reason_lease_is_expired(temp_db, project_scoped):
    now = utcnow()
    with db.get_conn() as conn:
        conn.execute(
            """
            INSERT INTO projects (
                id, title, status, created_at, reason_worker, reason_trigger,
                reason_started_at, reason_last_heartbeat_at
            )
            VALUES ('proj_reason', 'Reason', 'active', ?, 'worker', 'initial', ?, ?)
            """,
            (now, now, now),
        )
        statements: list[str] = []
        conn.set_trace_callback(statements.append)
        expire_reason_leases(conn, "proj_reason" if project_scoped else None)
        conn.set_trace_callback(None)

    updates = [statement for statement in statements if statement.strip().upper().startswith("UPDATE PROJECTS")]
    assert updates == []
