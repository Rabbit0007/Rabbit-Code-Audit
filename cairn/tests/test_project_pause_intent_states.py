import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from cairn.server.db import get_conn


@pytest.fixture
def project_client(temp_db):
    from cairn.server.routers import projects

    app = FastAPI()
    app.include_router(projects.router)
    return TestClient(app)


def test_pausing_project_releases_claims_without_reopening_superseded_intents(project_client):
    project = project_client.post(
        "/projects",
        json={"title": "pause states", "origin": "origin", "goal": "goal", "hints": []},
    ).json()
    project_id = project["project"]["id"]
    with get_conn() as conn:
        now = "2026-01-01T00:00:00Z"
        conn.execute(
            """
            INSERT INTO intents (
                id, project_id, description, creator, worker, last_heartbeat_at,
                created_at, fingerprint, status, superseded_by
            ) VALUES
                ('i001', ?, 'running', 'test', 'worker-1', ?, ?, 'running', 'claimed', NULL),
                ('i002', ?, 'old', 'test', NULL, NULL, ?, 'old', 'superseded', 'maintenance')
            """,
            (project_id, now, now, project_id, now),
        )
        conn.execute(
            "INSERT INTO intent_sources (intent_id, project_id, fact_id) VALUES ('i001', ?, 'origin')",
            (project_id,),
        )
        conn.execute(
            "INSERT INTO intent_sources (intent_id, project_id, fact_id) VALUES ('i002', ?, 'origin')",
            (project_id,),
        )

    response = project_client.put(f"/projects/{project_id}/status", json={"status": "stopped"})

    assert response.status_code == 200
    with get_conn() as conn:
        rows = conn.execute(
            "SELECT id, status, worker, superseded_by FROM intents WHERE project_id = ? ORDER BY id",
            (project_id,),
        ).fetchall()
    assert dict(rows[0]) == {"id": "i001", "status": "open", "worker": None, "superseded_by": None}
    assert dict(rows[1]) == {
        "id": "i002",
        "status": "superseded",
        "worker": None,
        "superseded_by": "maintenance",
    }


def test_project_summary_excludes_superseded_intents_from_open_counts(project_client):
    project = project_client.post(
        "/projects",
        json={"title": "summary states", "origin": "origin", "goal": "goal", "hints": []},
    ).json()
    project_id = project["project"]["id"]
    with get_conn() as conn:
        conn.execute(
            """
            INSERT INTO intents (
                id, project_id, description, creator, created_at, fingerprint,
                status, superseded_by
            ) VALUES ('i001', ?, 'old', 'test', '2026-01-01T00:00:00Z', 'old', 'superseded', 'maintenance')
            """,
            (project_id,),
        )
        conn.execute(
            "INSERT INTO intent_sources (intent_id, project_id, fact_id) VALUES ('i001', ?, 'origin')",
            (project_id,),
        )

    summary = next(item for item in project_client.get("/projects").json() if item["id"] == project_id)

    assert summary["working_intent_count"] == 0
    assert summary["unclaimed_intent_count"] == 0


def test_budget_pause_reason_is_visible_and_cleared_on_resume(project_client):
    project = project_client.post(
        "/projects",
        json={"title": "budget", "origin": "origin", "goal": "goal", "hints": []},
    ).json()
    project_id = project["project"]["id"]

    paused = project_client.put(
        f"/projects/{project_id}/status",
        json={"status": "stopped", "pause_reason": "model_call_count=500/500"},
    )
    assert paused.status_code == 200
    assert paused.json()["pause_reason"] == "model_call_count=500/500"

    resumed = project_client.put(
        f"/projects/{project_id}/status",
        json={"status": "active"},
    )
    assert resumed.status_code == 200
    assert resumed.json()["pause_reason"] is None
