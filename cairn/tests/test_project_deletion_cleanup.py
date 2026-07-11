from __future__ import annotations

from fastapi import FastAPI
from fastapi.testclient import TestClient

from cairn.server import db
from cairn.server.routers import projects, sources
from cairn.server.source_service import artifact_root


def _client(temp_db) -> TestClient:
    app = FastAPI()
    app.include_router(projects.router)
    app.include_router(sources.router)
    return TestClient(app)


def _create_project(client: TestClient) -> str:
    response = client.post(
        "/projects",
        json={
            "title": "cleanup target",
            "origin": "uploaded source",
            "goal": "remove all project data",
            "hints": [],
        },
    )
    assert response.status_code == 201
    return response.json()["project"]["id"]


def test_delete_project_removes_database_and_filesystem_artifacts(temp_db, tmp_path, monkeypatch):
    monkeypatch.setenv("CAIRN_ARTIFACT_ROOT", str(tmp_path / "artifacts"))
    client = _client(temp_db)
    project_id = _create_project(client)

    response = client.post(
        f"/api/projects/{project_id}/sources/zip",
        files={"archive": ("source.zip", b"PK\x05\x06" + b"\x00" * 18, "application/zip")},
    )
    assert response.status_code == 201
    snapshot_id = response.json()["id"]

    snapshot_dir = artifact_root() / "snapshots" / snapshot_id
    tool_run_dir = artifact_root() / "tool-runs" / snapshot_id
    tool_run_dir.mkdir(parents=True)
    (tool_run_dir / "result.json").write_text("{}", encoding="utf-8")

    with db.get_conn() as conn:
        conn.execute(
            """
            INSERT INTO worker_task_history (
                worker_name, project_id, task_type, started_at, outcome
            ) VALUES ('worker-a', ?, 'explore', '2026-01-01T00:00:00Z', 'success')
            """,
            (project_id,),
        )
        conn.execute(
            """
            INSERT INTO export_records (
                created_at, format, filename, scope, vulnerability_count, project_id
            ) VALUES ('2026-01-01T00:00:00Z', 'pdf', 'report.pdf', 'project', 0, ?)
            """,
            (project_id,),
        )
        conn.execute(
            """
            INSERT INTO model_usage_records (
                project_id, model, prompt_tokens, completion_tokens, total_tokens,
                created_at
            ) VALUES (?, 'test-model', 100, 20, 120, '2026-01-01T00:01:00Z')
            """,
            (project_id,),
        )

    response = client.delete(f"/projects/{project_id}")

    assert response.status_code == 204
    assert not snapshot_dir.exists()
    assert not tool_run_dir.exists()
    with db.get_conn() as conn:
        assert conn.execute("SELECT COUNT(*) FROM projects WHERE id = ?", (project_id,)).fetchone()[0] == 0
        assert conn.execute("SELECT COUNT(*) FROM source_snapshots WHERE project_id = ?", (project_id,)).fetchone()[0] == 0
        assert conn.execute("SELECT COUNT(*) FROM worker_task_history WHERE project_id = ?", (project_id,)).fetchone()[0] == 0
        assert conn.execute("SELECT COUNT(*) FROM model_usage_records WHERE project_id = ?", (project_id,)).fetchone()[0] == 0
        assert conn.execute("SELECT COUNT(*) FROM export_records WHERE project_id = ?", (project_id,)).fetchone()[0] == 0
        assert conn.execute("SELECT COUNT(*) FROM audit_log WHERE project_id = ?", (project_id,)).fetchone()[0] == 0
        assert conn.execute("SELECT COUNT(*) FROM notifications WHERE project_id = ?", (project_id,)).fetchone()[0] == 0
