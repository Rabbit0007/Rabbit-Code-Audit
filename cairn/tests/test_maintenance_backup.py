from __future__ import annotations

from fastapi import FastAPI
from fastapi.testclient import TestClient

from cairn.server import db
from cairn.server.routers import maintenance


def test_backup_verify_and_restore_round_trip(temp_db, tmp_path, monkeypatch):
    monkeypatch.setenv("CAIRN_ARTIFACT_ROOT", str(tmp_path / "artifacts"))
    with db.get_conn() as conn:
        conn.execute(
            "INSERT INTO projects (id, title, status, created_at) VALUES ('proj-b', 'Before', 'stopped', '2026-01-01T00:00:00Z')"
        )
    app = FastAPI()
    app.include_router(maintenance.router)
    client = TestClient(app)

    created = client.post("/api/maintenance/backups", json={"label": "known-good"})
    assert created.status_code == 201
    backup = created.json()
    assert backup["integrity_status"] == "ok"
    assert len(backup["sha256"]) == 64

    with db.get_conn() as conn:
        conn.execute("UPDATE projects SET title = 'After' WHERE id = 'proj-b'")
    verified = client.post(f"/api/maintenance/backups/{backup['id']}/verify")
    assert verified.status_code == 200
    assert verified.json()["integrity_status"] == "ok"

    restored = client.post(f"/api/maintenance/backups/{backup['id']}/restore")
    assert restored.status_code == 200
    assert restored.json()["restored_backup_id"] == backup["id"]
    with db.get_conn() as conn:
        assert conn.execute("SELECT title FROM projects WHERE id = 'proj-b'").fetchone()[0] == "Before"
    records = client.get("/api/maintenance/backups").json()
    assert {item["id"] for item in records} >= {
        backup["id"],
        restored.json()["safety_backup_id"],
    }


def test_restore_rejects_active_projects(temp_db, tmp_path, monkeypatch):
    monkeypatch.setenv("CAIRN_ARTIFACT_ROOT", str(tmp_path / "artifacts"))
    with db.get_conn() as conn:
        conn.execute(
            "INSERT INTO projects (id, title, status, created_at) VALUES ('proj-active', 'Active', 'active', '2026-01-01T00:00:00Z')"
        )
    app = FastAPI()
    app.include_router(maintenance.router)
    client = TestClient(app)
    backup = client.post("/api/maintenance/backups", json={}).json()

    response = client.post(f"/api/maintenance/backups/{backup['id']}/restore")

    assert response.status_code == 409
    assert "stopped" in response.json()["detail"]

