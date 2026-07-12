from __future__ import annotations

from io import BytesIO
import zipfile

from fastapi import FastAPI
from fastapi.testclient import TestClient

from cairn.server.routers import maintenance, projects, quality, sources, vulnerabilities


def _zip(files: dict[str, str]) -> bytes:
    buffer = BytesIO()
    with zipfile.ZipFile(buffer, "w", zipfile.ZIP_DEFLATED) as archive:
        for path, content in files.items():
            archive.writestr(path, content)
    return buffer.getvalue()


def test_complete_no_model_product_workflow(temp_db, tmp_path, monkeypatch):
    monkeypatch.setenv("CAIRN_ARTIFACT_ROOT", str(tmp_path / "artifacts"))
    app = FastAPI()
    for router in (projects.router, sources.router, quality.router, vulnerabilities.router, maintenance.router):
        app.include_router(router)
    client = TestClient(app)

    created = client.post(
        "/projects",
        json={"title": "E2E", "origin": "zip", "goal": "deterministic workflow", "hints": []},
    )
    assert created.status_code == 201
    project_id = created.json()["project"]["id"]

    first = client.post(
        f"/api/projects/{project_id}/sources/zip",
        files={"archive": ("v1.zip", _zip({"app.py": "def health(): return 'ok'\n"}), "application/zip")},
    )
    second = client.post(
        f"/api/projects/{project_id}/sources/zip",
        files={
            "archive": (
                "v2.zip",
                _zip({"app.py": "def health(): return 'changed'\n", "requirements.txt": "fastapi==1\n"}),
                "application/zip",
            )
        },
    )
    assert first.status_code == second.status_code == 201
    first_id = first.json()["id"]
    second_id = second.json()["id"]

    changes = client.get(
        f"/api/projects/{project_id}/sources/{second_id}/changes",
        params={"base_snapshot_id": first_id},
    )
    assert changes.status_code == 200
    assert changes.json()["modified_file_count"] == 1
    assert changes.json()["added_file_count"] == 1

    benchmark = client.post(
        f"/api/projects/{project_id}/quality/benchmarks",
        json={
            "suite_name": "e2e-ground-truth",
            "snapshot_id": second_id,
            "expectations": [{"id": "expected-1", "title": "Expected vulnerability", "file_path": "app.py"}],
        },
    )
    assert benchmark.status_code == 201
    assert benchmark.json()["false_negative"] == 1

    report = client.get(
        "/api/vulnerabilities/export", params={"format": "md", "project_id": project_id}
    )
    assert report.status_code == 200
    assert len(report.headers["x-content-sha256"]) == 64

    backup = client.post("/api/maintenance/backups", json={"label": "e2e"})
    assert backup.status_code == 201
    assert backup.json()["integrity_status"] == "ok"
    assert client.post(f"/api/maintenance/backups/{backup.json()['id']}/verify").status_code == 200

    deleted = client.delete(f"/projects/{project_id}")
    assert deleted.status_code == 204
    assert client.get("/projects").json() == []

