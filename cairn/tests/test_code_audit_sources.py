from __future__ import annotations

import io
import zipfile

from fastapi import FastAPI
from fastapi.testclient import TestClient

from cairn.dispatcher.contracts import validate_explore_payload
from cairn.server.routers import findings, projects, sources, vulnerabilities


def _app(temp_db) -> FastAPI:
    app = FastAPI()
    app.include_router(projects.router)
    app.include_router(sources.router)
    app.include_router(findings.router)
    app.include_router(vulnerabilities.router)
    return app


def _client(temp_db) -> TestClient:
    return TestClient(_app(temp_db))


def _create_project(client: TestClient) -> str:
    response = client.post(
        "/projects",
        json={
            "title": "audit",
            "origin": "source audit",
            "goal": "review scope",
            "hints": [],
        },
    )
    assert response.status_code == 201
    return response.json()["project"]["id"]


def _zip_bytes(files: dict[str, bytes]) -> bytes:
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w") as archive:
        for name, content in files.items():
            archive.writestr(name, content)
    return buffer.getvalue()


def test_explore_payload_accepts_structured_finding_and_review():
    kind, finding_result = validate_explore_payload(
        {
            "accepted": True,
            "data": {
                "description": "confirmed code evidence",
                "tool_findings": [
                    {
                        "tool_name": "semgrep",
                        "title": "candidate",
                        "description": "scanner output",
                    }
                ],
                "finding": {
                    "title": "authorization bypass",
                    "category": "authorization",
                    "severity": "high",
                    "description": "resource ownership is not checked",
                },
            },
        }
    )
    assert kind == "fact"
    assert finding_result["finding"]["severity"] == "high"
    assert finding_result["tool_findings"][0]["tool_name"] == "semgrep"

    _, review_result = validate_explore_payload(
        {
            "accepted": True,
            "data": {
                "description": "independent review completed",
                "review": {"finding_id": "finding_1", "decision": "confirmed"},
            },
        }
    )
    assert review_result["review"]["finding_id"] == "finding_1"


def test_zip_source_import_creates_immutable_snapshot_and_file_index(temp_db, monkeypatch, tmp_path):
    monkeypatch.setenv("CAIRN_ARTIFACT_ROOT", str(tmp_path / "artifacts"))
    client = _client(temp_db)
    project_id = _create_project(client)

    payload = _zip_bytes(
        {
            "demo/app.py": b"print('hello')\n",
            "demo/composer.json": b'{"require": {}}\n',
            "demo/public/index.php": b"<?php echo 'ok';\n",
        }
    )
    response = client.post(
        f"/api/projects/{project_id}/sources/zip",
        files={"archive": ("demo.zip", payload, "application/zip")},
    )

    assert response.status_code == 201
    snapshot = response.json()
    assert snapshot["status"] == "ready"
    assert snapshot["source_type"] == "zip"
    assert snapshot["file_count"] == 3
    assert snapshot["detected_languages"] == {"PHP": 1, "Python": 1}
    assert len(snapshot["archive_sha256"]) == 64
    assert len(snapshot["snapshot_sha256"]) == 64

    files = client.get(f"/api/projects/{project_id}/sources/{snapshot['id']}/files").json()
    assert [item["path"] for item in files] == ["app.py", "composer.json", "public/index.php"]
    assert {item["language"] for item in files} == {None, "PHP", "Python"}

    project = client.get(f"/projects/{project_id}").json()
    assert project["sources"][0]["id"] == snapshot["id"]


def test_zip_source_import_rejects_path_escape(temp_db, monkeypatch, tmp_path):
    monkeypatch.setenv("CAIRN_ARTIFACT_ROOT", str(tmp_path / "artifacts"))
    client = _client(temp_db)
    project_id = _create_project(client)
    payload = _zip_bytes({"../escape.php": b"<?php echo 'bad';"})

    response = client.post(
        f"/api/projects/{project_id}/sources/zip",
        files={"archive": ("escape.zip", payload, "application/zip")},
    )

    assert response.status_code == 400
    assert "escapes the archive root" in response.json()["detail"]
    snapshots = client.get(f"/api/projects/{project_id}/sources").json()
    assert snapshots[0]["status"] == "failed"


def test_zip_source_import_rejects_symbolic_link(temp_db, monkeypatch, tmp_path):
    monkeypatch.setenv("CAIRN_ARTIFACT_ROOT", str(tmp_path / "artifacts"))
    client = _client(temp_db)
    project_id = _create_project(client)
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w") as archive:
        link = zipfile.ZipInfo("app-link")
        link.create_system = 3
        link.external_attr = 0o120777 << 16
        archive.writestr(link, "/etc/passwd")

    response = client.post(
        f"/api/projects/{project_id}/sources/zip",
        files={"archive": ("link.zip", buffer.getvalue(), "application/zip")},
    )

    assert response.status_code == 400
    assert "symbolic link" in response.json()["detail"]


def test_git_source_import_rejects_private_network_url(temp_db):
    client = _client(temp_db)
    project_id = _create_project(client)

    response = client.post(
        f"/api/projects/{project_id}/sources/git",
        json={"repository_url": "http://127.0.0.1/private.git"},
    )

    assert response.status_code == 400
    assert "public network addresses" in response.json()["detail"]


def test_high_severity_finding_requires_different_reviewer(temp_db, monkeypatch, tmp_path):
    monkeypatch.setenv("CAIRN_ARTIFACT_ROOT", str(tmp_path / "artifacts"))
    client = _client(temp_db)
    project_id = _create_project(client)
    payload = _zip_bytes({"app.php": b"<?php echo $_GET['x'];"})
    snapshot = client.post(
        f"/api/projects/{project_id}/sources/zip",
        files={"archive": ("demo.zip", payload, "application/zip")},
    ).json()

    created = client.post(
        f"/api/projects/{project_id}/audit-findings",
        json={
            "snapshot_id": snapshot["id"],
            "title": "candidate",
            "category": "authorization",
            "severity": "high",
            "description": "evidence",
            "discovered_by": "worker-a",
        },
    )
    assert created.status_code == 201
    finding = created.json()
    assert finding["status"] == "pending_review"
    assert client.get("/api/vulnerabilities").json() == []

    same_worker = client.post(
        f"/api/projects/{project_id}/audit-findings/{finding['id']}/review",
        json={"reviewer": "worker-a", "decision": "confirmed"},
    )
    assert same_worker.status_code == 409

    reviewed = client.post(
        f"/api/projects/{project_id}/audit-findings/{finding['id']}/review",
        json={"reviewer": "worker-b", "decision": "confirmed"},
    )
    assert reviewed.status_code == 200
    assert reviewed.json()["status"] == "confirmed"
    assert reviewed.json()["reviewed_by"] == "worker-b"

    report = client.get("/api/vulnerabilities").json()
    assert len(report) == 1
    assert report[0]["fact_id"] == finding["id"]
    assert report[0]["source_worker"] == "worker-a"
