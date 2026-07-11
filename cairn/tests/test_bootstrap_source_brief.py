from __future__ import annotations

import io
import json
import zipfile

from fastapi import FastAPI
from fastapi.testclient import TestClient

from cairn.dispatcher.tasks.bootstrap import _bootstrap_source_inventory
from cairn.server.models import ProjectDetail
from cairn.server.routers import business_graph, findings, projects, sources


def _client(temp_db) -> TestClient:
    app = FastAPI()
    app.include_router(projects.router)
    app.include_router(sources.router)
    app.include_router(findings.router)
    app.include_router(business_graph.router)
    return TestClient(app)


def _zip_bytes(files: dict[str, bytes]) -> bytes:
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w") as archive:
        for name, content in files.items():
            archive.writestr(name, content)
    return buffer.getvalue()


def _create_project(client: TestClient) -> str:
    response = client.post(
        "/projects",
        json={"title": "brief", "origin": "test", "goal": "audit", "hints": []},
    )
    assert response.status_code == 201
    return response.json()["project"]["id"]


def test_bootstrap_brief_prioritizes_external_input_to_sql(temp_db, monkeypatch, tmp_path):
    monkeypatch.setenv("CAIRN_ARTIFACT_ROOT", str(tmp_path / "artifacts"))
    client = _client(temp_db)
    project_id = _create_project(client)
    payload = _zip_bytes(
        {
            "demo/app.php": b"""<?php
$id=$_GET['id'];
$sql="SELECT * FROM users WHERE id='$id'";
$result=mysql_query($sql);
""",
            "demo/help.php": b"<p>Your secret key is shown in this tutorial.</p>",
        }
    )
    snapshot = client.post(
        f"/api/projects/{project_id}/sources/zip",
        files={"archive": ("source.zip", payload, "application/zip")},
    ).json()

    candidates = client.get(f"/api/projects/{project_id}/audit-candidates").json()
    sql_candidates = [item for item in candidates if "外部输入到数据库执行能力" in item["title"]]
    assert len(sql_candidates) == 1
    assert sql_candidates[0]["severity"] == "high"

    capabilities = client.get(
        f"/api/projects/{project_id}/sources/{snapshot['id']}/capabilities"
    ).json()
    assert not [item for item in capabilities if item["category"] == "credential_access"]

    response = client.get(
        f"/api/projects/{project_id}/sources/{snapshot['id']}/bootstrap-brief"
    )
    assert response.status_code == 200
    brief = response.json()
    assert brief["source_path"].endswith(f"/{snapshot['id']}/source")
    assert brief["priority_candidates"][0]["file_path"] == "app.php"
    assert brief["priority_candidates"][0]["severity"] == "high"
    assert "文件/上传影响面" not in brief["priority_candidates"][0]["priority_reasons"]
    assert brief["entrypoints"][0]["path"] == "app.php"


def test_bootstrap_inventory_is_compact_and_uses_brief(temp_db, monkeypatch, tmp_path):
    monkeypatch.setenv("CAIRN_ARTIFACT_ROOT", str(tmp_path / "artifacts"))
    client = _client(temp_db)
    project_id = _create_project(client)
    payload = _zip_bytes({"demo/app.php": b"<?php echo $_GET['name'];"})
    snapshot = client.post(
        f"/api/projects/{project_id}/sources/zip",
        files={"archive": ("source.zip", payload, "application/zip")},
    ).json()
    detail = ProjectDetail.model_validate(client.get(f"/projects/{project_id}").json())
    brief = client.get(
        f"/api/projects/{project_id}/sources/{snapshot['id']}/bootstrap-brief"
    ).json()

    class BriefClient:
        def get_source_bootstrap_brief(self, requested_project_id: str, requested_snapshot_id: str):
            assert requested_project_id == project_id
            assert requested_snapshot_id == snapshot["id"]
            return brief

    inventory = json.loads(_bootstrap_source_inventory(BriefClient(), detail))
    assert inventory["status"] == "ready"
    assert inventory["file_count"] == 1
    assert inventory["priority_entrypoints"][0]["path"] == "app.php"
    assert "evidence" not in inventory["priority_entrypoints"][0]


def test_static_business_graph_deduplicates_route_feature_and_capability(temp_db, monkeypatch, tmp_path):
    monkeypatch.setenv("CAIRN_ARTIFACT_ROOT", str(tmp_path / "artifacts"))
    client = _client(temp_db)
    project_id = _create_project(client)
    payload = _zip_bytes(
        {
            "demo/app.php": b"""<?php
$token = $_GET['token'];
$password = $_POST['password'];
echo $token;
"""
        }
    )
    client.post(
        f"/api/projects/{project_id}/sources/zip",
        files={"archive": ("source.zip", payload, "application/zip")},
    )

    graph = client.get(f"/api/projects/{project_id}/business-graph").json()
    titles = [node["title"] for node in graph["nodes"]]
    assert titles.count("业务模块 app") == 1
    assert "业务功能 app" not in titles
    sensitive_assets = [
        node for node in graph["nodes"]
        if node["node_type"] == "asset" and node["title"].startswith("敏感资产")
    ]
    assert len(sensitive_assets) == 1
    assert all(node["semantic_key"].startswith("source:") for node in graph["nodes"])
    assert all(node["source_kind"] == "static_index" for node in graph["nodes"])
    assert {node["graph_layer"] for node in graph["nodes"]} <= {"evidence", "audit"}
