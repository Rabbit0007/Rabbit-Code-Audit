from __future__ import annotations

import io
import json
from types import SimpleNamespace
import zipfile

from fastapi import FastAPI
from fastapi.testclient import TestClient

from cairn.server import db
from cairn.server.audit_tool_runner import parse_tool_output, persist_tool_findings
from cairn.dispatcher.runtime.cancellation import TaskCancellation
from cairn.dispatcher.tasks.tool_scan import run_tool_scan_task
from cairn.server.routers import findings, projects, sources, tool_scans


def _app(temp_db) -> FastAPI:
    app = FastAPI()
    app.include_router(projects.router)
    app.include_router(sources.router)
    app.include_router(findings.router)
    app.include_router(tool_scans.router)
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


def test_semgrep_output_is_stored_as_tool_candidate_only(temp_db, monkeypatch, tmp_path):
    monkeypatch.setenv("CAIRN_ARTIFACT_ROOT", str(tmp_path / "artifacts"))
    client = _client(temp_db)
    project_id = _create_project(client)
    snapshot = client.post(
        f"/api/projects/{project_id}/sources/zip",
        files={"archive": ("demo.zip", _zip_bytes({"app.php": b"<?php echo $_GET['x'];"}), "application/zip")},
    ).json()

    parsed = parse_tool_output(
        "semgrep",
        json.dumps(
            {
                "results": [
                    {
                        "check_id": "php.lang.security.echoed-request",
                        "path": "app.php",
                        "start": {"line": 1},
                        "end": {"line": 1},
                        "extra": {
                            "severity": "WARNING",
                            "message": "User input is echoed without output encoding",
                        },
                    }
                ]
            }
        ),
        raw_artifact_path="/tmp/semgrep.json",
    )
    assert len(parsed) == 1
    assert parsed[0].severity == "medium"

    persist_tool_findings(project_id, snapshot["id"], parsed)

    with db.get_conn() as conn:
        tool_rows = conn.execute(
            "SELECT tool_name, rule_id, severity, status FROM tool_findings WHERE project_id = ?",
            (project_id,),
        ).fetchall()
        candidate_rows = conn.execute(
            "SELECT source, candidate_type, severity, status FROM audit_candidates WHERE project_id = ? AND source = 'tool'",
            (project_id,),
        ).fetchall()
        finding_rows = conn.execute(
            "SELECT id FROM audit_findings WHERE project_id = ?",
            (project_id,),
        ).fetchall()

    assert [row["tool_name"] for row in tool_rows] == ["semgrep"]
    assert tool_rows[0]["status"] == "candidate"
    assert len(candidate_rows) == 1
    assert candidate_rows[0]["source"] == "tool"
    assert candidate_rows[0]["candidate_type"] == "tool_finding"
    assert candidate_rows[0]["status"] == "candidate"
    assert finding_rows == []


def test_tool_scan_endpoint_delegates_to_candidate_runner(temp_db, monkeypatch, tmp_path):
    monkeypatch.setenv("CAIRN_ARTIFACT_ROOT", str(tmp_path / "artifacts"))
    client = _client(temp_db)
    project_id = _create_project(client)
    snapshot = client.post(
        f"/api/projects/{project_id}/sources/zip",
        files={"archive": ("demo.zip", _zip_bytes({"app.py": b"print('ok')"}), "application/zip")},
    ).json()

    from cairn.server.routers import sources

    calls = []

    def fake_runner(project_id_arg, *, snapshot_id=None, timeout_per_tool=180, selected_tools=None):
        calls.append(
            {
                "project_id": project_id_arg,
                "snapshot_id": snapshot_id,
                "timeout_per_tool": timeout_per_tool,
                "selected_tools": selected_tools,
            }
        )

        return [SimpleNamespace(tool_name="semgrep", status="skipped", finding_count=0)]

    monkeypatch.setattr(sources, "run_audit_tools_for_project", fake_runner)
    response = client.post(
        f"/api/projects/{project_id}/sources/{snapshot['id']}/tool-scan",
        params={"timeout_per_tool": 30, "tools": "semgrep,gitleaks"},
    )

    assert response.status_code == 200
    assert response.json()[0]["tool_name"] == "semgrep"
    assert calls == [
        {
            "project_id": project_id,
            "snapshot_id": snapshot["id"],
            "timeout_per_tool": 30,
            "selected_tools": {"semgrep", "gitleaks"},
        }
    ]


def test_tool_scan_task_lifecycle_is_background_candidate_work(temp_db, monkeypatch, tmp_path):
    monkeypatch.setenv("CAIRN_ARTIFACT_ROOT", str(tmp_path / "artifacts"))
    client = _client(temp_db)
    project_id = _create_project(client)
    snapshot = client.post(
        f"/api/projects/{project_id}/sources/zip",
        files={"archive": ("demo.zip", _zip_bytes({"app.py": b"print('ok')"}), "application/zip")},
    ).json()

    created = client.post(
        f"/api/projects/{project_id}/sources/{snapshot['id']}/tool-scan-tasks",
        json={"created_by": "tester", "tools": ["semgrep", "semgrep", "gitleaks"], "timeout_per_tool": 30},
    )
    assert created.status_code == 201
    task = created.json()
    assert task["status"] == "pending"
    assert task["tools"] == ["semgrep", "gitleaks"]

    pending = client.get("/api/tool-scans/pending").json()
    assert [item["id"] for item in pending] == [task["id"]]

    claimed = client.post(f"/api/tool-scans/{task['id']}/claim", json={"worker": "dispatcher.tool_scan"})
    assert claimed.status_code == 200
    assert claimed.json()["status"] == "running"

    completed = client.post(
        f"/api/tool-scans/{task['id']}/complete",
        json={
            "worker": "dispatcher.tool_scan",
            "summaries": [{"tool_name": "semgrep", "status": "skipped", "finding_count": 0}],
        },
    )
    assert completed.status_code == 200
    assert completed.json()["status"] == "completed"
    assert completed.json()["summaries"][0]["tool_name"] == "semgrep"

    with db.get_conn() as conn:
        rows = conn.execute("SELECT id FROM audit_findings WHERE project_id = ?", (project_id,)).fetchall()
    assert rows == []


def test_tool_scan_task_queue_cancel_and_retry(temp_db, monkeypatch, tmp_path):
    monkeypatch.setenv("CAIRN_ARTIFACT_ROOT", str(tmp_path / "artifacts"))
    client = _client(temp_db)
    project_id = _create_project(client)
    snapshot = client.post(
        f"/api/projects/{project_id}/sources/zip",
        files={"archive": ("demo.zip", _zip_bytes({"app.py": b"print('ok')"}), "application/zip")},
    ).json()
    task = client.post(
        f"/api/projects/{project_id}/sources/{snapshot['id']}/tool-scan-tasks",
        json={"created_by": "tester", "tools": ["semgrep"], "timeout_per_tool": 30},
    ).json()

    queue = client.get("/api/tool-scan-tasks").json()
    assert queue[0]["id"] == task["id"]
    assert queue[0]["project_title"]
    assert queue[0]["source_label"]

    cancelled = client.post(f"/api/tool-scans/{task['id']}/cancel", json={"worker": "Human"})
    assert cancelled.status_code == 200
    assert cancelled.json()["status"] == "failed"
    assert "Cancelled by Human" in cancelled.json()["error_message"]

    retried = client.post(f"/api/tool-scans/{task['id']}/retry", json={"worker": "Human"})
    assert retried.status_code == 200
    assert retried.json()["status"] == "pending"
    assert retried.json()["worker"] is None
    assert retried.json()["summaries"] == []


def test_stale_running_tool_scan_is_recovered_to_pending(temp_db, monkeypatch, tmp_path):
    monkeypatch.setenv("CAIRN_ARTIFACT_ROOT", str(tmp_path / "artifacts"))
    client = _client(temp_db)
    project_id = _create_project(client)
    snapshot = client.post(
        f"/api/projects/{project_id}/sources/zip",
        files={"archive": ("demo.zip", _zip_bytes({"app.py": b"print('ok')"}), "application/zip")},
    ).json()
    task = client.post(
        f"/api/projects/{project_id}/sources/{snapshot['id']}/tool-scan-tasks",
        json={"created_by": "tester", "tools": ["semgrep"], "timeout_per_tool": 30},
    ).json()
    claimed = client.post(f"/api/tool-scans/{task['id']}/claim", json={"worker": "dispatcher.tool_scan"})
    assert claimed.status_code == 200
    with db.get_conn() as conn:
        conn.execute(
            "UPDATE tool_scan_tasks SET last_heartbeat_at = '2020-01-01T00:00:00Z' WHERE id = ?",
            (task["id"],),
        )

    pending = client.get("/api/tool-scans/pending", params={"project_id": project_id}).json()

    assert [item["id"] for item in pending] == [task["id"]]
    assert pending[0]["status"] == "pending"
    assert pending[0]["worker"] is None
    assert "Recovered stale tool scan task" in pending[0]["error_message"]


def test_dispatcher_tool_scan_task_runs_tools_one_by_one():
    class _FakeResponse:
        status_code = 200
        text = ""

        @property
        def ok(self):
            return True

    class _FakeClient:
        def __init__(self):
            self.scanned: list[list[str]] = []
            self.completed = None

        def get_tool_plan(self, project_id, snapshot_id):
            return [{"name": "semgrep"}, {"name": "gitleaks"}]

        def tool_scan_heartbeat(self, task_id, worker):
            return _FakeResponse()

        def run_tool_scan(self, project_id, snapshot_id, *, timeout_per_tool, tools):
            self.scanned.append(tools)
            return [{"tool_name": tools[0], "status": "skipped", "finding_count": 0}]

        def complete_tool_scan(self, task_id, payload):
            self.completed = payload
            return _FakeResponse()

        def release_tool_scan(self, task_id, worker):
            return _FakeResponse()

        def fail_tool_scan(self, task_id, worker, error_message):
            return _FakeResponse()

    config = SimpleNamespace(tasks=SimpleNamespace(tool_scan=SimpleNamespace(timeout_per_tool=30)))
    client = _FakeClient()
    outcome = run_tool_scan_task(
        config,
        client,
        {
            "id": "scan_1",
            "project_id": "proj_001",
            "snapshot_id": "snap_1",
            "worker": "dispatcher.tool_scan",
            "timeout_per_tool": 30,
            "tools": [],
        },
        TaskCancellation(),
    )

    assert outcome.status == "success"
    assert client.scanned == [["semgrep"], ["gitleaks"]]
    assert client.completed["worker"] == "dispatcher.tool_scan"
    assert [item["tool_name"] for item in client.completed["summaries"]] == ["semgrep", "gitleaks"]


def test_dynamic_validation_plan_is_plan_only(temp_db, monkeypatch, tmp_path):
    monkeypatch.setenv("CAIRN_ARTIFACT_ROOT", str(tmp_path / "artifacts"))
    client = _client(temp_db)
    project_id = _create_project(client)
    payload = _zip_bytes(
        {
            "docker-compose.yml": b"services:\n  app:\n    build: .\n",
            "package.json": json.dumps({"scripts": {"start": "node server.js", "test": "vitest"}}).encode(),
            "server.js": b"require('express')()",
        }
    )
    snapshot = client.post(
        f"/api/projects/{project_id}/sources/zip",
        files={"archive": ("demo.zip", payload, "application/zip")},
    ).json()

    plan = client.get(f"/api/projects/{project_id}/sources/{snapshot['id']}/dynamic-validation-plan").json()

    assert plan["mode"] == "plan_only"
    assert plan["execution_default"] == "disabled"
    assert plan["status"] == "ready"
    assert any(item["type"] == "docker_compose" for item in plan["launch_indicators"])
    assert any("不会自动执行目标项目命令" in warning for warning in plan["warnings"])

    persisted = client.post(
        f"/api/projects/{project_id}/sources/{snapshot['id']}/dynamic-validation-plan",
        json={"created_by": "tester"},
    ).json()
    assert persisted["id"].startswith("vplan_")
    assert persisted["created_by"] == "tester"
