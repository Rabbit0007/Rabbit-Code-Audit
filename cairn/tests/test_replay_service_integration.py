"""End-to-end (server-side) test of the replay verification chain.

Upload source, create a high-severity finding that carries a verification plan,
configure the project's lab target, trigger a replay through the API, and assert
the finding is upgraded to the replay-only evidence level L4 with a proof packet
the server actually produced.  The safe twin must stay at its model-authored
level and never gain an L4.
"""

from __future__ import annotations

import io
import zipfile

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from cairn.server.routers import findings, projects, sources

from .lab_target import LabTarget


def _app(temp_db) -> FastAPI:
    app = FastAPI()
    app.include_router(projects.router)
    app.include_router(sources.router)
    app.include_router(findings.router)
    return app


@pytest.fixture
def client(temp_db):
    return TestClient(_app(temp_db))


@pytest.fixture
def lab():
    with LabTarget() as target:
        yield target


def _project(client) -> str:
    resp = client.post("/projects", json={"title": "audit", "origin": "src", "goal": "review", "hints": []})
    assert resp.status_code == 201
    return resp.json()["project"]["id"]


def _snapshot(client, project_id: str) -> str:
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w") as archive:
        archive.writestr("app.py", b"print('ok')")
    resp = client.post(
        f"/api/projects/{project_id}/sources/zip",
        files={"archive": ("demo.zip", buffer.getvalue(), "application/zip")},
    )
    assert resp.status_code == 201
    return resp.json()["id"]


STATIC_POC = {
    "payload": "q=x'",
    "request_template": "curl 'http://target/search?q=x%27'",
    "steps": ["send the request", "observe the database error in the response"],
    "expected_result": "a SQL syntax error is returned",
    "verification": "the error only appears when a quote is injected",
}


def _finding(client, project_id, snapshot_id, *, path_prefix, plan_path):
    body = {
        "snapshot_id": snapshot_id,
        "title": "SQL injection in search",
        "category": "sql injection",
        "severity": "high",
        "cwe": "CWE-89",
        "file_path": "app/search.py",
        "line_start": 10,
        "entry_point": f"GET {path_prefix}",
        "description": "The q parameter is concatenated into a SQL query without parameterization.",
        "impact": "database read",
        "evidence": "user input concatenated into a SQL query",
        "reproduction_poc": STATIC_POC,
        "verification_plan": {
            "oracle": "sql_error",
            "requests": {"attack": {"path": plan_path + "?q=x%27"}, "baseline": {"path": plan_path + "?q=x"}},
        },
        "discovered_by": "worker-a",
    }
    resp = client.post(f"/api/projects/{project_id}/audit-findings", json=body)
    assert resp.status_code == 201, resp.text
    return resp.json()


def _set_target(client, project_id, base_url, **extra):
    resp = client.put(
        f"/api/projects/{project_id}/audit-validation-target",
        json={"base_url": base_url, **extra},
    )
    assert resp.status_code == 200, resp.text
    return resp.json()


def test_finding_created_with_plan_is_l3_until_replayed(client, lab):
    project_id = _project(client)
    snapshot_id = _snapshot(client, project_id)
    finding = _finding(client, project_id, snapshot_id, path_prefix="/search", plan_path="/search")
    # A model-authored static PoC is L3; the plan alone does not raise it.
    assert finding["evidence_level"] == "L3"
    assert finding["verification_plan"]["oracle"] == "sql_error"
    assert finding["replay_verdict"] is None


def test_replay_confirms_real_bug_and_upgrades_to_l4(client, lab):
    project_id = _project(client)
    snapshot_id = _snapshot(client, project_id)
    finding = _finding(client, project_id, snapshot_id, path_prefix="/search", plan_path="/search")
    _set_target(client, project_id, lab.base_url)

    resp = client.post(f"/api/projects/{project_id}/audit-findings/{finding['id']}/replay")
    assert resp.status_code == 200, resp.text
    result = resp.json()
    assert result["verdict"] == "confirmed", result
    assert result["evidence_level"] == "L4"

    # The upgrade and a server-produced packet are persisted on the finding.
    detail = client.get(f"/api/projects/{project_id}/audit-findings").json()
    stored = next(item for item in detail if item["id"] == finding["id"])
    assert stored["evidence_level"] == "L4"
    assert stored["replay_verdict"] == "confirmed"
    assert any("服务端重放验证" in packet.get("title", "") for packet in stored["proof_packets"])


def test_replay_does_not_confirm_safe_twin(client, lab):
    project_id = _project(client)
    snapshot_id = _snapshot(client, project_id)
    finding = _finding(client, project_id, snapshot_id, path_prefix="/search_safe", plan_path="/search_safe")
    _set_target(client, project_id, lab.base_url)

    resp = client.post(f"/api/projects/{project_id}/audit-findings/{finding['id']}/replay")
    assert resp.status_code == 200, resp.text
    result = resp.json()
    assert result["verdict"] != "confirmed"
    assert result["evidence_level"] == "L3"  # unchanged


def test_replay_without_target_is_409(client, lab):
    project_id = _project(client)
    snapshot_id = _snapshot(client, project_id)
    finding = _finding(client, project_id, snapshot_id, path_prefix="/search", plan_path="/search")
    resp = client.post(f"/api/projects/{project_id}/audit-findings/{finding['id']}/replay")
    assert resp.status_code == 409


def test_target_secrets_are_redacted_on_read(client, lab):
    project_id = _project(client)
    _snapshot(client, project_id)
    _set_target(
        client,
        project_id,
        lab.base_url,
        profiles={"alice": {"headers": {"Cookie": "sid=alice-session"}}},
    )
    read = client.get(f"/api/projects/{project_id}/audit-validation-target").json()
    assert read["configured"] is True
    assert read["target"]["profiles"]["alice"]["headers"]["Cookie"] == "***"


def test_target_rejects_link_local_base_url(client):
    project_id = _project(client)
    resp = client.put(
        f"/api/projects/{project_id}/audit-validation-target",
        json={"base_url": "http://169.254.169.254/"},
    )
    assert resp.status_code == 400
