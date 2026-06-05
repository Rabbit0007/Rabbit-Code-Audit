from __future__ import annotations

import json

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from cairn.dispatcher.contracts import validate_report_enrichment_payload
from cairn.server import db


TS = "2026-01-01T00:00:00Z"


@pytest.fixture
def report_app(temp_db) -> FastAPI:
    from cairn.server.routers import report_enrichments

    app = FastAPI()
    app.include_router(report_enrichments.router)
    return app


@pytest.fixture
def client(report_app) -> TestClient:
    return TestClient(report_app)


def _insert_project(project_id: str = "p1", title: str = "Audit Project") -> None:
    with db.get_conn() as conn:
        conn.execute(
            "INSERT INTO projects (id, title, status, created_at) VALUES (?, ?, 'active', ?)",
            (project_id, title, TS),
        )


def _insert_snapshot(project_id: str = "p1", snapshot_id: str = "snap_1") -> None:
    with db.get_conn() as conn:
        conn.execute(
            """
            INSERT INTO source_snapshots (
                id, project_id, source_type, status, file_count, total_bytes,
                detected_languages_json, created_at
            )
            VALUES (?, ?, 'zip', 'ready', 1, 10, '{}', ?)
            """,
            (snapshot_id, project_id, TS),
        )


def _insert_finding(
    *,
    project_id: str = "p1",
    snapshot_id: str = "snap_1",
    finding_id: str = "finding_1",
    status: str = "confirmed",
) -> None:
    with db.get_conn() as conn:
        conn.execute(
            """
            INSERT INTO audit_findings (
                id, project_id, snapshot_id, title, category, severity, status,
                cwe, file_path, line_start, line_end, symbol, entry_point,
                business_node_id, description, impact, evidence, remediation,
                discovered_by, reviewed_by, created_at, reviewed_at
            )
            VALUES (
                ?, ?, ?, 'SQL injection', 'injection', 'high', ?,
                'CWE-89', 'index.php', 12, 18, 'showUser',
                'GET /index.php?id=', NULL,
                'id parameter reaches SQL concatenation',
                'authentication bypass and data exposure',
                '$_GET["id"] is concatenated into SELECT without binding',
                'use parameterized queries',
                'worker-a', 'reviewer-b', ?, ?
            )
            """,
            (finding_id, project_id, snapshot_id, status, TS, TS),
        )


def _setup_confirmed_finding() -> None:
    _insert_project()
    _insert_snapshot()
    _insert_finding()


def test_create_report_enrichment_requires_confirmed_finding(client, temp_db):
    _insert_project()
    _insert_snapshot()
    _insert_finding(status="pending_review")

    response = client.post(
        "/api/projects/p1/report-enrichments",
        json={"finding_id": "finding_1"},
    )

    assert response.status_code == 409
    assert response.json()["detail"] == "Report enrichment only accepts confirmed findings"


def test_report_enrichment_lifecycle_stores_report_only_material(client, temp_db):
    _setup_confirmed_finding()

    created = client.post(
        "/api/projects/p1/report-enrichments",
        json={"finding_id": "finding_1", "created_by": "tester"},
    )
    assert created.status_code == 201
    task_id = created.json()["id"]

    claimed = client.post(f"/api/report-enrichments/{task_id}/claim", json={"worker": "reporter-1"})
    assert claimed.status_code == 200
    assert claimed.json()["status"] == "running"

    completed = client.post(
        f"/api/report-enrichments/{task_id}/complete",
        json={
            "worker": "reporter-1",
            "packet_templates": [
                {
                    "title": "SQL 注入静态推测请求",
                    "payload": "id=1' OR '1'='1",
                    "request": "GET /index.php?id=1%27%20OR%20%271%27%3D%271 HTTP/1.1\nHost: target\nConnection: close",
                    "expected_result": "响应差异体现 SQL 条件被拼接执行",
                    "verification": "index.php 中 id 参数进入 SQL 拼接",
                    "note": "静态推测验证请求，不是实测抓包",
                }
            ],
            "reproduction_poc": {
                "payload": "id=1' OR '1'='1",
                "request_template": "curl -i 'http://target/index.php?id=1%27%20OR%20%271%27%3D%271'",
                "steps": ["替换 target", "发送请求", "观察响应差异"],
                "expected_result": "返回内容与正常请求不同",
                "verification": "源码证据显示参数未绑定",
                "limitations": ["静态推导，不包含真实响应包"],
            },
            "evidence_chain": ["finding_1 已确认", "审计日志记录 reviewer-b 确认"],
            "report_sections": {"影响说明": "攻击者可绕过查询条件。"},
            "delivery_notes": ["需在测试环境补充真实响应包。"],
        },
    )

    assert completed.status_code == 200
    body = completed.json()
    assert body["status"] == "completed"
    assert body["packet_templates"][0]["title"] == "SQL 注入静态推测请求"

    with db.get_conn() as conn:
        finding = conn.execute(
            "SELECT proof_packets_json, reproduction_poc_json FROM audit_findings WHERE id = 'finding_1'"
        ).fetchone()
        assert finding["proof_packets_json"] == "[]"
        assert finding["reproduction_poc_json"] == "{}"


def test_report_enrichment_queue_cancel_retry_and_dedupes_active_task(client, temp_db):
    _setup_confirmed_finding()

    created = client.post(
        "/api/projects/p1/report-enrichments",
        json={"finding_id": "finding_1", "created_by": "tester"},
    )
    assert created.status_code == 201
    task = created.json()

    duplicate = client.post(
        "/api/projects/p1/report-enrichments",
        json={"finding_id": "finding_1", "created_by": "tester-2"},
    )
    assert duplicate.status_code == 201
    assert duplicate.json()["id"] == task["id"]
    assert duplicate.json()["created_by"] == "tester"

    queue = client.get("/api/report-enrichment-tasks").json()
    assert queue[0]["id"] == task["id"]
    assert queue[0]["project_title"] == "Audit Project"
    assert queue[0]["finding_title"] == "SQL injection"
    assert queue[0]["finding_severity"] == "high"

    cancelled = client.post(f"/api/report-enrichments/{task['id']}/cancel", json={"worker": "Human"})
    assert cancelled.status_code == 200
    assert cancelled.json()["status"] == "failed"
    assert "Cancelled by Human" in cancelled.json()["error_message"]

    retried = client.post(f"/api/report-enrichments/{task['id']}/retry", json={"worker": "Human"})
    assert retried.status_code == 200
    assert retried.json()["status"] == "pending"
    assert retried.json()["worker"] is None
    assert retried.json()["packet_templates"] == []
    assert retried.json()["reproduction_poc"] == {}


def test_complete_rejects_observed_response_in_packet_template(client, temp_db):
    _setup_confirmed_finding()
    created = client.post("/api/projects/p1/report-enrichments", json={"finding_id": "finding_1"})
    task_id = created.json()["id"]
    client.post(f"/api/report-enrichments/{task_id}/claim", json={"worker": "reporter-1"})

    response = client.post(
        f"/api/report-enrichments/{task_id}/complete",
        json={
            "worker": "reporter-1",
            "packet_templates": [
                {
                    "title": "bad",
                    "request": "GET /index.php?id=1 HTTP/1.1\nHost: target",
                    "response": "HTTP/1.1 200 OK",
                    "expected_result": "difference",
                }
            ],
        },
    )

    assert response.status_code == 422
    assert "must not contain observed response" in response.json()["detail"]


def test_evidence_packet_contains_confirmed_context(client, temp_db):
    _setup_confirmed_finding()
    with db.get_conn() as conn:
        conn.execute(
            "INSERT INTO facts (id, project_id, description) VALUES ('f1', 'p1', 'SQL 注入确认时间线')"
        )
        conn.execute(
            """
            INSERT INTO intents (
                id, project_id, to_fact_id, description, creator, worker, created_at, concluded_at
            )
            VALUES ('intent_1', 'p1', 'f1', 'review SQL injection', 'system', 'worker-a', ?, ?)
            """,
            (TS, TS),
        )
        conn.execute(
            """
            INSERT INTO audit_log (created_at, actor, action, target_type, target_id, summary, detail)
            VALUES (?, 'reviewer-b', 'finding.review', 'audit_finding', 'finding_1', '已确认 finding_1', '{}')
            """,
            (TS,),
        )
        conn.execute(
            """
            INSERT INTO code_entrypoints (
                id, snapshot_id, path, language, kind, framework, method, route, handler, line_start, evidence
            )
            VALUES ('ep_1', 'snap_1', 'index.php', 'php', 'route', NULL, 'GET', '/index.php', 'showUser', 1, 'route evidence')
            """
        )

    created = client.post("/api/projects/p1/report-enrichments", json={"finding_id": "finding_1"})
    task_id = created.json()["id"]
    packet = client.get(f"/api/report-enrichments/{task_id}/packet")

    assert packet.status_code == 200
    body = packet.json()
    assert body["finding"]["id"] == "finding_1"
    assert body["finding"]["status"] == "confirmed"
    assert body["timeline"]["facts"][0]["description"] == "SQL 注入确认时间线"
    assert body["timeline"]["intents"][0]["id"] == "intent_1"
    assert body["audit_log"][0]["target_id"] == "finding_1"
    assert body["code_index"]["entrypoints"][0]["route"] == "/index.php"
    assert "Do not create proof_packets" in body["rules"]["proof_packets"]


def test_report_enrichment_contract_rejects_discovery_outputs():
    with pytest.raises(ValueError, match="unexpected keys"):
        validate_report_enrichment_payload(
            {
                "accepted": True,
                "data": {
                    "findings": [{"title": "new finding"}],
                    "packet_templates": [
                        {
                            "title": "request",
                            "request": "GET / HTTP/1.1\nHost: target",
                            "expected_result": "difference",
                        }
                    ],
                },
            }
        )

    with pytest.raises(ValueError, match="must not emit proof_packets"):
        validate_report_enrichment_payload(
            {
                "packet_templates": [
                    {
                        "title": "request",
                        "request": "GET / HTTP/1.1\nHost: target",
                        "expected_result": "difference",
                    }
                ],
                "proof_packets": [],
            }
        )


def test_report_enrichment_contract_accepts_static_material():
    kind, data = validate_report_enrichment_payload(
        {
            "finding_id": "finding_1",
            "packet_templates": [
                {
                    "title": "SQL 注入静态请求",
                    "request": "GET /index.php?id=1%27 HTTP/1.1\nHost: target",
                    "expected_result": "SQL 错误或响应差异",
                    "verification": "源码中 id 进入 SQL 拼接",
                }
            ],
            "evidence_chain": ["finding_1 已确认"],
            "report_sections": {"复测说明": "替换目标地址后发送请求。"},
            "delivery_notes": ["不是实测抓包。"],
        }
    )

    assert kind == "complete"
    assert data is not None
    assert data["finding_id"] == "finding_1"
    assert data["packet_templates"][0]["title"] == "SQL 注入静态请求"
