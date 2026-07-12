from __future__ import annotations

import json

from fastapi import FastAPI
from fastapi.testclient import TestClient

from cairn.server.routers import business_graph, intents, projects
from cairn.server.db import get_conn

from .conftest import BASE_URL


def _client() -> TestClient:
    app = FastAPI()
    app.include_router(projects.router)
    app.include_router(intents.router)
    app.include_router(business_graph.router)
    return TestClient(app, base_url=BASE_URL)


def _create_project(client: TestClient) -> str:
    response = client.post(
        "/projects",
        json={
            "title": "completion guard",
            "origin": "source archive",
            "goal": "audit the source",
        },
    )
    assert response.status_code == 201
    return response.json()["project"]["id"]


def _proof_packet_json() -> str:
    return json.dumps(
        [
            {
                "title": "authorization bypass proof",
                "payload": "order_id=1002&status=refunded",
                "request": (
                    "POST /refund HTTP/1.1\n"
                    "Host: audit.local\n"
                    "Content-Type: application/x-www-form-urlencoded\n"
                    "Content-Length: 29\n\n"
                    "order_id=1002&status=refunded"
                ),
                "response": (
                    "HTTP/1.1 200 OK\n"
                    "Content-Type: application/json\n\n"
                    '{"status":"refunded","order_id":1002}'
                ),
                "note": "test proof packet",
            }
        ],
        ensure_ascii=False,
    )


def _reproduction_poc_json() -> str:
    return json.dumps(
        {
            "payload": "id=1' OR '1'='1",
            "request_template": (
                "curl 'http://target/login.php?id=1%27%20OR%20%271%27%3D%271'"
            ),
            "steps": [
                "替换 target 为测试环境地址",
                "发送注入请求并观察响应差异",
            ],
            "expected_result": "响应返回额外数据或出现 SQL 错误差异",
            "verification": "源码中 $_GET['id'] 被拼接进 SELECT 查询",
            "limitations": ["该 PoC 为源码静态推导，未包含真实抓包响应"],
        },
        ensure_ascii=False,
    )


def test_complete_rejects_open_intents(temp_db):
    client = _client()
    project_id = _create_project(client)

    create_intent = client.post(
        f"/projects/{project_id}/intents",
        json={
            "from": ["origin"],
            "description": "review upload endpoint",
            "creator": "worker-1",
        },
    )
    assert create_intent.status_code == 201

    complete = client.post(
        f"/projects/{project_id}/complete",
        json={"from": ["origin"], "description": "done", "worker": "worker-1"},
    )

    assert complete.status_code == 409
    detail = complete.json()["detail"]
    assert detail["message"] == "Project still has open intents"
    assert detail["open_intents"][0]["description"] == "review upload endpoint"


def test_complete_ignores_superseded_intents_without_result_fact(temp_db):
    client = _client()
    project_id = _create_project(client)

    create_intent = client.post(
        f"/projects/{project_id}/intents",
        json={
            "from": ["origin"],
            "description": "obsolete investigation",
            "creator": "worker-1",
        },
    )
    assert create_intent.status_code == 201
    intent_id = create_intent.json()["id"]
    with get_conn() as conn:
        conn.execute(
            "UPDATE intents SET status = 'superseded' WHERE id = ? AND project_id = ?",
            (intent_id, project_id),
        )

    complete = client.post(
        f"/projects/{project_id}/complete",
        json={"from": ["origin"], "description": "done", "worker": "worker-1"},
    )

    assert complete.status_code == 200
    assert complete.json()["to"] == "goal"


def test_complete_rejects_unreviewed_high_risk_business_nodes(temp_db):
    client = _client()
    project_id = _create_project(client)

    node = client.post(
        f"/api/projects/{project_id}/business-graph/nodes",
        json={
            "node_type": "endpoint",
            "title": "file upload",
            "risk_level": "high",
            "review_status": "unreviewed",
            "created_by": "worker-1",
        },
    )
    assert node.status_code == 201

    complete = client.post(
        f"/projects/{project_id}/complete",
        json={"from": ["origin"], "description": "done", "worker": "worker-1"},
    )

    assert complete.status_code == 409
    detail = complete.json()["detail"]
    assert detail["message"] == (
        "Critical, high, or unknown-risk business nodes require code coverage before completion"
    )
    assert detail["business_nodes"][0]["title"] == "file upload"


def test_complete_rejects_open_required_audit_candidates(temp_db):
    client = _client()
    project_id = _create_project(client)

    with get_conn() as conn:
        conn.execute(
            """
            INSERT INTO source_snapshots (
                id, project_id, source_type, status, file_count, total_bytes,
                detected_languages_json, created_at
            )
            VALUES ('snap_1', ?, 'zip', 'ready', 1, 10, '{}', '2026-01-01T00:00:00Z')
            """,
            (project_id,),
        )
        conn.execute(
            """
            INSERT INTO audit_candidates (
                id, project_id, snapshot_id, source, candidate_type, severity,
                title, description, file_path, line_start, entry_point,
                status, created_by, created_at, updated_at
            )
            VALUES (
                'cand_1', ?, 'snap_1', 'index', 'data_flow', 'high',
                '审计数据流: 外部输入到文件写入 app.js:9', 'filename from request reaches writeFile',
                'app.js', 9, 'POST /upload', 'candidate',
                'source_index', '2026-01-01T00:00:01Z', '2026-01-01T00:00:01Z'
            )
            """,
            (project_id,),
        )

    complete = client.post(
        f"/projects/{project_id}/complete",
        json={"from": ["origin"], "description": "done", "worker": "worker-1"},
    )

    assert complete.status_code == 409
    detail = complete.json()["detail"]
    assert detail["message"] == (
        "Critical, high, or unknown audit candidates require closure before completion"
    )
    assert detail["audit_candidates"][0]["id"] == "cand_1"


def test_complete_ignores_required_candidate_from_stale_snapshot(temp_db):
    client = _client()
    project_id = _create_project(client)

    with get_conn() as conn:
        conn.execute(
            """
            INSERT INTO source_snapshots (
                id, project_id, source_type, status, file_count, total_bytes,
                detected_languages_json, created_at
            )
            VALUES ('snap_old', ?, 'zip', 'ready', 1, 10, '{}', '2026-01-01T00:00:00Z')
            """,
            (project_id,),
        )
        conn.execute(
            """
            INSERT INTO source_snapshots (
                id, project_id, source_type, status, file_count, total_bytes,
                detected_languages_json, created_at
            )
            VALUES ('snap_new', ?, 'zip', 'ready', 1, 10, '{}', '2026-01-02T00:00:00Z')
            """,
            (project_id,),
        )
        conn.execute(
            """
            INSERT INTO audit_candidates (
                id, project_id, snapshot_id, source, candidate_type, severity,
                title, description, file_path, line_start, entry_point,
                status, created_by, created_at, updated_at
            )
            VALUES (
                'cand_old', ?, 'snap_old', 'index', 'data_flow', 'high',
                'stale high-risk candidate', 'old upload flow',
                'old.js', 9, 'POST /old-upload', 'candidate',
                'source_index', '2026-01-01T00:00:01Z', '2026-01-01T00:00:01Z'
            )
            """,
            (project_id,),
        )

    complete = client.post(
        f"/projects/{project_id}/complete",
        json={"from": ["origin"], "description": "done", "worker": "worker-1"},
    )

    assert complete.status_code == 200
    assert complete.json()["to"] == "goal"


def test_complete_does_not_use_stale_snapshot_business_node_as_seed(temp_db):
    client = _client()
    project_id = _create_project(client)

    with get_conn() as conn:
        conn.execute(
            """
            INSERT INTO source_snapshots (
                id, project_id, source_type, status, file_count, total_bytes,
                detected_languages_json, created_at
            )
            VALUES ('snap_old', ?, 'zip', 'ready', 1, 10, '{}', '2026-01-01T00:00:00Z')
            """,
            (project_id,),
        )
        conn.execute(
            """
            INSERT INTO source_snapshots (
                id, project_id, source_type, status, file_count, total_bytes,
                detected_languages_json, created_at
            )
            VALUES ('snap_new', ?, 'zip', 'ready', 1, 10, '{}', '2026-01-02T00:00:00Z')
            """,
            (project_id,),
        )
        conn.execute(
            """
            INSERT INTO business_nodes (
                id, project_id, source_snapshot_id, node_type, title, risk_level,
                review_status, coverage_note, risk_tags_json, evidence_json,
                created_by, created_at, updated_at
            )
            VALUES (
                'biz_old', ?, 'snap_old', 'endpoint', 'old upload',
                'low', 'covered', 'old snapshot only', '[]', '[]',
                'source_index', '2026-01-01T00:00:01Z', '2026-01-01T00:00:01Z'
            )
            """,
            (project_id,),
        )
        conn.execute(
            """
            INSERT INTO code_entrypoints (
                id, snapshot_id, path, language, kind, method, route, handler,
                line_start, evidence, confidence, source
            )
            VALUES (
                'entry_new', 'snap_new', 'app.py', 'python', 'http_route',
                'GET', '/new', 'new_handler', 10, 'route decorator', 0.9,
                'heuristic'
            )
            """
        )

    complete = client.post(
        f"/projects/{project_id}/complete",
        json={"from": ["origin"], "description": "done", "worker": "worker-1"},
    )

    assert complete.status_code == 409
    detail = complete.json()["detail"]
    assert detail["message"] == "Ready source index requires business graph seed before completion"
    assert detail["snapshot_id"] == "snap_new"


def test_complete_allows_index_entrypoint_navigation_candidate(temp_db):
    client = _client()
    project_id = _create_project(client)

    with get_conn() as conn:
        conn.execute(
            """
            INSERT INTO source_snapshots (
                id, project_id, source_type, status, file_count, total_bytes,
                detected_languages_json, created_at
            )
            VALUES ('snap_1', ?, 'zip', 'ready', 1, 10, '{}', '2026-01-01T00:00:00Z')
            """,
            (project_id,),
        )
        conn.execute(
            """
            INSERT INTO audit_candidates (
                id, project_id, snapshot_id, source, candidate_type, severity,
                title, description, file_path, line_start, entry_point,
                status, created_by, created_at, updated_at
            )
            VALUES (
                'cand_nav', ?, 'snap_1', 'index', 'web_entrypoint', 'unknown',
                '审计 Web 脚本: login.php', '需要审计入口参数和权限控制',
                'login.php', 1, '/login.php', 'candidate',
                'source_index', '2026-01-01T00:00:01Z', '2026-01-01T00:00:01Z'
            )
            """,
            (project_id,),
        )

    complete = client.post(
        f"/projects/{project_id}/complete",
        json={"from": ["origin"], "description": "done", "worker": "worker-1"},
    )

    assert complete.status_code == 200
    assert complete.json()["to"] == "goal"


def test_complete_rejects_high_impact_candidate_needing_more_evidence(temp_db):
    client = _client()
    project_id = _create_project(client)

    with get_conn() as conn:
        conn.execute(
            """
            INSERT INTO source_snapshots (
                id, project_id, source_type, status, file_count, total_bytes,
                detected_languages_json, created_at
            )
            VALUES ('snap_1', ?, 'zip', 'ready', 1, 10, '{}', '2026-01-01T00:00:00Z')
            """,
            (project_id,),
        )
        conn.execute(
            """
            INSERT INTO business_nodes (
                id, project_id, node_type, title, risk_level, review_status,
                coverage_note, risk_tags_json, evidence_json, created_by, created_at, updated_at
            )
            VALUES (
                'biz_1', ?, 'risk', '待审计数据流 外部输入到文件读写/加载能力 app.js:9',
                'high', 'blocked', 'worker 只确认到写文件能力，还缺执行/加载边界',
                '["文件读写/加载能力"]', '[]', 'source_index',
                '2026-01-01T00:00:01Z', '2026-01-01T00:00:01Z'
            )
            """,
            (project_id,),
        )
        conn.execute(
            """
            INSERT INTO audit_candidates (
                id, project_id, snapshot_id, source, candidate_type, severity,
                title, description, file_path, line_start, entry_point, business_node_id,
                status, conclusion_summary, evidence, created_by, created_at, updated_at
            )
            VALUES (
                'cand_upload', ?, 'snap_1', 'index', 'data_flow', 'high',
                '审计数据流: 外部输入到文件读写/加载能力 app.js:9',
                'filename from request reaches writeFile',
                'app.js', 9, 'POST /upload', 'biz_1', 'needs_more_evidence',
                '已确认外部输入进入文件写入，但尚未确认执行边界',
                'app.js:9 writeFile(pathFromRequest, body)',
                'source_index', '2026-01-01T00:00:01Z', '2026-01-01T00:00:02Z'
            )
            """,
            (project_id,),
        )

    complete = client.post(
        f"/projects/{project_id}/complete",
        json={"from": ["origin"], "description": "done", "worker": "worker-1"},
    )

    assert complete.status_code == 409
    detail = complete.json()["detail"]
    assert detail["message"] == (
        "High-impact audit candidates require confirmed or rejected closure before completion"
    )
    assert detail["audit_candidates"][0]["reason"] == "high_impact_needs_more_evidence"


def test_complete_rejects_pending_high_audit_findings(temp_db):
    client = _client()
    project_id = _create_project(client)

    with get_conn() as conn:
        conn.execute(
            """
            INSERT INTO source_snapshots (
                id, project_id, source_type, status, file_count, total_bytes,
                detected_languages_json, created_at
            )
            VALUES ('snap_1', ?, 'zip', 'ready', 1, 10, '{}', '2026-01-01T00:00:00Z')
            """,
            (project_id,),
        )
        conn.execute(
            """
            INSERT INTO audit_findings (
                id, project_id, snapshot_id, title, category, severity, status,
                file_path, line_start, entry_point, description, impact,
                evidence, discovered_by, created_at
            )
            VALUES (
                'finding_1', ?, 'snap_1', 'SQL injection', 'injection',
                'high', 'pending_review', 'login.php', 12, '/login.php',
                'parameter reaches query construction', 'authentication bypass',
                '$_POST is concatenated into SELECT', 'worker-1',
                '2026-01-01T00:00:01Z'
            )
            """,
            (project_id,),
        )

    complete = client.post(
        f"/projects/{project_id}/complete",
        json={"from": ["origin"], "description": "done", "worker": "worker-1"},
    )

    assert complete.status_code == 409
    detail = complete.json()["detail"]
    assert detail["message"] == "High or critical audit findings require confirmation before completion"
    assert detail["audit_findings"][0]["id"] == "finding_1"


def test_complete_rejects_confirmed_high_finding_without_proof_or_static_poc(temp_db):
    client = _client()
    project_id = _create_project(client)

    with get_conn() as conn:
        conn.execute(
            """
            INSERT INTO source_snapshots (
                id, project_id, source_type, status, file_count, total_bytes,
                detected_languages_json, created_at
            )
            VALUES ('snap_1', ?, 'zip', 'ready', 1, 10, '{}', '2026-01-01T00:00:00Z')
            """,
            (project_id,),
        )
        conn.execute(
            """
            INSERT INTO audit_findings (
                id, project_id, snapshot_id, title, category, severity, status,
                file_path, line_start, entry_point, description, impact,
                evidence, discovered_by, reviewed_by, created_at, reviewed_at
            )
            VALUES (
                'finding_1', ?, 'snap_1', 'SQL injection', 'injection',
                'high', 'confirmed', 'login.php', 12, 'GET /login.php?id=',
                'parameter reaches query construction', 'authentication bypass',
                '$_GET is concatenated into SELECT', 'worker-1', 'worker-2',
                '2026-01-01T00:00:01Z', '2026-01-01T00:00:02Z'
            )
            """,
            (project_id,),
        )

    complete = client.post(
        f"/projects/{project_id}/complete",
        json={"from": ["origin"], "description": "done", "worker": "worker-1"},
    )

    assert complete.status_code == 409
    detail = complete.json()["detail"]
    assert detail["message"] == (
        "Confirmed high or critical audit findings require complete proof packets "
        "or static reproduction PoC before completion"
    )
    assert detail["audit_findings"][0]["id"] == "finding_1"


def test_complete_allows_confirmed_high_finding_with_static_poc(temp_db):
    client = _client()
    project_id = _create_project(client)

    with get_conn() as conn:
        conn.execute(
            """
            INSERT INTO source_snapshots (
                id, project_id, source_type, status, file_count, total_bytes,
                detected_languages_json, created_at
            )
            VALUES ('snap_1', ?, 'zip', 'ready', 1, 10, '{}', '2026-01-01T00:00:00Z')
            """,
            (project_id,),
        )
        conn.execute(
            """
            INSERT INTO audit_findings (
                id, project_id, snapshot_id, title, category, severity, status,
                file_path, line_start, entry_point, description, impact,
                evidence, reproduction_poc_json, discovered_by, reviewed_by,
                created_at, reviewed_at
            )
            VALUES (
                'finding_1', ?, 'snap_1', 'SQL injection', 'injection',
                'high', 'confirmed', 'login.php', 12, 'GET /login.php?id=',
                'parameter reaches query construction', 'authentication bypass',
                '$_GET is concatenated into SELECT', ?, 'worker-1', 'worker-2',
                '2026-01-01T00:00:01Z', '2026-01-01T00:00:02Z'
            )
            """,
            (project_id, _reproduction_poc_json()),
        )

    complete = client.post(
        f"/projects/{project_id}/complete",
        json={"from": ["origin"], "description": "done", "worker": "worker-1"},
    )

    assert complete.status_code == 200
    assert complete.json()["to"] == "goal"


def test_complete_rejects_covered_high_risk_business_node_without_conclusion(temp_db):
    client = _client()
    project_id = _create_project(client)

    response = client.post(
        f"/api/projects/{project_id}/business-graph/nodes",
        json={
            "node_type": "endpoint",
            "title": "file upload",
            "risk_level": "high",
            "review_status": "covered",
            "coverage_note": "reviewed upload validation and execution boundary",
            "created_by": "user:completion-guard-test",
        },
    )
    assert response.status_code == 201

    complete = client.post(
        f"/projects/{project_id}/complete",
        json={"from": ["origin"], "description": "done", "worker": "worker-1"},
    )

    assert complete.status_code == 409
    detail = complete.json()["detail"]
    assert detail["message"] == (
        "Critical, high, or unknown-risk business nodes require a structured audit conclusion before completion"
    )
    assert detail["business_nodes"][0]["reason"] == "missing_conclusion"


def test_complete_allows_rejected_high_risk_business_node_conclusion(temp_db):
    client = _client()
    project_id = _create_project(client)

    node = client.post(
        f"/api/projects/{project_id}/business-graph/nodes",
        json={
            "node_type": "endpoint",
            "title": "file upload",
            "risk_level": "high",
            "review_status": "covered",
            "coverage_note": "reviewed upload validation and execution boundary",
            "created_by": "worker-1",
        },
    ).json()
    conclusion = client.post(
        f"/api/projects/{project_id}/business-graph/conclusions",
        json={
            "business_node_id": node["id"],
            "conclusion": "rejected",
            "summary": "未发现文件上传绕过",
            "evidence": "app/upload.py validates extension and stores outside web root",
            "created_by": "worker-1",
        },
    )
    assert conclusion.status_code == 201

    complete = client.post(
        f"/projects/{project_id}/complete",
        json={"from": ["origin"], "description": "done", "worker": "worker-1"},
    )

    assert complete.status_code == 200
    assert complete.json()["to"] == "goal"


def test_complete_allows_historical_conclusion_for_stale_unreviewed_business_node(temp_db):
    client = _client()
    project_id = _create_project(client)

    node = client.post(
        f"/api/projects/{project_id}/business-graph/nodes",
        json={
            "node_type": "endpoint",
            "title": "file upload",
            "risk_level": "high",
            "review_status": "unreviewed",
            "created_by": "worker-1",
        },
    ).json()
    with get_conn() as conn:
        conn.execute(
            """
            INSERT INTO business_node_conclusions (
                id, project_id, business_node_id, conclusion, summary, evidence,
                created_by, created_at
            )
            VALUES (
                'biz_conclusion_legacy', ?, ?, 'rejected',
                '已确认上传路径没有文件执行入口',
                'app/upload.py validates extension and stores outside web root',
                'worker-1', '2026-01-01T00:00:00Z'
            )
            """,
            (project_id, node["id"]),
        )

    complete = client.post(
        f"/projects/{project_id}/complete",
        json={"from": ["origin"], "description": "done", "worker": "worker-1"},
    )

    assert complete.status_code == 200
    assert complete.json()["to"] == "goal"


def test_complete_allows_blocked_node_with_needs_more_evidence_conclusion(temp_db):
    client = _client()
    project_id = _create_project(client)

    node = client.post(
        f"/api/projects/{project_id}/business-graph/nodes",
        json={
            "node_type": "external_system",
            "title": "payment callback",
            "risk_level": "unknown",
            "review_status": "blocked",
            "coverage_note": "第三方回调签名密钥不在源码中，无法证明生产配置",
            "created_by": "worker-1",
        },
    ).json()
    conclusion = client.post(
        f"/api/projects/{project_id}/business-graph/conclusions",
        json={
            "business_node_id": node["id"],
            "conclusion": "needs_more_evidence",
            "summary": "源码有签名校验入口，但缺少生产密钥和网关配置证据",
            "evidence": "payments/callback.py calls verify_signature; deployment secret source is absent",
            "created_by": "worker-1",
        },
    )
    assert conclusion.status_code == 201

    complete = client.post(
        f"/projects/{project_id}/complete",
        json={"from": ["origin"], "description": "done", "worker": "worker-1"},
    )

    assert complete.status_code == 200
    assert complete.json()["to"] == "goal"


def test_complete_rejects_high_impact_node_with_needs_more_evidence_conclusion(temp_db):
    client = _client()
    project_id = _create_project(client)

    node = client.post(
        f"/api/projects/{project_id}/business-graph/nodes",
        json={
            "node_type": "risk",
            "title": "外部输入到文件读写/加载能力 app.js:9",
            "risk_level": "high",
            "review_status": "blocked",
            "coverage_note": "已看到 filename 进入 writeFile，但未确认加载/执行边界",
            "risk_tags": ["文件读写/加载能力"],
            "created_by": "worker-1",
        },
    ).json()
    conclusion = client.post(
        f"/api/projects/{project_id}/business-graph/conclusions",
        json={
            "business_node_id": node["id"],
            "conclusion": "needs_more_evidence",
            "summary": "已确认外部输入进入文件写入，但缺少运行时文件 API 边界证据",
            "evidence": "app.js reads filename from request and passes it to writeFile",
            "created_by": "worker-1",
        },
    )
    assert conclusion.status_code == 201

    complete = client.post(
        f"/projects/{project_id}/complete",
        json={"from": ["origin"], "description": "done", "worker": "worker-1"},
    )

    assert complete.status_code == 409
    detail = complete.json()["detail"]
    assert detail["message"] == (
        "Critical, high, or unknown-risk business nodes require a structured audit conclusion before completion"
    )
    assert detail["business_nodes"][0]["reason"] == "high_impact_needs_more_evidence"


def test_complete_allows_confirmed_finding_business_node_conclusion(temp_db):
    client = _client()
    project_id = _create_project(client)

    node = client.post(
        f"/api/projects/{project_id}/business-graph/nodes",
        json={
            "node_type": "endpoint",
            "title": "refund endpoint",
            "risk_level": "critical",
            "review_status": "covered",
            "coverage_note": "reviewed ownership check and state update",
            "created_by": "worker-1",
        },
    ).json()
    with get_conn() as conn:
        conn.execute(
            """
            INSERT INTO source_snapshots (
                id, project_id, source_type, status, file_count, total_bytes,
                detected_languages_json, created_at
            )
            VALUES ('snap_1', ?, 'zip', 'ready', 1, 10, '{}', '2026-01-01T00:00:00Z')
            """,
            (project_id,),
        )
        conn.execute(
            """
            INSERT INTO audit_findings (
                id, project_id, snapshot_id, title, category, severity, status,
                file_path, line_start, entry_point, business_node_id, description,
                impact, evidence, proof_packets_json, remediation, discovered_by, reviewed_by,
                created_at, reviewed_at
            )
            VALUES (
                'finding_1', ?, 'snap_1', 'refund authorization bypass',
                'authorization', 'critical', 'confirmed', 'app/refund.py', 42,
                'POST /refund', ?, 'missing owner check', 'refund another user order',
                'RefundService does not compare owner_id', ?, 'check owner before update',
                'worker-1', 'worker-2', '2026-01-01T00:00:01Z', '2026-01-01T00:00:02Z'
            )
            """,
            (project_id, node["id"], _proof_packet_json()),
        )
    conclusion = client.post(
        f"/api/projects/{project_id}/business-graph/conclusions",
        json={
            "business_node_id": node["id"],
            "conclusion": "confirmed_finding",
            "summary": "退款接口存在已确认的越权退款漏洞",
            "audit_finding_id": "finding_1",
            "created_by": "worker-2",
        },
    )
    assert conclusion.status_code == 201

    complete = client.post(
        f"/projects/{project_id}/complete",
        json={"from": ["origin"], "description": "done", "worker": "worker-1"},
    )

    assert complete.status_code == 200
    assert complete.json()["to"] == "goal"
