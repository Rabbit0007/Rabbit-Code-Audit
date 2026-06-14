from __future__ import annotations

from fastapi import FastAPI
from fastapi.testclient import TestClient
import yaml

from cairn.dispatcher.contracts import validate_bootstrap_execute_payload, validate_explore_payload
from cairn.server import product_db
from cairn.server.routers import business_graph, export, projects
from cairn.server.db import get_conn


def _app(temp_db) -> FastAPI:
    app = FastAPI()
    app.include_router(projects.router)
    app.include_router(business_graph.router)
    app.include_router(export.router)
    return app


def _client(temp_db) -> TestClient:
    return TestClient(_app(temp_db))


def _create_project(client: TestClient) -> str:
    response = client.post(
        "/projects",
        json={
            "title": "业务图审计",
            "origin": "source audit",
            "goal": "review business logic",
            "hints": [],
        },
    )
    assert response.status_code == 201
    return response.json()["project"]["id"]


def test_business_graph_crud_and_export(temp_db):
    client = _client(temp_db)
    project_id = _create_project(client)

    assert client.get(f"/api/projects/{project_id}/business-graph").json() == {"nodes": [], "edges": []}

    feature = client.post(
        f"/api/projects/{project_id}/business-graph/nodes",
        json={
            "node_type": "feature",
            "title": "订单退款",
            "description": "用户提交退款申请并修改订单状态",
            "risk_level": "high",
            "review_status": "investigating",
            "coverage_note": "已识别入口，待覆盖状态流转",
            "last_intent_id": "i001",
            "risk_tags": ["越权", "重复退款"],
            "evidence": ["app/refund.py:42"],
            "created_by": "worker-a",
        },
    )
    assert feature.status_code == 201
    feature_node = feature.json()
    assert feature_node["risk_tags"] == ["越权", "重复退款"]
    assert feature_node["risk_level"] == "high"
    assert feature_node["review_status"] == "investigating"

    endpoint = client.post(
        f"/api/projects/{project_id}/business-graph/nodes",
        json={
            "node_type": "endpoint",
            "title": "POST /api/refund",
            "created_by": "worker-a",
        },
    ).json()

    edge = client.post(
        f"/api/projects/{project_id}/business-graph/edges",
        json={
            "from_node_id": endpoint["id"],
            "to_node_id": feature_node["id"],
            "relation": "exposes",
            "description": "接口暴露退款功能",
            "created_by": "worker-a",
        },
    )
    assert edge.status_code == 201

    updated = client.put(
        f"/api/projects/{project_id}/business-graph/nodes/{feature_node['id']}",
        json={
            "node_type": "feature",
            "title": "订单退款流程",
            "risk_level": "high",
            "review_status": "covered",
            "coverage_note": "已覆盖入口和订单状态更新路径",
            "risk_tags": ["越权"],
        },
    )
    assert updated.status_code == 200
    assert updated.json()["title"] == "订单退款流程"
    assert updated.json()["risk_tags"] == ["越权"]
    assert updated.json()["review_status"] == "covered"

    conclusion = client.post(
        f"/api/projects/{project_id}/business-graph/conclusions",
        json={
            "business_node_id": feature_node["id"],
            "conclusion": "rejected",
            "summary": "未发现重复退款或越权退款漏洞",
            "evidence": "app/refund.py:42 checks order owner and refund state before update",
            "created_by": "worker-a",
        },
    )
    assert conclusion.status_code == 201
    conclusion_body = conclusion.json()
    assert conclusion_body["business_node_id"] == feature_node["id"]
    assert client.get(
        f"/api/projects/{project_id}/business-graph/nodes/{feature_node['id']}/conclusions"
    ).json()[0]["conclusion"] == "rejected"

    graph = client.get(f"/api/projects/{project_id}/business-graph").json()
    assert len(graph["nodes"]) == 2
    assert len(graph["edges"]) == 1

    exported = client.get(f"/projects/{project_id}/export?format=yaml")
    assert exported.status_code == 200
    data = yaml.safe_load(exported.text)
    assert {node["title"] for node in data["business_graph"]["nodes"]} == {"订单退款流程", "POST /api/refund"}
    assert data["business_graph"]["coverage"]["total_nodes"] == 2
    assert data["business_graph"]["coverage"]["high_or_unknown_open"][0]["title"] == "POST /api/refund"
    assert data["business_graph"]["coverage"]["high_or_unknown_without_conclusion"][0]["title"] == "POST /api/refund"
    assert data["business_graph"]["edges"][0]["relation"] == "exposes"
    assert data["business_graph"]["conclusions"][0]["conclusion"] == "rejected"
    assert data["business_graph"]["conclusions"][0]["business_node_id"] == feature_node["id"]

    delete = client.delete(f"/api/projects/{project_id}/business-graph/nodes/{endpoint['id']}")
    assert delete.status_code == 204
    graph_after_delete = client.get(f"/api/projects/{project_id}/business-graph").json()
    assert len(graph_after_delete["nodes"]) == 1
    assert graph_after_delete["edges"] == []


def test_business_graph_accepts_index_generated_inheritance_relations(temp_db):
    client = _client(temp_db)
    project_id = _create_project(client)

    base = client.post(
        f"/api/projects/{project_id}/business-graph/nodes",
        json={
            "node_type": "feature",
            "title": "Base serializer",
            "created_by": "indexer",
        },
    ).json()
    child = client.post(
        f"/api/projects/{project_id}/business-graph/nodes",
        json={
            "node_type": "feature",
            "title": "Account serializer",
            "created_by": "indexer",
        },
    ).json()

    for relation in ("extends", "extended_by"):
        response = client.post(
            f"/api/projects/{project_id}/business-graph/edges",
            json={
                "from_node_id": child["id"],
                "to_node_id": base["id"],
                "relation": relation,
                "description": f"index generated {relation} edge",
                "created_by": "indexer",
            },
        )
        assert response.status_code == 201

    graph = client.get(f"/api/projects/{project_id}/business-graph")
    assert graph.status_code == 200
    assert {edge["relation"] for edge in graph.json()["edges"]} == {"extends", "extended_by"}


def test_business_edge_requires_nodes_from_same_project(temp_db):
    client = _client(temp_db)
    project_a = _create_project(client)
    project_b = _create_project(client)
    a_node = client.post(
        f"/api/projects/{project_a}/business-graph/nodes",
        json={"node_type": "feature", "title": "A", "created_by": "worker"},
    ).json()
    b_node = client.post(
        f"/api/projects/{project_b}/business-graph/nodes",
        json={"node_type": "feature", "title": "B", "created_by": "worker"},
    ).json()

    response = client.post(
        f"/api/projects/{project_a}/business-graph/edges",
        json={
            "from_node_id": a_node["id"],
            "to_node_id": b_node["id"],
            "relation": "relates_to",
            "created_by": "worker",
        },
    )

    assert response.status_code == 404


def test_business_node_conclusion_requires_project_node(temp_db):
    client = _client(temp_db)
    project_a = _create_project(client)
    project_b = _create_project(client)
    b_node = client.post(
        f"/api/projects/{project_b}/business-graph/nodes",
        json={"node_type": "feature", "title": "B", "created_by": "worker"},
    ).json()

    response = client.post(
        f"/api/projects/{project_a}/business-graph/conclusions",
        json={
            "business_node_id": b_node["id"],
            "conclusion": "rejected",
            "summary": "not in project",
            "evidence": "node belongs to another project",
            "created_by": "worker",
        },
    )

    assert response.status_code == 404


def test_business_node_conclusions_sync_node_coverage(temp_db):
    client = _client(temp_db)
    project_id = _create_project(client)
    rejected_node = client.post(
        f"/api/projects/{project_id}/business-graph/nodes",
        json={
            "node_type": "feature",
            "title": "退款流程",
            "risk_level": "high",
            "review_status": "unreviewed",
            "created_by": "worker",
        },
    ).json()
    blocked_node = client.post(
        f"/api/projects/{project_id}/business-graph/nodes",
        json={
            "node_type": "external_system",
            "title": "支付回调",
            "risk_level": "unknown",
            "review_status": "unreviewed",
            "created_by": "worker",
        },
    ).json()
    confirmed_node = client.post(
        f"/api/projects/{project_id}/business-graph/nodes",
        json={
            "node_type": "endpoint",
            "title": "POST /refund",
            "risk_level": "critical",
            "review_status": "unreviewed",
            "created_by": "worker",
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
                impact, evidence, discovered_by, reviewed_by, created_at, reviewed_at
            )
            VALUES (
                'finding_1', ?, 'snap_1', 'refund bypass', 'authorization',
                'critical', 'confirmed', 'app/refund.py', 42, 'POST /refund',
                ?, 'missing owner check', 'refund another user order',
                'RefundService does not compare owner_id', 'worker-1', 'worker-2',
                '2026-01-01T00:00:01Z', '2026-01-01T00:00:02Z'
            )
            """,
            (project_id, confirmed_node["id"]),
        )

    assert client.post(
        f"/api/projects/{project_id}/business-graph/conclusions",
        json={
            "business_node_id": rejected_node["id"],
            "conclusion": "rejected",
            "summary": "已确认退款流程不存在越权退款",
            "evidence": "app/refund.py checks owner before state transition",
            "created_by": "worker",
        },
    ).status_code == 201
    assert client.post(
        f"/api/projects/{project_id}/business-graph/conclusions",
        json={
            "business_node_id": blocked_node["id"],
            "conclusion": "needs_more_evidence",
            "summary": "源码有签名入口，但缺少网关配置证据",
            "evidence": "payments/callback.py calls verify_signature; production secret source is absent",
            "created_by": "worker",
        },
    ).status_code == 201
    assert client.post(
        f"/api/projects/{project_id}/business-graph/conclusions",
        json={
            "business_node_id": confirmed_node["id"],
            "conclusion": "confirmed_finding",
            "summary": "退款接口存在已确认越权漏洞",
            "audit_finding_id": "finding_1",
            "created_by": "worker",
        },
    ).status_code == 201

    graph = client.get(f"/api/projects/{project_id}/business-graph").json()
    nodes = {node["id"]: node for node in graph["nodes"]}
    assert nodes[rejected_node["id"]]["review_status"] == "covered"
    assert nodes[rejected_node["id"]]["coverage_note"] == "已确认退款流程不存在越权退款"
    assert nodes[blocked_node["id"]]["review_status"] == "blocked"
    assert "缺少网关配置证据" in nodes[blocked_node["id"]]["coverage_note"]
    assert "production secret source is absent" in nodes[blocked_node["id"]]["coverage_note"]
    assert nodes[confirmed_node["id"]]["review_status"] == "covered"
    assert nodes[confirmed_node["id"]]["coverage_note"] == "退款接口存在已确认越权漏洞"


def test_export_treats_valid_historical_business_conclusion_as_covered(temp_db):
    client = _client(temp_db)
    project_id = _create_project(client)
    node = client.post(
        f"/api/projects/{project_id}/business-graph/nodes",
        json={
            "node_type": "feature",
            "title": "订单退款",
            "risk_level": "high",
            "review_status": "unreviewed",
            "created_by": "worker",
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
                '已检查退款状态流转，未发现重复退款',
                'app/refund.py checks state before update',
                'worker', '2026-01-01T00:00:00Z'
            )
            """,
            (project_id, node["id"]),
        )

    exported = client.get(f"/projects/{project_id}/export?format=yaml")
    assert exported.status_code == 200
    data = yaml.safe_load(exported.text)
    coverage = data["business_graph"]["coverage"]
    assert coverage["covered"] == 1
    assert coverage["unreviewed"] == 0
    assert coverage["high_or_unknown_open"] == []
    assert coverage["high_or_unknown_without_conclusion"] == []


def test_product_db_backfills_historical_business_conclusion_coverage(temp_db):
    client = _client(temp_db)
    project_id = _create_project(client)
    node = client.post(
        f"/api/projects/{project_id}/business-graph/nodes",
        json={
            "node_type": "feature",
            "title": "订单退款",
            "risk_level": "high",
            "review_status": "unreviewed",
            "created_by": "worker",
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
                '已检查退款状态流转，未发现重复退款',
                'app/refund.py checks state before update',
                'worker', '2026-01-01T00:00:00Z'
            )
            """,
            (project_id, node["id"]),
        )

    product_db.configure_product_db()

    graph = client.get(f"/api/projects/{project_id}/business-graph").json()
    updated = next(item for item in graph["nodes"] if item["id"] == node["id"])
    assert updated["review_status"] == "covered"
    assert updated["coverage_note"] == "已检查退款状态流转，未发现重复退款"


def test_confirmed_business_node_conclusion_requires_audit_finding(temp_db):
    client = _client(temp_db)
    project_id = _create_project(client)
    node = client.post(
        f"/api/projects/{project_id}/business-graph/nodes",
        json={"node_type": "feature", "title": "退款", "created_by": "worker"},
    ).json()

    missing_id = client.post(
        f"/api/projects/{project_id}/business-graph/conclusions",
        json={
            "business_node_id": node["id"],
            "conclusion": "confirmed_finding",
            "summary": "发现漏洞",
            "created_by": "worker",
        },
    )
    assert missing_id.status_code == 422

    missing_finding = client.post(
        f"/api/projects/{project_id}/business-graph/conclusions",
        json={
            "business_node_id": node["id"],
            "conclusion": "confirmed_finding",
            "summary": "发现漏洞",
            "audit_finding_id": "finding_missing",
            "created_by": "worker",
        },
    )
    assert missing_finding.status_code == 404


def test_worker_contract_accepts_business_graph_objects():
    _, result = validate_explore_payload(
        {
            "accepted": True,
            "data": {
                "description": "确认退款业务入口和风险点",
                "business_nodes": [
                    {
                        "ref": "refund",
                        "node_type": "feature",
                        "title": "订单退款",
                        "risk_level": "high",
                        "review_status": "covered",
                        "coverage_note": "已确认退款入口和状态更新路径",
                        "risk_tags": ["重复退款"],
                        "evidence": ["app/refund.py:42"],
                    }
                ],
                "business_edges": [
                    {
                        "from": "refund",
                        "to": "existing_endpoint",
                        "relation": "exposes",
                    }
                ],
                "business_node_conclusions": [
                    {
                        "business_node_ref": "refund",
                        "conclusion": "not_vulnerable",
                        "summary": "退款流程已覆盖，未发现越权退款",
                        "evidence": "app/refund.py:42 compares order.user_id with current user",
                    }
                ],
            },
        }
    )
    assert result["business_nodes"][0]["ref"] == "refund"
    assert result["business_nodes"][0]["risk_level"] == "high"
    assert result["business_edges"][0]["relation"] == "exposes"
    assert result["business_node_conclusions"][0]["conclusion"] == "rejected"
    assert result["business_node_conclusions"][0]["business_node_ref"] == "refund"

    kind, bootstrap = validate_bootstrap_execute_payload(
        {
            "accepted": True,
            "data": {
                "fact": {"description": "仓库包含退款模块"},
                "business_nodes": [{"type": "feature", "title": "退款模块"}],
            },
        }
    )
    assert kind == "fact"
    assert bootstrap["business_nodes"][0]["node_type"] == "feature"
    assert bootstrap["business_nodes"][0]["risk_level"] == "unknown"


def test_worker_contract_skips_business_conclusion_without_required_evidence():
    _, result = validate_explore_payload(
        {
            "accepted": True,
            "data": {
                "description": "确认业务节点",
                "business_node_conclusions": [
                    {
                        "business_node_id": "biz_existing",
                        "conclusion": "confirmed_finding",
                        "summary": "模型声称该业务节点存在漏洞",
                    }
                ],
            },
        }
    )

    assert result["business_node_conclusions"] == []


def test_worker_contract_downgrades_confirmed_business_conclusion_with_evidence_but_without_id():
    _, result = validate_explore_payload(
        {
            "accepted": True,
            "data": {
                "description": "确认业务节点",
                "business_node_conclusions": [
                    {
                        "business_node_id": "biz_existing",
                        "conclusion": "confirmed_finding",
                        "summary": "模型声称该业务节点存在漏洞",
                        "evidence": "已阅读 app/refund.py:42，但未绑定已确认 finding id",
                    }
                ],
            },
        }
    )

    conclusion = result["business_node_conclusions"][0]
    assert conclusion["conclusion"] == "needs_more_evidence"
    assert conclusion["audit_finding_id"] is None
    assert conclusion["evidence"] == "已阅读 app/refund.py:42，但未绑定已确认 finding id"


def test_worker_contract_treats_generic_confirmed_business_conclusion_as_incomplete_without_id():
    _, result = validate_explore_payload(
        {
            "accepted": True,
            "data": {
                "description": "确认业务节点",
                "business_node_conclusions": [
                    {
                        "business_node_id": "biz_existing",
                        "conclusion": "confirmed",
                        "summary": "模型声称该业务节点存在漏洞",
                    }
                ],
            },
        }
    )

    assert result["business_node_conclusions"] == []


def test_worker_contract_normalizes_common_business_node_type_aliases():
    _, result = validate_explore_payload(
        {
            "accepted": True,
            "data": {
                "description": "确认业务流程和 API 入口",
                "business_nodes": [
                    {"ref": "refund_flow", "node_type": "business_process", "title": "退款流程"},
                    {"ref": "refund_api", "node_type": "api_endpoint", "title": "POST /orders/{order_id}/refund"},
                    {"ref": "order_record", "node_type": "resource", "title": "订单记录"},
                    {"ref": "owner_check", "node_type": "authorization", "title": "订单归属校验"},
                ],
            },
        }
    )

    assert [node["node_type"] for node in result["business_nodes"]] == [
        "feature",
        "endpoint",
        "data_object",
        "control",
    ]


def test_worker_contract_normalizes_business_edge_relation_aliases():
    _, result = validate_explore_payload(
        {
            "accepted": True,
            "data": {
                "description": "确认登录接口和权限控制关系",
                "business_nodes": [
                    {"ref": "login_api", "node_type": "endpoint", "title": "POST /login"},
                    {"ref": "password_check", "node_type": "control", "title": "密码校验"},
                    {"ref": "session", "node_type": "asset", "title": "会话"},
                ],
                "business_edges": [
                    {"from": "login_api", "to": "password_check", "relation": "validates"},
                    {"from": "login_api", "to": "session", "relation": "produces"},
                ],
            },
        }
    )

    assert [edge["relation"] for edge in result["business_edges"]] == ["guards", "relates_to"]
