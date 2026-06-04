from __future__ import annotations

from fastapi import FastAPI
from fastapi.testclient import TestClient
import yaml

from cairn.dispatcher.contracts import validate_bootstrap_execute_payload, validate_explore_payload
from cairn.server.routers import business_graph, export, projects


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
