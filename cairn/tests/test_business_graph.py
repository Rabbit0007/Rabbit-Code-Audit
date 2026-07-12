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


def test_business_graph_merges_nodes_by_semantic_key(temp_db):
    client = _client(temp_db)
    project_id = _create_project(client)
    first = client.post(
        f"/api/projects/{project_id}/business-graph/nodes",
        json={
            "node_type": "feature",
            "semantic_key": "feature:order_refund",
            "title": "订单退款",
            "description": "提交退款申请",
            "risk_tags": ["越权"],
            "evidence": ["orders/refund.py:42"],
            "confidence": 0.78,
            "created_by": "worker-a",
        },
    ).json()
    second = client.post(
        f"/api/projects/{project_id}/business-graph/nodes",
        json={
            "node_type": "feature",
            "semantic_key": "feature:order_refund",
            "title": "退款订单",
            "description": "用户提交退款申请并进入财务审批流程",
            "risk_level": "high",
            "risk_tags": ["重复退款"],
            "evidence": ["orders/approval.py:18"],
            "confidence": 0.91,
            "created_by": "worker-b",
        },
    ).json()

    assert second["id"] == first["id"]
    assert second["revision"] == 2
    assert second["risk_level"] == "high"
    assert second["confidence"] == 0.9
    assert second["risk_tags"] == ["越权", "重复退款"]
    assert second["evidence"] == ["orders/refund.py:42", "orders/approval.py:18"]
    assert second["contributors"] == ["worker-a", "worker-b"]
    assert second["evidence_status"] == "source_backed"
    assert len(client.get(f"/api/projects/{project_id}/business-graph").json()["nodes"]) == 1


def test_business_graph_merges_duplicate_edges(temp_db):
    client = _client(temp_db)
    project_id = _create_project(client)
    source = client.post(
        f"/api/projects/{project_id}/business-graph/nodes",
        json={"node_type": "role", "title": "财务审核员", "created_by": "worker-a"},
    ).json()
    target = client.post(
        f"/api/projects/{project_id}/business-graph/nodes",
        json={"node_type": "feature", "title": "退款审批", "created_by": "worker-a"},
    ).json()
    payload = {
        "from_node_id": source["id"],
        "to_node_id": target["id"],
        "relation": "guards",
        "description": "财务角色审批退款",
        "created_by": "worker-a",
    }
    first = client.post(f"/api/projects/{project_id}/business-graph/edges", json=payload).json()
    payload["created_by"] = "worker-b"
    payload["confidence"] = 0.9
    second = client.post(f"/api/projects/{project_id}/business-graph/edges", json=payload).json()

    assert second["id"] == first["id"]
    assert second["revision"] == 2
    assert second["confidence"] == 0.9
    assert second["contributors"] == ["worker-a", "worker-b"]
    assert len(client.get(f"/api/projects/{project_id}/business-graph").json()["edges"]) == 1


def test_business_graph_reopens_unverified_model_node_instead_of_marking_it_covered(temp_db):
    client = _client(temp_db)
    project_id = _create_project(client)
    node = client.post(
        f"/api/projects/{project_id}/business-graph/nodes",
        json={
            "node_type": "role",
            "title": "管理员",
            "review_status": "covered",
            "created_by": "worker-a",
        },
    ).json()

    assert node["review_status"] == "investigating"
    assert node["evidence_status"] == "unverified"


def test_reason_graph_view_prioritizes_semantics_without_shrinking_full_coverage(temp_db, monkeypatch):
    client = _client(temp_db)
    project_id = _create_project(client)

    for index in range(5):
        client.post(
            f"/api/projects/{project_id}/business-graph/nodes",
            json={
                "node_type": "endpoint",
                "semantic_key": f"source:endpoint:{index}",
                "title": f"静态入口 {index}",
                "risk_level": "medium",
                "created_by": "source_index",
            },
        )
    semantic = client.post(
        f"/api/projects/{project_id}/business-graph/nodes",
        json={
            "node_type": "feature",
            "semantic_key": "feature:order_refund",
            "title": "订单退款",
            "risk_level": "medium",
            "created_by": "worker-a",
        },
    ).json()
    audit = client.post(
        f"/api/projects/{project_id}/business-graph/nodes",
        json={
            "node_type": "risk",
            "semantic_key": "risk:refund_replay",
            "title": "重复退款风险",
            "risk_level": "high",
            "created_by": "worker-b",
        },
    ).json()

    monkeypatch.setattr(export, "REASON_GRAPH_NODE_LIMIT", 2)
    response = client.get(f"/projects/{project_id}/export?format=yaml&profile=reason")
    assert response.status_code == 200
    graph = yaml.safe_load(response.text)["business_graph"]

    assert graph["coverage"]["total_nodes"] == 7
    assert graph["view"]["nodes_included"] == 2
    assert {node["id"] for node in graph["nodes"]} == {semantic["id"], audit["id"]}


def test_context_budget_keeps_business_semantics_and_removes_dangling_edges():
    semantic_nodes = [
        {
            "id": f"semantic-{index}",
            "graph_layer": "semantic",
            "review_status": "covered",
            "description": "业务语义" * 200,
        }
        for index in range(2)
    ]
    evidence_nodes = [
        {
            "id": f"evidence-{index}",
            "graph_layer": "evidence",
            "review_status": "covered",
            "description": "静态证据" * 200,
        }
        for index in range(30)
    ]
    nodes = [*evidence_nodes, *semantic_nodes]
    edges = [
        {
            "id": f"edge-{index}",
            "from": nodes[index]["id"],
            "to": nodes[index + 1]["id"],
            "relation": "relates_to",
        }
        for index in range(len(nodes) - 1)
    ]
    data = {
        "context_profile": {"focused_candidate_ids": [], "required_fact_ids": []},
        "business_graph": {
            "coverage": {"total_nodes": len(nodes)},
            "view": {
                "nodes_included": len(nodes),
                "nodes_omitted": 0,
                "edges_included": len(edges),
                "edges_omitted": 0,
            },
            "nodes": nodes,
            "edges": edges,
        },
        "audit_candidates": {"items": []},
        "audit_findings": [],
        "facts": [],
        "intents": [],
    }

    text = export._fit_context_to_budget(
        data,
        "reason",
        6_000,
        hard_max_bytes=50_000,
    )
    graph = yaml.safe_load(text)["business_graph"]
    visible_ids = {node["id"] for node in graph["nodes"]}

    assert {"semantic-0", "semantic-1"} <= visible_ids
    assert graph["view"]["nodes_included"] == len(graph["nodes"])
    assert graph["view"]["nodes_omitted"] == 32 - len(graph["nodes"])
    assert all(
        edge["from"] in visible_ids and edge["to"] in visible_ids
        for edge in graph["edges"]
    )


def test_business_graph_validates_model_evidence_and_calibrates_confidence(
    temp_db, monkeypatch, tmp_path
):
    monkeypatch.setenv("CAIRN_ARTIFACT_ROOT", str(tmp_path / "artifacts"))
    client = _client(temp_db)
    project_id = _create_project(client)
    source_root = tmp_path / "artifacts" / "snapshots" / "snap_graph" / "source"
    (source_root / "orders").mkdir(parents=True)
    (source_root / "orders" / "refund.py").write_text(
        "\n".join(["# filler"] * 41 + ["refund_order(order_id)", "# tail"]),
        encoding="utf-8",
    )
    (source_root / "weak.php").write_text(
        "<!DOCTYPE html>\n<?php\n$ok = true;\n",
        encoding="utf-8",
    )
    with get_conn() as conn:
        conn.execute(
            """
            INSERT INTO source_snapshots (
                id, project_id, source_type, status, file_count, total_bytes,
                detected_languages_json, created_at
            )
            VALUES ('snap_graph', ?, 'zip', 'ready', 1, 100, '{"Python": 1}', '2026-01-01T00:00:00Z')
            """,
            (project_id,),
        )
        conn.execute(
            """
            INSERT INTO code_files (snapshot_id, path, size_bytes, sha256, language, is_binary)
            VALUES ('snap_graph', 'orders/refund.py', 100, 'abc', 'Python', 0)
            """
        )
        conn.execute(
            """
            INSERT INTO code_files (snapshot_id, path, size_bytes, sha256, language, is_binary)
            VALUES ('snap_graph', 'weak.php', 30, 'def', 'PHP', 0),
                   ('snap_graph', 'bundle.zip', 50, 'ghi', NULL, 1)
            """
        )

    static_node = client.post(
        f"/api/projects/{project_id}/business-graph/nodes",
        json={
            "node_type": "risk",
            "semantic_key": "source:refund-risk",
            "title": "退款入口风险链",
            "evidence": ["orders/refund.py:42"],
            "created_by": "source_index",
        },
    ).json()

    node = client.post(
        f"/api/projects/{project_id}/business-graph/nodes",
        json={
            "node_type": "feature",
            "semantic_key": "feature:order_refund",
            "title": "订单退款",
            "evidence": [
                "orders/refund.py:42",
                "weak.php:1",
                "bundle.zip:1",
                "missing/file.py:9",
                "not-a-location",
            ],
            "confidence": 1,
            "created_by": "worker-a",
        },
    ).json()

    assert node["evidence"] == ["orders/refund.py:42"]
    assert node["evidence_status"] == "source_backed"
    assert node["confidence"] == 0.82
    graph = client.get(f"/api/projects/{project_id}/business-graph").json()
    evidence_edges = [edge for edge in graph["edges"] if edge["relation"] == "evidenced_by"]
    assert len(evidence_edges) == 1
    assert evidence_edges[0]["from_node_id"] == node["id"]
    assert evidence_edges[0]["to_node_id"] == static_node["id"]


def test_business_graph_caps_model_edge_confidence(temp_db):
    client = _client(temp_db)
    project_id = _create_project(client)
    source = client.post(
        f"/api/projects/{project_id}/business-graph/nodes",
        json={"node_type": "feature", "title": "Source", "created_by": "worker-a"},
    ).json()
    target = client.post(
        f"/api/projects/{project_id}/business-graph/nodes",
        json={"node_type": "asset", "title": "Target", "created_by": "worker-a"},
    ).json()

    edge = client.post(
        f"/api/projects/{project_id}/business-graph/edges",
        json={
            "from_node_id": source["id"],
            "to_node_id": target["id"],
            "relation": "uses",
            "confidence": 1,
            "created_by": "worker-a",
        },
    ).json()

    assert edge["confidence"] == 0.94


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


def test_weaker_business_conclusion_cannot_replace_decisive_current_result(temp_db):
    client = _client(temp_db)
    project_id = _create_project(client)
    node = client.post(
        f"/api/projects/{project_id}/business-graph/nodes",
        json={
            "node_type": "feature",
            "title": "订单读取",
            "risk_level": "high",
            "review_status": "unreviewed",
            "created_by": "worker",
        },
    ).json()

    decisive = client.post(
        f"/api/projects/{project_id}/business-graph/conclusions",
        json={
            "business_node_id": node["id"],
            "conclusion": "rejected",
            "summary": "已验证对象归属检查完整",
            "evidence": "orders.py:44 compares order.user_id with session.user_id",
            "created_by": "reviewer",
        },
    )
    assert decisive.status_code == 201
    weaker = client.post(
        f"/api/projects/{project_id}/business-graph/conclusions",
        json={
            "business_node_id": node["id"],
            "conclusion": "needs_more_evidence",
            "summary": "后续 worker 未读取完整文件",
            "evidence": "context was incomplete",
            "created_by": "worker-2",
        },
    )
    assert weaker.status_code == 201
    assert weaker.json()["is_current"] is False

    current = client.get(
        f"/api/projects/{project_id}/business-graph/nodes/{node['id']}/conclusions"
    ).json()
    assert len(current) == 1
    assert current[0]["id"] == decisive.json()["id"]
    assert current[0]["is_current"] is True

    history = client.get(
        f"/api/projects/{project_id}/business-graph/conclusions",
        params={"business_node_id": node["id"], "include_history": True},
    ).json()
    assert len(history) == 2
    assert sum(item["is_current"] for item in history) == 1

    graph = client.get(f"/api/projects/{project_id}/business-graph").json()
    graph_node = next(item for item in graph["nodes"] if item["id"] == node["id"])
    assert graph_node["review_status"] == "covered"
    assert graph_node["coverage_note"] == "已验证对象归属检查完整"


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
    assert result["business_nodes"][0]["semantic_key"] == "feature:refund"
    assert result["business_nodes"][0]["graph_layer"] == "semantic"
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
