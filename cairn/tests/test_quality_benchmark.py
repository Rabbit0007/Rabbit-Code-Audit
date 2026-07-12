from __future__ import annotations

from fastapi import FastAPI
from fastapi.testclient import TestClient

from cairn.server import db
from cairn.server.routers import quality


def _seed_project() -> None:
    with db.get_conn() as conn:
        conn.execute(
            "INSERT INTO projects (id, title, status, created_at) VALUES ('proj-q', 'Quality', 'stopped', '2026-01-01T00:00:00Z')"
        )
        conn.execute(
            """
            INSERT INTO source_snapshots (
                id, project_id, source_type, original_name, status, snapshot_sha256, created_at
            ) VALUES ('snap-q', 'proj-q', 'zip', 'quality.zip', 'ready', ?, '2026-01-01T00:00:01Z')
            """,
            ("a" * 64,),
        )
        conn.execute(
            """
            INSERT INTO audit_findings (
                id, project_id, snapshot_id, title, category, severity, status,
                evidence_level, cwe, file_path, line_start, entry_point,
                description, discovered_by, created_at
            ) VALUES (
                'finding-sqli', 'proj-q', 'snap-q', '订单查询 SQL 注入',
                'sql_injection', 'high', 'confirmed', 'L3', 'CWE-89',
                'app/orders.py', 42, 'GET /orders', '参数进入 SQL', 'worker-a',
                '2026-01-01T00:00:02Z'
            )
            """
        )
        conn.execute(
            """
            INSERT INTO audit_findings (
                id, project_id, snapshot_id, title, category, severity, status,
                evidence_level, file_path, description, discovered_by, created_at
            ) VALUES (
                'finding-extra', 'proj-q', 'snap-q', '额外发现', 'xss', 'medium',
                'confirmed', 'L3', 'app/view.py', '输出未编码', 'worker-b',
                '2026-01-01T00:00:03Z'
            )
            """
        )
        conn.execute(
            """
            INSERT INTO business_nodes (
                id, project_id, node_type, title, description, risk_level,
                review_status, risk_tags_json, evidence_json, graph_layer,
                source_kind, evidence_status, contributors_json, revision,
                created_by, created_at, updated_at
            ) VALUES (
                'node-orders', 'proj-q', 'endpoint', 'GET /orders', '订单查询入口',
                'high', 'covered', '[]', '["app/orders.py:42"]', 'evidence',
                'static_index', 'source_backed', '[]', 1, 'indexer',
                '2026-01-01T00:00:01Z', '2026-01-01T00:00:01Z'
            )
            """
        )


def test_quality_benchmark_calculates_and_persists_metrics(temp_db):
    _seed_project()
    app = FastAPI()
    app.include_router(quality.router)
    client = TestClient(app)

    response = client.post(
        "/api/projects/proj-q/quality/benchmarks",
        json={
            "suite_name": "orders-ground-truth",
            "snapshot_id": "snap-q",
            "expectations": [
                {
                    "id": "gt-sqli",
                    "title": "订单查询存在 SQL 注入",
                    "category": "sql_injection",
                    "cwe": "CWE-89",
                    "file_path": "app/orders.py",
                    "entry_point": "GET /orders",
                },
                {
                    "id": "gt-authz",
                    "title": "订单越权",
                    "category": "authorization",
                    "file_path": "app/auth.py",
                },
            ],
            "expected_business_entrypoints": ["GET /orders", "POST /admin"],
        },
    )

    assert response.status_code == 201
    result = response.json()
    assert result["true_positive"] == 1
    assert result["false_positive"] == 1
    assert result["false_negative"] == 1
    assert result["precision"] == 0.5
    assert result["recall"] == 0.5
    assert result["f1"] == 0.5
    assert result["business_entrypoint_coverage"] == 0.5
    assert result["missing_business_entrypoints"] == ["POST /admin"]

    history = client.get("/api/projects/proj-q/quality/benchmarks").json()
    assert len(history) == 1
    assert history[0]["id"] == result["id"]

