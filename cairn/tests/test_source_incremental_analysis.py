from __future__ import annotations

from fastapi import FastAPI
from fastapi.testclient import TestClient

from cairn.server import db
from cairn.server.routers import sources


def test_snapshot_change_analysis_tracks_files_and_impacted_entrypoints(temp_db):
    with db.get_conn() as conn:
        conn.execute(
            "INSERT INTO projects (id, title, status, created_at) VALUES ('proj-diff', 'Diff', 'stopped', '2026-01-01T00:00:00Z')"
        )
        for snapshot_id, created_at in (("snap-old", "2026-01-01T00:00:01Z"), ("snap-new", "2026-01-02T00:00:01Z")):
            conn.execute(
                """
                INSERT INTO source_snapshots (
                    id, project_id, source_type, original_name, status, snapshot_sha256, created_at
                ) VALUES (?, 'proj-diff', 'zip', ?, 'ready', ?, ?)
                """,
                (snapshot_id, f"{snapshot_id}.zip", snapshot_id.ljust(64, "0"), created_at),
            )
        files = [
            ("snap-old", "app/api.py", "old-api", "Python"),
            ("snap-old", "app/service.py", "same-service", "Python"),
            ("snap-old", "requirements.txt", "old-lock", None),
            ("snap-old", "legacy.py", "legacy", "Python"),
            ("snap-new", "app/api.py", "new-api", "Python"),
            ("snap-new", "app/service.py", "same-service", "Python"),
            ("snap-new", "requirements.txt", "new-lock", None),
            ("snap-new", "app/new.py", "new-file", "Python"),
        ]
        conn.executemany(
            """
            INSERT INTO code_files (snapshot_id, path, size_bytes, sha256, language, is_binary)
            VALUES (?, ?, 10, ?, ?, 0)
            """,
            files,
        )
        conn.execute(
            """
            INSERT INTO code_relationships (
                id, snapshot_id, from_path, from_symbol, to_path, to_symbol,
                relation, evidence, confidence, source
            ) VALUES (
                'rel-new', 'snap-new', 'app/api.py', 'orders', 'app/service.py',
                'load_order', 'calls', 'orders calls service', 0.9, 'ast'
            )
            """
        )
        conn.execute(
            """
            INSERT INTO code_entrypoints (
                id, snapshot_id, path, language, kind, framework, method, route,
                handler, line_start, evidence, confidence, source
            ) VALUES (
                'entry-new', 'snap-new', 'app/api.py', 'Python', 'http_route',
                'FastAPI', 'GET', '/orders', 'orders', 10, 'route', 0.9, 'ast'
            )
            """
        )

    app = FastAPI()
    app.include_router(sources.router)
    response = TestClient(app).get(
        "/api/projects/proj-diff/sources/snap-new/changes",
        params={"base_snapshot_id": "snap-old"},
    )

    assert response.status_code == 200
    result = response.json()
    assert result["added_file_count"] == 1
    assert result["modified_file_count"] == 2
    assert result["deleted_file_count"] == 1
    assert result["unchanged_file_count"] == 1
    assert "GET /orders" in result["impacted_entrypoints"]
    assert "app/service.py" in result["impacted_paths"]
    assert result["full_reaudit_recommended"] is True
    assert any("供应链" in reason for reason in result["recommendation_reasons"])

