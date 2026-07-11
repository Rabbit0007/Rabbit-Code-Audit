from __future__ import annotations

import sqlite3

import yaml
from fastapi import FastAPI
from fastapi.testclient import TestClient

from cairn.server import db
from cairn.server.db import get_conn
from cairn.server.routers import export, findings, hints, intents, projects
from cairn.server.services import build_intent_fingerprint

from .conftest import BASE_URL


def _client() -> TestClient:
    app = FastAPI()
    app.include_router(projects.router)
    app.include_router(intents.router)
    app.include_router(hints.router)
    app.include_router(findings.router)
    app.include_router(export.router)
    return TestClient(app, base_url=BASE_URL)


def _create_project(client: TestClient) -> str:
    response = client.post(
        "/projects",
        json={
            "title": "metadata",
            "origin": "source archive",
            "goal": "audit goal",
            "hints": [
                {
                    "content": "优先覆盖认证链路",
                    "creator": "user",
                    "hint_type": "priority",
                    "target": "auth",
                    "priority": 8,
                    "max_uses": 3,
                }
            ],
        },
    )
    assert response.status_code == 201
    body = response.json()
    assert body["facts"][0]["fact_type"] == "origin"
    assert body["hints"][0]["hint_type"] == "priority"
    return body["project"]["id"]


def test_intent_fingerprint_dedupes_open_intents_and_exports_metadata(temp_db):
    client = _client()
    project_id = _create_project(client)

    first = client.post(
        f"/projects/{project_id}/intents",
        json={
            "from": ["origin"],
            "description": "审计候选 cand_1234567890abcdef 对应的上传链路",
            "creator": "reason-worker",
            "target_kind": "audit_candidate",
            "target_id": "cand_1234567890abcdef",
            "objective": "confirm_or_reject",
        },
    )
    second = client.post(
        f"/projects/{project_id}/intents",
        json={
            "from": ["origin"],
            "description": "审计候选 cand_1234567890abcdef 对应的上传链路",
            "creator": "reason-worker",
            "target_kind": "audit_candidate",
            "target_id": "cand_1234567890abcdef",
            "objective": "confirm_or_reject",
        },
    )

    assert first.status_code == 201
    assert second.status_code == 201
    assert second.json()["id"] == first.json()["id"]
    assert first.json()["fingerprint"]
    assert second.json()["status"] == "open"

    with get_conn() as conn:
        count = conn.execute(
            "SELECT COUNT(*) AS count FROM intents WHERE project_id = ? AND to_fact_id IS NULL",
            (project_id,),
        ).fetchone()["count"]
    assert count == 1

    claim = client.post(
        f"/projects/{project_id}/intents/{first.json()['id']}/heartbeat",
        json={"worker": "explore-worker"},
    )
    assert claim.status_code == 200
    assert claim.json()["status"] == "claimed"

    release = client.post(
        f"/projects/{project_id}/intents/{first.json()['id']}/release",
        json={"worker": "explore-worker"},
    )
    assert release.status_code == 200
    assert release.json()["status"] == "open"

    exported = client.get(
        f"/projects/{project_id}/export",
        params={"format": "yaml", "profile": "reason"},
    )
    assert exported.status_code == 200
    data = yaml.safe_load(exported.text)
    assert data["context_profile"]["budgets"]["audit_candidate_limit"] == 200
    assert data["facts"][0]["fact_type"] == "origin"
    assert data["hints"][0]["target"] == "auth"
    assert data["intents"][0]["fingerprint"] == first.json()["fingerprint"]


def test_intent_fingerprint_uses_structured_targets_over_model_wording():
    first = build_intent_fingerprint(
        ["f001"],
        "闭环候选 candidate_ids: cand_1234567890abcdef。source_targets: Less-56/index.php。",
    )
    second = build_intent_fingerprint(
        ["f018"],
        "重新补齐这个候选项的证据，candidate_ids: cand_1234567890abcdef，source_targets: Less-56/index.php。",
    )
    unrelated = build_intent_fingerprint(
        ["f018"],
        "重新补齐另一个候选项的证据，candidate_ids: cand_abcdef1234567890，source_targets: Less-57/index.php。",
    )

    assert first == second
    assert first != unrelated


def test_configure_migrates_existing_core_schema_before_creating_indexes(tmp_path, monkeypatch):
    db_path = tmp_path / "old_core.db"
    with sqlite3.connect(db_path) as conn:
        conn.executescript(
            """
            CREATE TABLE projects (
                id TEXT PRIMARY KEY,
                title TEXT NOT NULL,
                status TEXT NOT NULL DEFAULT 'active',
                created_at TEXT NOT NULL,
                reason_worker TEXT,
                reason_trigger TEXT,
                reason_started_at TEXT,
                reason_last_heartbeat_at TEXT
            );
            CREATE TABLE facts (
                id TEXT NOT NULL,
                project_id TEXT NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
                description TEXT NOT NULL,
                PRIMARY KEY (id, project_id)
            );
            CREATE TABLE intents (
                id TEXT NOT NULL,
                project_id TEXT NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
                to_fact_id TEXT,
                description TEXT NOT NULL,
                creator TEXT NOT NULL,
                worker TEXT,
                last_heartbeat_at TEXT,
                created_at TEXT NOT NULL,
                concluded_at TEXT,
                PRIMARY KEY (id, project_id)
            );
            CREATE TABLE hints (
                id TEXT NOT NULL,
                project_id TEXT NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
                content TEXT NOT NULL,
                creator TEXT NOT NULL,
                created_at TEXT NOT NULL,
                PRIMARY KEY (id, project_id)
            );
            INSERT INTO projects (id, title, status, created_at)
            VALUES ('p1', 'old', 'active', '2026-01-01T00:00:00Z');
            INSERT INTO facts (id, project_id, description)
            VALUES ('origin', 'p1', 'old source');
            INSERT INTO intents (
                id, project_id, to_fact_id, description, creator,
                worker, last_heartbeat_at, created_at, concluded_at
            )
            VALUES (
                'i001', 'p1', NULL, 'old claimed intent', 'worker-1',
                'worker-1', '2026-01-01T00:00:00Z', '2026-01-01T00:00:00Z', NULL
            );
            INSERT INTO hints (id, project_id, content, creator, created_at)
            VALUES ('h001', 'p1', 'old hint', 'user', '2026-01-01T00:00:00Z');
            """
        )

    monkeypatch.setattr(db, "_db_path", None)
    db.configure(db_path)

    with db.get_conn() as conn:
        intent_columns = {
            row["name"] for row in conn.execute("PRAGMA table_info(intents)").fetchall()
        }
        hint_columns = {
            row["name"] for row in conn.execute("PRAGMA table_info(hints)").fetchall()
        }
        status = conn.execute(
            "SELECT status FROM intents WHERE id = 'i001' AND project_id = 'p1'"
        ).fetchone()["status"]
        index_names = {
            row["name"] for row in conn.execute("PRAGMA index_list(intents)").fetchall()
        }

    assert {"fingerprint", "status", "target_kind", "evidence_gap"} <= intent_columns
    assert {"hint_type", "target", "priority", "use_count"} <= hint_columns
    assert status == "claimed"
    assert "idx_intents_open_fingerprint_unique" in index_names


def test_audit_finding_evidence_level_upgrades_after_independent_review(temp_db):
    client = _client()
    project_id = _create_project(client)
    with get_conn() as conn:
        conn.execute(
            """
            INSERT INTO source_snapshots (
                id, project_id, source_type, original_name, status,
                file_count, total_bytes, detected_languages_json, created_at
            )
            VALUES ('snap1', ?, 'zip', 'demo.zip', 'ready', 1, 100, '{}', '2026-01-01T00:00:00Z')
            """,
            (project_id,),
        )

    finding = client.post(
        f"/api/projects/{project_id}/audit-findings",
        json={
            "snapshot_id": "snap1",
            "title": "上传链路缺少扩展名限制",
            "category": "file_upload",
            "severity": "high",
            "file_path": "app/upload.php",
            "line_start": 42,
            "entry_point": "POST /upload",
            "description": "上传文件名直接落盘，缺少扩展名与内容校验",
            "impact": "攻击者可上传可执行脚本并获取服务器权限",
            "evidence": "app/upload.php:42 使用 move_uploaded_file 保存用户文件",
            "proof_packets": [
                {
                    "title": "upload proof",
                    "payload": "shell.php",
                    "request": (
                        "POST /upload HTTP/1.1\n"
                        "Host: audit.local\n"
                        "Content-Type: multipart/form-data; boundary=x\n\n"
                        "--x\nContent-Disposition: form-data; name=\"file\"; filename=\"shell.php\"\n\n"
                        "<?php phpinfo();?>\n--x--"
                    ),
                    "response": "HTTP/1.1 200 OK\nContent-Type: text/plain\n\nuploaded",
                    "note": "源码静态证据与请求模板一致",
                }
            ],
            "discovered_by": "explore-worker",
        },
    )
    assert finding.status_code == 201
    body = finding.json()
    assert body["status"] == "pending_review"
    assert body["evidence_level"] == "L3"

    reviewed = client.post(
        f"/api/projects/{project_id}/audit-findings/{body['id']}/review",
        json={"reviewer": "review-worker", "decision": "confirmed"},
    )
    assert reviewed.status_code == 200
    assert reviewed.json()["status"] == "confirmed"
    assert reviewed.json()["evidence_level"] == "L3"

    exported = client.get(f"/projects/{project_id}/export?format=yaml")
    data = yaml.safe_load(exported.text)
    assert data["audit_findings"][0]["evidence_level"] == "L3"
