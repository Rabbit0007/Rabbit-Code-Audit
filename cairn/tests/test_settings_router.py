from __future__ import annotations

import sqlite3
from types import SimpleNamespace

from fastapi import FastAPI
from fastapi.testclient import TestClient

from cairn.server import db
from cairn.server.db import get_conn
from cairn.server.routers import settings as settings_router
from cairn.server.settings_service import load_settings

from .conftest import BASE_URL


def _client() -> TestClient:
    app = FastAPI()
    app.include_router(settings_router.router)
    return TestClient(app, base_url=BASE_URL)


def test_settings_endpoint_matches_8000_shape_and_persists(temp_db):
    client = _client()

    defaults = client.get("/settings")
    assert defaults.status_code == 200
    body = defaults.json()
    assert body == {
        "intent_timeout": 15,
        "reason_timeout": 15,
        "worker_unhealthy_retry_after_seconds": 5,
        "worker_rejected_retry_after_seconds": 5,
        "max_failed_login_attempts": 5,
        "rate_limit_window_minutes": 15,
        "session_duration_hours": 24,
        "log_retention_days": 30,
        "export_retention_days": 30,
        "notification_retention_days": 14,
        "project_idle_alert_hours": 12,
    }

    updated = dict(body)
    updated.update(
        {
            "worker_unhealthy_retry_after_seconds": 7,
            "worker_rejected_retry_after_seconds": 9,
            "max_failed_login_attempts": 3,
            "session_duration_hours": 12,
            "project_idle_alert_hours": 6,
        }
    )
    response = client.put("/settings", json=updated)

    assert response.status_code == 200
    assert response.json() == updated
    with get_conn() as conn:
        stored = load_settings(conn)
        audit_count = conn.execute("SELECT COUNT(*) AS n FROM audit_log WHERE action = 'settings.update'").fetchone()["n"]
        notification_count = conn.execute("SELECT COUNT(*) AS n FROM notifications WHERE title = '系统设置已更新'").fetchone()["n"]
    assert stored.worker_unhealthy_retry_after_seconds == 7
    assert stored.worker_rejected_retry_after_seconds == 9
    assert stored.max_failed_login_attempts == 3
    assert stored.session_duration_hours == 12
    assert audit_count == 1
    assert notification_count == 1


def test_settings_health_reports_dispatcher_and_database(temp_db, monkeypatch):
    client = _client()
    monkeypatch.setattr(
        settings_router,
        "_fetch_dispatcher_snapshot",
        lambda: (
            {
                "runtime": {
                    "interval": 3,
                    "running_task_count": 0,
                    "max_workers": 5,
                    "running_project_count": 0,
                },
                "workers": [
                    {"name": "gpt-5.5-1", "enabled": True, "status": "idle"},
                    {"name": "review-gpt55-1", "enabled": True, "status": "busy"},
                    {"name": "old-worker", "enabled": False, "status": "disabled"},
                ],
            },
            None,
        ),
    )

    response = client.get("/settings/health")

    assert response.status_code == 200
    body = response.json()
    assert body["summary"]["status"] == "ok"
    assert body["summary"]["dispatcher_reachable"] is True
    assert body["summary"]["online_workers"] == 2
    assert body["summary"]["offline_workers"] == 0
    assert {check["key"] for check in body["checks"]} >= {"server", "database", "dispatcher", "workers", "auth", "retention"}


def test_dispatcher_health_requests_include_internal_token(monkeypatch):
    monkeypatch.setenv("CAIRN_DISPATCHER_INTERNAL_TOKEN", "dispatcher-secret")
    seen: list[dict[str, str]] = []

    def fake_get(url, *, timeout, headers):
        seen.append(dict(headers))
        payload = {"workers": []} if url.endswith("/internal/status") else {"ok": True}
        return SimpleNamespace(status_code=200, json=lambda: payload)

    monkeypatch.setattr(settings_router.requests, "get", fake_get)

    snapshot, error = settings_router._fetch_dispatcher_snapshot()

    assert error is None
    assert snapshot == {"workers": []}
    assert seen == [
        {"X-Cairn-Dispatcher-Internal-Token": "dispatcher-secret"},
        {"X-Cairn-Dispatcher-Internal-Token": "dispatcher-secret"},
    ]


def test_configure_migrates_legacy_settings_columns(tmp_path, monkeypatch):
    db_path = tmp_path / "legacy_settings.db"
    with sqlite3.connect(db_path) as conn:
        conn.executescript(
            """
            CREATE TABLE settings (
                intent_timeout INTEGER NOT NULL DEFAULT 15,
                reason_timeout INTEGER NOT NULL DEFAULT 15
            );
            INSERT INTO settings (rowid, intent_timeout, reason_timeout)
            VALUES (1, 21, 22);
            """
        )

    monkeypatch.setattr(db, "_db_path", None)
    db.configure(db_path)

    with db.get_conn() as conn:
        columns = {row["name"] for row in conn.execute("PRAGMA table_info(settings)").fetchall()}
        loaded = load_settings(conn)

    assert {
        "worker_unhealthy_retry_after_seconds",
        "worker_rejected_retry_after_seconds",
        "max_failed_login_attempts",
        "rate_limit_window_minutes",
        "session_duration_hours",
        "log_retention_days",
        "export_retention_days",
        "notification_retention_days",
        "project_idle_alert_hours",
    } <= columns
    assert loaded.intent_timeout == 21
    assert loaded.reason_timeout == 22
    assert loaded.session_duration_hours == 24
