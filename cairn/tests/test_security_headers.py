from __future__ import annotations

from fastapi.testclient import TestClient

from cairn.server.app import app


def test_application_sets_browser_security_headers(temp_db):
    response = TestClient(app).get("/")

    assert response.status_code == 200
    assert response.headers["x-content-type-options"] == "nosniff"
    assert response.headers["x-frame-options"] == "DENY"
    assert response.headers["referrer-policy"] == "no-referrer"
    assert "frame-ancestors 'none'" in response.headers["content-security-policy"]
    assert "camera=()" in response.headers["permissions-policy"]

