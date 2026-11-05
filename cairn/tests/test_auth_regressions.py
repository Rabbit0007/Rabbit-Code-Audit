"""Regression tests for two authentication bugs.

1. With ``CAIRN_INTERNAL_TOKEN`` unset (the normal local-development setup),
   ``require_auth`` used to reject every request, including requests carrying a
   valid session cookie.  Login succeeded, then every API call returned 401 and
   the UI fell back to the login page.  A valid session must be accepted whether
   or not an internal token is configured; machine clients (the dispatcher) must
   still be rejected without a token.

2. bcrypt >= 5.0 raises ``ValueError`` for input longer than 72 bytes, but the
   password validators counted characters.  A multibyte password under the
   character limit therefore passed validation and crashed ``hash_password``
   with a 500.  Over-long passwords must fail validation with a 422.
"""

from __future__ import annotations

import re

import pytest
from fastapi.testclient import TestClient

from cairn.server.middleware.auth import (
    INTERNAL_TOKEN_ENV,
    INTERNAL_TOKEN_HEADER,
    OPEN_AUTH_ENV,
)

from .conftest import BASE_URL

PROTECTED_PATH = "/projects"


def _captcha_payload(client):
    body = client.get("/api/auth/captcha").json()
    nums = [int(value) for value in re.findall(r"\d+", body["question"])]
    return {"captcha_id": body["captcha_id"], "captcha_answer": str(sum(nums))}


def _register(client, username, password):
    return client.post(
        "/api/auth/register",
        json={"username": username, "password": password, **_captcha_payload(client)},
    )


@pytest.fixture
def app_client(temp_db, monkeypatch):
    monkeypatch.delenv(INTERNAL_TOKEN_ENV, raising=False)
    monkeypatch.delenv(OPEN_AUTH_ENV, raising=False)

    from cairn.server.app import app

    with TestClient(app, base_url=BASE_URL) as client:
        yield client


# ---------------------------------------------------------------------------
# Bug 1: valid session must work when no internal token is configured
# ---------------------------------------------------------------------------


def test_valid_session_is_accepted_when_internal_token_is_unset(app_client):
    assert _register(app_client, "alice", "password123").status_code == 201

    assert app_client.get(PROTECTED_PATH).status_code == 200


def test_login_session_survives_across_protected_calls_without_internal_token(app_client):
    _register(app_client, "alice", "password123")
    app_client.post("/api/auth/logout")
    assert app_client.get(PROTECTED_PATH).status_code == 401

    login = app_client.post(
        "/api/auth/login",
        json={
            "username": "alice",
            "password": "password123",
            **_captcha_payload(app_client),
        },
    )
    assert login.status_code == 200
    # The exact sequence from the bug report: login, then several API reads.
    assert app_client.get(PROTECTED_PATH).status_code == 200
    assert app_client.get(PROTECTED_PATH).status_code == 200


def test_unauthenticated_request_is_still_rejected_when_internal_token_is_unset(app_client):
    fresh = TestClient(app_client.app, base_url=BASE_URL)
    assert fresh.get(PROTECTED_PATH).status_code == 401


def test_machine_client_header_is_rejected_when_internal_token_is_unset(app_client):
    fresh = TestClient(app_client.app, base_url=BASE_URL)
    response = fresh.get(PROTECTED_PATH, headers={INTERNAL_TOKEN_HEADER: "guessed-token"})
    assert response.status_code == 401


def test_empty_machine_header_is_rejected_when_internal_token_is_unset(app_client):
    fresh = TestClient(app_client.app, base_url=BASE_URL)
    response = fresh.get(PROTECTED_PATH, headers={INTERNAL_TOKEN_HEADER: ""})
    assert response.status_code == 401


# ---------------------------------------------------------------------------
# Bug 2: bcrypt's 72-byte limit must be enforced as a validation error
# ---------------------------------------------------------------------------


def test_register_rejects_password_over_72_bytes_with_422(app_client):
    # 30 Chinese characters: well under the 72-character limit, 90 bytes.
    response = _register(app_client, "alice", "密" * 30)
    assert response.status_code == 422


def test_register_accepts_password_of_exactly_72_bytes(app_client):
    # 24 Chinese characters == 72 bytes.
    response = _register(app_client, "alice", "密" * 24)
    assert response.status_code == 201


def test_register_accepts_72_ascii_characters_and_rejects_73(app_client):
    assert _register(app_client, "alice", "a" * 72).status_code == 201
    assert _register(app_client, "bobby", "a" * 73).status_code == 422


def test_password_change_rejects_new_password_over_72_bytes_with_422(app_client):
    _register(app_client, "alice", "password123")
    # 100 ASCII characters satisfies the 128-character policy but not bcrypt.
    too_long = "Aa1!" + "x" * 96
    response = app_client.put(
        "/api/auth/password",
        json={"current_password": "password123", "new_password": too_long},
    )
    assert response.status_code == 422


def test_password_change_accepts_new_password_of_72_bytes(app_client):
    _register(app_client, "alice", "password123")
    ok_password = "Aa1!" + "x" * 68  # exactly 72 bytes
    response = app_client.put(
        "/api/auth/password",
        json={"current_password": "password123", "new_password": ok_password},
    )
    assert response.status_code == 204


def test_login_with_over_long_password_is_a_generic_401_not_a_500(app_client):
    _register(app_client, "alice", "password123")
    fresh = TestClient(app_client.app, base_url=BASE_URL)
    response = fresh.post(
        "/api/auth/login",
        json={
            "username": "alice",
            "password": "密" * 40,
            **_captcha_payload(fresh),
        },
    )
    assert response.status_code == 401
