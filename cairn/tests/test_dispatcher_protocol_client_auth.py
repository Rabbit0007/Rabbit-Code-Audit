from __future__ import annotations

from cairn.dispatcher.protocol.client import CairnClient, INTERNAL_TOKEN_HEADER


def test_cairn_client_applies_internal_token_header(monkeypatch):
    monkeypatch.setenv("CAIRN_INTERNAL_TOKEN", "server-secret")
    client = CairnClient("http://server")

    session = client._session()

    assert session.headers[INTERNAL_TOKEN_HEADER] == "server-secret"
    client.close()


def test_cairn_client_removes_internal_token_header_when_unset(monkeypatch):
    monkeypatch.setenv("CAIRN_INTERNAL_TOKEN", "server-secret")
    client = CairnClient("http://server")
    session = client._session()
    assert session.headers[INTERNAL_TOKEN_HEADER] == "server-secret"

    monkeypatch.delenv("CAIRN_INTERNAL_TOKEN", raising=False)
    assert client._session() is session
    assert INTERNAL_TOKEN_HEADER not in session.headers
    client.close()
