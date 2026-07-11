from __future__ import annotations

from types import SimpleNamespace

from fastapi.testclient import TestClient

from cairn.dispatcher.config import WorkerConfig
from cairn.dispatcher.internal_api import create_internal_app


class _UpstreamResponse:
    status_code = 200
    content = b'{"choices":[{"message":{"content":"pong"}}]}'
    headers = {"content-type": "application/json"}

    def json(self):
        return {
            "id": "req_1",
            "choices": [{"message": {"content": "pong"}}],
            "usage": {
                "prompt_tokens": 100,
                "completion_tokens": 20,
                "total_tokens": 120,
                "prompt_cache_hit_tokens": 40,
            },
        }


class _StreamingUpstreamResponse:
    status_code = 200
    headers = {"content-type": "text/event-stream"}

    def __init__(self):
        self.closed = False

    def iter_content(self, chunk_size):  # noqa: ARG002
        yield b'data: {"id":"req-stream","choices":[{"delta":{"content":"pong"}}]}\n\n'
        yield b'data: {"id":"req-stream","choices":[],"usage":{"prompt_tokens":80,"completion_tokens":10,"total_tokens":90}}\n\n'
        yield b"data: [DONE]\n\n"

    def close(self):
        self.closed = True


def test_model_proxy_keeps_upstream_key_out_of_worker_request(monkeypatch):
    monkeypatch.setenv("CAIRN_MODEL_PROXY_TOKEN", "scoped-worker-token")
    worker = WorkerConfig(
        name="reviewer",
        type="pi",
        enabled=True,
        task_types=["review"],
        max_running=1,
        priority=0,
        env={
            "PI_MODEL": "deepseek-v4-pro",
            "PI_BASE_URL": "https://api.deepseek.com",
            "PI_API_KEY": "real-upstream-secret",
            "PI_PROVIDER_API": "openai-completions",
            "PI_INPUT_COST_PER_MILLION": "1",
            "PI_OUTPUT_COST_PER_MILLION": "2",
            "PI_CACHED_INPUT_COST_PER_MILLION": "0.2",
        },
    )
    usage_records = []
    loop = SimpleNamespace(
        config=SimpleNamespace(workers=[worker]),
        container_manager=SimpleNamespace(project_id_for_ip=lambda ip: "proj_1"),
        client=SimpleNamespace(
            record_model_usage=lambda payload: (
                usage_records.append(payload)
                or SimpleNamespace(ok=True, status_code=201)
            )
        ),
    )
    captured = {}

    def fake_post(url, **kwargs):
        captured["url"] = url
        captured.update(kwargs)
        return _UpstreamResponse()

    monkeypatch.setattr("cairn.dispatcher.internal_api.requests.post", fake_post)
    client = TestClient(create_internal_app(loop))
    response = client.post(
        "/internal/model-proxy/v1/chat/completions",
        headers={"Authorization": "Bearer scoped-worker-token"},
        json={
            "model": "deepseek-v4-pro",
            "messages": [{"role": "user", "content": "ping"}],
        },
    )

    assert response.status_code == 200
    assert captured["url"] == "https://api.deepseek.com/v1/chat/completions"
    assert captured["headers"]["Authorization"] == "Bearer real-upstream-secret"
    assert "real-upstream-secret" not in response.text
    assert usage_records[0]["prompt_tokens"] == 100
    assert usage_records[0]["completion_tokens"] == 20
    assert usage_records[0]["estimated"] is False
    assert usage_records[0]["cost_usd"] > 0


def test_model_proxy_rejects_missing_scoped_token(monkeypatch):
    monkeypatch.setenv("CAIRN_MODEL_PROXY_TOKEN", "scoped-worker-token")
    loop = SimpleNamespace(config=SimpleNamespace(workers=[]))
    client = TestClient(create_internal_app(loop))

    response = client.post(
        "/internal/model-proxy/v1/chat/completions",
        json={"model": "anything", "messages": []},
    )

    assert response.status_code == 401


def test_streaming_model_proxy_requests_and_records_final_usage(monkeypatch):
    monkeypatch.setenv("CAIRN_MODEL_PROXY_TOKEN", "scoped-worker-token")
    worker = WorkerConfig(
        name="reasoner",
        type="pi",
        enabled=True,
        task_types=["reason"],
        max_running=1,
        priority=0,
        env={
            "PI_MODEL": "deepseek-v4-pro",
            "PI_BASE_URL": "https://api.deepseek.com",
            "PI_API_KEY": "secret",
            "PI_PROVIDER_API": "openai-completions",
        },
    )
    usage_records = []
    upstream = _StreamingUpstreamResponse()
    captured = {}

    def fake_post(url, **kwargs):  # noqa: ARG001
        captured.update(kwargs)
        return upstream

    loop = SimpleNamespace(
        config=SimpleNamespace(workers=[worker]),
        container_manager=SimpleNamespace(project_id_for_ip=lambda ip: "proj-stream"),
        client=SimpleNamespace(
            record_model_usage=lambda payload: (
                usage_records.append(payload)
                or SimpleNamespace(ok=True, status_code=201)
            )
        ),
    )
    monkeypatch.setattr("cairn.dispatcher.internal_api.requests.post", fake_post)

    response = TestClient(create_internal_app(loop)).post(
        "/internal/model-proxy/v1/chat/completions",
        headers={"Authorization": "Bearer scoped-worker-token"},
        json={"model": "deepseek-v4-pro", "messages": [], "stream": True},
    )

    assert response.status_code == 200
    assert captured["json"]["stream_options"]["include_usage"] is True
    assert captured["stream"] is True
    assert usage_records[0]["request_id"] == "req-stream"
    assert usage_records[0]["total_tokens"] == 90
    assert usage_records[0]["estimated"] is False
    assert upstream.closed is True
