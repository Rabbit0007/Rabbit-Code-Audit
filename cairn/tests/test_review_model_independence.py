"""Independent review must consider the backing model, not just the worker name.

These cover the pure identity logic used by the scheduler to exclude reviewers:
two workers backed by the same model share an identity (so neither can review
the other), while different models, different providers, and mock workers are
independent.
"""

from __future__ import annotations

from types import SimpleNamespace

from cairn.dispatcher.config import model_identity, workers_sharing_model


def _w(name, worker_type, **env):
    return SimpleNamespace(name=name, type=worker_type, env=env)


def test_same_pi_endpoint_and_model_share_identity():
    a = _w("audit-1", "pi", PI_BASE_URL="https://x/v1", PI_PROVIDER_API="openai-completions", PI_MODEL="m")
    b = _w("retest-1", "pi", PI_BASE_URL="https://x/v1", PI_PROVIDER_API="openai-completions", PI_MODEL="m")
    assert model_identity(a) == model_identity(b)
    assert workers_sharing_model([a, b], "audit-1") == {"audit-1", "retest-1"}


def test_trailing_slash_on_base_url_does_not_matter():
    a = _w("a", "pi", PI_BASE_URL="https://x/v1/", PI_PROVIDER_API="openai-completions", PI_MODEL="m")
    b = _w("b", "pi", PI_BASE_URL="https://x/v1", PI_PROVIDER_API="openai-completions", PI_MODEL="m")
    assert model_identity(a) == model_identity(b)


def test_different_model_is_independent():
    a = _w("a", "pi", PI_BASE_URL="https://x/v1", PI_PROVIDER_API="openai-completions", PI_MODEL="m1")
    b = _w("b", "pi", PI_BASE_URL="https://x/v1", PI_PROVIDER_API="openai-completions", PI_MODEL="m2")
    assert model_identity(a) != model_identity(b)
    assert workers_sharing_model([a, b], "a") == {"a"}


def test_different_provider_is_independent():
    a = _w("a", "pi", PI_BASE_URL="https://x/v1", PI_PROVIDER_API="openai-completions", PI_MODEL="m")
    b = _w("b", "codex", CODEX_BASE_URL="https://x/v1", CODEX_MODEL="m")
    assert model_identity(a) != model_identity(b)


def test_claudecode_same_model_shares():
    a = _w("a", "claudecode", ANTHROPIC_BASE_URL="https://api.anthropic.com", ANTHROPIC_MODEL="c")
    b = _w("b", "claudecode", ANTHROPIC_BASE_URL="https://api.anthropic.com", ANTHROPIC_MODEL="c")
    assert workers_sharing_model([a, b], "a") == {"a", "b"}


def test_mock_workers_are_always_independent():
    a = _w("mock-1", "mock")
    b = _w("mock-2", "mock")
    assert model_identity(a) != model_identity(b)
    assert workers_sharing_model([a, b], "mock-1") == {"mock-1"}


def test_unknown_name_returns_itself():
    a = _w("a", "pi", PI_BASE_URL="https://x/v1", PI_PROVIDER_API="openai-completions", PI_MODEL="m")
    assert workers_sharing_model([a], "ghost") == {"ghost"}


def test_default_single_model_fleet_all_shares_one_identity():
    # The shipped dispatch.yaml has five roles on one model.  With the flag on,
    # excluding the discoverer would exclude the whole fleet, which is exactly
    # why distinct-model review needs a second model configured.
    fleet = [
        _w(f"gpt-5-6-sol-{role}", "pi", PI_BASE_URL="https://vip.example/v1", PI_PROVIDER_API="openai-completions", PI_MODEL="gpt-5.6-sol")
        for role in ("audit-1", "audit-2", "audit-3", "report-1", "retest-1")
    ]
    assert workers_sharing_model(fleet, "gpt-5-6-sol-audit-1") == {w.name for w in fleet}
